mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use common::{
    agent_config, bound_socket, channel_sink, check_to_agent, error, is_check_from_agent,
    peer_config, recv_stun, success, wait_until, CheckOptions, Scripted, AGENT_PWD, PEER_PWD,
};
use ice::check::{response_error_code, verify_integrity, Integrity};
use ice::{IceAgent, IceRole, IntegrityMode};
use stun::attribute::types;
use stun::Attribute;

fn controlling_agent_with(peer: &Scripted) -> IceAgent {
    let agent = IceAgent::new(agent_config(IceRole::Controlling)).unwrap();
    agent.add_remote_candidate(peer.candidate()).unwrap();
    agent.start_gathering().unwrap();
    agent
}

#[test]
fn forged_role_conflict_is_ignored() {
    let first = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&first);
    let peer = Scripted::spawn(bound_socket(), move |socket, message, from| {
        if !is_check_from_agent(message) {
            return;
        }
        if seen.fetch_add(1, Ordering::SeqCst) == 0 {
            socket
                .send_to(&error(message, 487, Some("not the agent password")), from)
                .unwrap();
            socket.send_to(&error(message, 487, None), from).unwrap();
            thread::sleep(Duration::from_millis(30));
        }
        socket
            .send_to(&success(message, from, PEER_PWD), from)
            .unwrap();
    });
    let agent = controlling_agent_with(&peer);
    agent
        .wait_for_selected_pair(Duration::from_secs(5))
        .unwrap();
    assert_eq!(agent.role(), IceRole::Controlling);
    assert!(agent.stats().ignored_unauthenticated_responses >= 2);
}

#[test]
fn forged_success_does_not_strand_the_pair() {
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    let peer = Scripted::spawn(bound_socket(), move |socket, message, from| {
        if !is_check_from_agent(message) {
            return;
        }
        if seen.fetch_add(1, Ordering::SeqCst) == 0 {
            socket
                .send_to(&success(message, from, "wrong password for sure"), from)
                .unwrap();
            thread::sleep(Duration::from_millis(30));
        }
        socket
            .send_to(&success(message, from, PEER_PWD), from)
            .unwrap();
    });
    let agent = controlling_agent_with(&peer);
    let (_, remote) = agent
        .wait_for_selected_pair(Duration::from_secs(5))
        .unwrap();
    assert_eq!(remote.addr, peer.addr);
    assert!(agent.stats().ignored_unauthenticated_responses >= 1);
}

#[test]
fn response_from_another_address_fails_the_pair() {
    let other = bound_socket();
    let peer = Scripted::spawn(bound_socket(), move |_, message, from| {
        if is_check_from_agent(message) {
            other
                .send_to(&success(message, from, PEER_PWD), from)
                .unwrap();
        }
    });
    let agent = controlling_agent_with(&peer);
    assert!(wait_until(Duration::from_secs(2), || {
        agent.stats().asymmetric_responses >= 1
    }));
    thread::sleep(Duration::from_millis(300));
    assert!(agent.selected_pair().is_none());
}

#[test]
fn off_path_packets_never_reach_the_sink() {
    let agent_a = IceAgent::new(agent_config(IceRole::Controlling)).unwrap();
    let agent_b = IceAgent::new(peer_config(IceRole::Controlled)).unwrap();
    let (sink, rx) = channel_sink();
    agent_a.set_packet_sink(sink);
    agent_a.start_gathering().unwrap();
    agent_b.start_gathering().unwrap();
    for c in agent_a.local_candidates() {
        agent_b.add_remote_candidate(c).unwrap();
    }
    for c in agent_b.local_candidates() {
        agent_a.add_remote_candidate(c).unwrap();
    }
    agent_a
        .wait_for_selected_pair(Duration::from_secs(5))
        .unwrap();
    agent_b
        .wait_for_selected_pair(Duration::from_secs(5))
        .unwrap();

    let attacker = bound_socket();
    let target = agent_a.local_addr().unwrap();
    for _ in 0..5 {
        attacker.send_to(&[22, 0xfe, 0xfd, 0, 0], target).unwrap();
        attacker.send_to(&[0x80, 0x60, 0, 1], target).unwrap();
    }
    agent_b.send_on_selected(&[22, 0xfe, 0xfd, 1, 1]).unwrap();

    let (kind, bytes, from) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(kind, ice::PacketKind::Dtls);
    assert_eq!(bytes, vec![22, 0xfe, 0xfd, 1, 1]);
    assert_eq!(from, agent_b.local_addr().unwrap());
    assert!(wait_until(Duration::from_secs(1), || {
        agent_a.stats().dropped_unexpected_source >= 10
    }));
    assert!(rx.try_recv().is_err());
}

#[test]
fn controlling_agent_ignores_use_candidate() {
    let nominations = Arc::new(AtomicUsize::new(0));
    let sent = Arc::clone(&nominations);
    let peer = Scripted::spawn(bound_socket(), move |socket, message, from| {
        if !is_check_from_agent(message) || message.get(types::USE_CANDIDATE).is_some() {
            return;
        }
        socket
            .send_to(&success(message, from, PEER_PWD), from)
            .unwrap();
        if sent.load(Ordering::SeqCst) < 3 {
            let (_, check) = check_to_agent(CheckOptions {
                use_candidate: true,
                ..CheckOptions::default()
            });
            socket.send_to(&check, from).unwrap();
            sent.fetch_add(1, Ordering::SeqCst);
        }
    });
    let agent = controlling_agent_with(&peer);
    assert!(wait_until(Duration::from_secs(3), || {
        nominations.load(Ordering::SeqCst) >= 1
    }));
    thread::sleep(Duration::from_millis(500));
    assert!(agent.selected_pair().is_none());
    assert_eq!(agent.role(), IceRole::Controlling);
}

#[test]
fn role_conflict_reply_uses_the_request_integrity() {
    let agent = IceAgent::new(agent_config(IceRole::Controlling)).unwrap();
    agent.start_gathering().unwrap();
    let target = agent.local_addr().unwrap();
    let conflicting = bound_socket();

    let (_, sha1_check) = check_to_agent(CheckOptions {
        role: Attribute::IceControlling(0),
        ..CheckOptions::default()
    });
    conflicting.send_to(&sha1_check, target).unwrap();
    let (reply, _) = recv_stun(&conflicting, Duration::from_secs(2)).unwrap();
    assert_eq!(response_error_code(&reply), Some(487));
    assert!(reply.get(types::MESSAGE_INTEGRITY).is_some());
    assert!(reply.get(types::MESSAGE_INTEGRITY_SHA256).is_none());
    assert_eq!(
        verify_integrity(&reply, AGENT_PWD, IntegrityMode::Sha1).unwrap(),
        Integrity::Sha1
    );

    let (_, sha256_check) = check_to_agent(CheckOptions {
        role: Attribute::IceControlling(0),
        sha256: true,
        ..CheckOptions::default()
    });
    conflicting.send_to(&sha256_check, target).unwrap();
    let (reply, _) = recv_stun(&conflicting, Duration::from_secs(2)).unwrap();
    assert_eq!(response_error_code(&reply), Some(487));
    assert!(reply.get(types::MESSAGE_INTEGRITY).is_none());
    assert_eq!(
        verify_integrity(&reply, AGENT_PWD, IntegrityMode::Sha256).unwrap(),
        Integrity::Sha256
    );
    assert_eq!(agent.role(), IceRole::Controlling);
}

#[test]
fn checks_carry_only_sha1_integrity_by_default() {
    let peer_socket = bound_socket();
    let peer_addr = peer_socket.local_addr().unwrap();
    let agent = IceAgent::new(agent_config(IceRole::Controlling)).unwrap();
    agent.add_remote_candidate(common::host(peer_addr)).unwrap();
    agent.start_gathering().unwrap();
    let (check, _) = recv_stun(&peer_socket, Duration::from_secs(2)).unwrap();
    assert!(is_check_from_agent(&check));
    assert!(check.get(types::MESSAGE_INTEGRITY).is_some());
    assert!(check.get(types::MESSAGE_INTEGRITY_SHA256).is_none());
    assert!(matches!(
        check.get(types::PRIORITY),
        Some(Attribute::Priority(p)) if p >> 24 == 110
    ));
}

#[test]
fn unknown_comprehension_required_attribute_gets_420() {
    let agent = IceAgent::new(agent_config(IceRole::Controlled)).unwrap();
    agent.start_gathering().unwrap();
    let sender = bound_socket();
    let (_, check) = check_to_agent(CheckOptions {
        extra: vec![Attribute::Unknown {
            attribute_type: 0x7777,
            value: vec![0; 4],
        }],
        ..CheckOptions::default()
    });
    sender.send_to(&check, agent.local_addr().unwrap()).unwrap();
    let (reply, _) = recv_stun(&sender, Duration::from_secs(2)).unwrap();
    assert_eq!(response_error_code(&reply), Some(420));
    assert_eq!(
        reply.get(types::UNKNOWN_ATTRIBUTES),
        Some(&Attribute::UnknownAttributes(vec![0x7777]))
    );
    assert!(verify_integrity(&reply, AGENT_PWD, IntegrityMode::Sha1).is_ok());
}

#[test]
fn unauthenticated_requests_get_no_answer() {
    let agent = IceAgent::new(agent_config(IceRole::Controlled)).unwrap();
    agent.start_gathering().unwrap();
    let sender = bound_socket();
    let (_, check) = check_to_agent(CheckOptions {
        pwd: "definitely the wrong one",
        ..CheckOptions::default()
    });
    sender.send_to(&check, agent.local_addr().unwrap()).unwrap();
    assert!(recv_stun(&sender, Duration::from_millis(400)).is_none());
    assert_eq!(agent.stats().rejected_requests, 1);
}

fn nat_peer(
    answer_nominations: Arc<std::sync::atomic::AtomicBool>,
    dropped: Arc<AtomicUsize>,
) -> (Scripted, std::net::UdpSocket) {
    let socket = bound_socket();
    let sender = socket.try_clone().unwrap();
    let mapped: std::net::SocketAddr = "203.0.113.9:1234".parse().unwrap();
    let peer = Scripted::spawn(socket, move |socket, message, from| {
        if !is_check_from_agent(message) {
            return;
        }
        if message.get(types::USE_CANDIDATE).is_some() && !answer_nominations.load(Ordering::SeqCst)
        {
            dropped.fetch_add(1, Ordering::SeqCst);
            return;
        }
        socket
            .send_to(&success(message, mapped, PEER_PWD), from)
            .unwrap();
    });
    (peer, sender)
}

fn exhaust_retransmissions(clock: &common::ManualClock) {
    for _ in 0..10 {
        clock.advance(Duration::from_secs(20));
        thread::sleep(Duration::from_millis(80));
    }
}

#[test]
fn failed_nomination_behind_nat_reports_failure() {
    let answer = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dropped = Arc::new(AtomicUsize::new(0));
    let (peer, _sender) = nat_peer(Arc::clone(&answer), Arc::clone(&dropped));
    let clock = common::ManualClock::new();
    let mut config = agent_config(IceRole::Controlling);
    config.clock = clock.clone();
    let agent = IceAgent::new(config).unwrap();
    let (tx, failed) = std::sync::mpsc::channel();
    agent.on_connection_failed(move || {
        let _ = tx.send(());
    });
    agent.add_remote_candidate(peer.candidate()).unwrap();
    agent.remote_end_of_candidates();
    agent.start_gathering().unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        dropped.load(Ordering::SeqCst) >= 1
    }));
    assert!(agent
        .local_candidates()
        .iter()
        .all(|c| c.typ == ice::CandidateType::Host));

    exhaust_retransmissions(&clock);
    failed
        .recv_timeout(Duration::from_secs(2))
        .expect("the failed nomination ends ICE instead of stalling");
    assert!(agent.selected_pair().is_none());
}

#[test]
fn failed_nomination_recovers_when_the_peer_checks_again() {
    let answer = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dropped = Arc::new(AtomicUsize::new(0));
    let (peer, sender) = nat_peer(Arc::clone(&answer), Arc::clone(&dropped));
    let clock = common::ManualClock::new();
    let mut config = agent_config(IceRole::Controlling);
    config.clock = clock.clone();
    let agent = IceAgent::new(config).unwrap();
    agent.add_remote_candidate(peer.candidate()).unwrap();
    agent.start_gathering().unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        dropped.load(Ordering::SeqCst) >= 1
    }));

    exhaust_retransmissions(&clock);
    assert!(agent.selected_pair().is_none());
    answer.store(true, Ordering::SeqCst);
    let (_, check) = check_to_agent(CheckOptions::default());
    sender.send_to(&check, agent.local_addr().unwrap()).unwrap();

    let (local, remote) = agent
        .wait_for_selected_pair(Duration::from_secs(5))
        .unwrap();
    assert_eq!(remote.addr, peer.addr);
    assert_eq!(local.typ, ice::CandidateType::PeerReflexive);
    assert_eq!(local.addr, "203.0.113.9:1234".parse().unwrap());
}
