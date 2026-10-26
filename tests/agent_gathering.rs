mod common;

use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use common::{agent_config, bound_socket, channel_sink, peer_config, stun_server, FakeTurn};
use ice::{CandidateType, GatherState, IceAgent, IceRole, TransportPolicy};

#[test]
fn server_reflexive_candidate_is_learned_on_the_host_socket() {
    let mapped: SocketAddr = "203.0.113.20:40000".parse().unwrap();
    let stun = stun_server(Some(mapped));
    let mut config = agent_config(IceRole::Controlling);
    config
        .stun_servers
        .push(stun::Endpoint::new("127.0.0.1", stun.server.addr.port()));
    let agent = IceAgent::new(config).unwrap();
    let (tx, rx) = mpsc::channel();
    agent.on_local_candidate(move |c| {
        let _ = tx.send(c);
    });

    agent.start_gathering().unwrap();
    agent.wait_for_gathering(Duration::from_secs(5)).unwrap();

    let host = agent.local_addr().unwrap();
    let srflx = agent
        .local_candidates()
        .into_iter()
        .find(|c| c.typ == CandidateType::ServerReflexive)
        .expect("server-reflexive candidate");
    assert_eq!(srflx.addr, mapped);
    assert_eq!(srflx.base, host);
    assert_eq!(srflx.related, Some(host));
    let sources = stun.sources.lock().unwrap().clone();
    assert!(!sources.is_empty());
    assert!(sources.iter().all(|source| *source == host), "{sources:?}");

    let announced: Vec<CandidateType> = rx.try_iter().map(|c| c.typ).collect();
    assert_eq!(
        announced,
        vec![CandidateType::Host, CandidateType::ServerReflexive]
    );
}

#[test]
fn redundant_server_reflexive_candidate_is_dropped() {
    let stun = stun_server(None);
    let mut config = agent_config(IceRole::Controlling);
    config
        .stun_servers
        .push(stun::Endpoint::new("127.0.0.1", stun.server.addr.port()));
    let agent = IceAgent::new(config).unwrap();
    agent.start_gathering().unwrap();
    agent.wait_for_gathering(Duration::from_secs(5)).unwrap();
    assert!(!stun.sources.lock().unwrap().is_empty());
    let candidates = agent.local_candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].typ, CandidateType::Host);
}

#[test]
fn silent_stun_server_does_not_block_gathering() {
    let silent = bound_socket();
    let mut config = agent_config(IceRole::Controlling);
    config.stun_servers.push(stun::Endpoint::new(
        "127.0.0.1",
        silent.local_addr().unwrap().port(),
    ));
    let agent = IceAgent::new(config).unwrap();
    let started = Instant::now();
    agent.start_gathering().unwrap();
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(agent.local_candidates().len(), 1);
    assert_eq!(agent.gathering_state(), GatherState::Gathering);
}

#[test]
fn relay_candidate_is_allocated_on_the_host_socket_and_kept_alive() {
    let turn = FakeTurn::spawn();
    let mut config = agent_config(IceRole::Controlling);
    config.turn_servers.push(turn.config());
    let agent = IceAgent::new(config).unwrap();
    agent.start_gathering().unwrap();
    agent.wait_for_gathering(Duration::from_secs(5)).unwrap();

    let relay = agent
        .local_candidates()
        .into_iter()
        .find(|c| c.typ == CandidateType::Relayed)
        .expect("relayed candidate");
    assert_eq!(relay.addr, turn.relay_addr);
    assert_eq!(relay.base, turn.relay_addr);
    assert_eq!(relay.server, Some(turn.addr));
    assert_eq!(
        turn.state.lock().unwrap().client,
        Some(agent.local_addr().unwrap())
    );

    thread::sleep(Duration::from_millis(300));
    assert!(!turn.state.lock().unwrap().released);

    let started = Instant::now();
    drop(agent);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert!(turn.state.lock().unwrap().released);
}

#[test]
fn relayed_pair_carries_checks_and_media() {
    let turn = FakeTurn::spawn();
    let mut config_a = agent_config(IceRole::Controlling);
    config_a.policy = TransportPolicy::Relay;
    config_a.turn_servers.push(turn.config());
    let agent_a = IceAgent::new(config_a).unwrap();
    let agent_b = IceAgent::new(peer_config(IceRole::Controlled)).unwrap();
    let (sink_a, rx_a) = channel_sink();
    let (sink_b, rx_b) = channel_sink();
    agent_a.set_packet_sink(sink_a);
    agent_b.set_packet_sink(sink_b);

    agent_a.start_gathering().unwrap();
    agent_b.start_gathering().unwrap();
    agent_a.wait_for_gathering(Duration::from_secs(5)).unwrap();
    agent_b.wait_for_gathering(Duration::from_secs(5)).unwrap();

    let a_candidates = agent_a.local_candidates();
    assert_eq!(a_candidates.len(), 1);
    assert_eq!(a_candidates[0].typ, CandidateType::Relayed);
    for c in a_candidates {
        agent_b.add_remote_candidate(c).unwrap();
    }
    for c in agent_b.local_candidates() {
        agent_a.add_remote_candidate(c).unwrap();
    }
    for agent in [&agent_a, &agent_b] {
        agent.end_of_candidates();
        agent.remote_end_of_candidates();
    }

    let (local_a, remote_a) = agent_a
        .wait_for_selected_pair(Duration::from_secs(10))
        .unwrap();
    let (local_b, remote_b) = agent_b
        .wait_for_selected_pair(Duration::from_secs(10))
        .unwrap();
    let b_addr = agent_b.local_addr().unwrap();
    assert_eq!(local_a.typ, CandidateType::Relayed);
    assert_eq!(remote_a.addr, b_addr);
    assert_eq!(local_b.addr, b_addr);
    assert_eq!(remote_b.addr, turn.relay_addr);
    assert!(turn
        .state
        .lock()
        .unwrap()
        .permissions
        .contains(&b_addr.ip()));

    agent_a.send_on_selected(&[23, 1, 2, 3]).unwrap();
    let (_, bytes, from) = rx_b.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(bytes, vec![23, 1, 2, 3]);
    assert_eq!(from, turn.relay_addr);

    agent_b.send_on_selected(&[23, 9, 8, 7]).unwrap();
    let (_, bytes, from) = rx_a.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(bytes, vec![23, 9, 8, 7]);
    assert_eq!(from, b_addr);
    assert!(rx_a.try_recv().is_err());
    assert!(rx_b.try_recv().is_err());
}

#[test]
fn callbacks_may_reenter_the_agent_and_panics_are_contained() {
    let mapped: SocketAddr = "203.0.113.21:40001".parse().unwrap();
    let stun = stun_server(Some(mapped));
    let mut config = agent_config(IceRole::Controlling);
    config
        .stun_servers
        .push(stun::Endpoint::new("127.0.0.1", stun.server.addr.port()));
    let agent = std::sync::Arc::new(IceAgent::new(config).unwrap());
    let weak = std::sync::Arc::downgrade(&agent);
    let (tx, rx) = mpsc::channel();
    agent.on_local_candidate(move |c| {
        let Some(agent) = weak.upgrade() else {
            return;
        };
        tx.send((
            c.typ,
            agent.local_candidates().len(),
            agent.gathering_state(),
        ))
        .unwrap();
        assert!(c.typ != CandidateType::Host, "a panicking callback");
    });
    agent.start_gathering().unwrap();
    agent.wait_for_gathering(Duration::from_secs(5)).unwrap();
    let events: Vec<_> = rx.try_iter().collect();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].0, CandidateType::Host);
    assert_eq!(events[1].0, CandidateType::ServerReflexive);
    assert_eq!(events[1].1, 2);
    assert_eq!(agent.local_candidates().len(), 2);
}

#[test]
fn refused_permissions_fail_relayed_pairs_instead_of_stalling() {
    let turn = FakeTurn::spawn_with(|state| state.refuse_permissions = true);
    let mut config_a = agent_config(IceRole::Controlling);
    config_a.policy = TransportPolicy::Relay;
    config_a.turn_servers.push(turn.config());
    let agent_a = IceAgent::new(config_a).unwrap();
    let agent_b = IceAgent::new(peer_config(IceRole::Controlled)).unwrap();
    agent_a.start_gathering().unwrap();
    agent_b.start_gathering().unwrap();
    agent_a.wait_for_gathering(Duration::from_secs(5)).unwrap();
    for c in agent_b.local_candidates() {
        agent_a.add_remote_candidate(c).unwrap();
    }
    agent_a.remote_end_of_candidates();

    assert!(matches!(
        agent_a.wait_for_selected_pair(Duration::from_secs(5)),
        Err(ice::Error::Failed)
    ));
    assert!(agent_a.stats().relay_errors >= 1);

    let late = bound_socket();
    agent_a
        .add_remote_candidate(ice::Candidate::host(
            late.local_addr().unwrap(),
            ice::ComponentId::RTP,
        ))
        .unwrap();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        turn.state
            .lock()
            .unwrap()
            .count(turn::Method::CreatePermission),
        1
    );
}

#[test]
fn failing_relay_maintenance_backs_off() {
    let turn = FakeTurn::spawn_with(|state| {
        state.lifetime = 2;
        state.refresh_error = Some(403);
    });
    let mut config = agent_config(IceRole::Controlling);
    config.turn_servers.push(turn.config());
    let agent = IceAgent::new(config).unwrap();
    agent.start_gathering().unwrap();
    agent.wait_for_gathering(Duration::from_secs(5)).unwrap();
    thread::sleep(Duration::from_millis(3500));
    let refreshes = turn.state.lock().unwrap().count(turn::Method::Refresh);
    assert!((1..=4).contains(&refreshes), "{refreshes} refreshes");
    assert!(agent.stats().relay_errors >= 1);
}
