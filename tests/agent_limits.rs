mod common;

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use common::{
    agent_config, bound_socket, check_to_agent, host, recv_stun, wait_until, CheckOptions,
};
use ice::{Candidate, ComponentId, Error, IceAgent, IceRole, Transport};
use stun::Class;

fn silent_remotes(count: usize) -> Vec<UdpSocket> {
    (0..count).map(|_| bound_socket()).collect()
}

fn addr(socket: &UdpSocket) -> SocketAddr {
    socket.local_addr().unwrap()
}

#[test]
fn remote_candidate_limit_is_enforced() {
    let mut config = agent_config(IceRole::Controlling);
    config.limits.max_remote_candidates = 2;
    let agent = IceAgent::new(config).unwrap();
    let remotes = silent_remotes(3);
    agent.add_remote_candidate(host(addr(&remotes[0]))).unwrap();
    agent.add_remote_candidate(host(addr(&remotes[1]))).unwrap();
    agent.add_remote_candidate(host(addr(&remotes[1]))).unwrap();
    assert!(matches!(
        agent.add_remote_candidate(host(addr(&remotes[2]))),
        Err(Error::Limit(_))
    ));
    assert_eq!(agent.stats().rejected_candidates, 1);
}

#[test]
fn unusable_remote_candidates_are_rejected() {
    let agent = IceAgent::new(agent_config(IceRole::Controlling)).unwrap();
    for bad in [
        "127.0.0.1:0",
        "0.0.0.0:5000",
        "224.0.0.1:5000",
        "255.255.255.255:5000",
        "[ff02::1]:5000",
        "[::]:5000",
    ] {
        let result = agent.add_remote_candidate(host(bad.parse().unwrap()));
        assert!(
            matches!(result, Err(Error::Unsupported(_))),
            "{bad}: {result:?}"
        );
    }
    let remote = bound_socket();
    let mut tcp = host(addr(&remote));
    tcp.transport = Transport::Tcp;
    assert!(matches!(
        agent.add_remote_candidate(tcp),
        Err(Error::Unsupported(_))
    ));
    let rtcp = Candidate::host(addr(&remote), ComponentId::RTCP);
    assert!(matches!(
        agent.add_remote_candidate(rtcp),
        Err(Error::Unsupported(_))
    ));
    assert_eq!(agent.stats().rejected_candidates, 8);
}

#[test]
fn pair_limit_is_enforced() {
    let mut config = agent_config(IceRole::Controlling);
    config.limits.max_pairs = 2;
    let agent = IceAgent::new(config).unwrap();
    agent.start_gathering().unwrap();
    let remotes = silent_remotes(4);
    for (index, remote) in remotes.iter().enumerate() {
        let mut candidate = host(addr(remote));
        candidate.foundation = format!("remote{index}");
        agent.add_remote_candidate(candidate).unwrap();
    }
    assert_eq!(agent.stats().dropped_pairs, 2);
    let contacted: Vec<bool> = remotes
        .iter()
        .map(|remote| recv_stun(remote, Duration::from_millis(600)).is_some())
        .collect();
    assert_eq!(contacted, vec![true, true, false, false]);
}

#[test]
fn peer_reflexive_candidates_are_capped() {
    let mut config = agent_config(IceRole::Controlled);
    config.limits.max_peer_reflexive = 2;
    let agent = IceAgent::new(config).unwrap();
    agent.start_gathering().unwrap();
    let target = agent.local_addr().unwrap();
    let senders = silent_remotes(5);
    for sender in &senders {
        let (tid, check) = check_to_agent(CheckOptions::default());
        sender.send_to(&check, target).unwrap();
        let answered = wait_until(Duration::from_secs(1), || {
            recv_stun(sender, Duration::from_millis(20)).is_some_and(|(message, _)| {
                message.class() == Class::SuccessResponse && *message.transaction_id() == tid
            })
        });
        assert!(answered);
    }
    assert!(wait_until(Duration::from_secs(1), || {
        agent.stats().dropped_peer_reflexive == 3
    }));
    assert_eq!(agent.stats().dropped_peer_reflexive, 3);
}
