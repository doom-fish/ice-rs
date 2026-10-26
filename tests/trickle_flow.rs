//! Trickle ICE end-to-end: two in-process agents on the loopback interface
//! gather, exchange candidates incrementally, and both converge on a selected
//! pair whose endpoints are the reciprocal of each other.

use std::sync::mpsc;
use std::time::Duration;

use ice::{IceAgent, IceConfig, IceRole};

#[test]
fn two_agents_reach_selected_pairs() {
    let loopback = "127.0.0.1:0".parse().unwrap();

    let mut cfg_a = IceConfig::new(
        IceRole::Controlling,
        "ufragAAAA",
        "passwordAAAAAAAAAAAAAA",
        "ufragBBBB",
        "passwordBBBBBBBBBBBBBB",
    );
    cfg_a.bind_addr = Some(loopback);

    let mut cfg_b = IceConfig::new(
        IceRole::Controlled,
        "ufragBBBB",
        "passwordBBBBBBBBBBBBBB",
        "ufragAAAA",
        "passwordAAAAAAAAAAAAAA",
    );
    cfg_b.bind_addr = Some(loopback);

    let agent_a = IceAgent::new(cfg_a).expect("agent A");
    let agent_b = IceAgent::new(cfg_b).expect("agent B");

    let (tx_a, rx_a) = mpsc::channel();
    agent_a.on_local_candidate(move |c| {
        let _ = tx_a.send(c);
    });
    let (tx_b, rx_b) = mpsc::channel();
    agent_b.on_local_candidate(move |c| {
        let _ = tx_b.send(c);
    });

    agent_a.start_gathering().expect("gather A");
    agent_b.start_gathering().expect("gather B");

    // Trickle: deliver each candidate to the peer as it is signaled.
    let cand_a = rx_a
        .recv_timeout(Duration::from_secs(2))
        .expect("A host candidate");
    let cand_b = rx_b
        .recv_timeout(Duration::from_secs(2))
        .expect("B host candidate");
    agent_b.add_remote_candidate(cand_a).expect("A->B");
    agent_a.add_remote_candidate(cand_b).expect("B->A");

    // Drain any stragglers.
    for c in rx_a.try_iter() {
        let _ = agent_b.add_remote_candidate(c);
    }
    for c in rx_b.try_iter() {
        let _ = agent_a.add_remote_candidate(c);
    }

    agent_a.end_of_candidates();
    agent_b.end_of_candidates();
    agent_a.remote_end_of_candidates();
    agent_b.remote_end_of_candidates();

    let (la, ra) = agent_a
        .wait_for_selected_pair(Duration::from_secs(8))
        .expect("A selects a pair");
    let (lb, rb) = agent_b
        .wait_for_selected_pair(Duration::from_secs(8))
        .expect("B selects a pair");

    // The two agents must agree on the same 5-tuple, mirrored.
    assert_eq!(la.addr, rb.addr);
    assert_eq!(ra.addr, lb.addr);

    // The negotiated path is usable for application data.
    agent_a
        .send_on_selected(b"trickle payload")
        .expect("send over selected pair");
}
