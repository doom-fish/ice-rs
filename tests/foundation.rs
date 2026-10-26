//! Foundation equivalence: same type + base IP + server + transport.

use ice::candidate::{compute_foundation, CandidateType};
use ice::component::Transport;

#[test]
fn same_type_and_base_ip_share_foundation() {
    let ip = "192.0.2.7".parse().unwrap();
    let a = compute_foundation(CandidateType::Host, ip, None, Transport::Udp);
    let b = compute_foundation(CandidateType::Host, ip, None, Transport::Udp);
    assert_eq!(a, b);
}

#[test]
fn different_type_differs() {
    let ip = "192.0.2.7".parse().unwrap();
    let host = compute_foundation(CandidateType::Host, ip, None, Transport::Udp);
    let srflx = compute_foundation(CandidateType::ServerReflexive, ip, None, Transport::Udp);
    assert_ne!(host, srflx);
}

#[test]
fn different_base_ip_differs() {
    let a = compute_foundation(CandidateType::Host, "192.0.2.7".parse().unwrap(), None, Transport::Udp);
    let b = compute_foundation(CandidateType::Host, "192.0.2.8".parse().unwrap(), None, Transport::Udp);
    assert_ne!(a, b);
}

#[test]
fn different_server_differs() {
    let ip = "192.0.2.7".parse().unwrap();
    let s1 = Some("198.51.100.1:3478".parse().unwrap());
    let s2 = Some("198.51.100.2:3478".parse().unwrap());
    let a = compute_foundation(CandidateType::ServerReflexive, ip, s1, Transport::Udp);
    let b = compute_foundation(CandidateType::ServerReflexive, ip, s2, Transport::Udp);
    assert_ne!(a, b);
}

#[test]
fn foundation_is_short_token() {
    let f = compute_foundation(CandidateType::Host, "192.0.2.7".parse().unwrap(), None, Transport::Udp);
    assert!(!f.is_empty());
    assert!(f.len() <= 32);
    assert!(f.chars().all(|c| c.is_ascii_digit()));
}
