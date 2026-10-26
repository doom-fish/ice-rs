//! SDP `a=candidate:` line round-tripping (RFC 8839).

use ice::candidate::{Candidate, CandidateType};
use ice::component::ComponentId;
use ice::sdp;
use ice::MdnsPolicy;

#[test]
fn host_candidate_round_trips() {
    let c = Candidate::host("192.0.2.33:50000".parse().unwrap(), ComponentId::RTP);
    let line = sdp::to_sdp(&c);
    assert!(line.starts_with("candidate:"));
    assert!(line.contains("typ host"));
    assert!(line.contains("UDP") || line.contains("udp"));

    let back = sdp::parse(&line, &MdnsPolicy::Reject).unwrap();
    assert_eq!(back.addr, c.addr);
    assert_eq!(back.typ, CandidateType::Host);
    assert_eq!(back.priority, c.priority);
    assert_eq!(back.component, c.component);
}

#[test]
fn server_reflexive_carries_raddr_rport() {
    let c = Candidate::server_reflexive(
        "203.0.113.5:60000".parse().unwrap(),
        "192.0.2.33:50000".parse().unwrap(),
        "198.51.100.1:3478".parse().unwrap(),
        ComponentId::RTP,
    );
    let line = sdp::to_sdp(&c);
    assert!(line.contains("typ srflx"));
    assert!(line.contains("raddr 192.0.2.33"));
    assert!(line.contains("rport 50000"));

    let back = sdp::parse(&line, &MdnsPolicy::Reject).unwrap();
    assert_eq!(back.typ, CandidateType::ServerReflexive);
    assert_eq!(back.addr, c.addr);
    assert_eq!(back.related, Some("192.0.2.33:50000".parse().unwrap()));
}

#[test]
fn parse_rejects_garbage() {
    assert!(sdp::parse("a=candidate:not enough fields", &MdnsPolicy::Reject).is_err());
    assert!(sdp::parse("totally unrelated line", &MdnsPolicy::Reject).is_err());
}

#[test]
fn parse_accepts_leading_a_equals() {
    let line = "a=candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host";
    let c = sdp::parse(line, &MdnsPolicy::Reject).unwrap();
    assert_eq!(c.addr, "192.0.2.1:5000".parse().unwrap());
}
