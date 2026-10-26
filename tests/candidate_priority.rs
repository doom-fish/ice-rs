//! Candidate priority follows the RFC 8445 §5.1.2.1 formula.

use ice::candidate::{compute_priority, CandidateType};
use ice::component::ComponentId;

#[test]
fn host_priority_matches_formula() {
    let p = compute_priority(CandidateType::Host, u16::MAX, ComponentId::RTP);
    // (126 << 24) | (65535 << 8) | (256 - 1)
    let expected = (126u32 << 24) | (u32::from(u16::MAX) << 8) | (256 - 1);
    assert_eq!(p, expected);
}

#[test]
fn type_preferences_order() {
    let host = compute_priority(CandidateType::Host, u16::MAX, ComponentId::RTP);
    let prflx = compute_priority(CandidateType::PeerReflexive, u16::MAX, ComponentId::RTP);
    let srflx = compute_priority(CandidateType::ServerReflexive, u16::MAX, ComponentId::RTP);
    let relay = compute_priority(CandidateType::Relayed, u16::MAX, ComponentId::RTP);
    assert!(host > prflx);
    assert!(prflx > srflx);
    assert!(srflx > relay);
}

#[test]
fn rtcp_component_has_lower_priority_than_rtp() {
    let rtp = compute_priority(CandidateType::Host, 1000, ComponentId::RTP);
    let rtcp = compute_priority(CandidateType::Host, 1000, ComponentId::RTCP);
    assert!(rtp > rtcp);
    assert_eq!(rtp - rtcp, 1);
}
