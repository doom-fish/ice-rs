use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ice::{sdp, Error, MdnsPolicy};

const LINE: &str =
    "a=candidate:1 1 UDP 2130706431 4c7f6a19-3b1e-4c8e-9f3a-2d5b6c7d8e9f.local 54321 typ host";

#[test]
fn mdns_candidates_are_rejected_by_default() {
    assert!(matches!(MdnsPolicy::default(), MdnsPolicy::Reject));
    let error = sdp::parse(LINE, &MdnsPolicy::Reject).unwrap_err();
    assert!(
        matches!(error, Error::ParseCandidate(message) if message.contains("MdnsPolicy::Reject"))
    );
}

#[test]
fn mdns_candidates_resolve_through_the_configured_resolver() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let policy = MdnsPolicy::ResolveWith(Arc::new(move |name: &str| {
        counter.fetch_add(1, Ordering::SeqCst);
        (name == "4c7f6a19-3b1e-4c8e-9f3a-2d5b6c7d8e9f.local")
            .then(|| "192.0.2.50".parse::<IpAddr>().unwrap())
    }));
    let candidate = sdp::parse(LINE, &policy).unwrap();
    assert_eq!(candidate.addr, "192.0.2.50:54321".parse().unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn unresolved_mdns_candidates_are_errors() {
    let policy = MdnsPolicy::ResolveWith(Arc::new(|_: &str| None));
    assert!(matches!(
        sdp::parse(LINE, &policy),
        Err(Error::ParseCandidate(_))
    ));
}

#[test]
fn other_hostnames_are_never_resolved() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let policy = MdnsPolicy::ResolveWith(Arc::new(move |_: &str| {
        counter.fetch_add(1, Ordering::SeqCst);
        None
    }));
    let line = "a=candidate:1 1 UDP 2130706431 example.org 54321 typ host";
    assert!(matches!(
        sdp::parse(line, &policy),
        Err(Error::ParseCandidate(_))
    ));
    assert!(matches!(
        sdp::parse(line, &MdnsPolicy::Resolve),
        Err(Error::ParseCandidate(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
