//! Check-list freezing, ordering, and the per-pair state machine.

use ice::candidate::Candidate;
use ice::checklist::{Checklist, DEFAULT_MAX_PAIRS};
use ice::component::ComponentId;
use ice::pair::PairState;
use ice::role::IceRole;

fn host(addr: &str) -> Candidate {
    Candidate::host(addr.parse().unwrap(), ComponentId::RTP)
}

#[test]
fn unfreeze_promotes_one_pair_per_foundation() {
    let mut cl = Checklist::new(IceRole::Controlling, DEFAULT_MAX_PAIRS);
    cl.add_pair(host("192.0.2.1:1000"), host("198.51.100.1:2000"))
        .unwrap();
    cl.add_pair(host("192.0.2.1:1000"), host("198.51.100.2:2000"))
        .unwrap();
    assert_eq!(cl.count(PairState::Frozen), 2);

    cl.unfreeze_initial();
    // Distinct remote foundations → both promoted to Waiting.
    assert_eq!(cl.count(PairState::Waiting), 2);
    assert_eq!(cl.count(PairState::Frozen), 0);
}

#[test]
fn next_check_marks_in_progress_then_success() {
    let mut cl = Checklist::new(IceRole::Controlling, DEFAULT_MAX_PAIRS);
    let idx = cl
        .add_pair(host("192.0.2.1:1000"), host("198.51.100.1:2000"))
        .unwrap();
    cl.unfreeze_initial();

    let chosen = cl.next_check(|_| true).expect("a waiting pair");
    assert_eq!(chosen, idx);
    assert_eq!(cl.pairs()[idx].state, PairState::InProgress);

    cl.on_success(idx);
    assert_eq!(cl.pairs()[idx].state, PairState::Succeeded);
    assert_eq!(cl.best_succeeded(), None);
    cl.mark_valid(idx);
    assert_eq!(cl.best_succeeded(), Some(idx));
}

#[test]
fn triggered_check_takes_priority() {
    let mut cl = Checklist::new(IceRole::Controlling, DEFAULT_MAX_PAIRS);
    let low = cl
        .add_pair(host("192.0.2.1:1000"), host("198.51.100.1:2000"))
        .unwrap();
    let high = cl
        .add_pair(host("192.0.2.2:1000"), host("198.51.100.2:2000"))
        .unwrap();
    cl.unfreeze_initial();

    // Force the lower-priority pair to the front via the triggered queue.
    cl.enqueue_triggered(low);
    assert_eq!(cl.next_check(|_| true), Some(low));
    assert_eq!(cl.next_check(|_| true), Some(high));
}

#[test]
fn failure_is_terminal() {
    let mut cl = Checklist::new(IceRole::Controlling, DEFAULT_MAX_PAIRS);
    let idx = cl
        .add_pair(host("192.0.2.1:1000"), host("198.51.100.1:2000"))
        .unwrap();
    cl.unfreeze_initial();
    cl.on_failure(idx);
    assert_eq!(cl.pairs()[idx].state, PairState::Failed);
    assert!(cl.pairs()[idx].state.is_terminal());
}

#[test]
fn add_pair_is_idempotent_by_endpoints() {
    let mut cl = Checklist::new(IceRole::Controlling, DEFAULT_MAX_PAIRS);
    let a = cl
        .add_pair(host("192.0.2.1:1000"), host("198.51.100.1:2000"))
        .unwrap();
    let b = cl
        .add_pair(host("192.0.2.1:1000"), host("198.51.100.1:2000"))
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(cl.pairs().len(), 1);
}
