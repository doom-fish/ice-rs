//! Regular nomination: the controller picks the best succeeded pair; the
//! controlled agent does not nominate on its own.

use ice::candidate::Candidate;
use ice::checklist::{Checklist, DEFAULT_MAX_PAIRS};
use ice::component::ComponentId;
use ice::nomination::select_nominee;
use ice::role::IceRole;

fn host(addr: &str) -> Candidate {
    Candidate::host(addr.parse().unwrap(), ComponentId::RTP)
}

fn succeeded_checklist(role: IceRole) -> (Checklist, usize, usize) {
    let mut cl = Checklist::new(role, DEFAULT_MAX_PAIRS);
    let low = cl
        .add_pair(host("192.0.2.1:1000"), host("198.51.100.1:2000"))
        .unwrap();
    let high = cl
        .add_pair(host("192.0.2.2:1000"), host("198.51.100.2:2000"))
        .unwrap();
    cl.unfreeze_initial();
    cl.mark_valid(low);
    cl.mark_valid(high);
    (cl, low, high)
}

#[test]
fn controller_picks_highest_priority_succeeded() {
    let (cl, low, high) = succeeded_checklist(IceRole::Controlling);
    let nominee = select_nominee(&cl).expect("a nominee");

    // The nominee must be the highest-priority succeeded pair.
    let expected = (0..cl.pairs().len())
        .max_by_key(|&i| cl.pairs()[i].priority)
        .unwrap();
    assert_eq!(cl.pairs()[nominee].priority, cl.pairs()[expected].priority);
    assert!(nominee == low || nominee == high);
}

#[test]
fn controlled_does_not_self_nominate() {
    let (cl, _, _) = succeeded_checklist(IceRole::Controlled);
    assert_eq!(select_nominee(&cl), None);
}

#[test]
fn no_nominee_once_nominated() {
    let (mut cl, _, high) = succeeded_checklist(IceRole::Controlling);
    cl.set_nominated(high);
    assert_eq!(cl.nominated(), Some(high));
    assert_eq!(select_nominee(&cl), None);
}
