//! Regular nomination logic (RFC 8445 §8).
//!
//! WebRTC uses **regular** nomination (never aggressive): the controlling agent
//! waits for a candidate pair to succeed, then sends a *second* connectivity
//! check on the chosen pair with the `USE-CANDIDATE` attribute set. When that
//! nominating check succeeds, the pair becomes the selected pair. The
//! controlled agent never sets `USE-CANDIDATE`; it marks a pair nominated when
//! it validates an inbound check carrying `USE-CANDIDATE`.

use crate::checklist::Checklist;
use crate::role::IceRole;

/// Decide which valid pair (if any) the controlling agent should nominate.
///
/// Returns the index of the highest-priority valid, not-yet-nominated pair.
/// Only the controlling agent nominates, so this returns `None` for the
/// controlled role.
#[must_use]
pub fn select_nominee(checklist: &Checklist) -> Option<usize> {
    if checklist.role() != IceRole::Controlling {
        return None;
    }
    if checklist.nominated().is_some() {
        return None;
    }
    let pairs = checklist.pairs();
    (0..pairs.len())
        .filter(|&i| {
            pairs[i].valid
                && pairs[i].state == crate::pair::PairState::Succeeded
                && !pairs[i].nominated
        })
        .max_by_key(|&i| pairs[i].priority)
}
