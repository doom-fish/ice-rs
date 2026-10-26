//! Candidate pairs and the per-pair check state machine (RFC 8445 §6.1.2).

use crate::candidate::Candidate;
use crate::role::IceRole;

/// The state of a candidate pair in the check list (RFC 8445 §6.1.2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PairState {
    /// Not yet eligible to be checked; waiting for its foundation to unfreeze.
    Frozen,
    /// Eligible to be checked; waiting for its turn under the Ta pacing.
    Waiting,
    /// A check has been sent and a response is awaited.
    InProgress,
    /// A check succeeded; the pair is a valid path.
    Succeeded,
    /// A check failed (timeout or error response).
    Failed,
}

impl PairState {
    /// Returns `true` once the pair has reached a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

/// Compute the pair priority (RFC 8445 §6.1.2.3):
///
/// ```text
/// pair_priority = 2^32 * min(G, D) + 2 * max(G, D) + (G > D ? 1 : 0)
/// ```
///
/// where `G` is the **controlling** agent's candidate priority and `D` is the
/// **controlled** agent's candidate priority.
#[must_use]
pub fn pair_priority(local_prio: u32, remote_prio: u32, role: IceRole) -> u64 {
    let (g, d) = match role {
        IceRole::Controlling => (local_prio, remote_prio),
        IceRole::Controlled => (remote_prio, local_prio),
    };
    let g = u64::from(g);
    let d = u64::from(d);
    let tie = u64::from(g > d);
    (1u64 << 32) * g.min(d) + 2 * g.max(d) + tie
}

/// A local/remote candidate pair and its check state.
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// The local candidate (one we gathered).
    pub local: Candidate,
    /// The remote candidate (one the peer signaled).
    pub remote: Candidate,
    /// The current check state.
    pub state: PairState,
    /// Whether this pair has been nominated (controller chose it).
    pub nominated: bool,
    /// The combined pair priority for ordering the check list.
    pub priority: u64,
    /// How many connectivity checks we have sent for this pair.
    pub attempts: u32,
    #[allow(missing_docs)]
    pub valid: bool,
    #[allow(missing_docs)]
    pub valid_pair: Option<usize>,
    foundation: String,
}

impl CandidatePair {
    /// Build a pair from a local and remote candidate, computing its priority
    /// for the given role. The pair starts [`PairState::Frozen`].
    #[must_use]
    pub fn new(local: Candidate, remote: Candidate, role: IceRole) -> Self {
        let priority = pair_priority(local.priority, remote.priority, role);
        let foundation = format!("{}|{}", local.foundation, remote.foundation);
        Self {
            local,
            remote,
            state: PairState::Frozen,
            nominated: false,
            priority,
            attempts: 0,
            valid: false,
            valid_pair: None,
            foundation,
        }
    }

    /// The combined foundation of this pair (RFC 8445 §6.1.2.4), used for
    /// foundation-based freezing: pairs with equal combined foundations are
    /// frozen behind one another.
    #[must_use]
    pub fn foundation(&self) -> &str {
        &self.foundation
    }

    /// Recompute the pair priority after a role switch.
    pub fn recompute_priority(&mut self, role: IceRole) {
        self.priority = pair_priority(self.local.priority, self.remote.priority, role);
    }

    /// Identifies a pair by the `(local.addr, remote.addr)` 5-tuple endpoints.
    #[must_use]
    pub fn endpoints(&self) -> (std::net::SocketAddr, std::net::SocketAddr) {
        (self.local.addr, self.remote.addr)
    }
}
