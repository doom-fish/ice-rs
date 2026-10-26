//! Trickle ICE support (RFC 8838).
//!
//! Trickle ICE lets an agent begin connectivity checks before gathering is
//! complete: candidates are streamed to the peer as they are discovered, and
//! remote candidates are accepted incrementally. An explicit end-of-candidates
//! signal in each direction tells the other side no more will arrive, so a
//! check list can be declared failed only once both ends are done.
//!
//! Browsers default to trickle ICE, so this agent supports it natively rather
//! than batching the full candidate set.

/// Tracks the trickle end-of-candidates state for both directions.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrickleState {
    local_done: bool,
    remote_done: bool,
}

impl TrickleState {
    /// A fresh state with neither side finished.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            local_done: false,
            remote_done: false,
        }
    }

    /// Mark that local gathering has produced its final candidate.
    pub fn set_local_done(&mut self) {
        self.local_done = true;
    }

    /// Mark that the peer signaled end-of-candidates.
    pub fn set_remote_done(&mut self) {
        self.remote_done = true;
    }

    /// Whether local gathering is complete.
    #[must_use]
    pub const fn local_done(self) -> bool {
        self.local_done
    }

    /// Whether the peer has signaled end-of-candidates.
    #[must_use]
    pub const fn remote_done(self) -> bool {
        self.remote_done
    }

    /// Whether both directions have finished trickling.
    #[must_use]
    pub const fn both_done(self) -> bool {
        self.local_done && self.remote_done
    }
}

/// A callback invoked for each freshly gathered local candidate (RFC 8838 §4.1).
pub type LocalCandidateCallback = Box<dyn FnMut(crate::candidate::Candidate) + Send>;
