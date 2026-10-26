//! Error type for the ICE agent.

use std::fmt;

/// Errors produced while gathering candidates, running connectivity checks, or
/// driving the [`crate::agent::IceAgent`] state machine.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A candidate or SDP `a=candidate:` line could not be parsed.
    ParseCandidate(String),
    /// A STUN URI in the configuration could not be parsed.
    InvalidUri(String),
    /// An error bubbled up from the `stun` crate.
    Stun(stun::Error),
    /// An error bubbled up from the `turn` crate.
    Turn(turn::Error),
    /// An underlying socket / network operation failed.
    Network(String),
    /// No usable candidate pair completed before the deadline.
    Timeout,
    /// The agent has been shut down and can no longer accept commands.
    Shutdown,
    /// A configuration value was invalid.
    Config(&'static str),
    /// A received STUN check failed integrity or fingerprint validation.
    BadCheck(&'static str),
    #[allow(missing_docs)]
    NoSelectedPair,
    #[allow(missing_docs)]
    ConsentExpired,
    #[allow(missing_docs)]
    Failed,
    #[allow(missing_docs)]
    Limit(&'static str),
    #[allow(missing_docs)]
    Rng,
    #[allow(missing_docs)]
    Unsupported(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseCandidate(s) => write!(f, "invalid ICE candidate: {s}"),
            Self::InvalidUri(s) => write!(f, "invalid STUN/TURN URI: {s}"),
            Self::Stun(e) => write!(f, "STUN error: {e}"),
            Self::Turn(e) => write!(f, "TURN error: {e}"),
            Self::Network(s) => write!(f, "network error: {s}"),
            Self::Timeout => f.write_str("ICE negotiation timed out"),
            Self::Shutdown => f.write_str("ICE agent has been shut down"),
            Self::Config(s) => write!(f, "invalid ICE configuration: {s}"),
            Self::BadCheck(s) => write!(f, "rejected STUN connectivity check: {s}"),
            Self::NoSelectedPair => f.write_str("no candidate pair has been selected"),
            Self::ConsentExpired => {
                f.write_str("consent to send expired on the selected pair (RFC 7675)")
            }
            Self::Failed => f.write_str("ICE failed: every candidate pair failed"),
            Self::Limit(what) => write!(f, "ICE limit reached: {what}"),
            Self::Rng => f.write_str("the system random number generator failed"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<stun::Error> for Error {
    fn from(e: stun::Error) -> Self {
        Self::Stun(e)
    }
}

impl From<turn::Error> for Error {
    fn from(e: turn::Error) -> Self {
        Self::Turn(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Network(e.to_string())
    }
}

/// Convenient result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
