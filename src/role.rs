//! ICE roles, the 64-bit tiebreaker, and role-conflict resolution
//! (RFC 8445 §6.1.1, §7.3.1.1).

use stun::Attribute;

/// The ICE role of an agent for a given session (RFC 8445 §6.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IceRole {
    /// The **controlling** agent nominates the candidate pair to use.
    Controlling,
    /// The **controlled** agent waits to be told which pair was nominated.
    Controlled,
}

impl IceRole {
    /// The opposite role.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Controlling => Self::Controlled,
            Self::Controlled => Self::Controlling,
        }
    }

    /// Returns `true` for the controlling role.
    #[must_use]
    pub const fn is_controlling(self) -> bool {
        matches!(self, Self::Controlling)
    }

    /// Build the role attribute carried in a connectivity check for this role
    /// and tiebreaker value.
    #[must_use]
    pub const fn check_attribute(self, tiebreaker: u64) -> Attribute {
        match self {
            Self::Controlling => Attribute::IceControlling(tiebreaker),
            Self::Controlled => Attribute::IceControlled(tiebreaker),
        }
    }
}

/// The outcome of comparing an inbound check's role attribute against our own
/// role (RFC 8445 §7.3.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictOutcome {
    /// No conflict (or it resolved in our favor): keep our current role and
    /// process the check normally.
    KeepRole,
    /// We must switch roles, then continue processing the check.
    SwitchRole,
    /// Reply with a `487 Role Conflict` error; the peer must switch.
    Reply487,
}

/// Resolve a possible role conflict for an inbound Binding request.
///
/// `our_role` / `our_tiebreaker` describe us; `incoming` is the role attribute
/// (`ICE-CONTROLLING` or `ICE-CONTROLLED`) found in the peer's request, if any.
///
/// Per RFC 8445 §7.3.1.1:
///
/// * If we are **controlling** and the request also asserts controlling, then
///   if our tiebreaker `>=` theirs we reply `487`; otherwise we switch to
///   controlled.
/// * If we are **controlled** and the request also asserts controlled, then if
///   our tiebreaker `>=` theirs we switch to controlling; otherwise we reply
///   `487`.
/// * Otherwise there is no conflict.
#[must_use]
pub fn resolve_conflict(
    our_role: IceRole,
    our_tiebreaker: u64,
    incoming: Option<&Attribute>,
) -> ConflictOutcome {
    match (our_role, incoming) {
        (IceRole::Controlling, Some(Attribute::IceControlling(their_tb))) => {
            if our_tiebreaker >= *their_tb {
                ConflictOutcome::Reply487
            } else {
                ConflictOutcome::SwitchRole
            }
        }
        (IceRole::Controlled, Some(Attribute::IceControlled(their_tb))) => {
            if our_tiebreaker >= *their_tb {
                ConflictOutcome::SwitchRole
            } else {
                ConflictOutcome::Reply487
            }
        }
        _ => ConflictOutcome::KeepRole,
    }
}

/// Generate a fresh 64-bit tiebreaker from the system RNG (RFC 8445 §5.2).
///
/// # Errors
///
/// Returns [`crate::Error::Rng`] if the secure RNG is unavailable.
pub fn random_tiebreaker() -> crate::Result<u64> {
    stun::rng::random_array::<8>()
        .map(u64::from_be_bytes)
        .map_err(|_| crate::Error::Rng)
}
