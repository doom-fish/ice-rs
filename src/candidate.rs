//! ICE candidates: types, foundations, and priorities (RFC 8445 §5.1).

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::component::{ComponentId, Transport};

/// The kind of an ICE candidate (RFC 8445 §5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// A `host` candidate: an address on a local interface.
    Host,
    /// A `srflx` (server-reflexive) candidate learned from a STUN server.
    ServerReflexive,
    /// A `prflx` (peer-reflexive) candidate learned from an inbound check.
    PeerReflexive,
    /// A `relay` (relayed) candidate allocated on a TURN server.
    Relayed,
}

impl CandidateType {
    /// The type preference used in priority computation (RFC 8445 §5.1.2.2).
    ///
    /// `host=126`, `prflx=110`, `srflx=100`, `relay=0`.
    #[must_use]
    pub const fn type_preference(self) -> u32 {
        match self {
            Self::Host => 126,
            Self::PeerReflexive => 110,
            Self::ServerReflexive => 100,
            Self::Relayed => 0,
        }
    }

    /// The lowercase SDP `typ` token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "srflx",
            Self::PeerReflexive => "prflx",
            Self::Relayed => "relay",
        }
    }

    /// Parse an SDP `typ` token (`host` / `srflx` / `prflx` / `relay`).
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "host" => Some(Self::Host),
            "srflx" => Some(Self::ServerReflexive),
            "prflx" => Some(Self::PeerReflexive),
            "relay" => Some(Self::Relayed),
            _ => None,
        }
    }
}

impl fmt::Display for CandidateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Compute the standard ICE candidate priority (RFC 8445 §5.1.2.1):
///
/// ```text
/// priority = (2^24) * type_pref
///          + (2^8)  * local_pref
///          + (2^0)  * (256 - component_id)
/// ```
///
/// `local_pref` should be `65535` for the only address on an interface, or
/// `65535 - interface_metric` to break ties between multiple local addresses.
#[must_use]
pub fn compute_priority(typ: CandidateType, local_pref: u16, component: ComponentId) -> u32 {
    let type_pref = typ.type_preference();
    let component_term = 256u32.saturating_sub(u32::from(component.as_u16()));
    (type_pref << 24) | (u32::from(local_pref) << 8) | component_term
}

/// Compute a stable [`Candidate::foundation`] string (RFC 8445 §5.1.1.3).
///
/// Two candidates share a foundation **iff** they have the same type, the same
/// base IP address, the same STUN/TURN server (if any), and the same transport
/// protocol. We hash those four inputs with FNV-1a and render the digest as a
/// decimal string, which is an opaque, stable foundation token.
#[must_use]
pub fn compute_foundation(
    typ: CandidateType,
    base: IpAddr,
    server: Option<SocketAddr>,
    transport: Transport,
) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    let mut mix = |bytes: &[u8]| {
        for &b in bytes {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    };

    mix(&[typ.type_preference() as u8]);
    mix(typ.as_str().as_bytes());
    mix(base.to_string().as_bytes());
    if let Some(server) = server {
        mix(server.to_string().as_bytes());
    }
    mix(transport.as_str().as_bytes());

    // Keep it within the RFC's 1..=32 character bound.
    format!("{}", hash % 1_000_000_000)
}

/// A single ICE candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The candidate kind.
    pub typ: CandidateType,
    /// The component this candidate belongs to.
    pub component: ComponentId,
    /// The transport protocol.
    pub transport: Transport,
    /// The candidate's transport address (what the peer sends checks to).
    pub addr: SocketAddr,
    /// The base address (RFC 8445 §5.1.1.2): the local socket address from
    /// which this candidate sends. For host candidates `base == addr`.
    pub base: SocketAddr,
    /// The related address (`raddr`/`rport`) for reflexive and relayed
    /// candidates, used for diagnostics and SDP.
    pub related: Option<SocketAddr>,
    /// The STUN/TURN server this candidate was derived from, if any. Part of
    /// the foundation equivalence relation but not serialized to SDP.
    pub server: Option<SocketAddr>,
    /// The opaque foundation string.
    pub foundation: String,
    /// The candidate priority (RFC 8445 §5.1.2.1).
    pub priority: u32,
}

impl Candidate {
    /// Build a candidate, computing its foundation and priority automatically.
    ///
    /// `local_pref` defaults to `65535` when there is a single local address.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        typ: CandidateType,
        component: ComponentId,
        transport: Transport,
        addr: SocketAddr,
        base: SocketAddr,
        related: Option<SocketAddr>,
        server: Option<SocketAddr>,
        local_pref: u16,
    ) -> Self {
        let foundation = compute_foundation(typ, base.ip(), server, transport);
        let priority = compute_priority(typ, local_pref, component);
        Self {
            typ,
            component,
            transport,
            addr,
            base,
            related,
            server,
            foundation,
            priority,
        }
    }

    /// Build a `host` candidate for `addr` (its own base, `local_pref` 65535).
    #[must_use]
    pub fn host(addr: SocketAddr, component: ComponentId) -> Self {
        Self::new(
            CandidateType::Host,
            component,
            Transport::Udp,
            addr,
            addr,
            None,
            None,
            u16::MAX,
        )
    }

    /// Build a `srflx` candidate from a reflexive `addr` over `base`, learned
    /// from `server`.
    #[must_use]
    pub fn server_reflexive(
        addr: SocketAddr,
        base: SocketAddr,
        server: SocketAddr,
        component: ComponentId,
    ) -> Self {
        Self::new(
            CandidateType::ServerReflexive,
            component,
            Transport::Udp,
            addr,
            base,
            Some(base),
            Some(server),
            u16::MAX,
        )
    }

    /// Build a `relay` candidate for relayed `addr`, allocated on `server`,
    /// reached over local `base`.
    #[must_use]
    pub fn relayed(
        addr: SocketAddr,
        base: SocketAddr,
        server: SocketAddr,
        component: ComponentId,
    ) -> Self {
        Self::new(
            CandidateType::Relayed,
            component,
            Transport::Udp,
            addr,
            base,
            Some(base),
            Some(server),
            u16::MAX,
        )
    }

    /// Build a `prflx` candidate discovered at `addr` (RFC 8445 §7.3.1.3),
    /// with the priority carried in the peer's check.
    #[must_use]
    pub fn peer_reflexive(addr: SocketAddr, base: SocketAddr, priority: u32, component: ComponentId) -> Self {
        let foundation = compute_foundation(CandidateType::PeerReflexive, base.ip(), None, Transport::Udp);
        Self {
            typ: CandidateType::PeerReflexive,
            component,
            transport: Transport::Udp,
            addr,
            base,
            related: Some(base),
            server: None,
            foundation,
            priority,
        }
    }

    /// Returns `true` if both candidates have the same foundation.
    #[must_use]
    pub fn same_foundation(&self, other: &Self) -> bool {
        self.foundation == other.foundation
    }
}
