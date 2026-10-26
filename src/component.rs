//! ICE components and transport protocol (RFC 8445 §3, §4).

use std::fmt;

/// An ICE component identifier (RFC 8445 §3).
///
/// A media stream may be split into multiple components, each with its own
/// connectivity checks. With `rtcp-mux` (the WebRTC default) RTP and RTCP share
/// a single 5-tuple, so there is only ever **one** component, with id `1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ComponentId(pub u16);

impl ComponentId {
    /// The RTP component (id `1`) — the only component when `rtcp-mux` is used.
    pub const RTP: Self = Self(1);

    /// The RTCP component (id `2`) — present only without `rtcp-mux`.
    pub const RTCP: Self = Self(2);

    /// The raw component number as used in priority and SDP encoding.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl Default for ComponentId {
    fn default() -> Self {
        Self::RTP
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The transport protocol of a candidate (RFC 8445 §5.1.1).
///
/// WebRTC ICE uses UDP. TCP candidates (RFC 6544) are modeled for SDP
/// round-tripping but are not gathered or checked by this agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// User Datagram Protocol.
    Udp,
    /// Transmission Control Protocol (parsed for SDP compatibility only).
    Tcp,
}

impl Transport {
    /// The lowercase SDP token (`"udp"` / `"tcp"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }

    /// Parse a (case-insensitive) SDP transport token.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            "udp" => Some(Self::Udp),
            "tcp" => Some(Self::Tcp),
            _ => None,
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
