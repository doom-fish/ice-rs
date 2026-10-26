//! First-byte packet demultiplexing for the shared UDP socket.
//!
//! WebRTC multiplexes ICE/STUN, DTLS, and SRTP/SRTCP on a single UDP 5-tuple.
//! The three protocols are told apart by the value of the **first byte** of the
//! datagram (RFC 5764 §5.1.2, "The way to demultiplex … is the following"):
//!
//! ```text
//!              +----------------+
//!              |        [0..3]  -+--> forward to STUN
//!              |                 |
//!  packet -->  |  [16..19]      -+--> forward to ZRTP (unused here)
//!              |                 |
//!              |  [20..63]      -+--> forward to DTLS
//!              |                 |
//!              | [64..79]       -+--> forward to TURN ChannelData
//!              |                 |
//!              | [128..191]     -+--> forward to SRTP/SRTCP
//!              +----------------+
//! ```
//!
//! `ice-rs` consumes the STUN bytes itself and dispatches everything else to the
//! user-provided [`crate::socket::PacketSink`].

/// The protocol a received datagram belongs to, as classified by its first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketKind {
    /// A STUN message (first byte `0..=19`) — consumed by the ICE agent.
    Stun,
    /// A DTLS record (first byte `20..=63`).
    Dtls,
    /// An SRTP or SRTCP packet (first byte `128..=191`).
    Srtp,
    /// A TURN ChannelData frame (first byte `64..=79`).
    ChannelData,
    /// Anything that does not fall into a recognized range.
    Other,
}

impl PacketKind {
    /// Returns `true` for [`PacketKind::Stun`], which the agent handles itself.
    #[must_use]
    pub const fn is_stun(self) -> bool {
        matches!(self, Self::Stun)
    }
}

/// Classify a datagram by its first byte per RFC 5764 §5.1.2.
///
/// An empty datagram classifies as [`PacketKind::Other`].
#[must_use]
pub fn classify(bytes: &[u8]) -> PacketKind {
    match bytes.first() {
        None => PacketKind::Other,
        Some(&b) => match b {
            0..=19 => PacketKind::Stun,
            20..=63 => PacketKind::Dtls,
            64..=79 => PacketKind::ChannelData,
            128..=191 => PacketKind::Srtp,
            _ => PacketKind::Other,
        },
    }
}

/// Returns `true` if the datagram is a STUN message that the agent must handle.
#[must_use]
pub fn is_stun(bytes: &[u8]) -> bool {
    classify(bytes) == PacketKind::Stun
}
