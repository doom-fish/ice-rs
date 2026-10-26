//! `ice` — a synchronous, runtime-free ICE agent (RFC 8445) for WebRTC.
//!
//! This crate implements a full Interactive Connectivity Establishment agent
//! following the WebRTC ICE-bis profile:
//!
//! * **RFC 8445** — ICE: candidate gathering, prioritization, foundation-based
//!   freezing, connectivity checks, role-conflict resolution, and nomination.
//! * **RFC 8838** — Trickle ICE: incremental candidate exchange with explicit
//!   end-of-candidates signaling.
//! * **RFC 7675** — Consent freshness: keeping a selected pair alive and
//!   detecting when the remote peer stops consenting to receive.
//! * **RFC 8839** — the SDP `a=candidate:` attribute grammar.
//! * **RFC 5764 §5.1.2** — first-byte demultiplexing of ICE/STUN, DTLS, and
//!   SRTP on the shared 5-tuple.
//!
//! It builds on three sibling crates: `stun` for the STUN codec and integrity;
//! `turn` for relayed candidates, allocated over the agent's own socket; and
//! `networkframework` for interface enumeration.
//!
//! # Design
//!
//! The public API is **synchronous and uses no async runtime**. An
//! [`IceAgent`] owns a single background thread that runs the receive loop and
//! the `Ta`-paced check scheduler; the caller interacts through ordinary
//! blocking method calls. The agent communicates over a single
//! [`SharedSocket`], the same unconnected UDP socket the downstream DTLS/SRTP
//! layer uses — non-STUN packets from validated remotes are demultiplexed to a
//! [`PacketSink`], and [`IceAgent::send_on_selected`] sends on the selected
//! pair while consent lasts.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! use ice::{IceAgent, IceConfig, IceRole};
//!
//! let config = IceConfig::new(
//!     IceRole::Controlling,
//!     "localUfrag", "localPasswordValue",
//!     "remoteUfrag", "remotePasswordValue",
//! );
//! let agent = IceAgent::new(config)?;
//! agent.on_local_candidate(|c| {
//!     // ship `c` to the peer through your signaling channel
//!     let _ = c;
//! });
//! agent.start_gathering()?;
//! // ... feed remote candidates via agent.add_remote_candidate(...) ...
//! if let Ok((local, remote)) = agent.wait_for_selected_pair(Duration::from_secs(5)) {
//!     let _ = (local, remote);
//! }
//! # Ok::<(), ice::Error>(())
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod agent;
pub mod candidate;
pub mod check;
pub mod checklist;
pub mod component;
pub mod config;
pub mod consent;
pub mod error;
pub mod gather;
pub mod nomination;
pub mod packet;
pub mod pair;
mod relay;
pub mod role;
pub mod sdp;
pub mod socket;
pub mod trickle;

pub use agent::{AgentStats, IceAgent};
pub use candidate::{Candidate, CandidateType};
pub use checklist::Checklist;
pub use component::{ComponentId, Transport};
pub use config::{
    Clock, IceConfig, IntegrityMode, Limits, MdnsPolicy, SystemClock, TransportPolicy, TurnServer,
};
pub use consent::ConsentTracker;
pub use error::{Error, Result};
pub use gather::{local_addresses, GatherState, LocalAddress};
pub use packet::{classify, PacketKind};
pub use pair::{CandidatePair, PairState};
pub use role::{resolve_conflict, ConflictOutcome, IceRole};
pub use socket::{PacketSink, Received, SharedSocket};
pub use trickle::TrickleState;
