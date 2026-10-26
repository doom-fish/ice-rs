//! Configuration for an [`crate::agent::IceAgent`].

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use stun::Endpoint as StunEndpoint;
use turn::{Credential, TurnUri};
use zeroize::Zeroizing;

use crate::role::IceRole;

/// A TURN server entry: where to allocate and the long-term credential to use.
#[derive(Clone)]
pub struct TurnServer {
    /// The `turn:` / `turns:` URI of the server.
    pub uri: TurnUri,
    /// The long-term credential (username / realm / password).
    pub credential: Credential,
}

impl fmt::Debug for TurnServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnServer")
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

#[allow(missing_docs)]
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum IntegrityMode {
    #[default]
    Sha1,
    Sha256,
    Both,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TransportPolicy {
    #[default]
    All,
    Relay,
}

#[allow(missing_docs)]
pub type MdnsResolver = Arc<dyn Fn(&str) -> Option<IpAddr> + Send + Sync>;

#[allow(missing_docs)]
#[derive(Clone, Default)]
pub enum MdnsPolicy {
    #[default]
    Reject,
    Resolve,
    ResolveWith(MdnsResolver),
}

impl fmt::Debug for MdnsPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reject => f.write_str("Reject"),
            Self::Resolve => f.write_str("Resolve"),
            Self::ResolveWith(_) => f.write_str("ResolveWith(..)"),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_remote_candidates: usize,
    pub max_peer_reflexive: usize,
    pub max_pairs: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_remote_candidates: 100,
            max_peer_reflexive: 16,
            max_pairs: 100,
        }
    }
}

/// Configuration for a single ICE session.
#[derive(Clone)]
pub struct IceConfig {
    /// Our role for this session (full ICE; never ICE-lite).
    pub role: IceRole,
    /// Our `ice-ufrag` (RFC 8445 §5.3).
    pub local_ufrag: String,
    /// Our `ice-pwd`.
    pub local_pwd: Zeroizing<String>,
    /// The peer's `ice-ufrag`, learned from signaling.
    pub remote_ufrag: String,
    /// The peer's `ice-pwd`, learned from signaling.
    pub remote_pwd: Zeroizing<String>,
    /// STUN servers to query for server-reflexive candidates.
    pub stun_servers: Vec<StunEndpoint>,
    /// TURN servers to allocate relayed candidates on.
    pub turn_servers: Vec<TurnServer>,
    /// Optional explicit local bind address. When `Some` with a specific IP,
    /// the agent binds its shared socket here and gathers exactly one host
    /// candidate for it, bypassing interface enumeration; an unspecified IP
    /// keeps enumeration for that port. This is primarily for tests and for
    /// pinning the agent to a chosen interface (e.g. `127.0.0.1:0` for a
    /// network-free loopback pairing).
    pub bind_addr: Option<SocketAddr>,
    #[allow(missing_docs)]
    pub integrity: IntegrityMode,
    #[allow(missing_docs)]
    pub limits: Limits,
    #[allow(missing_docs)]
    pub mdns: MdnsPolicy,
    #[allow(missing_docs)]
    pub policy: TransportPolicy,
    #[allow(missing_docs)]
    pub clock: Arc<dyn Clock>,
}

impl fmt::Debug for IceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IceConfig")
            .field("role", &self.role)
            .field("local_ufrag", &self.local_ufrag)
            .field("local_pwd", &"<redacted>")
            .field("remote_ufrag", &self.remote_ufrag)
            .field("remote_pwd", &"<redacted>")
            .field("stun_servers", &self.stun_servers)
            .field("turn_servers", &self.turn_servers)
            .field("bind_addr", &self.bind_addr)
            .field("integrity", &self.integrity)
            .field("limits", &self.limits)
            .field("mdns", &self.mdns)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl IceConfig {
    /// Create a config with the four mandatory credential fields and a role,
    /// leaving server lists empty and using the default integrity mode,
    /// limits, and policies.
    #[must_use]
    pub fn new(
        role: IceRole,
        local_ufrag: impl Into<String>,
        local_pwd: impl Into<String>,
        remote_ufrag: impl Into<String>,
        remote_pwd: impl Into<String>,
    ) -> Self {
        Self {
            role,
            local_ufrag: local_ufrag.into(),
            local_pwd: Zeroizing::new(local_pwd.into()),
            remote_ufrag: remote_ufrag.into(),
            remote_pwd: Zeroizing::new(remote_pwd.into()),
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            bind_addr: None,
            integrity: IntegrityMode::default(),
            limits: Limits::default(),
            mdns: MdnsPolicy::default(),
            policy: TransportPolicy::default(),
            clock: Arc::new(SystemClock),
        }
    }

    /// The `USERNAME` an outbound check from us carries (RFC 8445 §7.2.2):
    /// `<remote-ufrag>:<local-ufrag>` — the **remote** fragment comes first.
    #[must_use]
    pub fn outbound_username(&self) -> String {
        format!("{}:{}", self.remote_ufrag, self.local_ufrag)
    }

    /// The `USERNAME` an inbound check from the peer is expected to carry:
    /// `<local-ufrag>:<remote-ufrag>`.
    #[must_use]
    pub fn expected_inbound_username(&self) -> String {
        format!("{}:{}", self.local_ufrag, self.remote_ufrag)
    }

    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Config`] if any mandatory credential is empty
    /// or a limit is zero.
    pub fn validate(&self) -> crate::Result<()> {
        if self.local_ufrag.is_empty() || self.local_pwd.is_empty() {
            return Err(crate::Error::Config("local ufrag/pwd must not be empty"));
        }
        if self.remote_ufrag.is_empty() || self.remote_pwd.is_empty() {
            return Err(crate::Error::Config("remote ufrag/pwd must not be empty"));
        }
        if self.limits.max_pairs == 0 || self.limits.max_remote_candidates == 0 {
            return Err(crate::Error::Config("limits must allow at least one pair"));
        }
        Ok(())
    }
}
