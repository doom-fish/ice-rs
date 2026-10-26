//! Consent freshness for the selected pair (RFC 7675).
//!
//! Once a pair is selected, the agent keeps proving that the remote peer still
//! consents to receive traffic by sending a STUN Binding request on the
//! selected pair every 4 to 6 seconds (5 s randomized by 0.8–1.2, RFC 7675
//! §5.1). Each request is sent once; a matching authenticated response to any
//! request sent within the last 30 seconds refreshes consent. If no such
//! response arrives for 30 seconds, consent expires: the agent stops sending on
//! the pair and fires its failure callback so the application can re-gather
//! and re-negotiate.

use std::time::{Duration, Instant};

/// Base consent-check interval (RFC 7675 §5.1 recommends 5 s).
pub const CONSENT_INTERVAL: Duration = Duration::from_secs(5);

#[allow(missing_docs)]
pub const CONSENT_TIMEOUT: Duration = Duration::from_secs(30);

const JITTER_FRACTION: f64 = 0.2;

/// Tracks consent-freshness timing for the selected pair.
#[derive(Debug, Clone)]
pub struct ConsentTracker {
    last_response: Instant,
    next_send: Instant,
    expired: bool,
}

impl ConsentTracker {
    /// Start tracking consent as of `now`, scheduling the first check one
    /// jittered interval out.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            last_response: now,
            next_send: now + jittered(CONSENT_INTERVAL),
            expired: false,
        }
    }

    /// Whether it is time to send the next consent check.
    #[must_use]
    pub fn due(&self, now: Instant) -> bool {
        !self.expired && now >= self.next_send
    }

    /// Record that a consent check was just sent and schedule the next one.
    pub fn on_sent(&mut self, now: Instant) {
        self.next_send = now + jittered(CONSENT_INTERVAL);
    }

    /// Record a valid consent response received at `now`. Responses that
    /// arrive after consent expired do not restore it.
    pub fn on_response(&mut self, now: Instant) {
        if !self.expired && now > self.last_response {
            self.last_response = now;
        }
    }

    #[allow(missing_docs)]
    pub fn poll_expiry(&mut self, now: Instant) -> bool {
        if self.expired || now < self.expires_at() {
            return false;
        }
        self.expired = true;
        true
    }

    #[allow(missing_docs)]
    pub fn revoke(&mut self) {
        self.expired = true;
    }

    #[allow(missing_docs)]
    #[must_use]
    pub const fn is_expired(&self) -> bool {
        self.expired
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn expires_at(&self) -> Instant {
        self.last_response + CONSENT_TIMEOUT
    }

    /// The instant the next consent check is due.
    #[must_use]
    pub const fn next_send(&self) -> Instant {
        self.next_send
    }
}

/// Apply ±[`JITTER_FRACTION`] jitter to `base` using the system RNG.
#[must_use]
fn jittered(base: Duration) -> Duration {
    let r = match stun::rng::random_array::<2>() {
        Ok(bytes) => f64::from(u16::from_be_bytes(bytes)) / f64::from(u16::MAX),
        Err(_) => 0.5,
    };
    // Map [0,1] onto [-JITTER_FRACTION, +JITTER_FRACTION].
    let factor = 1.0 + (r * 2.0 - 1.0) * JITTER_FRACTION;
    base.mul_f64(factor)
}
