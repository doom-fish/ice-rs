use std::time::{Duration, Instant};

use ice::consent::{ConsentTracker, CONSENT_INTERVAL, CONSENT_TIMEOUT};

#[test]
fn not_due_immediately() {
    let now = Instant::now();
    let tracker = ConsentTracker::new(now);
    assert!(!tracker.due(now));
    assert!(!tracker.is_expired());
    assert_eq!(tracker.expires_at(), now + CONSENT_TIMEOUT);
}

#[test]
fn checks_are_spaced_four_to_six_seconds_apart() {
    assert_eq!(CONSENT_INTERVAL, Duration::from_secs(5));
    assert_eq!(CONSENT_TIMEOUT, Duration::from_secs(30));
    for _ in 0..50 {
        let now = Instant::now();
        let mut tracker = ConsentTracker::new(now);
        let first = tracker.next_send() - now;
        assert!(
            first >= Duration::from_secs(4) && first <= Duration::from_secs(6),
            "{first:?}"
        );
        assert!(!tracker.due(now + Duration::from_millis(3999)));
        assert!(tracker.due(now + Duration::from_secs(6)));
        let sent = now + Duration::from_secs(6);
        tracker.on_sent(sent);
        let next = tracker.next_send() - sent;
        assert!(
            next >= Duration::from_secs(4) && next <= Duration::from_secs(6),
            "{next:?}"
        );
    }
}

#[test]
fn consent_expires_thirty_seconds_after_the_last_response() {
    let now = Instant::now();
    let mut tracker = ConsentTracker::new(now);
    assert!(!tracker.poll_expiry(now + Duration::from_secs(29)));
    tracker.on_response(now + Duration::from_secs(20));
    assert!(!tracker.poll_expiry(now + Duration::from_secs(49)));
    assert!(tracker.poll_expiry(now + Duration::from_secs(50)));
    assert!(tracker.is_expired());
    assert!(!tracker.poll_expiry(now + Duration::from_secs(51)));
    assert!(!tracker.due(now + Duration::from_secs(60)));
}

#[test]
fn responses_after_expiry_do_not_restore_consent() {
    let now = Instant::now();
    let mut tracker = ConsentTracker::new(now);
    assert!(tracker.poll_expiry(now + CONSENT_TIMEOUT));
    tracker.on_response(now + CONSENT_TIMEOUT + Duration::from_secs(1));
    assert!(tracker.is_expired());
    assert_eq!(tracker.expires_at(), now + CONSENT_TIMEOUT);
}

#[test]
fn revocation_is_immediate() {
    let now = Instant::now();
    let mut tracker = ConsentTracker::new(now);
    tracker.revoke();
    assert!(tracker.is_expired());
    assert!(!tracker.due(now + Duration::from_secs(10)));
}
