//! Role-conflict resolution per RFC 8445 §7.3.1.1.

use ice::role::{resolve_conflict, ConflictOutcome, IceRole};
use stun::Attribute;

#[test]
fn no_conflict_when_roles_complementary() {
    // We are controlling; peer asserts controlled — no conflict.
    let outcome = resolve_conflict(
        IceRole::Controlling,
        100,
        Some(&Attribute::IceControlled(200)),
    );
    assert_eq!(outcome, ConflictOutcome::KeepRole);
}

#[test]
fn both_controlling_higher_tiebreaker_replies_487() {
    let outcome = resolve_conflict(
        IceRole::Controlling,
        500,
        Some(&Attribute::IceControlling(200)),
    );
    assert_eq!(outcome, ConflictOutcome::Reply487);
}

#[test]
fn both_controlling_lower_tiebreaker_switches() {
    let outcome = resolve_conflict(
        IceRole::Controlling,
        100,
        Some(&Attribute::IceControlling(900)),
    );
    assert_eq!(outcome, ConflictOutcome::SwitchRole);
}

#[test]
fn both_controlled_higher_tiebreaker_switches() {
    let outcome = resolve_conflict(
        IceRole::Controlled,
        900,
        Some(&Attribute::IceControlled(100)),
    );
    assert_eq!(outcome, ConflictOutcome::SwitchRole);
}

#[test]
fn both_controlled_lower_tiebreaker_replies_487() {
    let outcome = resolve_conflict(
        IceRole::Controlled,
        100,
        Some(&Attribute::IceControlled(900)),
    );
    assert_eq!(outcome, ConflictOutcome::Reply487);
}

#[test]
fn missing_role_attribute_keeps_role() {
    assert_eq!(
        resolve_conflict(IceRole::Controlling, 100, None),
        ConflictOutcome::KeepRole
    );
}

#[test]
fn tiebreaker_comes_from_the_system_rng() {
    let first = ice::role::random_tiebreaker().unwrap();
    let second = ice::role::random_tiebreaker().unwrap();
    assert_ne!(first, second);
}
