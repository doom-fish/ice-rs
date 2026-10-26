//! A built connectivity check validates against the matching credentials and is
//! rejected when integrity, fingerprint, or username do not match.

use ice::check::{build_check, validate_request, CheckParams, Integrity};
use ice::role::IceRole;
use ice::IntegrityMode;
use stun::attribute::types;
use stun::Message;

fn params(use_candidate: bool) -> CheckParams {
    CheckParams {
        username: "ufragB:ufragA".to_string(),
        remote_pwd: "thePeerPasswordValue22".to_string().into(),
        priority: 1_853_628_927,
        role: IceRole::Controlling,
        tiebreaker: 0x1122_3344_5566_7788,
        use_candidate,
        integrity: IntegrityMode::Sha1,
    }
}

#[test]
fn valid_check_round_trips() {
    let built = build_check(&params(false)).unwrap();
    let msg = Message::decode(&built.bytes).expect("decode");

    // The responder verifies with its own password (== our remote_pwd here).
    let validated =
        validate_request(&msg, "ufragB:ufragA", "thePeerPasswordValue22").expect("valid");
    assert_eq!(validated.username, "ufragB:ufragA");
    assert_eq!(validated.priority, 1_853_628_927);
    assert!(!validated.use_candidate);
}

#[test]
fn use_candidate_is_carried() {
    let built = build_check(&params(true)).unwrap();
    let msg = Message::decode(&built.bytes).expect("decode");
    let validated =
        validate_request(&msg, "ufragB:ufragA", "thePeerPasswordValue22").expect("valid");
    assert!(validated.use_candidate);
}

#[test]
fn wrong_password_is_rejected() {
    let built = build_check(&params(false)).unwrap();
    let msg = Message::decode(&built.bytes).expect("decode");
    let err = validate_request(&msg, "ufragB:ufragA", "wrongPasswordValue2222");
    assert!(err.is_err());
}

#[test]
fn wrong_username_is_rejected() {
    let built = build_check(&params(false)).unwrap();
    let msg = Message::decode(&built.bytes).expect("decode");
    let err = validate_request(&msg, "ufragX:ufragY", "thePeerPasswordValue22");
    assert!(err.is_err());
}

#[test]
fn checks_carry_only_sha1_integrity_by_default() {
    let built = build_check(&params(false)).unwrap();
    let msg = Message::decode(&built.bytes).expect("decode");
    assert!(msg.get(types::MESSAGE_INTEGRITY).is_some());
    assert!(msg.get(types::MESSAGE_INTEGRITY_SHA256).is_none());
    assert!(msg.get(types::FINGERPRINT).is_some());
    let validated =
        validate_request(&msg, "ufragB:ufragA", "thePeerPasswordValue22").expect("valid");
    assert_eq!(validated.integrity, Integrity::Sha1);
}

#[test]
fn sha256_integrity_only_when_configured() {
    let mut sha256 = params(false);
    sha256.integrity = IntegrityMode::Sha256;
    let msg = Message::decode(&build_check(&sha256).unwrap().bytes).unwrap();
    assert!(msg.get(types::MESSAGE_INTEGRITY).is_none());
    assert!(msg.get(types::MESSAGE_INTEGRITY_SHA256).is_some());
    let validated = validate_request(&msg, "ufragB:ufragA", "thePeerPasswordValue22").unwrap();
    assert_eq!(validated.integrity, Integrity::Sha256);

    let mut both = params(false);
    both.integrity = IntegrityMode::Both;
    let msg = Message::decode(&build_check(&both).unwrap().bytes).unwrap();
    assert!(msg.get(types::MESSAGE_INTEGRITY).is_some());
    assert!(msg.get(types::MESSAGE_INTEGRITY_SHA256).is_some());
}

#[test]
fn role_conflict_response_mirrors_the_request_integrity() {
    let tid = stun::TransactionId::from_bytes([3; 12]);
    let sha1 = Message::decode(
        &ice::check::build_error_response(
            tid,
            487,
            "Role Conflict",
            "localPasswordValue22",
            Integrity::Sha1,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(sha1.get(types::MESSAGE_INTEGRITY).is_some());
    assert!(sha1.get(types::MESSAGE_INTEGRITY_SHA256).is_none());
    assert_eq!(
        ice::check::verify_integrity(&sha1, "localPasswordValue22", IntegrityMode::Sha1).unwrap(),
        Integrity::Sha1
    );
    assert_eq!(ice::check::response_error_code(&sha1), Some(487));

    let sha256 = Message::decode(
        &ice::check::build_error_response(
            tid,
            487,
            "Role Conflict",
            "localPasswordValue22",
            Integrity::Sha256,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(sha256.get(types::MESSAGE_INTEGRITY).is_none());
    assert!(sha256.get(types::MESSAGE_INTEGRITY_SHA256).is_some());
}

#[test]
fn response_integrity_must_match_what_was_sent() {
    let tid = stun::TransactionId::from_bytes([4; 12]);
    let peer = "192.0.2.4:4000".parse().unwrap();
    let sha1_only = Message::decode(
        &ice::check::build_success_response(tid, peer, "thePeerPasswordValue22", Integrity::Sha1)
            .unwrap(),
    )
    .unwrap();
    assert!(ice::check::verify_integrity(
        &sha1_only,
        "thePeerPasswordValue22",
        IntegrityMode::Sha256
    )
    .is_err());
    assert!(ice::check::verify_integrity(
        &sha1_only,
        "thePeerPasswordValue22",
        IntegrityMode::Both
    )
    .is_ok());
    assert!(ice::check::verify_integrity(
        &sha1_only,
        "wrongPasswordValue2222",
        IntegrityMode::Sha1
    )
    .is_err());
}

#[test]
fn unknown_comprehension_required_attributes_are_reported() {
    let key = stun::auth::short_term_key("thePeerPasswordValue22");
    let bytes = Message::builder(stun::Method::Binding, stun::Class::Request)
        .transaction_id(stun::TransactionId::from_bytes([5; 12]))
        .attribute(stun::Attribute::Username("ufragB:ufragA".into()))
        .attribute(stun::Attribute::Priority(1))
        .attribute(stun::Attribute::Unknown {
            attribute_type: 0x7777,
            value: vec![1, 2, 3, 4],
        })
        .with_message_integrity_sha1(&key)
        .with_fingerprint()
        .build_and_encode()
        .unwrap();
    let msg = Message::decode(&bytes).unwrap();
    let validated = validate_request(&msg, "ufragB:ufragA", "thePeerPasswordValue22").unwrap();
    assert_eq!(validated.unknown_attributes, vec![0x7777]);
    let response = Message::decode(
        &ice::check::build_unknown_attributes_response(
            &msg,
            &validated.unknown_attributes,
            "thePeerPasswordValue22",
            validated.integrity,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(ice::check::response_error_code(&response), Some(420));
    assert_eq!(
        response.get(types::UNKNOWN_ATTRIBUTES),
        Some(&stun::Attribute::UnknownAttributes(vec![0x7777]))
    );
    assert!(
        ice::check::verify_integrity(&response, "thePeerPasswordValue22", IntegrityMode::Sha1)
            .is_ok()
    );
}
