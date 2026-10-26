//! Connectivity-check STUN message construction and validation (RFC 8445 §7).
//!
//! A connectivity check is a STUN Binding request carrying `USERNAME`,
//! `PRIORITY`, the role attribute (`ICE-CONTROLLING` / `ICE-CONTROLLED`),
//! optionally `USE-CANDIDATE`, the message-integrity attributes selected by
//! [`IntegrityMode`] (`MESSAGE-INTEGRITY` alone by default), and a
//! `FINGERPRINT`. Responses carry the integrity attribute the request used.

use std::fmt;
use std::net::SocketAddr;

use stun::attribute::types;
use stun::auth::short_term_key;
use stun::{Attribute, Class, ErrorCode, Message, MessageBuilder, Method, TransactionId};
use zeroize::Zeroizing;

use crate::config::IntegrityMode;
use crate::error::{Error, Result};
use crate::role::IceRole;

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Integrity {
    Sha1,
    Sha256,
}

/// All the inputs needed to build a single connectivity check.
#[derive(Clone)]
pub struct CheckParams {
    /// `USERNAME` value: `<remote-ufrag>:<local-ufrag>`.
    pub username: String,
    /// The `ice-pwd` of the **peer**, used as the integrity key.
    pub remote_pwd: Zeroizing<String>,
    /// `PRIORITY` the local candidate would have as a peer-reflexive candidate.
    pub priority: u32,
    /// Our role.
    pub role: IceRole,
    /// Our 64-bit tiebreaker.
    pub tiebreaker: u64,
    /// Whether to set `USE-CANDIDATE` (controller nomination only).
    pub use_candidate: bool,
    #[allow(missing_docs)]
    pub integrity: IntegrityMode,
}

impl fmt::Debug for CheckParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckParams")
            .field("username", &self.username)
            .field("remote_pwd", &"<redacted>")
            .field("priority", &self.priority)
            .field("role", &self.role)
            .field("tiebreaker", &self.tiebreaker)
            .field("use_candidate", &self.use_candidate)
            .field("integrity", &self.integrity)
            .finish()
    }
}

/// A built connectivity check: its transaction ID and encoded bytes.
#[derive(Debug, Clone)]
pub struct BuiltCheck {
    /// The transaction ID, used to correlate the response.
    pub transaction_id: TransactionId,
    /// The encoded request bytes, ready to send.
    pub bytes: Vec<u8>,
}

fn with_integrity(builder: MessageBuilder, key: &[u8], integrity: IntegrityMode) -> MessageBuilder {
    match integrity {
        IntegrityMode::Sha1 => builder.with_message_integrity_sha1(key),
        IntegrityMode::Sha256 => builder.with_message_integrity_sha256(key),
        IntegrityMode::Both => builder
            .with_message_integrity_sha1(key)
            .with_message_integrity_sha256(key),
    }
}

const fn mode_of(integrity: Integrity) -> IntegrityMode {
    match integrity {
        Integrity::Sha1 => IntegrityMode::Sha1,
        Integrity::Sha256 => IntegrityMode::Sha256,
    }
}

/// Build a connectivity-check Binding **request**.
///
/// # Errors
///
/// Returns [`Error::Stun`] if the transaction ID or message cannot be built.
pub fn build_check(params: &CheckParams) -> Result<BuiltCheck> {
    let transaction_id = TransactionId::try_random()?;
    let key = short_term_key(&params.remote_pwd);

    let mut builder = Message::builder(Method::Binding, Class::Request)
        .transaction_id(transaction_id)
        .attribute(Attribute::Username(params.username.clone()))
        .attribute(Attribute::Priority(params.priority))
        .attribute(params.role.check_attribute(params.tiebreaker));

    if params.use_candidate {
        builder = builder.attribute(Attribute::UseCandidate);
    }

    // The builder appends MESSAGE-INTEGRITY (SHA1), then
    // MESSAGE-INTEGRITY-SHA256, then FINGERPRINT — exactly the RFC 8489 order.
    builder = with_integrity(builder, &key, params.integrity).with_fingerprint();

    Ok(BuiltCheck {
        transaction_id,
        bytes: builder.build_and_encode()?,
    })
}

/// Build a Binding **success response** for an accepted inbound check.
///
/// `mapped` is the source address of the request (echoed as
/// `XOR-MAPPED-ADDRESS`), `local_pwd` keys the integrity attribute, and
/// `integrity` is the attribute the request was authenticated with.
///
/// # Errors
///
/// Returns [`Error::Stun`] if the message cannot be built.
pub fn build_success_response(
    transaction_id: TransactionId,
    mapped: SocketAddr,
    local_pwd: &str,
    integrity: Integrity,
) -> Result<Vec<u8>> {
    let key = short_term_key(local_pwd);
    let builder = Message::builder(Method::Binding, Class::SuccessResponse)
        .transaction_id(transaction_id)
        .attribute(Attribute::XorMappedAddress(mapped));
    Ok(with_integrity(builder, &key, mode_of(integrity))
        .with_fingerprint()
        .build_and_encode()?)
}

/// Build a Binding **error response** with the given code (e.g. `487`, `400`),
/// authenticated with the attribute the request used.
///
/// # Errors
///
/// Returns [`Error::Stun`] if the message cannot be built.
pub fn build_error_response(
    transaction_id: TransactionId,
    code: u16,
    reason: &str,
    local_pwd: &str,
    integrity: Integrity,
) -> Result<Vec<u8>> {
    let key = short_term_key(local_pwd);
    let builder = Message::builder(Method::Binding, Class::ErrorResponse)
        .transaction_id(transaction_id)
        .attribute(Attribute::ErrorCode(ErrorCode::new(code, reason)));
    Ok(with_integrity(builder, &key, mode_of(integrity))
        .with_fingerprint()
        .build_and_encode()?)
}

#[allow(missing_docs)]
pub fn build_unknown_attributes_response(
    request: &Message,
    unknown: &[u16],
    local_pwd: &str,
    integrity: Integrity,
) -> Result<Vec<u8>> {
    let key = short_term_key(local_pwd);
    Ok(with_integrity(
        request.unknown_attribute_response(unknown),
        &key,
        mode_of(integrity),
    )
    .with_fingerprint()
    .build_and_encode()?)
}

/// Validate an inbound connectivity-check **request** against our credentials.
///
/// Checks the `FINGERPRINT`, the `USERNAME` (must equal `expected_username`),
/// and the message integrity (SHA-256 preferred, SHA-1 accepted) keyed by our
/// local password. On success returns the `PRIORITY` and the role attribute (if
/// any) so the caller can run peer-reflexive discovery and role-conflict logic.
///
/// # Errors
///
/// Returns [`Error::BadCheck`] describing the first validation failure.
pub fn validate_request(
    message: &Message,
    expected_username: &str,
    local_pwd: &str,
) -> Result<ValidatedRequest> {
    if message.method() != Method::Binding || message.class() != Class::Request {
        return Err(Error::BadCheck("not a Binding request"));
    }
    message
        .verify_fingerprint()
        .map_err(|_| Error::BadCheck("FINGERPRINT mismatch"))?;

    let username = match message.get(types::USERNAME) {
        Some(Attribute::Username(u)) => u.clone(),
        _ => return Err(Error::BadCheck("missing USERNAME")),
    };
    if username != expected_username {
        return Err(Error::BadCheck("USERNAME mismatch"));
    }

    let integrity = verify_integrity(message, local_pwd, IntegrityMode::Both)?;

    let unknown_attributes = message.unknown_comprehension_required();
    let priority = match message.get(types::PRIORITY) {
        Some(Attribute::Priority(p)) => *p,
        _ if !unknown_attributes.is_empty() => 0,
        _ => return Err(Error::BadCheck("missing PRIORITY")),
    };

    let role_attr = message
        .get(types::ICE_CONTROLLING)
        .or_else(|| message.get(types::ICE_CONTROLLED))
        .cloned();

    let use_candidate = message.get(types::USE_CANDIDATE).is_some();

    Ok(ValidatedRequest {
        username,
        priority,
        role_attr,
        use_candidate,
        integrity,
        unknown_attributes,
    })
}

/// Verify message integrity with `pwd`, accepting only the attributes
/// `accept` allows: `Sha1` needs `MESSAGE-INTEGRITY`, `Sha256` needs
/// `MESSAGE-INTEGRITY-SHA256`, and `Both` prefers SHA-256 and falls back to
/// SHA-1. Returns the attribute that verified.
///
/// # Errors
///
/// Returns [`Error::BadCheck`] if no accepted integrity attribute is present
/// or the present one does not verify with `pwd`.
pub fn verify_integrity(message: &Message, pwd: &str, accept: IntegrityMode) -> Result<Integrity> {
    let key = short_term_key(pwd);
    let sha256 = message.get(types::MESSAGE_INTEGRITY_SHA256).is_some();
    let sha1 = message.get(types::MESSAGE_INTEGRITY).is_some();
    let use_sha256 = match accept {
        IntegrityMode::Sha1 => false,
        IntegrityMode::Sha256 => true,
        IntegrityMode::Both => sha256,
    };
    if use_sha256 {
        if !sha256 {
            return Err(Error::BadCheck("no MESSAGE-INTEGRITY-SHA256 attribute"));
        }
        return message
            .verify_message_integrity_sha256(&key)
            .map(|()| Integrity::Sha256)
            .map_err(|_| Error::BadCheck("MESSAGE-INTEGRITY-SHA256 mismatch"));
    }
    if !sha1 {
        return Err(Error::BadCheck("no MESSAGE-INTEGRITY attribute"));
    }
    message
        .verify_message_integrity(&key)
        .map(|()| Integrity::Sha1)
        .map_err(|_| Error::BadCheck("MESSAGE-INTEGRITY mismatch"))
}

/// The validated, trusted contents of an inbound connectivity check.
#[derive(Debug, Clone)]
pub struct ValidatedRequest {
    /// The `USERNAME` (already verified equal to the expected value).
    pub username: String,
    /// The peer's `PRIORITY` for the sending candidate (peer-reflexive prio).
    pub priority: u32,
    /// The role attribute (`ICE-CONTROLLING`/`ICE-CONTROLLED`), if present.
    pub role_attr: Option<Attribute>,
    /// Whether `USE-CANDIDATE` was set.
    pub use_candidate: bool,
    #[allow(missing_docs)]
    pub integrity: Integrity,
    #[allow(missing_docs)]
    pub unknown_attributes: Vec<u16>,
}

/// Extract the reflexive [`SocketAddr`] from a Binding **success response**,
/// preferring `XOR-MAPPED-ADDRESS`.
#[must_use]
pub fn response_mapped_address(message: &Message) -> Option<SocketAddr> {
    if let Some(Attribute::XorMappedAddress(addr)) = message.get(types::XOR_MAPPED_ADDRESS) {
        return Some(*addr);
    }
    if let Some(Attribute::MappedAddress(addr)) = message.get(types::MAPPED_ADDRESS) {
        return Some(*addr);
    }
    None
}

/// Returns the `ERROR-CODE` value of a Binding error response, if present.
#[must_use]
pub fn response_error_code(message: &Message) -> Option<u16> {
    match message.get(types::ERROR_CODE) {
        Some(Attribute::ErrorCode(ec)) => Some(ec.code()),
        _ => None,
    }
}
