//! An ACME server (RFC 8555) for TLS certificates on the fips mesh
//! (docs/acme.md, docs/spec.md §8a). The mesh connection is the proof:
//! the server listens on the CA node's fips address only, the peer's
//! source address names the requesting key, and an operator allowlist
//! says who may ask. No challenge round. The X.509 root is published
//! through the PKI as the domain's `_x509@<domain>` statement.
//!
//! Policy modules take no I/O and are table-tested: [`jws`] (the
//! request signature), [`policy`] (allowlist, peer, identifiers, order
//! state), [`nonce`], [`x509`] (root, CSR, issuing, root check). [`zone`]
//! reads the name → key binding, [`store`] the state directory, and
//! [`server`] is the HTTP side over all of them.

pub mod jws;
pub mod nonce;
pub mod policy;
pub mod server;
pub mod store;
pub mod x509;
pub mod zone;

use serde::Serialize;

/// Plain HTTP on the mesh; the mesh encrypts and authenticates.
pub const DEFAULT_PORT: u16 = 8555;
pub const NONCE_TTL_SECS: u64 = 600;
pub const MAX_NONCES: usize = 10_000;
/// `expires` of orders and authorizations.
pub const ORDER_TTL_SECS: u64 = 3600;
pub const MAX_IDENTIFIERS: usize = 16;
/// The JWS body limit; an RSA-4096 CSR fits with room.
pub const MAX_BODY: usize = 64 * 1024;
pub const MAX_CONTACTS: usize = 8;
pub const DEFAULT_LEAF_VALIDITY_SECS: u64 = 30 * 86_400;
pub const DEFAULT_ROOT_VALIDITY_SECS: u64 = 10 * 365 * 86_400;
pub const MIN_RSA_BITS: usize = 2048;
/// Clock skew allowed on a leaf's `notBefore`.
pub const NOT_BEFORE_SKEW_SECS: u64 = 300;
/// A root DER larger than this is refused by `check_root_content`.
pub const MAX_ROOT_DER: usize = 8 * 1024;
/// Live orders one account may hold; past it, `rateLimited`.
pub const MAX_ORDERS_PER_ACCOUNT: usize = 16;
/// HTTP deadlines: the request head, the body, a whole connection.
pub const HEADER_TIMEOUT_SECS: u64 = 10;
pub const BODY_TIMEOUT_SECS: u64 = 15;
pub const CONNECTION_TIMEOUT_SECS: u64 = 120;

/// RFC 8555 §6.7 error types, as `urn:ietf:params:acme:error:<type>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorType {
    AccountDoesNotExist,
    AlreadyRevoked,
    BadCsr,
    BadNonce,
    BadPublicKey,
    BadRevocationReason,
    BadSignatureAlgorithm,
    Malformed,
    OrderNotReady,
    RateLimited,
    RejectedIdentifier,
    ServerInternal,
    Unauthorized,
    UnsupportedContact,
    UnsupportedIdentifier,
}

impl ErrorType {
    pub fn urn(self) -> String {
        let name = match self {
            Self::AccountDoesNotExist => "accountDoesNotExist",
            Self::AlreadyRevoked => "alreadyRevoked",
            Self::BadCsr => "badCSR",
            Self::BadNonce => "badNonce",
            Self::BadPublicKey => "badPublicKey",
            Self::BadRevocationReason => "badRevocationReason",
            Self::BadSignatureAlgorithm => "badSignatureAlgorithm",
            Self::Malformed => "malformed",
            Self::OrderNotReady => "orderNotReady",
            Self::RateLimited => "rateLimited",
            Self::RejectedIdentifier => "rejectedIdentifier",
            Self::ServerInternal => "serverInternal",
            Self::Unauthorized => "unauthorized",
            Self::UnsupportedContact => "unsupportedContact",
            Self::UnsupportedIdentifier => "unsupportedIdentifier",
        };
        format!("urn:ietf:params:acme:error:{name}")
    }

    /// The HTTP status the type goes with (RFC 8555 §6.7).
    pub fn status(self) -> u16 {
        match self {
            Self::Unauthorized | Self::RejectedIdentifier | Self::OrderNotReady => 403,
            Self::RateLimited => 429,
            Self::ServerInternal => 500,
            _ => 400,
        }
    }
}

/// One identifier of an order; only DNS names exist here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum Identifier {
    Dns(String),
}

impl Identifier {
    pub fn value(&self) -> &str {
        match self {
            Self::Dns(v) => v,
        }
    }
}

/// RFC 7807 problem document with an ACME error type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    #[serde(rename = "type", serialize_with = "urn_of")]
    pub kind: ErrorType,
    pub detail: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subproblems: Vec<Subproblem>,
}

fn urn_of<S: serde::Serializer>(t: &ErrorType, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.urn())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Subproblem {
    #[serde(rename = "type", serialize_with = "urn_of")]
    pub kind: ErrorType,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<Identifier>,
}

impl Problem {
    pub fn new(kind: ErrorType, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            status: kind.status(),
            subproblems: Vec::new(),
        }
    }

    /// `rejectedIdentifier` with one subproblem per refused identifier
    /// (RFC 8555 §6.7.1).
    pub fn rejected(subs: Vec<Subproblem>) -> Self {
        let mut p = Self::new(
            ErrorType::RejectedIdentifier,
            "one or more identifiers were refused",
        );
        p.subproblems = subs;
        p
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.urn(), self.detail)
    }
}

impl std::error::Error for Problem {}

/// Unix seconds as RFC 3339, for `expires`, `validated` and friends.
pub fn rfc3339(secs: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problems_serialize_as_acme_wants_them() {
        let p = Problem::rejected(vec![Subproblem {
            kind: ErrorType::RejectedIdentifier,
            detail: "not in the zone".into(),
            identifier: Some(Identifier::Dns("mail.example.org".into())),
        }]);
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        assert_eq!(v["type"], "urn:ietf:params:acme:error:rejectedIdentifier");
        assert_eq!(v["status"], 403);
        assert_eq!(v["subproblems"][0]["identifier"]["type"], "dns");
        assert_eq!(
            v["subproblems"][0]["identifier"]["value"],
            "mail.example.org"
        );
        let plain = serde_json::to_value(Problem::new(ErrorType::BadNonce, "x")).unwrap();
        assert_eq!(plain.get("subproblems"), None);
        assert_eq!(plain["status"], 400);
        assert_eq!(ErrorType::BadCsr.urn(), "urn:ietf:params:acme:error:badCSR");
        assert_eq!(rfc3339(1_790_000_000), "2026-09-21T14:13:20Z");
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        let id: Identifier =
            serde_json::from_str(r#"{"type":"dns","value":"a.example.org"}"#).unwrap();
        assert_eq!(id, Identifier::Dns("a.example.org".into()));
        assert!(serde_json::from_str::<Identifier>(r#"{"type":"ip","value":"::1"}"#).is_err());
    }
}
