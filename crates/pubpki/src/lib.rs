//! I/O for fips-pub-pki: everything `pubpki-core` deliberately does not
//! do. Relays, the issuer's DNSSEC proof and keys come from
//! `pubdom-resolve` (`RelayClient::fetch_raw`, `proof::DnssecProofs`,
//! `load_keys`); encryption is NIP-44 through nostr-sdk.
//!
//! - [`Verifier`]: the tables fed from relays or a bundle, anchoring, the
//!   file (spec §2, §4, §6, §7).
//! - [`sig`]: detached signatures as events (spec §8).
//! - [`crypto`]: NIP-44 to a key (spec §8).
//! - [`bundle`]: the bundle as JSON, signatures checked on the way in.
//! - [`issuer`]: the issuer's key, domain and file; issue, renew, revoke,
//!   the claim, publishing the exact signed event.
//!
//! No `cfg(target_os)` here (docs/architecture.md).

pub mod bundle;
pub mod config;
pub mod crypto;
pub mod issuer;
pub mod sig;
pub mod store;
pub mod verifier;

pub use config::Config;
pub use issuer::{Issued, Issuer, Request, publish_events, sign_at};
pub use pubdom_resolve;
pub use pubdom_resolve::nostr_sdk;
pub use pubdom_resolve::relay::load_keys;
pub use pubpki_core;
pub use store::FileStore;
pub use verifier::{Anchored, Verifier, VerifyError};

use pubpki_core::pubdom_core::claim::Event as CoreEvent;

/// The core crates' view of a relay event: what the policy looks at.
/// Content and signature are dropped — the relay pool verified the
/// signature on receipt, and a certificate's content is display only.
pub fn core_event(ev: &nostr_sdk::Event) -> CoreEvent {
    CoreEvent {
        kind: ev.kind.as_u16(),
        pubkey: ev.pubkey.to_hex(),
        created_at: ev.created_at.as_secs(),
        tags: ev.tags.iter().map(|t| t.clone().to_vec()).collect(),
    }
}

/// Unix seconds now — the one clock this crate reads.
pub fn now() -> u64 {
    pubdom_resolve::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubdom_resolve::relay::sign_event;
    use pubpki_core::{Certificate, KIND_CERT, Name, Usage};

    #[test]
    fn a_signed_certificate_parses_back_through_core() {
        let keys = nostr_sdk::Keys::generate();
        let subject = pubpki_core::pubdom_core::Npub::from_bytes([2; 32]);
        let cert = Certificate {
            issuer: crypto::npub_of(&keys),
            name: Name::parse("alice@example.org").unwrap(),
            subjects: vec![subject],
            expiration: 1_797_776_000,
            usages: vec![Usage::Sign],
            revoked: None,
            pathlen: None,
            relays: Vec::new(),
            other_usages: Vec::new(),
            digest: None,
            created_at: 0,
        };
        let ev = sign_event(&keys, KIND_CERT, cert.tags(), "").unwrap();
        ev.verify().unwrap();
        let parsed = Certificate::parse(&core_event(&ev)).unwrap();
        assert_eq!(parsed.issuer, cert.issuer);
        assert_eq!(parsed.subjects, vec![subject]);
        assert_eq!(parsed.name.to_string(), "alice@example.org");
        let json = bundle::render(std::slice::from_ref(&ev)).unwrap();
        assert_eq!(bundle::parse(&json).unwrap(), vec![ev]);
        assert!(bundle::parse("[1]").is_err());
    }
}
