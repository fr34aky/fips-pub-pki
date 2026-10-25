//! I/O for fips-pub-pki: everything `pubpki-core` deliberately does not
//! do. Relays, the issuer's DNSSEC proof and keys come from
//! `pubdom-resolve` (`RelayClient::fetch_raw`, `proof::verify_chain_for`,
//! `load_keys`); encryption is NIP-44 through the nostr-sdk it re-exports.
//!
//! No `cfg(target_os)` here (docs/architecture.md).

pub use pubdom_resolve;
pub use pubdom_resolve::nostr_sdk;
pub use pubpki_core;

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
            issuer: pubpki_core::pubdom_core::Npub::from_hex(&keys.public_key().to_hex()).unwrap(),
            name: Name::parse("alice@example.org").unwrap(),
            subjects: vec![subject],
            expiration: 1_797_776_000,
            usages: vec![Usage::Sign],
            revoked: None,
            pathlen: None,
            relays: Vec::new(),
            created_at: 0,
        };
        let ev = sign_event(&keys, KIND_CERT, cert.tags(), "").unwrap();
        ev.verify().unwrap();
        let parsed = Certificate::parse(&core_event(&ev)).unwrap();
        assert_eq!(parsed.issuer, cert.issuer);
        assert_eq!(parsed.subjects, vec![subject]);
        assert_eq!(parsed.name.to_string(), "alice@example.org");
    }
}
