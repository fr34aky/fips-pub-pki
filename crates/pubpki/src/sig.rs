//! Detached signatures as events (spec §8): sign with nostr-sdk, verify
//! the event, then let `pubpki_core::Signature` match it to the data.

use crate::core_event;
use nostr_sdk::{Event, Keys};
use pubdom_resolve::relay::sign_event;
use pubpki_core::{KIND_SIGNATURE, Signature, digest};

/// A kind 9200 event over `data`'s hash, signed by `keys`. Never published.
pub fn sign_detached(keys: &Keys, data: &[u8], media: Option<&str>) -> Result<Event, String> {
    sign_event(
        keys,
        KIND_SIGNATURE,
        Signature::tags(&digest(data), media, Some(data.len() as u64)),
        "",
    )
}

/// Check the event's signature and that it covers `data`; the signer is
/// in the result. Whose name the signer holds is a certificate's question
/// (`Verifier::names_of`).
pub fn verify_detached(ev: &Event, data: &[u8]) -> Result<Signature, String> {
    ev.verify()
        .map_err(|e| format!("bad event signature: {e}"))?;
    let sig = Signature::parse(&core_event(ev)).map_err(|e| e.to_string())?;
    if !sig.covers(data) {
        return Err("the signature does not cover this data".into());
    }
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::npub_of;

    #[test]
    fn signs_and_verifies_the_data_not_its_neighbour() {
        let keys = Keys::generate();
        let ev = sign_detached(&keys, b"release-1.0.tar", Some("application/x-tar")).unwrap();
        let sig = verify_detached(&ev, b"release-1.0.tar").unwrap();
        assert_eq!(sig.signer, npub_of(&keys));
        assert_eq!(sig.size, Some(15));
        assert!(verify_detached(&ev, b"release-1.1.tar").is_err());
        let json = serde_json::to_string(&ev)
            .unwrap()
            .replace("x-tar", "x-jar");
        let forged: Event = serde_json::from_str(&json).unwrap();
        assert!(
            verify_detached(&forged, b"release-1.0.tar").is_err(),
            "a changed tag breaks the event signature"
        );
    }
}
