//! NIP-44 (v2) to a key (spec §8). Which key to encrypt to is a
//! certificate's business (`Certificate::allows(Usage::Encrypt)`); this
//! is the primitive, one recipient at a time. Multi-recipient wrapping is
//! the application's (NIP-59).

use nostr_sdk::nips::nip44::{self, Version};
use nostr_sdk::{Keys, PublicKey};
use pubpki_core::pubdom_core::Npub;

pub fn public_key(npub: &Npub) -> Result<PublicKey, String> {
    PublicKey::from_slice(npub.as_bytes()).map_err(|e| e.to_string())
}

/// Encrypt `plaintext` from `keys` to `to`; the payload is NIP-44 base64.
pub fn encrypt(keys: &Keys, to: &Npub, plaintext: &[u8]) -> Result<String, String> {
    nip44::encrypt(keys.secret_key(), &public_key(to)?, plaintext, Version::V2)
        .map_err(|e| e.to_string())
}

/// Decrypt a NIP-44 payload sent by `from` to `keys`.
pub fn decrypt(keys: &Keys, from: &Npub, payload: &str) -> Result<Vec<u8>, String> {
    nip44::decrypt_to_bytes(keys.secret_key(), &public_key(from)?, payload)
        .map_err(|e| e.to_string())
}

/// This key's npub, as the core crates spell it.
pub fn npub_of(keys: &Keys) -> Npub {
    Npub::from_bytes(keys.public_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_between_two_keys_and_nobody_else() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let eve = Keys::generate();
        let payload = encrypt(&alice, &npub_of(&bob), b"meet at the relay").unwrap();
        assert_eq!(
            decrypt(&bob, &npub_of(&alice), &payload).unwrap(),
            b"meet at the relay"
        );
        assert!(decrypt(&eve, &npub_of(&alice), &payload).is_err());
        assert!(decrypt(&bob, &npub_of(&eve), &payload).is_err());
        assert!(decrypt(&bob, &npub_of(&alice), "not a payload").is_err());
    }
}
