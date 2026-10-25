//! Detached signatures (spec §8, nip.md "Signing"): a signature over
//! arbitrary data is a kind 9200 event, never published, whose `x` tag is
//! the data's SHA-256. A key thus never signs raw bytes another protocol
//! might interpret. Signing and signature checking are the I/O crate's
//! (nostr-sdk); here are the tags and the match against the data.

use crate::{KIND_SIGNATURE, MAX_TAGS};
use pubdom_core::Npub;
use pubdom_core::claim::Event;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum SigError {
    #[error("kind {0} is not a detached signature")]
    Kind(u16),
    #[error("invalid signer pubkey")]
    Signer,
    #[error("missing or invalid x tag (the data's SHA-256)")]
    Digest,
    #[error("invalid size tag")]
    Size,
    #[error("too many tags")]
    TooLarge,
}

/// "`signer` signed data hashing to `digest`", with optional hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub signer: Npub,
    pub digest: [u8; 32],
    /// Media type hint (`m`), never a security input.
    pub media: Option<String>,
    /// Size hint (`size`), checked against the data when present.
    pub size: Option<u64>,
    /// The signer's own timestamp, nothing more.
    pub created_at: u64,
}

/// SHA-256 of `data`, as the `x` tag carries it.
pub fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

impl Signature {
    pub fn parse(ev: &Event) -> Result<Self, SigError> {
        if ev.kind != KIND_SIGNATURE {
            return Err(SigError::Kind(ev.kind));
        }
        if ev.tags.len() > MAX_TAGS {
            return Err(SigError::TooLarge);
        }
        let signer = Npub::from_hex(&ev.pubkey).map_err(|_| SigError::Signer)?;
        let x = tag(&ev.tags, "x").ok_or(SigError::Digest)?;
        let bytes = hex_decode(x).ok_or(SigError::Digest)?;
        let digest: [u8; 32] = bytes.try_into().map_err(|_| SigError::Digest)?;
        let size = match tag(&ev.tags, "size") {
            Some(v) => Some(v.parse::<u64>().map_err(|_| SigError::Size)?),
            None => None,
        };
        Ok(Self {
            signer,
            digest,
            media: tag(&ev.tags, "m").map(str::to_string),
            size,
            created_at: ev.created_at,
        })
    }

    /// The tags of a signature over data hashing to `digest`.
    pub fn tags(digest: &[u8; 32], media: Option<&str>, size: Option<u64>) -> Vec<Vec<String>> {
        let mut tags = vec![vec!["x".to_string(), hex_encode(digest)]];
        if let Some(m) = media {
            tags.push(vec!["m".into(), m.into()]);
        }
        if let Some(n) = size {
            tags.push(vec!["size".into(), n.to_string()]);
        }
        tags
    }

    /// Does this signature cover `data`? The hash must match and, if a
    /// size was stated, the size too.
    pub fn covers(&self, data: &[u8]) -> bool {
        self.digest == digest(data) && self.size.is_none_or(|n| n == data.len() as u64)
    }
}

fn tag<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(tags: Vec<Vec<String>>) -> Event {
        Event {
            kind: KIND_SIGNATURE,
            pubkey: Npub::from_bytes([3; 32]).to_hex(),
            created_at: 1_790_000_000,
            tags,
        }
    }

    #[test]
    fn round_trips_and_matches_the_data_only() {
        let data = b"hello, mesh";
        let d = digest(data);
        let ev = event(Signature::tags(
            &d,
            Some("text/plain"),
            Some(data.len() as u64),
        ));
        let s = Signature::parse(&ev).unwrap();
        assert_eq!(s.signer, Npub::from_bytes([3; 32]));
        assert_eq!(s.media.as_deref(), Some("text/plain"));
        assert!(s.covers(data));
        assert!(!s.covers(b"hello, mesh!"));
        let mut lying = s.clone();
        lying.size = Some(3);
        assert!(!lying.covers(data), "a stated size must hold");
        let bare = Signature::parse(&event(Signature::tags(&d, None, None))).unwrap();
        assert_eq!(bare.media, None);
        assert!(bare.covers(data));
        assert_eq!(
            digest(b"")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn rejects_what_is_not_a_signature() {
        let d = digest(b"x");
        let good = event(Signature::tags(&d, None, Some(1)));
        let mut e = good.clone();
        e.kind = 1;
        assert_eq!(Signature::parse(&e), Err(SigError::Kind(1)));
        let mut e = good.clone();
        e.pubkey = "zz".into();
        assert_eq!(Signature::parse(&e), Err(SigError::Signer));
        let mut e = good.clone();
        e.tags[0][1] = "abc".into();
        assert_eq!(Signature::parse(&e), Err(SigError::Digest));
        let mut e = good.clone();
        e.tags[0][1].truncate(62);
        assert_eq!(Signature::parse(&e), Err(SigError::Digest), "31 bytes");
        let mut e = good.clone();
        e.tags.remove(0);
        assert_eq!(Signature::parse(&e), Err(SigError::Digest));
        let mut e = good.clone();
        e.tags[1][1] = "-1".into();
        assert_eq!(Signature::parse(&e), Err(SigError::Size));
        let mut e = good;
        e.tags
            .extend(std::iter::repeat_n(vec!["y".to_string()], MAX_TAGS));
        assert_eq!(Signature::parse(&e), Err(SigError::TooLarge));
    }
}
