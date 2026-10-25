//! The verifier's persistent state (spec §6): which issuers it has placed
//! for which domains, how strongly, and the anti-rollback table. Its own
//! file, `/var/lib/fips-pubpki/issuers.json`; the fips-pubdom pin file is
//! the phone's and is not touched.
//!
//! Like `pubdom_core::pins`, the trait is synchronous and the file
//! implementation lives in the I/O crate; [`MemoryStore`] is for tests
//! and as the in-memory layer of a file store.

use crate::cert::Certificate;
use crate::name::Name;
use crate::path::{Anchors, Certs};
use crate::{KIND_CERT, MAX_FUTURE_SECS};
use pubdom_core::domain::normalize;
use pubdom_core::{Method, Npub};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// How an issuer pin was established, weakest first. A pin is replaced
/// only by a verification at least as strong, and forgotten only on a
/// denial at least as strong (NIP-DB's rule). `Pinned` is what the user
/// configured by hand (a bare key, a known issuer): no verification
/// outranks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IssuerMethod {
    Attested,
    DnsSingle,
    Dns,
    Dnssec,
    Pinned,
}

impl IssuerMethod {
    /// From a NIP-DB verification; `Unverified` pins nothing.
    pub fn from_verification(m: Method) -> Option<Self> {
        match m {
            Method::Unverified => None,
            Method::Attested => Some(Self::Attested),
            Method::DnsSingle => Some(Self::DnsSingle),
            Method::Dns => Some(Self::Dns),
            Method::Dnssec => Some(Self::Dnssec),
        }
    }
}

/// An issuer the verifier has placed for a domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerPin {
    pub domain: String,
    pub npub: Npub,
    pub method: IssuerMethod,
    /// Unix seconds of the verification (or configuration) this rests on.
    pub verified_at: u64,
}

/// Key of the anti-rollback table: an addressable event's coordinates.
/// `d` is the certificate's name, or the claim's domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SeenKey {
    pub kind: u16,
    pub author: Npub,
    pub d: String,
}

/// What [`Snapshot::pin`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinChange {
    Added,
    /// Same key, method at least as strong: `verified_at` and `method`
    /// updated.
    Refreshed,
    /// A weaker verification than the pin's: nothing changed.
    Kept,
}

/// The on-disk shape (spec §6). Unknown fields are ignored and missing
/// ones default, so the file survives versions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub issuers: Vec<IssuerPin>,
    #[serde(default)]
    pub seen: Vec<(SeenKey, u64)>,
}

impl Snapshot {
    /// Place an issuer. A single label or an unnormalizable domain pins
    /// nothing (`Kept`), as `Anchors::add` refuses it.
    pub fn pin(&mut self, mut pin: IssuerPin) -> PinChange {
        let Some(domain) = normalize(&pin.domain).filter(|d| d.contains('.')) else {
            return PinChange::Kept;
        };
        pin.domain = domain;
        match self
            .issuers
            .iter_mut()
            .find(|p| p.domain == pin.domain && p.npub == pin.npub)
        {
            Some(have) if pin.method < have.method => PinChange::Kept,
            Some(have) => {
                have.method = pin.method;
                have.verified_at = pin.verified_at;
                PinChange::Refreshed
            }
            None => {
                self.issuers.push(pin);
                PinChange::Added
            }
        }
    }

    /// Forget `npub` for `domain` on a denial of strength `by` (the record
    /// no longer names the key, verified that strongly; the user, with
    /// `Pinned`). A weaker denial changes nothing. Returns whether it did.
    pub fn unpin(&mut self, domain: &str, npub: &Npub, by: IssuerMethod) -> bool {
        let Some(domain) = normalize(domain) else {
            return false;
        };
        let before = self.issuers.len();
        self.issuers
            .retain(|p| !(p.domain == domain && p.npub == *npub && p.method <= by));
        self.issuers.len() != before
    }

    /// The issuers placed for exactly `domain`.
    pub fn issuers_for<'a>(&'a self, domain: &'a str) -> impl Iterator<Item = &'a IssuerPin> + 'a {
        self.issuers.iter().filter(move |p| p.domain == domain)
    }

    /// The anchors table path validation runs against.
    pub fn anchors(&self) -> Anchors {
        let mut a = Anchors::new();
        for p in &self.issuers {
            a.add(&p.domain, p.npub);
        }
        a
    }

    /// Seed a certificate table with the floors remembered for kind 37200.
    pub fn seed(&self, certs: &mut Certs) {
        for (k, at) in &self.seen {
            if k.kind == KIND_CERT
                && let Some(name) = Name::parse(&k.d)
            {
                certs.set_floor(k.author, name, *at);
            }
        }
    }

    /// Replace the kind 37200 entries with what `certs` knows; entries of
    /// other kinds (the issuers' claims) stay.
    pub fn record(&mut self, certs: &Certs) {
        self.seen.retain(|(k, _)| k.kind != KIND_CERT);
        for (issuer, name, at) in certs.seen() {
            self.seen.push((
                SeenKey {
                    kind: KIND_CERT,
                    author: issuer,
                    d: name.to_string(),
                },
                at,
            ));
        }
    }

    pub fn newest_seen(&self, key: &SeenKey) -> Option<u64> {
        self.seen.iter().find(|(k, _)| k == key).map(|(_, at)| *at)
    }

    /// Record `created_at` for `key` if newer than what was seen and not
    /// absurdly in the future; whether it was. For the issuers' claims
    /// (kind 37197), which the certificate table does not hold.
    pub fn note_seen(&mut self, key: SeenKey, created_at: u64, now: u64) -> bool {
        if created_at > now.saturating_add(MAX_FUTURE_SECS) {
            return false;
        }
        match self.seen.iter_mut().find(|(k, _)| *k == key) {
            Some((_, at)) if *at >= created_at => false,
            Some((_, at)) => {
                *at = created_at;
                true
            }
            None => {
                self.seen.push((key, created_at));
                true
            }
        }
    }

    /// Keep the anti-rollback entries whose author `keep` accepts. The
    /// verifier calls it with "is an issuer I placed, or holds a
    /// sub-issuer certificate", so untrusted authors never grow the file.
    pub fn retain_authors(&mut self, mut keep: impl FnMut(&Npub) -> bool) {
        self.seen.retain(|(k, _)| keep(&k.author));
    }

    /// Does `cert`'s issuer deserve remembering: an issuer placed for some
    /// domain, or the subject of a live sub-issuer certificate in `certs`?
    pub fn is_trusted_author(&self, certs: &Certs, author: &Npub, now: u64) -> bool {
        self.issuers.iter().any(|p| p.npub == *author)
            || certs
                .by_subject(author)
                .any(|c: &Certificate| c.is_ca() && c.is_live_at(now))
    }
}

/// Load and save a [`Snapshot`]. Implementations with files live in the
/// I/O crate.
pub trait IssuerStore: Send + Sync {
    fn load(&self) -> Result<Snapshot, String>;
    fn save(&self, snap: &Snapshot) -> Result<(), String>;
}

/// A store that forgets on drop: tests, and the in-memory layer of a
/// file store.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Snapshot>,
}

impl MemoryStore {
    pub fn new(snap: Snapshot) -> Self {
        Self {
            inner: Mutex::new(snap),
        }
    }
}

impl IssuerStore for MemoryStore {
    fn load(&self) -> Result<Snapshot, String> {
        Ok(self.inner.lock().map_err(|e| e.to_string())?.clone())
    }

    fn save(&self, snap: &Snapshot) -> Result<(), String> {
        *self.inner.lock().map_err(|e| e.to_string())? = snap.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Usage;
    use crate::path::{AnchorKind, Ignored};

    const NOW: u64 = 1_790_000_000;

    fn key(n: u8) -> Npub {
        Npub::from_bytes([n; 32])
    }

    fn pin(domain: &str, n: u8, method: IssuerMethod, at: u64) -> IssuerPin {
        IssuerPin {
            domain: domain.into(),
            npub: key(n),
            method,
            verified_at: at,
        }
    }

    fn cert(issuer: u8, name: &str, subject: u8, usages: &[Usage]) -> Certificate {
        Certificate {
            issuer: key(issuer),
            name: Name::parse(name).unwrap(),
            subjects: vec![key(subject)],
            expiration: NOW + 86_400,
            usages: usages.to_vec(),
            revoked: None,
            pathlen: None,
            relays: Vec::new(),
            created_at: NOW - 60,
        }
    }

    #[test]
    fn a_pin_is_replaced_by_an_equal_or_stronger_verification_only() {
        let mut s = Snapshot::default();
        assert_eq!(
            s.pin(pin("Example.ORG.", 1, IssuerMethod::Dns, NOW)),
            PinChange::Added
        );
        assert_eq!(s.issuers[0].domain, "example.org", "normalized");
        assert_eq!(
            s.pin(pin("example.org", 1, IssuerMethod::DnsSingle, NOW + 1)),
            PinChange::Kept
        );
        assert_eq!(
            s.issuers[0].verified_at, NOW,
            "a weaker look changes nothing"
        );
        assert_eq!(
            s.pin(pin("example.org", 1, IssuerMethod::Dns, NOW + 2)),
            PinChange::Refreshed
        );
        assert_eq!(s.issuers[0].verified_at, NOW + 2);
        assert_eq!(
            s.pin(pin("example.org", 1, IssuerMethod::Dnssec, NOW + 3)),
            PinChange::Refreshed
        );
        assert_eq!(s.issuers[0].method, IssuerMethod::Dnssec);
        // What the user configured outranks every verification.
        assert_eq!(
            s.pin(pin("example.org", 1, IssuerMethod::Pinned, NOW + 4)),
            PinChange::Refreshed
        );
        assert_eq!(
            s.pin(pin("example.org", 1, IssuerMethod::Dnssec, NOW + 5)),
            PinChange::Kept
        );
        // A second key for the domain is a second pin, in order.
        assert_eq!(
            s.pin(pin("example.org", 2, IssuerMethod::Attested, NOW)),
            PinChange::Added
        );
        assert_eq!(s.issuers_for("example.org").count(), 2);
        // Single labels and junk pin nothing.
        for bad in ["org", "fips", "", "not a domain"] {
            assert_eq!(
                s.pin(pin(bad, 3, IssuerMethod::Pinned, NOW)),
                PinChange::Kept,
                "{bad:?}"
            );
        }
        assert_eq!(s.issuers.len(), 2);
        assert_eq!(IssuerMethod::from_verification(Method::Unverified), None);
        assert_eq!(
            IssuerMethod::from_verification(Method::Dnssec),
            Some(IssuerMethod::Dnssec)
        );
        assert!(IssuerMethod::Attested < IssuerMethod::DnsSingle);
        assert!(IssuerMethod::Dnssec < IssuerMethod::Pinned);
    }

    #[test]
    fn a_pin_is_forgotten_on_a_denial_at_least_as_strong() {
        let mut s = Snapshot::default();
        s.pin(pin("example.org", 1, IssuerMethod::Dnssec, NOW));
        s.pin(pin("example.org", 2, IssuerMethod::Attested, NOW));
        assert!(
            !s.unpin("example.org", &key(1), IssuerMethod::Dns),
            "unsigned DNS cannot withdraw a DNSSEC pin"
        );
        assert!(s.unpin("example.org", &key(2), IssuerMethod::Dns));
        assert!(s.unpin("EXAMPLE.org", &key(1), IssuerMethod::Dnssec));
        assert!(s.issuers.is_empty());
        s.pin(pin("example.org", 1, IssuerMethod::Pinned, NOW));
        assert!(!s.unpin("example.org", &key(1), IssuerMethod::Dnssec));
        assert!(s.unpin("example.org", &key(1), IssuerMethod::Pinned));
        assert!(!s.unpin("not a domain", &key(1), IssuerMethod::Pinned));
    }

    #[test]
    fn anchors_floors_and_the_file_shape_round_trip() {
        let mut s = Snapshot::default();
        s.pin(pin("example.org", 1, IssuerMethod::Dnssec, NOW));
        let mut certs = Certs::new();
        let alice = cert(1, "alice@example.org", 4, &[]);
        certs.insert(alice.clone(), NOW).unwrap();
        s.record(&certs);
        s.note_seen(
            SeenKey {
                kind: 37197,
                author: key(1),
                d: "example.org".into(),
            },
            NOW - 10,
            NOW,
        );
        let json = serde_json::to_string(&s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["issuers"][0]["method"], "dnssec", "spec §6 shape");
        assert!(
            v["issuers"][0]["npub"]
                .as_str()
                .unwrap()
                .starts_with("npub1")
        );
        assert_eq!(v["seen"][0][0]["kind"], 37200);
        assert_eq!(v["seen"][0][0]["d"], "alice@example.org");
        assert_eq!(v["seen"][0][1], NOW - 60);
        assert_eq!(v["seen"][1][0]["kind"], 37197);
        let back: Snapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
        // Across a restart: anchors and floors come back, nothing older
        // than the floor gets in, the claim entry is still known.
        let anchors = back.anchors();
        assert_eq!(
            anchors
                .anchor_for(&key(1), "sales.example.org")
                .map(|a| a.kind),
            Some(AnchorKind::Pinned)
        );
        let mut fresh = Certs::new();
        back.seed(&mut fresh);
        let mut older = alice.clone();
        older.created_at -= 1;
        assert_eq!(fresh.insert(older, NOW), Err(Ignored::Stale));
        assert_eq!(fresh.insert(alice, NOW), Ok(()));
        assert_eq!(
            back.newest_seen(&SeenKey {
                kind: 37197,
                author: key(1),
                d: "example.org".into()
            }),
            Some(NOW - 10)
        );
        // An empty or old file is a default snapshot.
        let empty: Snapshot = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, Snapshot::default());
        let future: Snapshot =
            serde_json::from_str(r#"{"issuers":[],"seen":[],"later":1}"#).unwrap();
        assert_eq!(future, Snapshot::default());
    }

    #[test]
    fn note_seen_moves_forward_only_and_retain_bounds_the_file() {
        let mut s = Snapshot::default();
        let k = SeenKey {
            kind: 37197,
            author: key(1),
            d: "example.org".into(),
        };
        assert!(s.note_seen(k.clone(), NOW - 5, NOW));
        assert!(!s.note_seen(k.clone(), NOW - 5, NOW), "same");
        assert!(!s.note_seen(k.clone(), NOW - 6, NOW), "older");
        assert!(s.note_seen(k.clone(), NOW, NOW));
        assert!(
            !s.note_seen(k.clone(), NOW + MAX_FUTURE_SECS + 1, NOW),
            "the future is not seen"
        );
        assert_eq!(s.newest_seen(&k), Some(NOW));
        let evil = SeenKey {
            kind: KIND_CERT,
            author: key(6),
            d: "alice@example.org".into(),
        };
        s.note_seen(evil.clone(), NOW, NOW);
        s.pin(pin("example.org", 1, IssuerMethod::Dnssec, NOW));
        let mut certs = Certs::new();
        certs
            .insert(cert(1, "_@example.org", 2, &[Usage::Ca]), NOW)
            .unwrap();
        certs
            .insert(cert(6, "alice@example.org", 6, &[]), NOW)
            .unwrap();
        assert!(s.is_trusted_author(&certs, &key(1), NOW), "pinned");
        assert!(s.is_trusted_author(&certs, &key(2), NOW), "certified");
        assert!(!s.is_trusted_author(&certs, &key(6), NOW));
        let snap = s.clone();
        s.retain_authors(|a| snap.is_trusted_author(&certs, a, NOW));
        assert_eq!(s.newest_seen(&evil), None);
        assert_eq!(s.newest_seen(&k), Some(NOW));
        // record() replaces the certificate entries and keeps the rest.
        let trusted: Vec<Npub> = [key(1), key(2), key(6)]
            .into_iter()
            .filter(|a| snap.is_trusted_author(&certs, a, NOW))
            .collect();
        certs.retain_issuers(|a| trusted.contains(a));
        s.record(&certs);
        assert_eq!(s.seen.len(), 2);
        assert!(
            s.seen
                .iter()
                .any(|(k, _)| k.kind == KIND_CERT && k.author == key(1))
        );
    }

    #[test]
    fn the_memory_store_hands_back_what_it_was_given() {
        let store = MemoryStore::default();
        assert_eq!(store.load().unwrap(), Snapshot::default());
        let mut s = Snapshot::default();
        s.pin(pin("example.org", 1, IssuerMethod::Pinned, NOW));
        store.save(&s).unwrap();
        assert_eq!(store.load().unwrap(), s);
        assert_eq!(MemoryStore::new(s.clone()).load().unwrap(), s);
    }
}
