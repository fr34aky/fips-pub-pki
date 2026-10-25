//! Path validation (spec §4, nip.md "Path validation"): from a certificate
//! up through sub-issuer certificates to an issuer the verifier can place,
//! over tables and nothing else. What the verifier knows is two tables:
//!
//! - [`Anchors`]: the issuers it has placed for a domain — `fips-ca`
//!   keys whose NIP-DB claim it accepted, or bare keys it configured —
//!   plus the structural rule that the key of `<npub>.fips` is anchored
//!   for that overlay domain;
//! - [`Certs`]: the newest certificate per (issuer, name) it has seen,
//!   with the anti-rollback floor carried across restarts (spec §6).
//!
//! [`validate`] checks one certificate; [`resolve`] answers "who is this
//! name" and detects disputes; [`names_of`] answers "which names does
//! this key hold".

use crate::cert::Certificate;
use crate::name::{Name, is_under, overlay_key};
use crate::{MAX_FUTURE_SECS, MAX_PATH};
use pubdom_core::Npub;
use pubdom_core::domain::normalize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Where a path ends: an issuer the verifier placed for a domain at or
/// above the certificate's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub issuer: Npub,
    /// The domain the issuer is anchored for (the certificate's or one
    /// above it).
    pub domain: String,
    pub kind: AnchorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnchorKind {
    /// In the verifier's issuer table: a verified `fips-ca` binding or a
    /// configured bare key.
    Pinned,
    /// The key of `<npub>.fips` for a name under that overlay domain.
    Overlay,
}

/// The verifier's anchored issuers, by domain. Domains are normalized on
/// the way in; a single label (`org`, `fips`) is never a domain one can
/// be anchored for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Anchors {
    pins: Vec<(String, Npub)>,
}

impl Anchors {
    pub fn new() -> Self {
        Self::default()
    }

    /// Anchor `issuer` for `domain`. Returns `false` if it already was,
    /// or if `domain` is not a domain one can be anchored for.
    pub fn add(&mut self, domain: &str, issuer: Npub) -> bool {
        let Some(domain) = pin_domain(domain) else {
            return false;
        };
        if self.pins.iter().any(|(d, k)| *d == domain && *k == issuer) {
            return false;
        }
        self.pins.push((domain, issuer));
        true
    }

    /// Withdraw `issuer` for `domain` (the TXT record dropped it, or the
    /// user did). Returns whether it was there.
    pub fn remove(&mut self, domain: &str, issuer: &Npub) -> bool {
        let Some(domain) = pin_domain(domain) else {
            return false;
        };
        let before = self.pins.len();
        self.pins.retain(|(d, k)| !(*d == domain && k == issuer));
        self.pins.len() != before
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// The anchored issuers for exactly `domain`.
    pub fn for_domain<'a>(&'a self, domain: &'a str) -> impl Iterator<Item = &'a Npub> + 'a {
        self.pins
            .iter()
            .filter(move |(d, _)| d == domain)
            .map(|(_, k)| k)
    }

    /// Is `issuer` anchored for `domain` or a domain above it? The
    /// nearest domain wins, pins before the overlay rule. The walk stops
    /// at an overlay domain `<npub>.fips`: nothing above it (the label
    /// `fips`) anchors names under it.
    pub fn anchor_for(&self, issuer: &Npub, domain: &str) -> Option<Anchor> {
        let mut scope = domain;
        loop {
            if self.pins.iter().any(|(d, k)| d == scope && k == issuer) {
                return Some(Anchor {
                    issuer: *issuer,
                    domain: scope.to_string(),
                    kind: AnchorKind::Pinned,
                });
            }
            if let Some(key) = overlay_key(scope) {
                return (key == *issuer).then(|| Anchor {
                    issuer: *issuer,
                    domain: scope.to_string(),
                    kind: AnchorKind::Overlay,
                });
            }
            scope = scope.split_once('.')?.1;
            if !scope.contains('.') {
                return None;
            }
        }
    }
}

/// A domain one can pin an issuer for: normalized, at least two labels.
fn pin_domain(domain: &str) -> Option<String> {
    normalize(domain).filter(|d| d.contains('.'))
}

/// Dated more than `MAX_FUTURE_SECS` ahead of `now` (NIP-DB's rule).
fn too_far_ahead(cert: &Certificate, now: u64) -> bool {
    cert.created_at > now.saturating_add(MAX_FUTURE_SECS)
}

/// Why a certificate was not taken into [`Certs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ignored {
    /// Dated more than `MAX_FUTURE_SECS` ahead of `now`.
    Future,
    /// Not newer than what is known for (issuer, name): a replay.
    Stale,
}

/// The certificates a verifier holds: the newest per (issuer, name),
/// never rolled back below what it has seen.
#[derive(Debug, Clone, Default)]
pub struct Certs {
    newest: HashMap<(Npub, Name), Certificate>,
    /// The highest `created_at` seen per (issuer, name) before this
    /// process started, from the store (spec §6).
    floor: HashMap<(Npub, Name), u64>,
}

impl Certs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember that `created_at` was seen for (issuer, name), so that
    /// nothing older is accepted later. The store feeds this at start.
    pub fn set_floor(&mut self, issuer: Npub, name: Name, created_at: u64) {
        let e = self.floor.entry((issuer, name)).or_insert(0);
        *e = (*e).max(created_at);
    }

    /// Take a certificate in; the newest per (issuer, name) wins.
    pub fn insert(&mut self, cert: Certificate, now: u64) -> Result<(), Ignored> {
        if too_far_ahead(&cert, now) {
            return Err(Ignored::Future);
        }
        let key = (cert.issuer, cert.name.clone());
        if let Some(floor) = self.floor.get(&key)
            && cert.created_at < *floor
        {
            return Err(Ignored::Stale);
        }
        if let Some(have) = self.newest.get(&key)
            && cert.created_at <= have.created_at
        {
            return Err(Ignored::Stale);
        }
        self.newest.insert(key, cert);
        Ok(())
    }

    /// Drop every certificate whose `expiration` has passed, markers
    /// included (a marker expires with what it revoked); their floors
    /// stay, so nothing older can return. Relays drop them too (NIP-40).
    pub fn prune_expired(&mut self, now: u64) -> usize {
        let before = self.newest.len();
        let floor = &mut self.floor;
        self.newest.retain(|key, c| {
            if now < c.expiration {
                return true;
            }
            let e = floor.entry(key.clone()).or_insert(0);
            *e = (*e).max(c.created_at);
            false
        });
        before - self.newest.len()
    }

    /// Keep the certificates and floors `keep` accepts, by issuer. The
    /// store uses this to bound what untrusted relay traffic can grow:
    /// anything from an issuer that is neither anchored nor certified
    /// need not be remembered.
    pub fn retain_issuers(&mut self, mut keep: impl FnMut(&Npub) -> bool) {
        self.newest.retain(|(issuer, _), _| keep(issuer));
        self.floor.retain(|(issuer, _), _| keep(issuer));
    }

    /// The newest certificate `issuer` published for `name`, marker or not.
    pub fn get(&self, issuer: &Npub, name: &Name) -> Option<&Certificate> {
        self.newest.get(&(*issuer, name.clone()))
    }

    /// Every issuer's newest certificate for `name`.
    pub fn by_name<'a>(&'a self, name: &'a Name) -> impl Iterator<Item = &'a Certificate> + 'a {
        self.newest
            .iter()
            .filter(move |((_, n), _)| n == name)
            .map(|(_, c)| c)
    }

    /// Every certificate naming `key` as a subject.
    pub fn by_subject<'a>(&'a self, key: &'a Npub) -> impl Iterator<Item = &'a Certificate> + 'a {
        self.newest
            .values()
            .filter(move |c| c.subjects.contains(key))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Certificate> {
        self.newest.values()
    }

    pub fn len(&self) -> usize {
        self.newest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.newest.is_empty()
    }

    /// What to persist: the highest `created_at` known per (issuer,
    /// name), floors included.
    pub fn seen(&self) -> Vec<(Npub, Name, u64)> {
        let mut out: HashMap<&(Npub, Name), u64> =
            self.floor.iter().map(|(k, v)| (k, *v)).collect();
        for (k, c) in &self.newest {
            let e = out.entry(k).or_insert(0);
            *e = (*e).max(c.created_at);
        }
        let mut v: Vec<_> = out
            .into_iter()
            .map(|((issuer, name), at)| (*issuer, name.clone(), at))
            .collect();
        v.sort_by(|a, b| (a.0, &a.1.domain, &a.1.local).cmp(&(b.0, &b.1.domain, &b.1.local)));
        v
    }

    /// The newest known `created_at` for (issuer, name), from the table
    /// or the floor.
    fn newest_seen(&self, issuer: &Npub, name: &Name) -> Option<u64> {
        let key = (*issuer, name.clone());
        let a = self.newest.get(&key).map(|c| c.created_at);
        let b = self.floor.get(&key).copied();
        a.max(b)
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    #[error("expired")]
    Expired,
    #[error("revoked: {0}")]
    Revoked(String),
    /// A newer certificate from the same issuer for the same name is
    /// known: this one is a replay.
    #[error("superseded by a newer certificate")]
    Superseded,
    #[error("dated too far in the future")]
    Future,
    /// Neither anchored for the name's domain nor holder of a live
    /// sub-issuer certificate reaching it.
    #[error("issuer not anchored or certified for this name")]
    NoIssuer,
    #[error("path longer than {MAX_PATH} certificates")]
    TooLong,
    #[error("pathlen of a sub-issuer certificate exceeded")]
    Pathlen,
    /// The failure of the sub-issuer certificate named, up the path.
    #[error("through {0}: {1}")]
    Via(String, Box<PathError>),
}

/// A validated path: the certificate first, then the sub-issuer
/// certificates up to the one the anchor signed. Serialized for display;
/// never read back (a path is recomputed from events, not trusted from
/// a file), which keeps `certs` non-empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Path {
    pub certs: Vec<Certificate>,
    pub anchor: Anchor,
}

impl Path {
    /// The certificate that was validated.
    pub fn cert(&self) -> &Certificate {
        &self.certs[0]
    }

    pub fn len(&self) -> usize {
        self.certs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }
}

/// Validate `cert` at `now` against what the verifier knows. `cert` need
/// not be in `certs` (a bundle, a `#p` answer): what is in `certs` is
/// knowledge that may contradict it.
pub fn validate(
    certs: &Certs,
    anchors: &Anchors,
    cert: &Certificate,
    now: u64,
) -> Result<Path, PathError> {
    let mut trail: Vec<(Npub, Name)> = Vec::new();
    let chain = build(certs, anchors, cert, now, 0, &mut trail)?;
    Ok(chain)
}

fn check_link(certs: &Certs, cert: &Certificate, now: u64) -> Result<(), PathError> {
    if too_far_ahead(cert, now) {
        return Err(PathError::Future);
    }
    if let Some(reason) = &cert.revoked {
        return Err(PathError::Revoked(reason.clone()));
    }
    if let Some(newest) = certs.newest_seen(&cert.issuer, &cert.name)
        && newest > cert.created_at
    {
        // The newer one may be the revocation marker: say so.
        if let Some(have) = certs.get(&cert.issuer, &cert.name)
            && have.created_at == newest
            && let Some(reason) = &have.revoked
        {
            return Err(PathError::Revoked(reason.clone()));
        }
        return Err(PathError::Superseded);
    }
    if now >= cert.expiration {
        return Err(PathError::Expired);
    }
    Ok(())
}

/// `ca_below`: sub-issuer certificates already in the path below `cert`
/// (what a `pathlen` on the next link up is checked against).
fn build(
    certs: &Certs,
    anchors: &Anchors,
    cert: &Certificate,
    now: u64,
    ca_below: u32,
    trail: &mut Vec<(Npub, Name)>,
) -> Result<Path, PathError> {
    check_link(certs, cert, now)?;
    if let Some(anchor) = anchors.anchor_for(&cert.issuer, &cert.name.domain) {
        return Ok(Path {
            certs: vec![cert.clone()],
            anchor,
        });
    }
    if trail.len() + 1 >= MAX_PATH {
        return Err(PathError::TooLong);
    }
    // Candidates: live sub-issuer certificates naming our issuer, for a
    // domain at or above ours, from another key (a key delegating to
    // itself adds a link and answers nothing: the anchor question for it
    // was just asked). Nearest first, then newest, then by issuer and
    // name so that equal inputs give equal paths on every verifier.
    let mut candidates: Vec<&Certificate> = certs
        .iter()
        .filter(|s| {
            s.is_ca()
                && s.issuer != cert.issuer
                && s.subjects.contains(&cert.issuer)
                && is_under(&cert.name.domain, &s.name.domain)
                && !trail.iter().any(|(i, n)| *i == s.issuer && *n == s.name)
        })
        .collect();
    if candidates.is_empty() {
        return Err(PathError::NoIssuer);
    }
    candidates.sort_by(|a, b| {
        b.name
            .domain
            .len()
            .cmp(&a.name.domain.len())
            .then(b.created_at.cmp(&a.created_at))
            .then(a.issuer.cmp(&b.issuer))
            .then(a.name.to_string().cmp(&b.name.to_string()))
    });
    let below = ca_below + u32::from(cert.is_ca());
    let mut first_err = None;
    trail.push((cert.issuer, cert.name.clone()));
    for s in candidates {
        let via = |e: PathError| PathError::Via(s.name.to_string(), Box::new(e));
        let r = if s.pathlen.is_some_and(|n| below > n) {
            Err(via(PathError::Pathlen))
        } else {
            build(certs, anchors, s, now, below, trail).map_err(via)
        };
        match r {
            Ok(mut path) => {
                trail.pop();
                path.certs.insert(0, cert.clone());
                return Ok(path);
            }
            Err(e) => first_err.get_or_insert(e),
        };
    }
    trail.pop();
    Err(first_err.unwrap_or(PathError::NoIssuer))
}

/// What a name resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// One subject (set of keys), through the shortest valid path; other
    /// valid paths agree on the keys.
    Verified(Path),
    /// Valid paths disagree on the subject: use none (nip.md).
    Disputed(Vec<Path>),
    /// Certificates exist for the name but none validates.
    Refused(Vec<(Certificate, PathError)>),
    /// No certificate for the name is known.
    Unknown,
}

/// Resolve `name` at `now` from every issuer's newest certificate for it.
pub fn resolve(certs: &Certs, anchors: &Anchors, name: &Name, now: u64) -> Resolution {
    let mut valid: Vec<Path> = Vec::new();
    let mut refused = Vec::new();
    for c in certs.by_name(name) {
        match validate(certs, anchors, c, now) {
            Ok(p) => valid.push(p),
            Err(e) => refused.push((c.clone(), e)),
        }
    }
    if valid.is_empty() {
        return if refused.is_empty() {
            Resolution::Unknown
        } else {
            refused.sort_by_key(|(c, _)| std::cmp::Reverse(c.created_at));
            Resolution::Refused(refused)
        };
    }
    let keys = |p: &Path| {
        let mut k = p.cert().subjects.clone();
        k.sort();
        k
    };
    let first = keys(&valid[0]);
    if valid.iter().any(|p| keys(p) != first) {
        return Resolution::Disputed(valid);
    }
    valid.sort_by(|a, b| {
        a.len()
            .cmp(&b.len())
            .then(b.cert().created_at.cmp(&a.cert().created_at))
            .then(a.cert().issuer.cmp(&b.cert().issuer))
    });
    Resolution::Verified(valid.swap_remove(0))
}

/// The names `key` validly holds at `now`: every certificate naming it as
/// a subject that validates. Disputes are not resolved here; a caller
/// that needs the name → key direction uses [`resolve`] on each name.
pub fn names_of(certs: &Certs, anchors: &Anchors, key: &Npub, now: u64) -> Vec<Path> {
    let mut out: Vec<Path> = certs
        .by_subject(key)
        .filter_map(|c| validate(certs, anchors, c, now).ok())
        .collect();
    out.sort_by_key(|p| p.cert().name.to_string());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Usage;

    const NOW: u64 = 1_790_000_000;
    const DAY: u64 = 86_400;

    fn key(n: u8) -> Npub {
        Npub::from_bytes([n; 32])
    }
    const ROOT: u8 = 1;
    const ONLINE: u8 = 2;
    const SALES: u8 = 3;
    const ALICE: u8 = 4;
    const BOB: u8 = 5;
    const EVIL: u8 = 6;
    const EMEA: u8 = 7;

    fn cert(issuer: u8, name: &str, subject: u8) -> Certificate {
        Certificate {
            issuer: key(issuer),
            name: Name::parse(name).unwrap(),
            subjects: vec![key(subject)],
            expiration: NOW + 90 * DAY,
            usages: Vec::new(),
            revoked: None,
            pathlen: None,
            relays: Vec::new(),
            created_at: NOW - DAY,
        }
    }

    fn ca(issuer: u8, domain: &str, subject: u8) -> Certificate {
        let mut c = cert(issuer, &format!("_@{domain}"), subject);
        c.usages = vec![Usage::Ca];
        c
    }

    fn world(certs: &[Certificate]) -> (Certs, Anchors) {
        let mut table = Certs::new();
        for c in certs {
            table.insert(c.clone(), NOW).unwrap();
        }
        let mut anchors = Anchors::new();
        anchors.add("example.org", key(ROOT));
        (table, anchors)
    }

    fn name(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    fn names(p: &Path) -> Vec<String> {
        p.certs.iter().map(|c| c.name.to_string()).collect()
    }

    #[test]
    fn an_anchored_issuer_issues_directly_for_its_domain_and_below() {
        let alice = cert(ROOT, "alice@example.org", ALICE);
        let bob = cert(ROOT, "bob@sales.example.org", BOB);
        let (certs, anchors) = world(&[alice.clone(), bob.clone()]);
        let p = validate(&certs, &anchors, &alice, NOW).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(
            p.anchor,
            Anchor {
                issuer: key(ROOT),
                domain: "example.org".into(),
                kind: AnchorKind::Pinned
            }
        );
        let p = validate(&certs, &anchors, &bob, NOW).unwrap();
        assert_eq!(p.anchor.domain, "example.org", "a domain above");
        // Anchored for another domain is not anchored here.
        let net = cert(ROOT, "alice@example.net", ALICE);
        assert_eq!(
            validate(&certs, &anchors, &net, NOW),
            Err(PathError::NoIssuer)
        );
        // A lookalike is not below.
        let evil = cert(ROOT, "alice@evilexample.org", ALICE);
        assert_eq!(
            validate(&certs, &anchors, &evil, NOW),
            Err(PathError::NoIssuer)
        );
        // An unknown issuer is placed nowhere.
        let forged = cert(EVIL, "alice@example.org", EVIL);
        assert_eq!(
            validate(&certs, &anchors, &forged, NOW),
            Err(PathError::NoIssuer)
        );
    }

    #[test]
    fn sub_issuers_chain_down_to_max_path() {
        let chain = vec![
            ca(ROOT, "example.org", ONLINE),
            ca(ONLINE, "sales.example.org", SALES),
            ca(SALES, "emea.sales.example.org", EMEA),
        ];
        let alice = cert(ONLINE, "alice@example.org", ALICE);
        let bob = cert(SALES, "bob@sales.example.org", BOB);
        let carol = cert(EMEA, "carol@emea.sales.example.org", 8);
        let mut all = chain.clone();
        all.extend([alice.clone(), bob.clone(), carol.clone()]);
        let (certs, anchors) = world(&all);
        let p = validate(&certs, &anchors, &alice, NOW).unwrap();
        assert_eq!(names(&p), ["alice@example.org", "_@example.org"]);
        assert_eq!(p.anchor.issuer, key(ROOT));
        let p = validate(&certs, &anchors, &bob, NOW).unwrap();
        assert_eq!(
            names(&p),
            [
                "bob@sales.example.org",
                "_@sales.example.org",
                "_@example.org"
            ]
        );
        let p = validate(&certs, &anchors, &carol, NOW).unwrap();
        assert_eq!(p.len(), MAX_PATH);
        // One more level is one too many.
        let deep_ca = ca(EMEA, "x.emea.sales.example.org", 9);
        let dave = cert(9, "dave@x.emea.sales.example.org", 10);
        let mut certs = certs;
        certs.insert(deep_ca, NOW).unwrap();
        certs.insert(dave.clone(), NOW).unwrap();
        assert!(
            matches!(
            validate(&certs, &anchors, &dave, NOW),
            Err(PathError::Via(_, e)) if matches!(*e, PathError::Via(_, _)) ),
            "the failure is reported up the path"
        );
        let mut e = validate(&certs, &anchors, &dave, NOW).unwrap_err();
        while let PathError::Via(_, inner) = e {
            e = *inner;
        }
        assert_eq!(e, PathError::TooLong);
    }

    #[test]
    fn a_sub_issuer_reaches_no_higher_than_its_domain() {
        let sales_ca = ca(ONLINE, "sales.example.org", SALES);
        let root_ca = ca(ROOT, "example.org", ONLINE);
        let up = cert(SALES, "alice@example.org", ALICE);
        let sideways = cert(SALES, "alice@hr.example.org", ALICE);
        let (certs, anchors) = world(&[root_ca, sales_ca, up.clone(), sideways.clone()]);
        assert_eq!(
            validate(&certs, &anchors, &up, NOW),
            Err(PathError::NoIssuer)
        );
        assert_eq!(
            validate(&certs, &anchors, &sideways, NOW),
            Err(PathError::NoIssuer)
        );
        // `ca` on a person's certificate delegates nothing.
        let mut person = cert(ROOT, "alice@example.org", ALICE);
        person.usages = vec![Usage::Ca];
        let bob = cert(ALICE, "bob@example.org", BOB);
        let (certs, anchors) = world(&[person, bob.clone()]);
        assert_eq!(
            validate(&certs, &anchors, &bob, NOW),
            Err(PathError::NoIssuer)
        );
        // A self-signed sub-issuer certificate certifies nobody and is
        // not even a candidate.
        let selfie = ca(EVIL, "example.org", EVIL);
        let forged = cert(EVIL, "alice@example.org", EVIL);
        let (certs, anchors) = world(&[selfie, forged.clone()]);
        assert_eq!(
            validate(&certs, &anchors, &forged, NOW),
            Err(PathError::NoIssuer)
        );
        // Nor does a legitimate key's delegation to itself lengthen a
        // path or shadow the real one.
        let root_ca = ca(ROOT, "example.org", ONLINE);
        let mut own = ca(ONLINE, "example.org", ONLINE);
        own.created_at = NOW;
        let alice = cert(ONLINE, "alice@example.org", ALICE);
        let (certs, anchors) = world(&[root_ca, own, alice.clone()]);
        assert_eq!(validate(&certs, &anchors, &alice, NOW).unwrap().len(), 2);
        // Two keys certifying each other go nowhere either.
        let a = ca(EVIL, "example.org", 9);
        let b = ca(9, "example.org", EVIL);
        let (certs, anchors) = world(&[a, b, forged.clone()]);
        assert!(validate(&certs, &anchors, &forged, NOW).is_err());
    }

    #[test]
    fn a_dead_link_invalidates_everything_below_it() {
        let root_ca = ca(ROOT, "example.org", ONLINE);
        let sales_ca = ca(ONLINE, "sales.example.org", SALES);
        let bob = cert(SALES, "bob@sales.example.org", BOB);
        // Expired sub-issuer certificate.
        let mut expired = sales_ca.clone();
        expired.expiration = NOW;
        let (certs, anchors) = world(&[root_ca.clone(), expired, bob.clone()]);
        assert_eq!(
            validate(&certs, &anchors, &bob, NOW),
            Err(PathError::Via(
                "_@sales.example.org".into(),
                Box::new(PathError::Expired)
            ))
        );
        // Revocation marker for the root's delegation, published later.
        let mut marker = root_ca.clone();
        marker.created_at = NOW;
        marker.revoked = Some("key compromised".into());
        let (mut certs, anchors) = world(&[root_ca.clone(), sales_ca.clone(), bob.clone()]);
        assert!(validate(&certs, &anchors, &bob, NOW).is_ok());
        certs.insert(marker, NOW).unwrap();
        assert_eq!(
            validate(&certs, &anchors, &bob, NOW),
            Err(PathError::Via(
                "_@sales.example.org".into(),
                Box::new(PathError::Via(
                    "_@example.org".into(),
                    Box::new(PathError::Revoked("key compromised".into()))
                ))
            ))
        );
        // The old delegation presented out of band is refused as revoked,
        // not merely superseded: the verifier has seen the marker.
        assert_eq!(
            validate(&certs, &anchors, &root_ca, NOW),
            Err(PathError::Revoked("key compromised".into()))
        );
        // Expired end entity, and one not yet issued.
        let mut late = cert(ROOT, "alice@example.org", ALICE);
        late.expiration = NOW - 1;
        assert_eq!(
            validate(&certs, &anchors, &late, NOW),
            Err(PathError::Expired)
        );
        let mut future = cert(ROOT, "alice@example.org", ALICE);
        future.created_at = NOW + MAX_FUTURE_SECS + 1;
        assert_eq!(
            validate(&certs, &anchors, &future, NOW),
            Err(PathError::Future)
        );
        assert_eq!(certs.insert(future, NOW), Err(Ignored::Future));
    }

    #[test]
    fn rollback_is_refused_from_the_table_and_from_the_floor() {
        let old = cert(ROOT, "alice@example.org", ALICE);
        let mut new = old.clone();
        new.created_at = NOW;
        new.subjects = vec![key(BOB)];
        let (mut certs, anchors) = world(&[new.clone()]);
        assert_eq!(certs.insert(old.clone(), NOW), Err(Ignored::Stale));
        assert_eq!(
            certs.insert(new.clone(), NOW),
            Err(Ignored::Stale),
            "same age"
        );
        assert_eq!(
            validate(&certs, &anchors, &old, NOW),
            Err(PathError::Superseded)
        );
        assert_eq!(
            certs.get(&key(ROOT), &name("alice@example.org")),
            Some(&new)
        );
        // Across a restart only the floor remains.
        let mut fresh = Certs::new();
        for (issuer, n, at) in certs.seen() {
            fresh.set_floor(issuer, n, at);
        }
        assert_eq!(fresh.insert(old.clone(), NOW), Err(Ignored::Stale));
        assert_eq!(
            validate(&fresh, &anchors, &old, NOW),
            Err(PathError::Superseded)
        );
        assert_eq!(
            fresh.insert(new.clone(), NOW),
            Ok(()),
            "the floor itself passes"
        );
        assert_eq!(
            fresh.seen(),
            vec![(key(ROOT), name("alice@example.org"), NOW)]
        );
    }

    #[test]
    fn pathlen_bounds_further_delegation() {
        let mut root_ca = ca(ROOT, "example.org", ONLINE);
        root_ca.pathlen = Some(0);
        let sales_ca = ca(ONLINE, "sales.example.org", SALES);
        let alice = cert(ONLINE, "alice@example.org", ALICE);
        let bob = cert(SALES, "bob@sales.example.org", BOB);
        let (certs, anchors) = world(&[
            root_ca.clone(),
            sales_ca.clone(),
            alice.clone(),
            bob.clone(),
        ]);
        assert!(
            validate(&certs, &anchors, &alice, NOW).is_ok(),
            "pathlen 0 still issues end entities"
        );
        assert_eq!(
            validate(&certs, &anchors, &sales_ca, NOW),
            Err(PathError::Via(
                "_@example.org".into(),
                Box::new(PathError::Pathlen)
            ))
        );
        assert_eq!(
            validate(&certs, &anchors, &bob, NOW),
            Err(PathError::Via(
                "_@sales.example.org".into(),
                Box::new(PathError::Via(
                    "_@example.org".into(),
                    Box::new(PathError::Pathlen)
                ))
            ))
        );
        // pathlen 1: one department, no further.
        root_ca.pathlen = Some(1);
        root_ca.created_at = NOW;
        let emea_ca = ca(SALES, "emea.sales.example.org", EMEA);
        let carol = cert(EMEA, "carol@emea.sales.example.org", 8);
        let mut certs = certs;
        certs.insert(root_ca, NOW).unwrap();
        certs.insert(emea_ca, NOW).unwrap();
        certs.insert(carol.clone(), NOW).unwrap();
        assert!(validate(&certs, &anchors, &bob, NOW).is_ok());
        let mut e = validate(&certs, &anchors, &carol, NOW).unwrap_err();
        while let PathError::Via(_, inner) = e {
            e = *inner;
        }
        assert_eq!(e, PathError::Pathlen);
    }

    #[test]
    fn the_nearest_sub_issuer_certificate_is_preferred_and_others_fall_back() {
        let root_ca = ca(ROOT, "example.org", ONLINE);
        // ONLINE certifies SALES for the department and, separately, for
        // the whole domain.
        let near = ca(ONLINE, "sales.example.org", SALES);
        let far = ca(ONLINE, "example.org", SALES);
        let bob = cert(SALES, "bob@sales.example.org", BOB);
        let (certs, anchors) = world(&[root_ca.clone(), near.clone(), far.clone(), bob.clone()]);
        let p = validate(&certs, &anchors, &bob, NOW).unwrap();
        assert_eq!(names(&p)[1], "_@sales.example.org");
        // The near one expires: the far one carries.
        let mut gone = near;
        gone.expiration = NOW;
        let (certs, anchors) = world(&[root_ca, gone, far, bob.clone()]);
        let p = validate(&certs, &anchors, &bob, NOW).unwrap();
        assert_eq!(names(&p)[1], "_@example.org");
    }

    #[test]
    fn resolution_verified_disputed_refused_unknown() {
        let n = name("alice@example.org");
        let root_ca = ca(ROOT, "example.org", ONLINE);
        let by_root = cert(ROOT, "alice@example.org", ALICE);
        let by_online = cert(ONLINE, "alice@example.org", ALICE);
        let by_evil = cert(EVIL, "alice@example.org", EVIL);
        // Two issuers of the domain agree: the shortest path, and the
        // forgery does not count.
        let (certs, anchors) = world(&[
            root_ca.clone(),
            by_root.clone(),
            by_online.clone(),
            by_evil.clone(),
        ]);
        match resolve(&certs, &anchors, &n, NOW) {
            Resolution::Verified(p) => {
                assert_eq!(p.len(), 1);
                assert_eq!(p.cert().issuer, key(ROOT));
            }
            other => panic!("{other:?}"),
        }
        // They disagree: disputed, nobody wins.
        let mut other = by_online.clone();
        other.subjects = vec![key(BOB)];
        let (certs, anchors) = world(&[root_ca.clone(), by_root.clone(), other]);
        match resolve(&certs, &anchors, &n, NOW) {
            Resolution::Disputed(paths) => assert_eq!(paths.len(), 2),
            other => panic!("{other:?}"),
        }
        // Only a forgery and a revoked one: refused, newest first.
        let mut revoked = by_root.clone();
        revoked.revoked = Some("left".into());
        revoked.created_at = NOW;
        let (certs, anchors) = world(&[revoked, by_evil]);
        match resolve(&certs, &anchors, &n, NOW) {
            Resolution::Refused(r) => {
                assert_eq!(r.len(), 2);
                assert_eq!(r[0].1, PathError::Revoked("left".into()));
                assert_eq!(r[1].1, PathError::NoIssuer);
            }
            other => panic!("{other:?}"),
        }
        // Nothing at all.
        let (certs, anchors) = world(&[]);
        assert_eq!(resolve(&certs, &anchors, &n, NOW), Resolution::Unknown);
        // Several devices in any order are one subject.
        let mut two = by_root.clone();
        two.subjects = vec![key(ALICE), key(8)];
        let mut two_rev = by_online.clone();
        two_rev.subjects = vec![key(8), key(ALICE)];
        let (certs, anchors) = world(&[root_ca, two, two_rev]);
        assert!(matches!(
            resolve(&certs, &anchors, &n, NOW),
            Resolution::Verified(_)
        ));
    }

    #[test]
    fn a_bare_key_on_the_overlay_anchors_itself_and_may_delegate() {
        let issuer = key(ROOT);
        let domain = issuer.fips_name();
        let alice = cert(ROOT, &format!("alice@{domain}"), ALICE);
        let delegated = ca(ROOT, &domain, ONLINE);
        let bob = cert(ONLINE, &format!("bob@{domain}"), BOB);
        let forged = cert(EVIL, &format!("alice@{domain}"), EVIL);
        let mut certs = Certs::new();
        for c in [&alice, &delegated, &bob, &forged] {
            certs.insert(c.clone(), NOW).unwrap();
        }
        let anchors = Anchors::new();
        let p = validate(&certs, &anchors, &alice, NOW).unwrap();
        assert_eq!(p.anchor.kind, AnchorKind::Overlay);
        assert_eq!(p.anchor.domain, domain);
        let p = validate(&certs, &anchors, &bob, NOW).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(
            validate(&certs, &anchors, &forged, NOW),
            Err(PathError::NoIssuer)
        );
        // A pin for the overlay domain is reported as a pin.
        let mut pinned = Anchors::new();
        assert!(pinned.add(&domain, issuer));
        assert!(!pinned.add(&domain, issuer));
        assert_eq!(
            validate(&certs, &pinned, &alice, NOW).unwrap().anchor.kind,
            AnchorKind::Pinned
        );
        assert!(pinned.remove(&domain, &issuer));
        assert!(!pinned.remove(&domain, &issuer));
        assert!(pinned.is_empty());
    }

    #[test]
    fn anchors_normalize_refuse_single_labels_and_stop_at_the_overlay() {
        let mut anchors = Anchors::new();
        assert!(anchors.add("Example.ORG.", key(ROOT)));
        assert!(!anchors.add("example.org", key(ROOT)), "the same pin");
        assert_eq!(anchors.for_domain("example.org").count(), 1);
        assert!(anchors.remove("EXAMPLE.org", &key(ROOT)));
        assert!(anchors.is_empty());
        for bad in ["org", "fips", "", "not a domain", "-x.org"] {
            assert!(!anchors.add(bad, key(EVIL)), "{bad:?}");
        }
        assert!(anchors.is_empty());
        // A pin above an overlay domain anchors nothing under it; a pin
        // on a public domain still covers its subdomains.
        let overlay = key(ROOT).fips_name();
        let under = format!("alice@{overlay}");
        assert!(!anchors.add("fips", key(EVIL)));
        assert!(anchors.add("sub.fips", key(EVIL)));
        let forged = cert(EVIL, &under, EVIL);
        let certs = Certs::new();
        assert_eq!(
            validate(&certs, &anchors, &forged, NOW),
            Err(PathError::NoIssuer)
        );
        assert_eq!(
            anchors.anchor_for(&key(EVIL), &format!("x.{overlay}")),
            None
        );
        assert_eq!(
            anchors
                .anchor_for(&key(ROOT), &format!("x.{overlay}"))
                .map(|a| a.kind),
            Some(AnchorKind::Overlay),
            "a subdomain of the overlay domain is the key's"
        );
        assert!(anchors.add("example.org", key(ROOT)));
        assert_eq!(
            anchors
                .anchor_for(&key(ROOT), "deep.sales.example.org")
                .map(|a| a.domain),
            Some("example.org".to_string())
        );
        assert_eq!(anchors.anchor_for(&key(ROOT), "example.net"), None);
    }

    #[test]
    fn equal_inputs_give_the_same_path_whatever_the_table_order() {
        // Two anchored keys delegate to ONLINE in the same second.
        let r1 = ca(ROOT, "example.org", ONLINE);
        let r2 = ca(9, "example.org", ONLINE);
        let alice = cert(ONLINE, "alice@example.org", ALICE);
        let mut anchors = Anchors::new();
        anchors.add("example.org", key(ROOT));
        anchors.add("example.org", key(9));
        let mut seen = std::collections::HashSet::new();
        for order in [[&r1, &r2, &alice], [&r2, &r1, &alice], [&alice, &r2, &r1]] {
            let mut certs = Certs::new();
            for c in order {
                certs.insert(c.clone(), NOW).unwrap();
            }
            let p = validate(&certs, &anchors, &alice, NOW).unwrap();
            seen.insert(p.anchor.issuer);
            // And resolve, with a second same-age certificate by the
            // other anchored key: the lower issuer key wins the tie.
            certs
                .insert(cert(9, "alice@example.org", ALICE), NOW)
                .unwrap();
            certs
                .insert(cert(ROOT, "alice@example.org", ALICE), NOW)
                .unwrap();
            match resolve(&certs, &anchors, &name("alice@example.org"), NOW) {
                Resolution::Verified(p) => assert_eq!(p.cert().issuer, key(ROOT)),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(seen.len(), 1, "one anchor on every run");
        assert_eq!(seen.into_iter().next(), Some(key(ROOT)), "the lower key");
    }

    #[test]
    fn pruning_forgets_expired_certificates_and_untrusted_issuers_not_floors() {
        let alice = cert(ROOT, "alice@example.org", ALICE);
        let mut gone = cert(ROOT, "bob@example.org", BOB);
        gone.expiration = NOW;
        let forged = cert(EVIL, "alice@example.org", EVIL);
        let (mut certs, anchors) = world(&[alice.clone(), gone.clone(), forged]);
        assert_eq!(certs.prune_expired(NOW), 1);
        assert_eq!(certs.len(), 2);
        let mut older = gone.clone();
        older.created_at -= 1;
        older.expiration = NOW + DAY;
        assert_eq!(
            certs.insert(older, NOW),
            Err(Ignored::Stale),
            "the floor outlives the certificate"
        );
        assert_eq!(
            certs.insert(gone.clone(), NOW),
            Ok(()),
            "the same one may return"
        );
        assert_eq!(
            validate(&certs, &anchors, &gone, NOW),
            Err(PathError::Expired)
        );
        assert_eq!(certs.prune_expired(NOW), 1);
        certs.retain_issuers(|k| anchors.anchor_for(k, "example.org").is_some());
        assert_eq!(certs.len(), 1);
        assert!(certs.seen().iter().all(|(k, _, _)| *k == key(ROOT)));
        assert!(validate(&certs, &anchors, &alice, NOW).is_ok());
    }

    #[test]
    fn names_of_a_key_are_its_valid_certificates_only() {
        let root_ca = ca(ROOT, "example.org", ONLINE);
        let alice = cert(ROOT, "alice@example.org", ALICE);
        let mut alt = cert(ONLINE, "a.smith@example.org", ALICE);
        alt.subjects.push(key(8));
        let forged = cert(EVIL, "root@example.org", ALICE);
        let (certs, anchors) = world(&[root_ca, alice, alt, forged]);
        let found: Vec<String> = names_of(&certs, &anchors, &key(ALICE), NOW)
            .iter()
            .map(|p| p.cert().name.to_string())
            .collect();
        assert_eq!(found, ["a.smith@example.org", "alice@example.org"]);
        assert_eq!(names_of(&certs, &anchors, &key(8), NOW).len(), 1);
        assert!(names_of(&certs, &anchors, &key(BOB), NOW).is_empty());
        assert_eq!(certs.by_subject(&key(ALICE)).count(), 3);
        assert_eq!(certs.len(), 4);
    }
}
