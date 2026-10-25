//! The offline bundle (spec §7, nip.md "Offline bundle"): a list of
//! events a subject hands over so that a verifier with no network can run
//! path validation. The certificate comes first, then the sub-issuer
//! certificates up the path, then the anchored issuer's kind 37197 claim
//! with its `fips-ca` chain, then attestations.
//!
//! This module sorts and validates; it does not check signatures (the
//! I/O crate does, on the full events, before reducing them to
//! `pubdom_core::Event`) and it does not verify the claim's DNSSEC chain
//! (`pubdom_resolve::proof` does). What it gives the I/O crate is: the
//! claims whose chains to verify and the attestations to count, so that
//! it can fill an [`Anchors`] and call [`Bundle::validate`].

use crate::cert::{CertError, Certificate};
use crate::path::{Anchors, Certs, Path, PathError, validate};
use crate::{KIND_CERT, SERVICE_CA};
use pubdom_core::claim::{Attestation, ClaimError, Event, ServiceClaim};
use pubdom_core::{KIND_ATTESTATION, KIND_CLAIM, Npub};

/// Events in a bundle at most: a path of `MAX_PATH`, a claim per anchored
/// key, attestations from a handful of witnesses.
pub const MAX_BUNDLE_EVENTS: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleError {
    #[error("empty bundle")]
    Empty,
    #[error("more than {MAX_BUNDLE_EVENTS} events")]
    TooLarge,
    #[error("the first event is not a certificate: {0}")]
    First(CertError),
    #[error("event {0}: {1}")]
    Certificate(usize, CertError),
    #[error("event {0}: {1}")]
    Claim(usize, ClaimError),
    #[error("event {0}: {1}")]
    Attestation(usize, ClaimError),
    #[error("event {0}: kind {1} does not belong in a bundle")]
    Kind(usize, u16),
}

/// A parsed bundle. `cert` is the first event, the one to validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub cert: Certificate,
    /// Every certificate in the bundle, `cert` included, in order.
    pub certs: Vec<Certificate>,
    /// The `fips-ca` claims: the issuer bindings to verify.
    pub claims: Vec<ServiceClaim>,
    pub attestations: Vec<Attestation>,
}

impl Bundle {
    /// Sort a bundle's events. Signatures are the caller's business.
    pub fn from_events(events: &[Event]) -> Result<Self, BundleError> {
        let first = events.first().ok_or(BundleError::Empty)?;
        if events.len() > MAX_BUNDLE_EVENTS {
            return Err(BundleError::TooLarge);
        }
        if first.kind != KIND_CERT {
            return Err(BundleError::First(CertError::Kind(first.kind)));
        }
        let cert = Certificate::parse(first).map_err(BundleError::First)?;
        let mut certs = vec![cert.clone()];
        let mut claims = Vec::new();
        let mut attestations = Vec::new();
        for (i, ev) in events.iter().enumerate().skip(1) {
            match ev.kind {
                KIND_CERT => {
                    certs.push(Certificate::parse(ev).map_err(|e| BundleError::Certificate(i, e))?)
                }
                KIND_CLAIM => claims.push(
                    ServiceClaim::parse(ev, SERVICE_CA).map_err(|e| BundleError::Claim(i, e))?,
                ),
                KIND_ATTESTATION => attestations
                    .push(Attestation::parse(ev).map_err(|e| BundleError::Attestation(i, e))?),
                k => return Err(BundleError::Kind(i, k)),
            }
        }
        Ok(Self {
            cert,
            certs,
            claims,
            attestations,
        })
    }

    /// Validate the bundle's certificate at `now`, with the bundle's
    /// certificates added to what the verifier already `known`. What is
    /// known wins: a bundle cannot roll a certificate back below a seen
    /// marker or renewal.
    pub fn validate(&self, known: &Certs, anchors: &Anchors, now: u64) -> Result<Path, PathError> {
        let mut table = known.clone();
        for c in &self.certs {
            // Stale or future ones are refused here and, if the path
            // needs them, named by validate.
            let _ = table.insert(c.clone(), now);
        }
        validate(&table, anchors, &self.cert, now)
    }

    /// The `fips-ca` claims of `issuer` for `domain`: what the I/O crate
    /// verifies (chain, witnesses) to anchor the path.
    pub fn claims_of<'a>(
        &'a self,
        issuer: &'a Npub,
        domain: &'a str,
    ) -> impl Iterator<Item = &'a ServiceClaim> + 'a {
        self.claims
            .iter()
            .filter(move |c| c.author == *issuer && c.domain == domain)
    }

    /// The attestations naming `issuer` for `domain` in the `fips-ca`
    /// role, by witness; the I/O crate counts the configured witnesses
    /// among them.
    pub fn attestations_of<'a>(
        &'a self,
        issuer: &'a Npub,
        domain: &'a str,
    ) -> impl Iterator<Item = &'a Attestation> + 'a {
        self.attestations.iter().filter(move |a| {
            a.domain == domain
                && a.others
                    .iter()
                    .any(|(role, k)| role == SERVICE_CA && k == issuer)
        })
    }

    /// The issuers the bundle's path would need an anchor for: the author
    /// of every certificate in it that no other certificate in it
    /// certifies. Usually one key, the anchored issuer; the I/O crate
    /// verifies its claim and pins it before [`Bundle::validate`].
    pub fn anchors_needed(&self) -> Vec<(Npub, String)> {
        let mut out: Vec<(Npub, String)> = Vec::new();
        for c in &self.certs {
            let certified = self
                .certs
                .iter()
                .any(|s| s.is_ca() && s.issuer != c.issuer && s.subjects.contains(&c.issuer));
            if !certified
                && !out
                    .iter()
                    .any(|(k, d)| *k == c.issuer && *d == c.name.domain)
            {
                out.push((c.issuer, c.name.domain.clone()));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Usage;
    use crate::name::Name;
    use pubdom_core::Method;

    const NOW: u64 = 1_790_000_000;

    fn key(n: u8) -> Npub {
        Npub::from_bytes([n; 32])
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

    fn event(c: &Certificate) -> Event {
        Event {
            kind: KIND_CERT,
            pubkey: c.issuer.to_hex(),
            created_at: c.created_at,
            tags: c.tags(),
        }
    }

    fn claim(author: u8, domain: &str) -> Event {
        Event {
            kind: KIND_CLAIM,
            pubkey: key(author).to_hex(),
            created_at: NOW - 100,
            tags: ServiceClaim::tags(domain, SERVICE_CA, None, Some("Y2hhaW4=")),
        }
    }

    fn attestation(witness: u8, domain: &str, issuer: u8) -> Event {
        Event {
            kind: KIND_ATTESTATION,
            pubkey: key(witness).to_hex(),
            created_at: NOW - 50,
            tags: Attestation::tags_with(
                domain,
                &[key(9)],
                &[(SERVICE_CA.to_string(), key(issuer))],
                Method::Dnssec,
                NOW - 50,
            ),
        }
    }

    fn fixture() -> (Vec<Event>, Certificate, Certificate) {
        let root_ca = cert(1, "_@example.org", 2, &[Usage::Ca]);
        let alice = cert(2, "alice@example.org", 4, &[]);
        let events = vec![
            event(&alice),
            event(&root_ca),
            claim(1, "example.org"),
            attestation(7, "example.org", 1),
        ];
        (events, alice, root_ca)
    }

    #[test]
    fn sorts_the_events_and_names_what_needs_anchoring() {
        let (events, alice, root_ca) = fixture();
        let b = Bundle::from_events(&events).unwrap();
        assert_eq!(b.cert, alice);
        assert_eq!(b.certs, vec![alice, root_ca]);
        assert_eq!(b.claims.len(), 1);
        assert_eq!(b.claims[0].service, SERVICE_CA);
        assert_eq!(b.claims[0].dnssec.as_deref(), Some("Y2hhaW4="));
        assert_eq!(b.attestations.len(), 1);
        assert_eq!(
            b.anchors_needed(),
            vec![(key(1), "example.org".to_string())]
        );
        assert_eq!(b.claims_of(&key(1), "example.org").count(), 1);
        assert_eq!(b.claims_of(&key(2), "example.org").count(), 0);
        assert_eq!(b.claims_of(&key(1), "example.net").count(), 0);
        assert_eq!(b.attestations_of(&key(1), "example.org").count(), 1);
        assert_eq!(
            b.attestations_of(&key(9), "example.org").count(),
            0,
            "a fips-dns server is not an issuer"
        );
    }

    #[test]
    fn validates_with_the_bundle_s_path_and_defers_to_what_is_known() {
        let (events, alice, root_ca) = fixture();
        let b = Bundle::from_events(&events).unwrap();
        let mut anchors = Anchors::new();
        assert_eq!(
            b.validate(&Certs::new(), &anchors, NOW),
            Err(PathError::Via(
                "_@example.org".into(),
                Box::new(PathError::NoIssuer)
            )),
            "until the claim is verified and the issuer anchored"
        );
        anchors.add("example.org", key(1));
        let p = b.validate(&Certs::new(), &anchors, NOW).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p.cert(), &alice);
        // The verifier has seen the root revoke its delegation: the
        // bundle's older copy does not bring it back.
        let mut marker = root_ca.clone();
        marker.created_at = NOW;
        marker.revoked = Some("rotated".into());
        let mut known = Certs::new();
        known.insert(marker, NOW).unwrap();
        assert_eq!(
            b.validate(&known, &anchors, NOW),
            Err(PathError::Via(
                "_@example.org".into(),
                Box::new(PathError::Revoked("rotated".into()))
            ))
        );
        // And a newer certificate for alice herself supersedes the bundle's.
        let mut newer = alice.clone();
        newer.created_at = NOW;
        let mut known = Certs::new();
        known.insert(newer, NOW).unwrap();
        assert_eq!(
            b.validate(&known, &anchors, NOW),
            Err(PathError::Superseded)
        );
        // A bare-key issuer needs no claim at all.
        let issuer = key(5);
        let bob = cert(5, &format!("bob@{}", issuer.fips_name()), 6, &[]);
        let b = Bundle::from_events(&[event(&bob)]).unwrap();
        assert!(b.validate(&Certs::new(), &Anchors::new(), NOW).is_ok());
        assert_eq!(b.anchors_needed(), vec![(issuer, issuer.fips_name())]);
    }

    #[test]
    fn rejects_what_is_not_a_bundle() {
        let (events, alice, _) = fixture();
        assert_eq!(Bundle::from_events(&[]), Err(BundleError::Empty));
        let mut e = events.clone();
        e.swap(0, 2);
        assert_eq!(
            Bundle::from_events(&e),
            Err(BundleError::First(CertError::Kind(KIND_CLAIM)))
        );
        let mut e = events.clone();
        e[0].tags.retain(|t| t[0] != "p");
        assert_eq!(
            Bundle::from_events(&e),
            Err(BundleError::First(CertError::Subject))
        );
        let mut e = events.clone();
        e[1].tags.retain(|t| t[0] != "expiration");
        assert_eq!(
            Bundle::from_events(&e),
            Err(BundleError::Certificate(1, CertError::Expiration))
        );
        let mut e = events.clone();
        e[2].tags.retain(|t| t[0] != "service");
        assert_eq!(
            Bundle::from_events(&e),
            Err(BundleError::Claim(2, ClaimError::Service))
        );
        let mut e = events.clone();
        e[2].tags[1] = vec!["service".into(), "fips-dns".into(), "5355".into()];
        assert_eq!(
            Bundle::from_events(&e),
            Err(BundleError::Claim(2, ClaimError::Service)),
            "a DNS claim is not an issuer binding"
        );
        let mut e = events.clone();
        e[3].tags.retain(|t| t[0] != "method");
        assert!(matches!(
            Bundle::from_events(&e),
            Err(BundleError::Attestation(3, _))
        ));
        let mut e = events.clone();
        e.push(Event {
            kind: 1,
            pubkey: key(1).to_hex(),
            created_at: NOW,
            tags: Vec::new(),
        });
        assert_eq!(Bundle::from_events(&e), Err(BundleError::Kind(4, 1)));
        let many: Vec<Event> = std::iter::repeat_n(event(&alice), MAX_BUNDLE_EVENTS + 1).collect();
        assert_eq!(Bundle::from_events(&many), Err(BundleError::TooLarge));
    }
}
