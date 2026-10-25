//! The verifier (spec §2, §4, §6, §7): the tables of `pubpki-core` fed
//! from relays, the issuer's claim and its chain, and the file. The one
//! rule that shapes it: the verifier never queries DNS. An issuer is
//! placed by the user's pin, by the DNSSEC chain inside its claim, or by
//! `k` configured witnesses; a bare key on the overlay by structure.

use crate::config::Config;
use crate::core_event;
use crate::store::FileStore;
use nostr_sdk::{Event, Filter, Kind, PublicKey};
use pubdom_resolve::RelayClient;
use pubdom_resolve::proof::DnssecProofs;
use pubdom_resolve::relay::RelayScope;
use pubpki_core::name::overlay_key;
use pubpki_core::pubdom_core::claim::{Attestation, ServiceClaim};
use pubpki_core::pubdom_core::{KIND_ATTESTATION, KIND_CLAIM, Npub};
use pubpki_core::{
    AnchorKind, Anchors, Bundle, BundleError, Certificate, Certs, IssuerMethod, IssuerPin,
    IssuerStore, KIND_CERT, MAX_BUNDLE_EVENTS, MAX_FUTURE_SECS, MAX_PATH, Name, Path, PathError,
    Resolution, SERVICE_CA, SeenKey, Snapshot, attesting_witnesses, certifies, path,
};
use std::collections::HashSet;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("more than {MAX_BUNDLE_EVENTS} events")]
    TooLarge,
    #[error("event {0}: bad signature: {1}")]
    Signature(usize, String),
    #[error("{0}")]
    Bundle(#[from] BundleError),
    #[error("{0}")]
    Path(#[from] PathError),
}

/// How an issuer came to be anchored during a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchored {
    pub domain: String,
    pub issuer: Npub,
    pub method: IssuerMethod,
}

pub struct Verifier {
    cfg: Config,
    relays: RelayClient,
    proofs: DnssecProofs,
    store: Box<dyn IssuerStore>,
    snap: Snapshot,
    certs: Certs,
    /// What one `resolve`/`names_of` call has already asked the relays
    /// for, so spam certificates cannot make it ask again and again.
    fetched_domains: HashSet<String>,
    fetched_keys: HashSet<Npub>,
}

impl Verifier {
    /// Open the file named by `cfg`, seed the tables, connect the relays
    /// lazily. With no relays configured every fetch is empty, which is
    /// what an offline bundle check wants.
    pub async fn open(cfg: Config) -> Result<Self, String> {
        let store = FileStore::new(&cfg.issuers);
        Self::with_store(cfg, Box::new(store)).await
    }

    pub async fn with_store(cfg: Config, store: Box<dyn IssuerStore>) -> Result<Self, String> {
        let snap = store.load()?;
        let mut certs = Certs::new();
        snap.seed(&mut certs);
        let relays = RelayClient::new(&cfg.public_relays, &cfg.mesh_relays, cfg.budget()).await;
        Ok(Self {
            cfg,
            relays,
            proofs: DnssecProofs::default(),
            store,
            snap,
            certs,
            fetched_domains: HashSet::new(),
            fetched_keys: HashSet::new(),
        })
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snap
    }

    pub fn certs(&self) -> &Certs {
        &self.certs
    }

    /// Pin an issuer by hand (`Pinned`: no verification outranks it).
    pub fn pin(&mut self, domain: &str, issuer: Npub, now: u64) -> bool {
        matches!(
            self.snap.pin(IssuerPin {
                domain: domain.to_string(),
                npub: issuer,
                method: IssuerMethod::Pinned,
                verified_at: now,
            }),
            pubpki_core::PinChange::Added | pubpki_core::PinChange::Refreshed
        )
    }

    /// Forget an issuer the user placed or any verification placed.
    pub fn unpin(&mut self, domain: &str, issuer: &Npub) -> bool {
        self.snap.unpin(domain, issuer, IssuerMethod::Pinned)
    }

    /// Take a certificate in (fetched, or from a bundle).
    pub fn learn(&mut self, cert: Certificate, now: u64) {
        if let Err(e) = self.certs.insert(cert.clone(), now) {
            tracing::debug!(name = %cert.name, issuer = %cert.issuer, ?e, "certificate ignored");
        }
    }

    /// Anchor the `fips-ca` keys of `domain` from claims and attestations
    /// already in hand (fetched, or a bundle's): the chain in a claim
    /// earns `Dnssec`, `k` configured witnesses earn `Attested`. Claims
    /// and attestations rolled back below what was seen, or dated in the
    /// future, are ignored; the newest attestation per configured witness
    /// is remembered, so a withdrawn attestation cannot be replayed.
    /// Returns what was anchored by this call.
    pub fn anchor_from(
        &mut self,
        domain: &str,
        claims: &[ServiceClaim],
        attestations: &[Attestation],
        now: u64,
    ) -> Vec<Anchored> {
        let seen_key = |witness: Npub| SeenKey {
            kind: KIND_ATTESTATION,
            author: witness,
            d: domain.to_string(),
        };
        let attestations: Vec<Attestation> = attestations
            .iter()
            .filter(|a| {
                a.domain == domain
                    && self.cfg.witnesses.contains(&a.witness)
                    && a.created_at <= now + MAX_FUTURE_SECS
                    && !self
                        .snap
                        .newest_seen(&seen_key(a.witness))
                        .is_some_and(|seen| a.created_at < seen)
            })
            .cloned()
            .collect();
        for a in &attestations {
            self.snap.note_seen(seen_key(a.witness), a.created_at, now);
        }
        let mut out = Vec::new();
        for claim in claims
            .iter()
            .filter(|c| c.domain == domain && c.service == SERVICE_CA)
        {
            if claim.created_at > now + MAX_FUTURE_SECS {
                tracing::debug!(domain, issuer = %claim.author, "claim from the future; ignored");
                continue;
            }
            let key = SeenKey {
                kind: KIND_CLAIM,
                author: claim.author,
                d: domain.to_string(),
            };
            if self
                .snap
                .newest_seen(&key)
                .is_some_and(|seen| claim.created_at < seen)
            {
                tracing::debug!(domain, issuer = %claim.author, "claim older than seen; ignored");
                continue;
            }
            let method = match self.proofs.check_service(claim, now) {
                Ok(_) => Some(IssuerMethod::Dnssec),
                Err(e) => {
                    tracing::debug!(domain, issuer = %claim.author, %e, "no chain; trying witnesses");
                    let k = self.cfg.attestation_threshold;
                    let who = attesting_witnesses(
                        domain,
                        &claim.author,
                        &attestations,
                        &self.cfg.witnesses,
                        now,
                    );
                    (k > 0 && who.len() >= k).then_some(IssuerMethod::Attested)
                }
            };
            let Some(method) = method else {
                continue;
            };
            self.snap.pin(IssuerPin {
                domain: domain.to_string(),
                npub: claim.author,
                method,
                verified_at: now,
            });
            self.snap.note_seen(key, claim.created_at, now);
            out.push(Anchored {
                domain: domain.to_string(),
                issuer: claim.author,
                method,
            });
        }
        out
    }

    async fn fetch_certs(&mut self, filter: Filter, now: u64) -> usize {
        let events = self.relays.fetch_raw(filter, RelayScope::Offline).await;
        let mut n = 0;
        for ev in &events {
            match Certificate::parse(&core_event(ev)) {
                Ok(c) => {
                    self.learn(c, now);
                    n += 1;
                }
                Err(e) => tracing::debug!(id = %ev.id, %e, "not a certificate"),
            }
        }
        n
    }

    fn cert_filter() -> Filter {
        Filter::new().kind(Kind::from(KIND_CERT)).limit(32)
    }

    /// Fetch `domain`'s `fips-ca` claims and the configured witnesses'
    /// attestations, and anchor what they prove. For a bare-key overlay
    /// domain nothing is fetched: the key anchors itself. Once per domain
    /// and call.
    pub async fn fetch_anchor(&mut self, domain: &str, now: u64) -> Vec<Anchored> {
        if overlay_key(domain).is_some() || !self.fetched_domains.insert(domain.to_string()) {
            return Vec::new();
        }
        let claims: Vec<ServiceClaim> = self
            .relays
            .fetch_claims(domain, RelayScope::Offline)
            .await
            .iter()
            .filter_map(|ev| ServiceClaim::parse(ev, SERVICE_CA).ok())
            .collect();
        if claims.is_empty() {
            return Vec::new();
        }
        let attestations: Vec<Attestation> = if self.cfg.attestation_threshold > 0 {
            self.relays
                .fetch_attestations(domain, &self.cfg.witnesses, RelayScope::Offline)
                .await
                .iter()
                .filter_map(|ev| Attestation::parse(ev).ok())
                .collect()
        } else {
            Vec::new()
        };
        self.anchor_from(domain, &claims, &attestations, now)
    }

    /// Make sure `issuer` can be placed for `domain`: anchored already, or
    /// anchored now from the claims of `domain` or a domain above it
    /// (asked first: a directly anchorable issuer must not depend on
    /// whatever delegations strangers publish for it), or certified by a
    /// sub-issuer certificate (fetched by `#p`) whose own issuer is placed
    /// the same way. Bounded by `MAX_PATH`; each domain and key is asked
    /// for once per call.
    async fn ensure_anchor(&mut self, issuer: Npub, domain: &str, now: u64, depth: usize) {
        if self.snap.anchors().anchor_for(&issuer, domain).is_some() || depth >= MAX_PATH {
            return;
        }
        let mut scope = domain;
        while scope.contains('.') {
            self.fetch_anchor(scope, now).await;
            if self.snap.anchors().anchor_for(&issuer, domain).is_some() {
                return;
            }
            let Some((_, rest)) = scope.split_once('.') else {
                break;
            };
            scope = rest;
        }
        if self.fetched_keys.insert(issuer)
            && let Ok(pk) = PublicKey::from_slice(issuer.as_bytes())
        {
            self.fetch_certs(Self::cert_filter().pubkey(pk), now).await;
        }
        let certifiers: Vec<(Npub, String)> = self
            .certs
            .iter()
            .filter(|s| certifies(s, &issuer, domain) && s.is_live_at(now))
            .map(|s| (s.issuer, s.name.domain.clone()))
            .collect();
        for (ca_issuer, ca_domain) in certifiers {
            Box::pin(self.ensure_anchor(ca_issuer, &ca_domain, now, depth + 1)).await;
        }
    }

    /// A bare key on the overlay anchors itself by structure, but it
    /// enters the file only when the user chose it: by resolving a name
    /// under it, or by verifying its bundle. Then it is pinned, and what
    /// it issues and revokes is remembered.
    fn adopt_overlay(&mut self, path: &Path, now: u64) {
        if path.anchor.kind == AnchorKind::Overlay {
            self.pin(&path.anchor.domain.clone(), path.anchor.issuer, now);
        }
    }

    /// Resolve `name` from the relays and what is known (spec §4).
    pub async fn resolve(&mut self, name: &Name, now: u64) -> Resolution {
        self.fetched_domains.clear();
        self.fetched_keys.clear();
        self.fetch_certs(Self::cert_filter().identifier(name.to_string()), now)
            .await;
        let issuers: Vec<Npub> = self.certs.by_name(name).map(|c| c.issuer).collect();
        for issuer in issuers {
            self.ensure_anchor(issuer, &name.domain, now, 0).await;
        }
        let r = path::resolve(&self.certs, &self.snap.anchors(), name, now);
        if let Resolution::Verified(p) = &r {
            self.adopt_overlay(p, now);
        }
        r
    }

    /// The names `key` validly holds, from the relays and what is known.
    /// Nothing is adopted here: a certificate naming a key is unsolicited.
    pub async fn names_of(&mut self, key: &Npub, now: u64) -> Vec<Path> {
        self.fetched_domains.clear();
        self.fetched_keys.clear();
        if self.fetched_keys.insert(*key)
            && let Ok(pk) = PublicKey::from_slice(key.as_bytes())
        {
            self.fetch_certs(Self::cert_filter().pubkey(pk), now).await;
        }
        let pending: Vec<(Npub, String)> = self
            .certs
            .by_subject(key)
            .map(|c| (c.issuer, c.name.domain.clone()))
            .collect();
        for (issuer, domain) in pending {
            self.ensure_anchor(issuer, &domain, now, 0).await;
        }
        path::names_of(&self.certs, &self.snap.anchors(), key, now)
    }

    /// Verify an offline bundle (spec §7) with no network: signatures,
    /// then the issuer anchored from the bundle's own claim and
    /// attestations, then path validation against what is known.
    pub fn verify_bundle(&mut self, events: &[Event], now: u64) -> Result<Path, VerifyError> {
        if events.len() > MAX_BUNDLE_EVENTS {
            return Err(VerifyError::TooLarge);
        }
        for (i, ev) in events.iter().enumerate() {
            ev.verify()
                .map_err(|e| VerifyError::Signature(i, e.to_string()))?;
        }
        let core: Vec<_> = events.iter().map(core_event).collect();
        let bundle = Bundle::from_events(&core)?;
        for (issuer, domain) in bundle.anchors_needed() {
            if self.snap.anchors().anchor_for(&issuer, &domain).is_some() {
                continue;
            }
            let claim_domains: HashSet<String> = bundle
                .claims_of(issuer, &domain)
                .map(|c| c.domain.clone())
                .collect();
            for d in claim_domains {
                let claims: Vec<ServiceClaim> = bundle
                    .claims_of(issuer, &domain)
                    .filter(|c| c.domain == d)
                    .cloned()
                    .collect();
                // Every attestation for the domain, not only those naming
                // the issuer: a witness's newer one without the key is a
                // withdrawal, and it must be seen to count against it.
                let attestations: Vec<Attestation> = bundle
                    .attestations
                    .iter()
                    .filter(|a| a.domain == d)
                    .cloned()
                    .collect();
                self.anchor_from(&d, &claims, &attestations, now);
            }
        }
        let anchors: Anchors = self.snap.anchors();
        let path = bundle.validate(&self.certs, &anchors, now)?;
        for c in &bundle.certs {
            self.learn(c.clone(), now);
        }
        self.adopt_overlay(&path, now);
        Ok(path)
    }

    /// Prune, keep trusted authors only, write the file.
    pub fn save(&mut self, now: u64) -> Result<(), String> {
        self.certs.prune_expired(now);
        let authors: HashSet<Npub> = self.certs.iter().map(|c| c.issuer).collect();
        let trusted: HashSet<Npub> = authors
            .into_iter()
            .filter(|a| self.snap.is_trusted_author(&self.certs, a, now))
            .collect();
        self.certs.retain_issuers(|a| trusted.contains(a));
        self.snap.record(&self.certs, |a| trusted.contains(a));
        self.store.save(&self.snap)
    }

    pub async fn shutdown(&self) {
        self.relays.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::npub_of;
    use nostr_sdk::Keys;
    use pubdom_resolve::relay::sign_event;
    use pubpki_core::pubdom_core::{KIND_ATTESTATION, Method};
    use pubpki_core::{AnchorKind, MemoryStore, Usage};

    /// Signed events carry the real clock, so the tests do too.
    #[allow(non_snake_case)]
    fn NOW() -> u64 {
        crate::now()
    }

    fn cert(issuer: &Keys, name: &str, subject: &Keys, usages: &[Usage]) -> Certificate {
        Certificate {
            issuer: npub_of(issuer),
            name: Name::parse(name).unwrap(),
            subjects: vec![npub_of(subject)],
            expiration: NOW() + 86_400,
            usages: usages.to_vec(),
            revoked: None,
            pathlen: None,
            relays: Vec::new(),
            created_at: NOW() - 60,
        }
    }

    fn signed(keys: &Keys, kind: u16, tags: Vec<Vec<String>>) -> Event {
        sign_event(keys, kind, tags, "").unwrap()
    }

    /// `sign_event` dates events now; a replay needs an older one.
    fn signed_at(keys: &Keys, kind: u16, tags: Vec<Vec<String>>, created_at: u64) -> Event {
        use nostr_sdk::{EventBuilder, Tag, Timestamp};
        let tags: Vec<Tag> = tags.into_iter().map(|t| Tag::parse(t).unwrap()).collect();
        EventBuilder::new(Kind::from(kind), "")
            .tags(tags)
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(keys)
            .unwrap()
    }

    async fn verifier(cfg: Config) -> Verifier {
        Verifier::with_store(cfg, Box::new(MemoryStore::default()))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_bare_key_issuer_s_bundle_verifies_with_nothing_configured() {
        let issuer = Keys::generate();
        let alice = Keys::generate();
        let domain = npub_of(&issuer).fips_name();
        let c = cert(&issuer, &format!("alice@{domain}"), &alice, &[]);
        let ev = signed(&issuer, KIND_CERT, c.tags());
        let mut v = verifier(Config::default()).await;
        let path = v.verify_bundle(std::slice::from_ref(&ev), NOW()).unwrap();
        assert_eq!(path.len(), 1);
        assert_eq!(path.anchor.kind, AnchorKind::Overlay);
        assert_eq!(path.cert().subjects, vec![npub_of(&alice)]);
        // A forged event fails on the signature before anything else.
        let json = serde_json::to_string(&ev)
            .unwrap()
            .replace(&npub_of(&alice).to_hex(), &npub_of(&issuer).to_hex());
        let forged: Event = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            v.verify_bundle(&[forged], NOW()),
            Err(VerifyError::Signature(0, _))
        ));
        // Another key's certificate for a name under this overlay: no issuer.
        let other = Keys::generate();
        let bad = cert(&other, &format!("bob@{domain}"), &alice, &[]);
        assert!(matches!(
            v.verify_bundle(&[signed(&other, KIND_CERT, bad.tags())], NOW()),
            Err(VerifyError::Path(PathError::NoIssuer))
        ));
        // Only the bundle that validated taught anything; the user chose
        // this issuer by verifying its bundle, so it is pinned and kept.
        assert_eq!(v.certs().len(), 1);
        assert_eq!(v.snapshot().issuers.len(), 1);
        assert_eq!(v.snapshot().issuers[0].domain, domain);
        v.save(NOW()).unwrap();
        assert!(v.certs().by_name(&c.name).next().is_some());
        // An unsolicited certificate naming a key, from a key nobody
        // chose, is answered but not kept.
        let stranger = Keys::generate();
        let s = cert(
            &stranger,
            &format!("alice@{}", npub_of(&stranger).fips_name()),
            &alice,
            &[],
        );
        v.learn(s.clone(), NOW());
        assert_eq!(v.names_of(&npub_of(&alice), NOW()).await.len(), 2);
        v.save(NOW()).unwrap();
        assert!(v.certs().by_name(&s.name).next().is_none(), "not kept");
        assert_eq!(v.snapshot().issuers.len(), 1, "not pinned");
        // Resolving the name is choosing the issuer.
        v.learn(s.clone(), NOW());
        assert!(matches!(
            v.resolve(&s.name, NOW()).await,
            Resolution::Verified(_)
        ));
        assert_eq!(v.snapshot().issuers.len(), 2);
    }

    #[tokio::test]
    async fn a_pinned_issuer_and_a_delegation_verify_offline_and_persist() {
        let root = Keys::generate();
        let online = Keys::generate();
        let alice = Keys::generate();
        let root_ca = cert(&root, "_@example.org", &online, &[Usage::Ca]);
        let a = cert(&online, "alice@example.org", &alice, &[]);
        let bundle = [
            signed(&online, KIND_CERT, a.tags()),
            signed(&root, KIND_CERT, root_ca.tags()),
        ];
        let store = Box::new(MemoryStore::default());
        let mut v = Verifier::with_store(Config::default(), store)
            .await
            .unwrap();
        assert!(matches!(
            v.verify_bundle(&bundle, NOW()),
            Err(VerifyError::Path(PathError::Via(_, _)))
        ));
        assert!(v.pin("example.org", npub_of(&root), NOW()));
        let path = v.verify_bundle(&bundle, NOW()).unwrap();
        assert_eq!(path.len(), 2);
        assert_eq!(path.anchor.issuer, npub_of(&root));
        v.save(NOW()).unwrap();
        let snap = v.snapshot().clone();
        assert_eq!(snap.issuers.len(), 1);
        assert_eq!(
            snap.seen.len(),
            2,
            "the root's delegation and the online key's certificate"
        );
        // A second verifier from that file refuses a rolled-back delegation.
        let seen_at = bundle[1].created_at.as_secs();
        let mut v2 = Verifier::with_store(Config::default(), Box::new(MemoryStore::new(snap)))
            .await
            .unwrap();
        let stale = [
            signed(&online, KIND_CERT, a.tags()),
            signed_at(&root, KIND_CERT, root_ca.tags(), seen_at - 1),
        ];
        let r = v2.verify_bundle(&stale, NOW());
        assert!(
            matches!(
                &r,
                Err(VerifyError::Path(PathError::Via(_, e))) if **e == PathError::Superseded
            ),
            "{r:?}"
        );
        assert!(v2.unpin("example.org", &npub_of(&root)));
        assert!(matches!(
            v2.verify_bundle(&bundle, NOW()),
            Err(VerifyError::Path(PathError::Via(_, _)))
        ));
    }

    #[tokio::test]
    async fn witnesses_anchor_a_claim_without_a_chain_when_enough_agree() {
        let issuer = Keys::generate();
        let w1 = Keys::generate();
        let w2 = Keys::generate();
        let alice = Keys::generate();
        let claim = signed(
            &issuer,
            KIND_CLAIM,
            ServiceClaim::tags("example.org", SERVICE_CA, None, None),
        );
        let att = |w: &Keys| {
            signed(
                w,
                KIND_ATTESTATION,
                Attestation::tags_with(
                    "example.org",
                    &[npub_of(&alice)],
                    &[(SERVICE_CA.to_string(), npub_of(&issuer))],
                    Method::Dnssec,
                    NOW() - 10,
                ),
            )
        };
        let c = cert(&issuer, "alice@example.org", &alice, &[]);
        let bundle = [
            signed(&issuer, KIND_CERT, c.tags()),
            claim,
            att(&w1),
            att(&w2),
        ];
        let cfg = Config {
            witnesses: vec![npub_of(&w1), npub_of(&w2)],
            attestation_threshold: 2,
            ..Config::default()
        };
        let mut v = verifier(cfg.clone()).await;
        let path = v.verify_bundle(&bundle, NOW()).unwrap();
        assert_eq!(path.anchor.kind, AnchorKind::Pinned);
        let pin = &v.snapshot().issuers[0];
        assert_eq!(pin.method, IssuerMethod::Attested);
        assert_eq!(pin.domain, "example.org");
        assert_eq!(
            v.snapshot().newest_seen(&SeenKey {
                kind: KIND_CLAIM,
                author: npub_of(&issuer),
                d: "example.org".into()
            }),
            Some(bundle[1].created_at.as_secs())
        );
        // One witness short: nothing anchored, the path has no issuer.
        let mut v = verifier(Config {
            attestation_threshold: 3,
            ..cfg.clone()
        })
        .await;
        assert!(matches!(
            v.verify_bundle(&bundle, NOW()),
            Err(VerifyError::Path(PathError::NoIssuer))
        ));
        assert!(v.snapshot().issuers.is_empty());
        // A claim from the future anchors nothing, whatever vouches for it.
        let mut v = verifier(cfg.clone()).await;
        let future = signed_at(
            &issuer,
            KIND_CLAIM,
            ServiceClaim::tags("example.org", SERVICE_CA, None, None),
            NOW() + MAX_FUTURE_SECS + 5,
        );
        let late = [
            bundle[0].clone(),
            future,
            bundle[2].clone(),
            bundle[3].clone(),
        ];
        assert!(v.verify_bundle(&late, NOW()).is_err());
        assert!(v.snapshot().issuers.is_empty());
        // A witness that re-published without the key has withdrawn it,
        // and once seen, its older attestation is a replay.
        let mut v = verifier(cfg.clone()).await;
        let withdrawn = signed_at(
            &w2,
            KIND_ATTESTATION,
            Attestation::tags_with(
                "example.org",
                &[npub_of(&alice)],
                &[],
                Method::Dnssec,
                NOW(),
            ),
            NOW() + 1,
        );
        let gone = [
            bundle[0].clone(),
            bundle[1].clone(),
            bundle[2].clone(),
            withdrawn,
        ];
        assert!(v.verify_bundle(&gone, NOW()).is_err());
        assert!(v.snapshot().issuers.is_empty());
        assert!(
            v.verify_bundle(&bundle, NOW()).is_err(),
            "the day-1 attestation replayed after the withdrawal was seen"
        );
        // Attestations off: a chainless claim anchors nothing.
        let mut v = verifier(Config {
            attestation_threshold: 0,
            ..cfg
        })
        .await;
        assert!(v.verify_bundle(&bundle, NOW()).is_err());
        // Without relays, resolving finds nothing beyond what is known,
        // cleanly; a learnt certificate whose issuer is never placed is
        // refused, not unknown.
        assert_eq!(
            v.resolve(&Name::parse("alice@example.org").unwrap(), NOW())
                .await,
            Resolution::Unknown
        );
        v.learn(c.clone(), NOW());
        assert_eq!(
            v.resolve(&Name::parse("alice@example.org").unwrap(), NOW())
                .await,
            Resolution::Refused(vec![(c, PathError::NoIssuer)])
        );
        assert!(v.names_of(&npub_of(&alice), NOW()).await.is_empty());
    }
}
