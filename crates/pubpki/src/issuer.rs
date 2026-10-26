//! The issuer's side: its key and domain, what it has issued, and the
//! events it signs (spec §3, §5). Policy (names under the domain, `ca`
//! only on the apex, the limits) is `pubpki-core`'s; this signs, stores
//! and publishes the exact signed event.

use crate::crypto::npub_of;
use crate::store::write_atomic;
use nostr_sdk::{Client, Event, EventBuilder, Keys, Kind, Tag, Timestamp};
use pubdom_resolve::relay::Outcome;
use pubpki_core::pubdom_core::claim::ServiceClaim;
use pubpki_core::pubdom_core::domain::normalize;
use pubpki_core::pubdom_core::txt::TxtRecord;
use pubpki_core::pubdom_core::{KIND_CLAIM, Npub};
use pubpki_core::{Certificate, KIND_CERT, MAX_RELAY_HINTS, MAX_SUBJECTS, Name, SERVICE_CA, Usage};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// `/var/lib/fips-pubpki/issued.json`: every event this issuer signed,
/// newest per name, markers included, and which of them no relay has
/// accepted yet. What `ca renew --watch` works from and `ca status`
/// lists. Reloaded by every command and every loop iteration, since the
/// unit and the operator's commands share it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issued {
    #[serde(default)]
    pub events: Vec<Event>,
    /// Ids (hex) of events in `events` that still reached no relay; the
    /// renewal loop and `ca publish` retry them.
    #[serde(default)]
    pub unpublished: Vec<String>,
}

impl Issued {
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(path, &bytes).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The `d` tag of an event.
    pub fn d_of(ev: &Event) -> Option<String> {
        ev.tags
            .iter()
            .map(|t| t.clone().to_vec())
            .find(|t| t.len() >= 2 && t[0] == "d")
            .map(|t| t[1].clone())
    }

    /// Record `ev` as not yet published; a newer event for the same name
    /// replaces the older (and the older's publication is moot). Returns
    /// whether it was taken.
    pub fn put(&mut self, ev: Event) -> bool {
        let d = Self::d_of(&ev);
        let id = ev.id.to_hex();
        match self
            .events
            .iter_mut()
            .find(|e| e.kind == ev.kind && Self::d_of(e) == d)
        {
            Some(have) if have.created_at >= ev.created_at => return false,
            Some(have) => {
                let old = have.id.to_hex();
                self.unpublished.retain(|u| *u != old);
                *have = ev;
            }
            None => self.events.push(ev),
        }
        self.unpublished.push(id);
        true
    }

    /// The events still to publish, unexpired ones only.
    pub fn pending(&self, now: u64) -> Vec<Event> {
        self.events
            .iter()
            .filter(|e| self.unpublished.contains(&e.id.to_hex()))
            .filter(|e| {
                Certificate::parse(&crate::core_event(e))
                    .map(|c| now < c.expiration)
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    /// A relay accepted `id`.
    pub fn mark_published(&mut self, id: &str) {
        self.unpublished.retain(|u| u != id);
    }

    /// The newest certificate event for `name`.
    pub fn get(&self, name: &Name) -> Option<&Event> {
        let d = name.to_string();
        self.events
            .iter()
            .find(|e| e.kind.as_u16() == KIND_CERT && Self::d_of(e).as_deref() == Some(&d))
    }

    /// Every certificate event parsed, in file order.
    pub fn certificates(&self) -> Vec<(Certificate, &Event)> {
        self.events
            .iter()
            .filter_map(|e| {
                Certificate::parse(&crate::core_event(e))
                    .ok()
                    .map(|c| (c, e))
            })
            .collect()
    }
}

/// Sign an event dated `created_at`, not now: an issuer dates a renewal
/// or a marker at least a second after what it replaces, so that relays,
/// which keep the newest addressable event (lowest id on a tie), never
/// keep the old one. Self-tagging is allowed: nostr-sdk's builder drops a
/// `p` tag naming the author by default, and a bare key certifying its
/// own name (`alice@<npub>.fips`) is exactly that.
pub fn sign_at(
    keys: &Keys,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: &str,
    created_at: u64,
) -> Result<Event, String> {
    let tags: Result<Vec<Tag>, String> = tags
        .into_iter()
        .map(|t| Tag::parse(t).map_err(|e| e.to_string()))
        .collect();
    EventBuilder::new(Kind::from(kind), content)
        .tags(tags?)
        .allow_self_tagging()
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .map_err(|e| e.to_string())
}

/// What to issue (`Issuer::issue`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub name: Name,
    pub subjects: Vec<Npub>,
    pub usages: Vec<Usage>,
    /// From the signing time.
    pub validity_secs: u64,
    pub pathlen: Option<u32>,
    pub relays: Vec<String>,
    /// The event's content: empty, display fields, or the base64 DER of
    /// an X.509 root (`usage x509`); the `x` tag is computed from it.
    pub content: String,
}

impl Request {
    pub fn new(name: Name, subjects: Vec<Npub>) -> Self {
        Self {
            name,
            subjects,
            usages: Vec::new(),
            validity_secs: pubpki_core::DEFAULT_VALIDITY_SECS,
            pathlen: None,
            relays: Vec::new(),
            content: String::new(),
        }
    }

    /// The X.509 root statement for `domain`: `_x509@<domain>`, the DER
    /// base64 in the content, its SHA-256 in the `x` tag, the operating
    /// nodes as subjects.
    pub fn x509_root(domain: &str, nodes: Vec<Npub>, der: &[u8]) -> Option<Self> {
        use base64::Engine;
        let mut req = Self::new(Name::x509(domain)?, nodes);
        req.usages = vec![Usage::X509];
        req.content = base64::engine::general_purpose::STANDARD.encode(der);
        Some(req)
    }
}

/// The `x` tag of a root statement: SHA-256 of the DER the content
/// decodes to (the certificate's usual fingerprint), `None` when the
/// content is not base64.
pub fn root_digest(content: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(content.trim())
        .ok()?;
    (!der.is_empty()).then(|| pubpki_core::sig::digest(&der))
}

/// An issuer: a key, and the domain it issues for.
pub struct Issuer {
    pub keys: Keys,
    /// Normalized; `<npub>.fips` for a bare key.
    pub domain: String,
}

impl Issuer {
    /// `domain` `None` makes the key its own overlay issuer.
    pub fn new(keys: Keys, domain: Option<&str>) -> Result<Self, String> {
        let domain = match domain {
            Some(d) => normalize(d).ok_or_else(|| format!("{d}: not a domain"))?,
            None => npub_of(&keys).fips_name(),
        };
        if !domain.contains('.') {
            return Err(format!("{domain}: a single label is not a domain"));
        }
        Ok(Self { keys, domain })
    }

    pub fn npub(&self) -> Npub {
        npub_of(&self.keys)
    }

    /// A bare key on the overlay: no DNS record, no claim.
    pub fn is_overlay(&self) -> bool {
        pubpki_core::name::overlay_key(&self.domain) == Some(self.npub())
    }

    /// The legacy DNS record a public-domain issuer publishes, as
    /// (owner name, text); `None` for a bare key.
    pub fn txt_record(&self) -> Option<(String, String)> {
        if self.is_overlay() {
            return None;
        }
        let r = TxtRecord {
            npub: self.npub(),
            port: None,
        };
        Some((
            pubpki_core::pubdom_core::domain::txt_name_for(SERVICE_CA, &self.domain),
            r.render(),
        ))
    }

    /// Issue a certificate dated `now`: the name at or under the domain,
    /// `ca` only on an apex name, validity from `now`. Replacing an
    /// earlier certificate for the name is [`Issuer::renew`]'s job, which
    /// keeps the timestamps in order.
    pub fn issue(&self, req: &Request, now: u64) -> Result<Event, String> {
        if !req.name.is_under(&self.domain) {
            return Err(format!("{} is not under {}", req.name, self.domain));
        }
        if req.subjects.is_empty() || req.subjects.len() > MAX_SUBJECTS {
            return Err(format!("1 to {MAX_SUBJECTS} subject keys"));
        }
        if req.usages.contains(&Usage::Ca) && !req.name.is_apex() {
            return Err(format!(
                "usage ca belongs on _@{}, not on a person's name",
                req.name.domain
            ));
        }
        if req.name.is_x509() != req.usages.contains(&Usage::X509) {
            return Err(format!(
                "usage x509 and the name _x509@{} go together",
                req.name.domain
            ));
        }
        let digest = if req.name.is_x509() {
            Some(root_digest(&req.content).ok_or_else(|| {
                "the X.509 root statement needs the root's DER, base64, as content".to_string()
            })?)
        } else {
            None
        };
        if req.name.is_reserved() && !req.name.is_apex() && !req.name.is_x509() {
            return Err(format!(
                "{}: local parts starting with _ are reserved for the domain's own statements",
                req.name
            ));
        }
        if req.pathlen.is_some() && !req.usages.contains(&Usage::Ca) {
            return Err("pathlen needs usage ca".into());
        }
        if req.relays.len() > MAX_RELAY_HINTS {
            return Err(format!("at most {MAX_RELAY_HINTS} relay hints"));
        }
        let cert = Certificate {
            issuer: self.npub(),
            name: req.name.clone(),
            subjects: req.subjects.clone(),
            expiration: now + req.validity_secs.max(60),
            usages: req.usages.clone(),
            revoked: None,
            pathlen: req.pathlen,
            relays: req.relays.clone(),
            other_usages: Vec::new(),
            digest,
            created_at: now,
        };
        sign_at(&self.keys, KIND_CERT, cert.tags(), &req.content, now)
    }

    /// A timestamp after `prev`'s: `now`, or one second later than `prev`
    /// when the clock has not moved (or went back). Anything replacing an
    /// event for a name is dated this way, a re-issue after a marker too.
    pub fn after(prev: &Certificate, now: u64) -> u64 {
        now.max(prev.created_at + 1)
    }

    /// Renew the certificate event `ev`: the same tags and content, a
    /// fresh validity of the same length, dated after it. The content
    /// travels along, so an X.509 root statement keeps its DER.
    pub fn renew(&self, ev: &Event, now: u64) -> Result<Event, String> {
        let cert = Certificate::parse(&crate::core_event(ev)).map_err(|e| e.to_string())?;
        if cert.issuer != self.npub() {
            return Err("not this issuer's certificate".into());
        }
        if cert.revoked.is_some() {
            return Err(format!(
                "{} is revoked; issue it anew if intended",
                cert.name
            ));
        }
        let length = cert.expiration.saturating_sub(cert.created_at).max(60);
        let at = Self::after(&cert, now);
        let mut fresh = cert.clone();
        fresh.expiration = at + length;
        fresh.created_at = at;
        sign_at(&self.keys, KIND_CERT, fresh.tags(), &ev.content, at)
    }

    /// The revocation marker for the certificate event `ev`: same name,
    /// same keys, same content, the same expiration, `revoked` with
    /// `reason`, dated after it.
    pub fn revoke(&self, ev: &Event, reason: &str, now: u64) -> Result<Event, String> {
        let cert = Certificate::parse(&crate::core_event(ev)).map_err(|e| e.to_string())?;
        if cert.issuer != self.npub() {
            return Err("not this issuer's certificate".into());
        }
        let mut marker = cert.clone();
        marker.revoked = Some(reason.to_string());
        sign_at(
            &self.keys,
            KIND_CERT,
            marker.tags(),
            &ev.content,
            Self::after(&cert, now),
        )
    }

    /// The issuer's NIP-DB claim in the `fips-ca` role, with the DNSSEC
    /// chain for `_fips-ca.<domain>` when the issuer has one. A bare key
    /// has no claim.
    pub fn claim(&self, chain: Option<&str>) -> Result<Event, String> {
        if self.is_overlay() {
            return Err("a bare-key issuer publishes no claim".into());
        }
        let tags = ServiceClaim::tags(&self.domain, SERVICE_CA, None, chain);
        let ev = sign_at(&self.keys, KIND_CLAIM, tags, "", crate::now())?;
        // What we publish must parse as what the verifier expects.
        ServiceClaim::parse(&crate::core_event(&ev), SERVICE_CA).map_err(|e| e.to_string())?;
        Ok(ev)
    }

    /// `/.well-known/nostr.json` from what is issued: live, unrevoked
    /// certificates for names directly at this domain, first key each.
    pub fn nostr_json(&self, issued: &Issued, now: u64) -> serde_json::Value {
        let mut names = serde_json::Map::new();
        let mut relays = serde_json::Map::new();
        for (c, _) in issued.certificates() {
            // Reserved names are the domain's statements, not people.
            if c.name.domain != self.domain || c.name.is_reserved() || !c.is_live_at(now) {
                continue;
            }
            let Some(key) = c.subjects.first() else {
                continue;
            };
            names.insert(
                c.name.local.clone(),
                serde_json::Value::String(key.to_hex()),
            );
            if !c.relays.is_empty() {
                relays.insert(key.to_hex(), serde_json::json!(c.relays));
            }
        }
        let mut out = serde_json::json!({ "names": names });
        if !relays.is_empty() {
            out["relays"] = serde_json::Value::Object(relays);
        }
        out
    }
}

/// Publish already signed events to `relays`, as they are: a renewal or
/// a marker must reach the relays with the `created_at` the issuer
/// recorded. One connection round for all of them; connections awaited
/// up to `timeout`, then each event sent with that deadline. One result
/// per event, in order.
pub async fn publish_events(
    events: &[Event],
    relays: &[String],
    timeout: Duration,
) -> Result<Vec<Result<Outcome, String>>, String> {
    if relays.is_empty() {
        return Err("no relays configured (ca_relays, mesh_relays or public_relays)".into());
    }
    if events.is_empty() {
        return Ok(Vec::new());
    }
    let client = Client::default();
    for u in relays {
        client.add_relay(u).await.map_err(|e| format!("{u}: {e}"))?;
    }
    let configured = |printed: &str| -> String {
        relays
            .iter()
            .find(|u| {
                nostr_sdk::RelayUrl::parse(u)
                    .map(|r| r.to_string() == printed)
                    .unwrap_or(false)
            })
            .cloned()
            .unwrap_or_else(|| printed.to_string())
    };
    client.connect().await;
    client.wait_for_connection(timeout).await;
    let mut results = Vec::with_capacity(events.len());
    for event in events {
        let r = match tokio::time::timeout(timeout, client.send_event(event)).await {
            Err(_) => Err("timed out publishing".to_string()),
            Ok(Err(e)) => Err(e.to_string()),
            Ok(Ok(out)) => Ok(Outcome {
                accepted: out
                    .success
                    .iter()
                    .map(|u| configured(&u.to_string()))
                    .collect(),
                rejected: out
                    .failed
                    .iter()
                    .map(|(u, why)| (configured(&u.to_string()), why.to_string()))
                    .collect(),
            }),
        };
        results.push(r);
    }
    client.disconnect().await;
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubpki_core::path::validate;
    use pubpki_core::pubdom_core::claim::Claim;
    use pubpki_core::{Anchors, Certs, DEFAULT_VALIDITY_SECS, PathError};

    fn now() -> u64 {
        crate::now()
    }

    #[test]
    fn issues_under_its_domain_only_and_ca_on_the_apex_only() {
        let issuer = Issuer::new(Keys::generate(), Some("Example.ORG.")).unwrap();
        assert_eq!(issuer.domain, "example.org");
        assert!(!issuer.is_overlay());
        let (owner, text) = issuer.txt_record().unwrap();
        assert_eq!(owner, "_fips-ca.example.org");
        assert!(text.starts_with("v=fips1 npub=npub1") && !text.contains("port"));
        let alice = Npub::from_bytes([4; 32]);
        let mut req = Request::new(Name::parse("alice@example.org").unwrap(), vec![alice]);
        req.usages = vec![Usage::Sign];
        req.relays = vec!["wss://relay.example.org".into()];
        assert_eq!(req.validity_secs, DEFAULT_VALIDITY_SECS);
        let ev = issuer.issue(&req, now()).unwrap();
        ev.verify().unwrap();
        let c = Certificate::parse(&crate::core_event(&ev)).unwrap();
        assert_eq!(c.subjects, vec![alice]);
        assert_eq!(c.relays, ["wss://relay.example.org"]);
        let mut anchors = Anchors::new();
        anchors.add("example.org", issuer.npub());
        assert!(validate(&Certs::new(), &anchors, &c, now()).is_ok());
        for (name, usages, pathlen) in [
            ("alice@example.net", vec![], None),
            ("alice@evilexample.org", vec![], None),
            ("alice@example.org", vec![Usage::Ca], None),
            ("alice@example.org", vec![], Some(1)),
        ] {
            let mut req = Request::new(Name::parse(name).unwrap(), vec![alice]);
            req.usages = usages.clone();
            req.pathlen = pathlen;
            req.validity_secs = 3600;
            assert!(
                issuer.issue(&req, now()).is_err(),
                "{name} {usages:?} {pathlen:?}"
            );
        }
        let mut dept = Request::new(Name::parse("_@sales.example.org").unwrap(), vec![alice]);
        dept.usages = vec![Usage::Ca];
        dept.pathlen = Some(0);
        assert!(issuer.issue(&dept, now()).is_ok());
        assert!(Issuer::new(Keys::generate(), Some("org")).is_err());
    }

    #[test]
    fn renew_and_revoke_keep_the_name_and_keys() {
        let issuer = Issuer::new(Keys::generate(), None).unwrap();
        assert!(issuer.is_overlay());
        assert_eq!(issuer.txt_record(), None);
        assert!(issuer.claim(None).is_err(), "no claim for a bare key");
        // A bare key naming itself: the `p` tag must survive signing.
        let me = Request::new(
            Name::parse(&format!("me@{}", issuer.domain)).unwrap(),
            vec![issuer.npub()],
        );
        let ev = issuer.issue(&me, now()).unwrap();
        let c = Certificate::parse(&crate::core_event(&ev)).unwrap();
        assert_eq!(c.subjects, vec![issuer.npub()]);
        assert!(validate(&Certs::new(), &Anchors::new(), &c, now()).is_ok());
        let name = Name::parse(&format!("alice@{}", issuer.domain)).unwrap();
        let alice = Npub::from_bytes([4; 32]);
        let t0 = now() - 3600;
        let mut req = Request::new(name.clone(), vec![alice]);
        req.validity_secs = 7200;
        let ev = issuer.issue(&req, t0).unwrap();
        let c = Certificate::parse(&crate::core_event(&ev)).unwrap();
        assert_eq!(c.created_at, t0, "dated as asked, not at the clock");
        assert_eq!(c.expiration, t0 + 7200);
        let renewed_ev = issuer.renew(&ev, now()).unwrap();
        let renewed = Certificate::parse(&crate::core_event(&renewed_ev)).unwrap();
        assert_eq!(renewed.subjects, c.subjects);
        assert_eq!(renewed.expiration - renewed.created_at, 7200, "same length");
        assert!(renewed.created_at > c.created_at);
        // Renewing twice within one second still moves forward.
        let again = Certificate::parse(&crate::core_event(
            &issuer.renew(&renewed_ev, renewed.created_at).unwrap(),
        ))
        .unwrap();
        assert_eq!(again.created_at, renewed.created_at + 1);
        let marker_ev = issuer.revoke(&ev, "lost phone", c.created_at).unwrap();
        let marker = Certificate::parse(&crate::core_event(&marker_ev)).unwrap();
        assert_eq!(marker.created_at, c.created_at + 1, "after what it revokes");
        assert_eq!(marker.revoked.as_deref(), Some("lost phone"));
        assert_eq!(marker.expiration, c.expiration);
        assert_eq!(marker.subjects, c.subjects);
        assert!(
            issuer.renew(&marker_ev, now()).is_err(),
            "a marker is not renewed"
        );
        let other = Issuer::new(Keys::generate(), None).unwrap();
        assert!(other.revoke(&ev, "x", now()).is_err());
        // The marker, learnt, refuses the certificate.
        let mut certs = Certs::new();
        certs.insert(marker, now()).unwrap();
        assert_eq!(
            validate(&certs, &Anchors::new(), &c, now()),
            Err(PathError::Revoked("lost phone".into()))
        );
    }

    #[test]
    fn the_x509_root_statement_keeps_its_der_through_renewal_and_revocation() {
        let issuer = Issuer::new(Keys::generate(), Some("example.org")).unwrap();
        let node = Npub::from_bytes([7; 32]);
        let der = b"not really DER, but bytes";
        let req = Request::x509_root("example.org", vec![node], der).unwrap();
        let ev = issuer.issue(&req, now()).unwrap();
        ev.verify().unwrap();
        let c = Certificate::parse(&crate::core_event(&ev)).unwrap();
        assert!(c.is_x509());
        assert_eq!(c.digest, Some(pubpki_core::sig::digest(der)));
        assert_eq!(c.subjects, vec![node]);
        assert!(!ev.content.is_empty());
        let renewed = issuer.renew(&ev, now() + 10).unwrap();
        assert_eq!(renewed.content, ev.content, "the DER survives renewal");
        let rc = Certificate::parse(&crate::core_event(&renewed)).unwrap();
        assert_eq!(rc.digest, c.digest);
        let marker = issuer.revoke(&ev, "rotated", now() + 10).unwrap();
        assert_eq!(marker.content, ev.content);
        // The pieces go together or not at all.
        let mut no_usage = req.clone();
        no_usage.usages.clear();
        assert!(
            issuer.issue(&no_usage, now()).is_err(),
            "_x509 without usage x509"
        );
        let mut elsewhere = req.clone();
        elsewhere.name = Name::parse("_@example.org").unwrap();
        assert!(
            issuer.issue(&elsewhere, now()).is_err(),
            "usage x509 off its name"
        );
        let mut no_der = req.clone();
        no_der.content.clear();
        assert!(issuer.issue(&no_der, now()).is_err());
        let mut not_b64 = req.clone();
        not_b64.content = "not base64!".into();
        assert!(issuer.issue(&not_b64, now()).is_err());
        assert_eq!(
            root_digest(&req.content),
            Some(pubpki_core::sig::digest(der)),
            "the DER's hash, not the text's"
        );
        let mut other_reserved = Request::new(Name::parse("_foo@example.org").unwrap(), vec![node]);
        other_reserved.validity_secs = 3600;
        assert!(issuer.issue(&other_reserved, now()).is_err(), "reserved");
        assert!(
            Request::x509_root("org", vec![node], der).is_none()
                || issuer
                    .issue(&Request::x509_root("org", vec![node], der).unwrap(), now())
                    .is_err()
        );
    }

    #[test]
    fn the_issued_file_keeps_the_newest_per_name_and_renders_nostr_json() {
        let issuer = Issuer::new(Keys::generate(), Some("example.org")).unwrap();
        let alice = Npub::from_bytes([4; 32]);
        let bob = Npub::from_bytes([5; 32]);
        let mut ra = Request::new(Name::parse("alice@example.org").unwrap(), vec![alice]);
        ra.validity_secs = 3600;
        ra.relays = vec!["wss://r".into()];
        let a = issuer.issue(&ra, now() - 10).unwrap();
        let mut rb = Request::new(Name::parse("bob@sales.example.org").unwrap(), vec![bob]);
        rb.validity_secs = 3600;
        let b = issuer.issue(&rb, now() - 10).unwrap();
        let mut rc = Request::new(Name::parse("_@example.org").unwrap(), vec![bob]);
        rc.usages = vec![Usage::Ca];
        rc.validity_secs = 3600;
        let ca = issuer.issue(&rc, now() - 10).unwrap();
        let mut issued = Issued::default();
        assert!(issued.put(a.clone()) && issued.put(b.clone()) && issued.put(ca));
        assert!(!issued.put(a.clone()), "the same again");
        assert_eq!(issued.unpublished.len(), 3);
        assert_eq!(issued.pending(now()).len(), 3);
        issued.mark_published(&b.id.to_hex());
        assert_eq!(issued.pending(now()).len(), 2);
        let renewed = issuer.renew(&a, now()).unwrap();
        assert!(issued.put(renewed.clone()));
        assert_eq!(issued.events.len(), 3);
        assert!(
            !issued.unpublished.contains(&a.id.to_hex()),
            "the replaced event's publication is moot"
        );
        assert!(issued.unpublished.contains(&renewed.id.to_hex()));
        assert_eq!(
            issued.pending(now()).len(),
            2,
            "the renewal and the delegation"
        );
        assert!(
            issued.pending(now() + 4000).is_empty(),
            "expired ones are not pending"
        );
        assert_eq!(
            issued.get(&Name::parse("alice@example.org").unwrap()),
            Some(&renewed)
        );
        issued.put(
            issuer
                .issue(
                    &Request::x509_root("example.org", vec![bob], b"DER").unwrap(),
                    now() - 10,
                )
                .unwrap(),
        );
        let json = issuer.nostr_json(&issued, now());
        assert_eq!(json["names"]["alice"], alice.to_hex());
        assert_eq!(
            json["names"].get("_x509"),
            None,
            "a statement, not a person"
        );
        assert_eq!(json["names"].get("bob"), None, "another domain");
        assert_eq!(json["names"].get("_"), None, "the apex is no name");
        assert_eq!(json["relays"][alice.to_hex()][0], "wss://r");
        let dir = std::env::temp_dir().join(format!("pubpki-issued-{}", std::process::id()));
        let path = dir.join("issued.json");
        issued.save(&path).unwrap();
        assert_eq!(Issued::load(&path).unwrap(), issued);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            Issued::load(&dir.join("none.json")).unwrap(),
            Issued::default()
        );
        // The claim parses as the verifier expects, chain or not.
        let claim = issuer.claim(Some("Y2hhaW4=")).unwrap();
        let sc = ServiceClaim::parse(&crate::core_event(&claim), SERVICE_CA).unwrap();
        assert_eq!(sc.dnssec.as_deref(), Some("Y2hhaW4="));
        assert!(
            Claim::parse(&crate::core_event(&claim)).is_err(),
            "not a fips-dns claim"
        );
    }
}
