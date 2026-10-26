//! Kind 37200 certificates (docs/nip.md "Kind 37200"): parsed from the
//! transport-neutral `pubdom_core::Event`, and built for publishing.

use crate::name::Name;
use crate::{KIND_CERT, MAX_RELAY_HINTS, MAX_SUBJECTS, MAX_TAGS};
use pubdom_core::Npub;
use pubdom_core::claim::Event;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum CertError {
    #[error("kind {0} is not a certificate")]
    Kind(u16),
    #[error("invalid issuer pubkey")]
    Issuer,
    #[error("missing or invalid d tag (the name)")]
    Name,
    #[error("missing, invalid or too many p tags (the subject)")]
    Subject,
    #[error("missing or invalid expiration tag")]
    Expiration,
    #[error("invalid pathlen tag")]
    Pathlen,
    #[error("missing or invalid x tag (the content's SHA-256), required with usage x509")]
    Digest,
    #[error("too many tags")]
    TooLarge,
}

/// What a subject's keys may be used for. Unknown values are kept
/// verbatim in [`Certificate::other_usages`], so that a certificate meant
/// for something this client does not know is not read as a plain key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Usage {
    Sign,
    Encrypt,
    /// The subject is a sub-issuer for names under the certificate's
    /// domain (`d` must be `_@<domain>`).
    Ca,
    /// The certificate's content is an X.509 CA certificate (base64 DER)
    /// whose SHA-256 is the `x` tag; the subject keys are the nodes
    /// operating it (`d` must be `_x509@<domain>`). The TLS bridge
    /// (docs/acme.md).
    X509,
}

impl Usage {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "sign" => Some(Self::Sign),
            "encrypt" => Some(Self::Encrypt),
            "ca" => Some(Self::Ca),
            "x509" => Some(Self::X509),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Encrypt => "encrypt",
            Self::Ca => "ca",
            Self::X509 => "x509",
        }
    }
}

impl std::str::FromStr for Usage {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| format!("{s}: usage is sign, encrypt or ca"))
    }
}

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Kind 37200: "`issuer` says `name` is `subjects`, until `expiration`".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    pub issuer: Npub,
    pub name: Name,
    /// One or more keys of one subject (several devices), in tag order.
    pub subjects: Vec<Npub>,
    /// Unix seconds (NIP-40); the certificate is unusable from then on.
    pub expiration: u64,
    /// The known usages, as published. No `usage` tag at all means `sign`
    /// and `encrypt` ([`Certificate::allows`]).
    pub usages: Vec<Usage>,
    /// Usage values this client does not know, verbatim: they count as
    /// usages (the certificate allows nothing this client knows unless a
    /// known one is listed too) and are written back by [`Certificate::tags`].
    pub other_usages: Vec<String>,
    /// SHA-256 of the event's content (the `x` tag), required with
    /// `usage x509`; what `fips-pubpki trust` checks the DER against.
    pub digest: Option<[u8; 32]>,
    /// A revocation marker replacing the certificate, with its reason.
    pub revoked: Option<String>,
    /// How many sub-issuer certificates may follow below this one.
    pub pathlen: Option<u32>,
    pub relays: Vec<String>,
    pub created_at: u64,
}

impl Certificate {
    pub fn parse(ev: &Event) -> Result<Self, CertError> {
        if ev.kind != KIND_CERT {
            return Err(CertError::Kind(ev.kind));
        }
        if ev.tags.len() > MAX_TAGS {
            return Err(CertError::TooLarge);
        }
        let issuer = Npub::from_hex(&ev.pubkey).map_err(|_| CertError::Issuer)?;
        let d = tag_value(&ev.tags, "d").ok_or(CertError::Name)?;
        let name = Name::parse(d).ok_or(CertError::Name)?;
        if name.to_string() != d {
            // `d` must already be canonical, as NIP-DB's domains are.
            return Err(CertError::Name);
        }
        let mut subjects: Vec<Npub> = Vec::new();
        for t in ev.tags.iter().filter(|t| t.len() >= 2 && t[0] == "p") {
            let key = Npub::from_hex(&t[1]).map_err(|_| CertError::Subject)?;
            if !subjects.contains(&key) {
                subjects.push(key);
            }
            if subjects.len() > MAX_SUBJECTS {
                return Err(CertError::Subject);
            }
        }
        if subjects.is_empty() {
            return Err(CertError::Subject);
        }
        let expiration = tag_value(&ev.tags, "expiration")
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or(CertError::Expiration)?;
        let mut usages = Vec::new();
        let mut other_usages: Vec<String> = Vec::new();
        for t in ev.tags.iter().filter(|t| t.len() >= 2 && t[0] == "usage") {
            match Usage::parse(&t[1]) {
                Some(u) if !usages.contains(&u) => usages.push(u),
                Some(_) => {}
                None if !other_usages.contains(&t[1]) => other_usages.push(t[1].clone()),
                None => {}
            }
        }
        let digest = match tag_value(&ev.tags, "x") {
            Some(v) => Some(crate::sig::hex_digest(v).ok_or(CertError::Digest)?),
            None => None,
        };
        if usages.contains(&Usage::X509) && digest.is_none() {
            return Err(CertError::Digest);
        }
        let revoked = ev
            .tags
            .iter()
            .find(|t| !t.is_empty() && t[0] == "revoked")
            .map(|t| t.get(1).cloned().unwrap_or_default());
        let pathlen = match tag_value(&ev.tags, "pathlen") {
            Some(v) => Some(v.parse::<u32>().map_err(|_| CertError::Pathlen)?),
            None => None,
        };
        let relays: Vec<String> = ev
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "relay")
            .map(|t| t[1].clone())
            .take(MAX_RELAY_HINTS)
            .collect();
        Ok(Self {
            issuer,
            name,
            subjects,
            expiration,
            usages,
            other_usages,
            digest,
            revoked,
            pathlen,
            relays,
            created_at: ev.created_at,
        })
    }

    /// The tags of a certificate — what an issuer publishes. The
    /// revocation marker is the same with `revoked`.
    pub fn tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![vec!["d".to_string(), self.name.to_string()]];
        for s in &self.subjects {
            tags.push(vec!["p".into(), s.to_hex()]);
        }
        tags.push(vec!["expiration".into(), self.expiration.to_string()]);
        for u in &self.usages {
            tags.push(vec!["usage".into(), u.as_str().into()]);
        }
        for u in &self.other_usages {
            tags.push(vec!["usage".into(), u.clone()]);
        }
        if let Some(d) = &self.digest {
            tags.push(vec!["x".into(), crate::sig::hex_encode(d)]);
        }
        if let Some(reason) = &self.revoked {
            tags.push(vec!["revoked".into(), reason.clone()]);
        }
        if let Some(n) = self.pathlen {
            tags.push(vec!["pathlen".into(), n.to_string()]);
        }
        for r in &self.relays {
            tags.push(vec!["relay".into(), r.clone()]);
        }
        tags
    }

    /// Does the certificate allow `usage`? No `usage` tag at all means
    /// `sign` and `encrypt`; `ca` and `x509` are never implied; a
    /// certificate whose usages this client does not know allows nothing
    /// it knows.
    pub fn allows(&self, usage: Usage) -> bool {
        if self.usages.is_empty() && self.other_usages.is_empty() {
            matches!(usage, Usage::Sign | Usage::Encrypt)
        } else {
            self.usages.contains(&usage)
        }
    }

    /// The X.509 root statement: `_x509@<domain>` with `usage x509`.
    pub fn is_x509(&self) -> bool {
        self.name.is_x509() && self.allows(Usage::X509)
    }

    /// A sub-issuer certificate: `_@<domain>` with `usage` `ca`.
    pub fn is_ca(&self) -> bool {
        self.name.is_apex() && self.allows(Usage::Ca)
    }

    /// Unexpired and not a revocation marker at `now`. Path validation
    /// adds the rollback and issuer checks (spec §4).
    pub fn is_live_at(&self, now: u64) -> bool {
        self.revoked.is_none() && now < self.expiration
    }

    /// May a holder of this certificate issue a certificate for `name`?
    /// Only a sub-issuer certificate, and only for names at or under its
    /// domain: the scope is structural, not a separate tag.
    pub fn may_issue_for(&self, name: &Name) -> bool {
        self.is_ca() && name.is_under(&self.name.domain)
    }
}

fn tag_value<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;

    fn issuer() -> Npub {
        Npub::from_bytes([1; 32])
    }

    fn cert(name: &str, usages: &[Usage]) -> Certificate {
        Certificate {
            issuer: issuer(),
            name: Name::parse(name).unwrap(),
            subjects: vec![Npub::from_bytes([2; 32])],
            expiration: NOW + 86_400,
            usages: usages.to_vec(),
            revoked: None,
            pathlen: None,
            relays: Vec::new(),
            other_usages: Vec::new(),
            digest: None,
            created_at: NOW,
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

    #[test]
    fn round_trips_through_the_builder() {
        let mut c = cert("alice@example.org", &[Usage::Sign, Usage::Encrypt]);
        c.subjects.push(Npub::from_bytes([3; 32]));
        c.relays.push("wss://relay.example.org".into());
        let again = Certificate::parse(&event(&c)).unwrap();
        assert_eq!(again, c);
        assert_eq!(again.tags()[0], vec!["d", "alice@example.org"]);
        assert!(again.allows(Usage::Sign) && again.allows(Usage::Encrypt));
        assert!(!again.allows(Usage::Ca) && !again.is_ca());
        assert!(again.is_live_at(NOW));
        assert!(!again.is_live_at(NOW + 86_400), "expiration is exclusive");
    }

    #[test]
    fn absent_usage_means_sign_and_encrypt_never_ca() {
        let c = Certificate::parse(&event(&cert("alice@example.org", &[]))).unwrap();
        assert!(c.allows(Usage::Sign) && c.allows(Usage::Encrypt) && !c.allows(Usage::Ca));
        let apex = Certificate::parse(&event(&cert("_@example.org", &[]))).unwrap();
        assert!(
            !apex.is_ca(),
            "a service certificate for the domain is no sub-issuer"
        );
        let only_ca = Certificate::parse(&event(&cert("_@example.org", &[Usage::Ca]))).unwrap();
        assert!(only_ca.is_ca() && !only_ca.allows(Usage::Sign));
    }

    #[test]
    fn a_sub_issuer_issues_at_or_under_its_domain_only() {
        let ca = cert("_@example.org", &[Usage::Ca]);
        for ok in [
            "alice@example.org",
            "_@example.org",
            "bob@sales.example.org",
            "_@emea.sales.example.org",
        ] {
            assert!(ca.may_issue_for(&Name::parse(ok).unwrap()), "{ok}");
        }
        for no in ["alice@example.net", "alice@evilexample.org", "alice@org"] {
            assert!(!ca.may_issue_for(&Name::parse(no).unwrap()), "{no}");
        }
        // A sub-issuer for a department reaches no higher.
        let sales = cert("_@sales.example.org", &[Usage::Ca]);
        assert!(sales.may_issue_for(&Name::parse("bob@sales.example.org").unwrap()));
        assert!(!sales.may_issue_for(&Name::parse("alice@example.org").unwrap()));
        // `ca` on a person's certificate delegates nothing.
        let person = cert("alice@example.org", &[Usage::Ca]);
        assert!(!person.is_ca());
        assert!(!person.may_issue_for(&Name::parse("bob@example.org").unwrap()));
    }

    #[test]
    fn revocation_marker_pathlen_and_unknown_usage() {
        let mut c = cert("_@sales.example.org", &[Usage::Ca]);
        c.pathlen = Some(0);
        c.revoked = Some("key compromised".into());
        let ev = event(&c);
        let p = Certificate::parse(&ev).unwrap();
        assert_eq!(p.revoked.as_deref(), Some("key compromised"));
        assert_eq!(p.pathlen, Some(0));
        assert!(!p.is_live_at(NOW), "a marker is never live");
        let mut unknown = ev.clone();
        unknown.tags.push(vec!["usage".into(), "fly".into()]);
        let u = Certificate::parse(&unknown).unwrap();
        assert_eq!(u.usages, vec![Usage::Ca]);
        assert_eq!(u.other_usages, vec!["fly"]);
        assert!(
            u.tags()
                .contains(&vec!["usage".to_string(), "fly".to_string()])
        );
        let mut bad = ev.clone();
        bad.tags.iter_mut().find(|t| t[0] == "pathlen").unwrap()[1] = "-1".into();
        assert_eq!(Certificate::parse(&bad), Err(CertError::Pathlen));
        let mut bare = ev;
        bare.tags
            .iter_mut()
            .find(|t| t[0] == "revoked")
            .unwrap()
            .truncate(1);
        assert_eq!(
            Certificate::parse(&bare).unwrap().revoked.as_deref(),
            Some("")
        );
    }

    #[test]
    fn unknown_usages_allow_nothing_known_and_absent_means_sign_encrypt() {
        let mut only_unknown = event(&cert("alice@example.org", &[]));
        only_unknown
            .tags
            .push(vec!["usage".into(), "teleport".into()]);
        let c = Certificate::parse(&only_unknown).unwrap();
        assert!(c.usages.is_empty() && c.other_usages == ["teleport"]);
        assert!(
            !c.allows(Usage::Sign) && !c.allows(Usage::Encrypt),
            "a certificate for something this client does not know is not a plain key"
        );
        let mut mixed = only_unknown.clone();
        mixed.tags.push(vec!["usage".into(), "sign".into()]);
        let m = Certificate::parse(&mixed).unwrap();
        assert!(m.allows(Usage::Sign) && !m.allows(Usage::Encrypt));
        let none = Certificate::parse(&event(&cert("alice@example.org", &[]))).unwrap();
        assert!(none.allows(Usage::Sign) && none.allows(Usage::Encrypt));
    }

    #[test]
    fn x509_needs_its_digest_and_its_reserved_name() {
        let mut root = cert("_x509@example.org", &[Usage::X509]);
        root.digest = Some(crate::sig::digest(b"DER"));
        let ev = event(&root);
        let p = Certificate::parse(&ev).unwrap();
        assert_eq!(p, root);
        assert!(p.is_x509() && p.allows(Usage::X509) && !p.allows(Usage::Sign));
        assert!(p.tags().iter().any(|t| t[0] == "x" && t[1].len() == 64));
        let mut no_x = ev.clone();
        no_x.tags.retain(|t| t[0] != "x");
        assert_eq!(Certificate::parse(&no_x), Err(CertError::Digest));
        let mut bad_x = ev.clone();
        bad_x.tags.iter_mut().find(|t| t[0] == "x").unwrap()[1] = "zz".into();
        assert_eq!(Certificate::parse(&bad_x), Err(CertError::Digest));
        // The tag without the usage is carried but means nothing.
        let mut plain = cert("alice@example.org", &[]);
        plain.digest = Some([9; 32]);
        let q = Certificate::parse(&event(&plain)).unwrap();
        assert_eq!(q.digest, Some([9; 32]));
        assert!(!q.is_x509());
        // x509 on another name is not the root statement.
        let mut elsewhere = cert("_@example.org", &[Usage::X509]);
        elsewhere.digest = Some([1; 32]);
        assert!(!Certificate::parse(&event(&elsewhere)).unwrap().is_x509());
    }

    #[test]
    fn rejects_bad_certificates() {
        let base = event(&cert("alice@example.org", &[]));
        let mut e = base.clone();
        e.kind = 1;
        assert_eq!(Certificate::parse(&e), Err(CertError::Kind(1)));
        let mut e = base.clone();
        e.pubkey = "zz".into();
        assert_eq!(Certificate::parse(&e), Err(CertError::Issuer));
        let mut e = base.clone();
        e.tags[0][1] = "Alice@example.org".into();
        assert_eq!(
            Certificate::parse(&e),
            Err(CertError::Name),
            "d must be canonical"
        );
        let mut e = base.clone();
        e.tags[0][1] = "alice".into();
        assert_eq!(Certificate::parse(&e), Err(CertError::Name));
        let mut e = base.clone();
        e.tags.retain(|t| t[0] != "p");
        assert_eq!(Certificate::parse(&e), Err(CertError::Subject));
        let mut e = base.clone();
        e.tags[1][1] = "nothex".into();
        assert_eq!(Certificate::parse(&e), Err(CertError::Subject));
        let mut e = base.clone();
        for i in 0..MAX_SUBJECTS as u8 {
            e.tags
                .push(vec!["p".into(), Npub::from_bytes([100 + i; 32]).to_hex()]);
        }
        assert_eq!(
            Certificate::parse(&e),
            Err(CertError::Subject),
            "one too many"
        );
        let mut e = base.clone();
        e.tags.retain(|t| t[0] != "expiration");
        assert_eq!(Certificate::parse(&e), Err(CertError::Expiration));
        let mut e = base;
        e.tags
            .extend(std::iter::repeat_n(vec!["x".to_string()], MAX_TAGS));
        assert_eq!(Certificate::parse(&e), Err(CertError::TooLarge));
    }
}
