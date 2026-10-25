//! Names: `<local>@<domain>` in the NIP-05 grammar, `_@<domain>` for the
//! domain itself, and the scope rule that makes sub-issuers safe: a name
//! is *under* a domain when its domain is that domain or ends in `.` plus
//! that domain (docs/nip.md "Sub-issuers").

use pubdom_core::Npub;
use pubdom_core::domain::normalize;
use pubdom_core::identity::looks_like_npub;
use serde::{Deserialize, Serialize};

/// Longest local part accepted (NIP-05 gives no bound; mailboxes stop at
/// 64).
pub const MAX_LOCAL: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Name {
    /// Lowercase, `a-z0-9-_.`; `_` for the domain itself.
    pub local: String,
    /// Normalized as `pubdom_core::domain::normalize`: lowercase, no
    /// trailing dot, hostname syntax. `<npub>.fips` for a bare-key issuer.
    pub domain: String,
}

impl Name {
    /// `alice@Example.org.` → `alice@example.org`; `None` for anything an
    /// application should never have asked.
    pub fn parse(s: &str) -> Option<Self> {
        let (local, domain) = s.split_once('@')?;
        let local = local.to_ascii_lowercase();
        if local.is_empty()
            || local.len() > MAX_LOCAL
            || !local.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
            })
        {
            return None;
        }
        let domain = normalize(domain)?;
        Some(Self { local, domain })
    }

    /// The domain itself: `_@<domain>`.
    pub fn apex(domain: &str) -> Option<Self> {
        Some(Self {
            local: "_".into(),
            domain: normalize(domain)?,
        })
    }

    pub fn is_apex(&self) -> bool {
        self.local == "_"
    }

    /// `<npub>.fips`: a bare key on the overlay is its own issuer.
    pub fn overlay_issuer(&self) -> Option<Npub> {
        overlay_key(&self.domain)
    }

    /// Is this name within the authority of an issuer for `scope`?
    pub fn is_under(&self, scope: &str) -> bool {
        is_under(&self.domain, scope)
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// `domain` is `scope` or a subdomain of it. Both already normalized.
pub fn is_under(domain: &str, scope: &str) -> bool {
    domain == scope
        || (domain.len() > scope.len()
            && domain.ends_with(scope)
            && domain.as_bytes()[domain.len() - scope.len() - 1] == b'.')
}

/// The key of an overlay domain `<npub>.fips`, if it is one.
pub fn overlay_key(domain: &str) -> Option<Npub> {
    let (label, tld) = domain.split_once('.')?;
    if tld != "fips" || !looks_like_npub(label) {
        return None;
    }
    Npub::parse(label).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes() {
        let n = Name::parse("Alice.Smith@Example.ORG.").unwrap();
        assert_eq!(n.to_string(), "alice.smith@example.org");
        assert!(!n.is_apex());
        assert_eq!(
            Name::apex("example.org").unwrap().to_string(),
            "_@example.org"
        );
        assert!(Name::apex("example.org").unwrap().is_apex());
        assert_eq!(
            Name::parse(&format!("{}@example.org", "a".repeat(64))).map(|n| n.local.len()),
            Some(64)
        );
    }

    #[test]
    fn rejects_what_no_application_should_ask() {
        for bad in [
            "",
            "alice",
            "@example.org",
            "alice@",
            "al ice@example.org",
            "al@ice@example.org",
            "alice@exa mple.org",
            "alice@-example.org",
            "ali+ce@example.org",
        ] {
            assert_eq!(Name::parse(bad), None, "{bad:?}");
        }
        assert_eq!(
            Name::parse(&format!("{}@example.org", "a".repeat(65))),
            None
        );
    }

    #[test]
    fn scope_is_the_domain_or_below_it_never_a_lookalike() {
        assert!(is_under("example.org", "example.org"));
        assert!(is_under("sales.example.org", "example.org"));
        assert!(is_under("emea.sales.example.org", "example.org"));
        assert!(!is_under("example.org", "sales.example.org"));
        assert!(!is_under("evilexample.org", "example.org"));
        assert!(!is_under("example.org.evil", "example.org"));
        assert!(!is_under("org", "example.org"));
        let n = Name::parse("bob@sales.example.org").unwrap();
        assert!(n.is_under("example.org"));
        assert!(n.is_under("sales.example.org"));
        assert!(!n.is_under("example.net"));
    }

    #[test]
    fn a_bare_key_on_the_overlay_is_its_own_issuer() {
        let key = Npub::from_bytes([7; 32]);
        let n = Name::parse(&format!("alice@{}", key.fips_name())).unwrap();
        assert_eq!(n.overlay_issuer(), Some(key));
        assert_eq!(
            Name::parse("alice@example.org").unwrap().overlay_issuer(),
            None
        );
        assert_eq!(overlay_key("www.fips"), None);
        assert_eq!(
            overlay_key(&format!(
                "{}.org",
                key.fips_name().trim_end_matches(".fips")
            )),
            None
        );
    }
}
