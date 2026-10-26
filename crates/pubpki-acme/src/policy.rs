//! Who may ask, for what, and the state of what they asked (spec §8a,
//! docs/acme.md). No I/O; every rule is a table test.

use crate::{ErrorType, Identifier, MAX_IDENTIFIERS, ORDER_TTL_SECS, Problem, Subproblem};
use pubpki_core::name::{is_under, overlay_key};
use pubpki_core::pubdom_core::Npub;
use pubpki_core::pubdom_core::claim::ZoneRecord;
use pubpki_core::pubdom_core::domain::{normalize, relative_label};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};

/// The operator's allowlist: the keys whose nodes may ask for
/// certificates. `acme allow|deny|list`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowlist {
    #[serde(default)]
    pub peers: Vec<AllowedPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedPeer {
    pub npub: Npub,
    #[serde(default)]
    pub note: String,
    pub added_at: u64,
}

impl Allowlist {
    /// `false` if already there.
    pub fn allow(&mut self, npub: Npub, note: &str, now: u64) -> bool {
        if self.contains(&npub) {
            return false;
        }
        self.peers.push(AllowedPeer {
            npub,
            note: note.to_string(),
            added_at: now,
        });
        true
    }

    pub fn deny(&mut self, npub: &Npub) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| p.npub != *npub);
        self.peers.len() != before
    }

    pub fn contains(&self, npub: &Npub) -> bool {
        self.peers.iter().any(|p| p.npub == *npub)
    }

    /// The fips address of every allowed key → the key. What a peer's
    /// source address is matched against.
    pub fn addresses(&self) -> HashMap<Ipv6Addr, Npub> {
        self.peers
            .iter()
            .map(|p| (p.npub.fips_address(), p.npub))
            .collect()
    }
}

/// Who is on the other end, from the socket address alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// A mesh address of an allowed key.
    Allowed(Npub),
    /// A mesh address nobody allowed.
    Unknown,
    /// Not a mesh address at all: never served.
    NotMesh,
}

/// `fd00::/8` (every fips address starts with `fd`).
pub fn is_mesh(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => v6.octets()[0] == 0xfd,
        IpAddr::V4(_) => false,
    }
}

/// The mesh authenticates the source address; this only looks it up.
/// The listener must accept connections from the fips interface alone
/// (the server binds the node's fips address and, on Linux, the
/// interface; a host route or a proxy in front would defeat it), or a
/// spoofed `fd…` source on another interface would pass here.
/// `override_` names whom a loopback peer counts as, for tests on a
/// loopback listener and nowhere else.
pub fn peer_of(ip: IpAddr, table: &HashMap<Ipv6Addr, Npub>, override_: Option<Npub>) -> Peer {
    if let (true, Some(npub)) = (ip.is_loopback(), override_) {
        return Peer::Allowed(npub);
    }
    match ip {
        IpAddr::V6(v6) if is_mesh(&ip) => match table.get(&v6) {
            Some(npub) => Peer::Allowed(*npub),
            None => Peer::Unknown,
        },
        _ => Peer::NotMesh,
    }
}

/// Why an identifier was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    NotAHostname,
    Wildcard,
    /// `<npub>.fips` of a key other than the peer.
    OverlayOfOtherKey,
    NotUnderDomain,
    /// No zone loaded, or the label is absent or `legacy`.
    NotInZone,
    ZoneNamesOtherKey(Npub),
}

impl Why {
    pub fn detail(&self) -> String {
        match self {
            Self::NotAHostname => "not a hostname".into(),
            Self::Wildcard => "wildcard identifiers are not issued".into(),
            Self::OverlayOfOtherKey => "the .fips name of another key".into(),
            Self::NotUnderDomain => "not under this CA's domain".into(),
            Self::NotInZone => "the domain's zone does not map this name to a node".into(),
            Self::ZoneNamesOtherKey(k) => format!("the domain's zone maps this name to {k}"),
        }
    }
}

/// Why an order was refused as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// RFC 8555 §7.4: at least one identifier.
    NoIdentifiers,
    TooMany(usize),
    /// One or more identifiers, each with its reason; the rest are not
    /// issued either (no partial orders).
    Identifiers(Vec<(Identifier, Why)>),
}

/// Approve every identifier or refuse the order (RFC 8555 §7.4: no
/// partial orders). `<peer>.fips` always; a name under `ca_domain` when
/// the zone maps its label to the peer. The approved names are
/// normalized and deduplicated, in the order given.
pub fn approve(
    ids: &[Identifier],
    peer: Npub,
    ca_domain: &str,
    zone: Option<&ZoneRecord>,
) -> Result<Vec<String>, Refused> {
    if ids.is_empty() {
        return Err(Refused::NoIdentifiers);
    }
    if ids.len() > MAX_IDENTIFIERS {
        return Err(Refused::TooMany(ids.len()));
    }
    let mut names: Vec<String> = Vec::new();
    let mut refused = Vec::new();
    for id in ids {
        let raw = id.value();
        if raw.starts_with("*.") {
            refused.push((id.clone(), Why::Wildcard));
            continue;
        }
        let Some(name) = normalize(raw) else {
            refused.push((id.clone(), Why::NotAHostname));
            continue;
        };
        let verdict = if let Some(key) = overlay_key(&name) {
            if key == peer {
                Ok(())
            } else {
                Err(Why::OverlayOfOtherKey)
            }
        } else if !is_under(&name, ca_domain) {
            Err(Why::NotUnderDomain)
        } else {
            match zone.and_then(|z| relative_label(&name, ca_domain).and_then(|l| z.lookup(l))) {
                Some(k) if k == peer => Ok(()),
                Some(k) => Err(Why::ZoneNamesOtherKey(k)),
                None => Err(Why::NotInZone),
            }
        };
        match verdict {
            Ok(()) => {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            Err(why) => refused.push((id.clone(), why)),
        }
    }
    if refused.is_empty() {
        Ok(names)
    } else {
        Err(Refused::Identifiers(refused))
    }
}

/// The problem document for what [`approve`] refused.
pub fn rejected(refused: &Refused) -> Problem {
    match refused {
        Refused::NoIdentifiers => Problem::new(
            ErrorType::Malformed,
            "an order needs at least one identifier",
        ),
        Refused::TooMany(n) => Problem::new(
            ErrorType::Malformed,
            format!("{n} identifiers; at most {MAX_IDENTIFIERS}"),
        ),
        Refused::Identifiers(list) => Problem::rejected(
            list.iter()
                .map(|(id, why)| Subproblem {
                    kind: ErrorType::RejectedIdentifier,
                    detail: why.detail(),
                    identifier: Some(id.clone()),
                })
                .collect(),
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Valid,
    Deactivated,
}

/// An ACME account: the key's thumbprint is its id, the peer it was
/// created from is the only peer that may use it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub key: crate::jws::Jwk,
    pub npub: Npub,
    pub status: AccountStatus,
    #[serde(default)]
    pub contact: Vec<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    /// Authorizations are valid from the start: an order is born ready.
    Ready,
    Processing,
    Valid,
    Invalid,
}

/// An authorization, always valid: the mesh connection validated it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authz {
    pub id: String,
    pub identifier: Identifier,
    pub expires: u64,
    pub validated_at: u64,
    /// The one synthetic challenge's id (RFC 8555 §7.1.4 wants one).
    pub challenge_id: String,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    pub id: String,
    pub account: String,
    pub npub: Npub,
    pub identifiers: Vec<Identifier>,
    /// The approved names, what the certificate will carry.
    pub names: Vec<String>,
    pub authzs: Vec<Authz>,
    pub status: OrderStatus,
    pub expires: u64,
    pub serial: Option<String>,
    pub error: Option<String>,
    pub created_at: u64,
}

impl Order {
    /// A ready order for approved `names`, its authorizations valid;
    /// `ids` yields fresh identifiers (orders, authzs, challenges, tokens).
    pub fn new(
        id: String,
        account: &Account,
        identifiers: Vec<Identifier>,
        names: Vec<String>,
        now: u64,
        mut ids: impl FnMut() -> String,
    ) -> Self {
        let authzs = identifiers
            .iter()
            .map(|identifier| Authz {
                id: ids(),
                identifier: identifier.clone(),
                expires: now + ORDER_TTL_SECS,
                validated_at: now,
                challenge_id: ids(),
                token: ids(),
            })
            .collect();
        Self {
            id,
            account: account.id.clone(),
            npub: account.npub,
            identifiers,
            names,
            authzs,
            status: OrderStatus::Ready,
            expires: now + ORDER_TTL_SECS,
            serial: None,
            error: None,
            created_at: now,
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires
    }

    /// Finalize: `ready` → `valid` with the serial, or `invalid` with the
    /// problem; anything else is `orderNotReady`.
    pub fn finalize(&mut self, outcome: Result<String, Problem>) -> Result<(), Problem> {
        if self.status != OrderStatus::Ready {
            return Err(Problem::new(
                ErrorType::OrderNotReady,
                format!("order is {:?}", self.status),
            ));
        }
        match outcome {
            Ok(serial) => {
                self.status = OrderStatus::Valid;
                self.serial = Some(serial);
                Ok(())
            }
            Err(p) => {
                self.status = OrderStatus::Invalid;
                self.error = Some(p.to_string());
                Err(p)
            }
        }
    }
}

/// The CSR must ask for exactly the order's names: the same set of DNS
/// SANs, and a CN, if any, among them.
pub fn csr_matches(
    order_names: &[String],
    csr_sans: &[String],
    csr_cn: Option<&str>,
) -> Result<(), Problem> {
    let mut want: Vec<String> = order_names.iter().map(|n| n.to_ascii_lowercase()).collect();
    let mut have: Vec<String> = csr_sans.iter().map(|n| n.to_ascii_lowercase()).collect();
    want.sort();
    want.dedup();
    have.sort();
    have.dedup();
    if want != have {
        return Err(Problem::new(
            ErrorType::BadCsr,
            format!(
                "the CSR's names ({}) are not the order's ({})",
                have.join(", "),
                want.join(", ")
            ),
        ));
    }
    if let Some(cn) = csr_cn
        && !want.contains(&cn.to_ascii_lowercase())
    {
        return Err(Problem::new(
            ErrorType::BadCsr,
            format!("the CSR's common name {cn} is not one of the order's names"),
        ));
    }
    Ok(())
}

/// An account is used from the address it was created from.
pub fn same_peer(acct: &Account, peer: Npub) -> Result<(), Problem> {
    if acct.npub != peer {
        return Err(Problem::new(
            ErrorType::Unauthorized,
            "this account belongs to another node",
        ));
    }
    if acct.status != AccountStatus::Valid {
        return Err(Problem::new(ErrorType::Unauthorized, "account deactivated"));
    }
    Ok(())
}

/// An issued certificate as the index records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertEntry {
    pub serial: String,
    pub npub: Npub,
    pub account: String,
    pub names: Vec<String>,
    pub not_before: u64,
    pub not_after: u64,
    /// (when, RFC 5280 reason).
    pub revoked: Option<(u64, u32)>,
}

/// RFC 5280 §5.3.1 reason codes in use (2 and 7 are unassigned).
pub fn valid_reason(code: u32) -> bool {
    matches!(code, 0 | 1 | 3 | 4 | 5 | 6 | 9 | 10)
}

/// Only the node a certificate was issued to may revoke it.
pub fn may_revoke(entry: &CertEntry, peer: Npub, reason: Option<u32>) -> Result<(), Problem> {
    if entry.npub != peer {
        return Err(Problem::new(
            ErrorType::Unauthorized,
            "the certificate was issued to another node",
        ));
    }
    if entry.revoked.is_some() {
        return Err(Problem::new(ErrorType::AlreadyRevoked, "already revoked"));
    }
    if let Some(r) = reason
        && !valid_reason(r)
    {
        return Err(Problem::new(
            ErrorType::BadRevocationReason,
            format!("reason code {r} is not one of 0, 1, 3, 4, 5, 6, 9, 10"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubpki_core::pubdom_core::claim::Target;

    fn key(n: u8) -> Npub {
        Npub::from_bytes([n; 32])
    }

    fn zone(author: u8) -> ZoneRecord {
        ZoneRecord {
            author: key(author),
            domain: "example.org".into(),
            created_at: 0,
            names: vec![
                ("@".into(), Target::Author),
                ("www".into(), Target::Node(key(1))),
                ("mail".into(), Target::Node(key(2))),
                ("old".into(), Target::Legacy),
            ],
        }
    }

    fn dns(s: &str) -> Identifier {
        Identifier::Dns(s.into())
    }

    #[test]
    fn allowlist_and_peers() {
        let mut a = Allowlist::default();
        assert!(a.allow(key(1), "web node", 10));
        assert!(!a.allow(key(1), "", 11), "once");
        assert!(a.allow(key(2), "", 12));
        let table = a.addresses();
        assert_eq!(table.len(), 2);
        assert_eq!(table.get(&key(1).fips_address()), Some(&key(1)));
        assert_eq!(
            peer_of(IpAddr::V6(key(1).fips_address()), &table, None),
            Peer::Allowed(key(1))
        );
        assert_eq!(
            peer_of(IpAddr::V6(key(3).fips_address()), &table, None),
            Peer::Unknown
        );
        assert_eq!(
            peer_of("2001:db8::1".parse().unwrap(), &table, None),
            Peer::NotMesh
        );
        assert_eq!(
            peer_of("127.0.0.1".parse().unwrap(), &table, None),
            Peer::NotMesh
        );
        assert_eq!(
            peer_of("::ffff:10.0.0.1".parse().unwrap(), &table, None),
            Peer::NotMesh
        );
        assert_eq!(peer_of("::1".parse().unwrap(), &table, None), Peer::NotMesh);
        assert_eq!(
            peer_of("::1".parse().unwrap(), &table, Some(key(9))),
            Peer::Allowed(key(9)),
            "the test hook"
        );
        assert_eq!(
            peer_of(IpAddr::V6(key(3).fips_address()), &table, Some(key(9))),
            Peer::Unknown,
            "the hook is for loopback only"
        );
        assert!(a.deny(&key(1)) && !a.deny(&key(1)));
        assert!(!a.contains(&key(1)) && a.contains(&key(2)));
    }

    #[test]
    fn approves_the_peer_s_overlay_name_and_zone_mapped_names_only() {
        let z = zone(5);
        let peer = key(1);
        let ok = approve(
            &[
                dns(&peer.fips_name()),
                dns("WWW.example.org."),
                dns("www.example.org"),
            ],
            peer,
            "example.org",
            Some(&z),
        )
        .unwrap();
        assert_eq!(
            ok,
            vec![peer.fips_name(), "www.example.org".to_string()],
            "normalized, deduplicated"
        );
        let refused = approve(
            &[
                dns("mail.example.org"),
                dns("old.example.org"),
                dns("nothere.example.org"),
                dns("example.org"),
                dns("example.net"),
                dns("evilexample.org"),
                dns(&key(2).fips_name()),
                dns("*.example.org"),
                dns("not a host"),
                dns("www.example.org"),
            ],
            peer,
            "example.org",
            Some(&z),
        )
        .unwrap_err();
        let Refused::Identifiers(refused) = refused else {
            panic!("per identifier");
        };
        let whys: Vec<(String, Why)> = refused
            .iter()
            .map(|(i, w)| (i.value().to_string(), w.clone()))
            .collect();
        assert_eq!(
            whys,
            vec![
                (
                    "mail.example.org".to_string(),
                    Why::ZoneNamesOtherKey(key(2))
                ),
                ("old.example.org".to_string(), Why::NotInZone),
                ("nothere.example.org".to_string(), Why::NotInZone),
                ("example.org".to_string(), Why::ZoneNamesOtherKey(key(5))),
                ("example.net".to_string(), Why::NotUnderDomain),
                ("evilexample.org".to_string(), Why::NotUnderDomain),
                (key(2).fips_name(), Why::OverlayOfOtherKey),
                ("*.example.org".to_string(), Why::Wildcard),
                ("not a host".to_string(), Why::NotAHostname),
            ],
            "all or nothing: the good one is not approved alongside"
        );
        // The apex through `self` when the peer is the zone's author.
        assert_eq!(
            approve(&[dns("example.org")], key(5), "example.org", Some(&z)).unwrap(),
            vec!["example.org".to_string()]
        );
        // A wildcard entry in the zone covers unlisted labels.
        let mut wild = zone(5);
        wild.names.push(("*".into(), Target::Node(key(1))));
        assert!(
            approve(
                &[dns("anything.example.org")],
                peer,
                "example.org",
                Some(&wild)
            )
            .is_ok()
        );
        assert!(
            approve(&[dns("old.example.org")], peer, "example.org", Some(&wild)).is_err(),
            "legacy carves out"
        );
        // No zone: only the overlay name.
        assert!(approve(&[dns(&peer.fips_name())], peer, "example.org", None).is_ok());
        assert_eq!(
            approve(&[dns("www.example.org")], peer, "example.org", None).unwrap_err(),
            Refused::Identifiers(vec![(dns("www.example.org"), Why::NotInZone)])
        );
        // None, and too many.
        assert_eq!(
            approve(&[], peer, "example.org", Some(&wild)).unwrap_err(),
            Refused::NoIdentifiers
        );
        let many: Vec<Identifier> = (0..MAX_IDENTIFIERS + 1)
            .map(|i| dns(&format!("n{i}.example.org")))
            .collect();
        assert_eq!(
            approve(&many, peer, "example.org", Some(&wild)).unwrap_err(),
            Refused::TooMany(MAX_IDENTIFIERS + 1)
        );
        assert_eq!(rejected(&Refused::NoIdentifiers).kind, ErrorType::Malformed);
        assert_eq!(rejected(&Refused::TooMany(17)).status, 400);
        let p = rejected(&Refused::Identifiers(refused));
        assert_eq!(p.status, 403);
        assert_eq!(p.subproblems.len(), 9);
    }

    #[test]
    fn orders_csrs_accounts_and_revocation() {
        let acct = Account {
            id: "thumb".into(),
            key: crate::jws::Jwk::Okp {
                crv: "Ed25519".into(),
                x: "AA".into(),
            },
            npub: key(1),
            status: AccountStatus::Valid,
            contact: vec![],
            created_at: 0,
        };
        let mut n = 0;
        let mut o = Order::new(
            "o1".into(),
            &acct,
            vec![dns("www.example.org"), dns(&key(1).fips_name())],
            vec!["www.example.org".into(), key(1).fips_name()],
            1000,
            || {
                n += 1;
                format!("id{n}")
            },
        );
        assert_eq!(o.status, OrderStatus::Ready);
        assert_eq!(o.authzs.len(), 2);
        assert_eq!(o.expires, 1000 + ORDER_TTL_SECS);
        assert!(!o.is_expired(1000) && o.is_expired(1000 + ORDER_TTL_SECS));
        assert_eq!(o.authzs[0].id, "id1");
        assert_ne!(o.authzs[0].token, o.authzs[1].token);
        assert!(
            csr_matches(
                &o.names,
                &[key(1).fips_name(), "WWW.example.org".into()],
                Some("www.example.org")
            )
            .is_ok()
        );
        assert_eq!(
            csr_matches(&o.names, &["www.example.org".into()], None)
                .unwrap_err()
                .kind,
            ErrorType::BadCsr
        );
        assert!(
            csr_matches(
                &o.names,
                &[
                    key(1).fips_name(),
                    "www.example.org".into(),
                    "x.example.org".into()
                ],
                None
            )
            .is_err()
        );
        assert!(
            csr_matches(
                &o.names,
                &[key(1).fips_name(), "www.example.org".into()],
                Some("other.example.org")
            )
            .is_err()
        );
        o.finalize(Ok("01ab".into())).unwrap();
        assert_eq!(o.status, OrderStatus::Valid);
        assert_eq!(o.serial.as_deref(), Some("01ab"));
        assert_eq!(
            o.finalize(Ok("x".into())).unwrap_err().kind,
            ErrorType::OrderNotReady
        );
        let mut bad = o.clone();
        bad.status = OrderStatus::Ready;
        assert!(
            bad.finalize(Err(Problem::new(ErrorType::BadCsr, "no")))
                .is_err()
        );
        assert_eq!(bad.status, OrderStatus::Invalid);
        assert!(bad.error.as_deref().unwrap().contains("badCSR"));
        assert!(same_peer(&acct, key(1)).is_ok());
        assert_eq!(
            same_peer(&acct, key(2)).unwrap_err().kind,
            ErrorType::Unauthorized
        );
        let mut off = acct.clone();
        off.status = AccountStatus::Deactivated;
        assert!(same_peer(&off, key(1)).is_err());
        let mut e = CertEntry {
            serial: "01ab".into(),
            npub: key(1),
            account: "thumb".into(),
            names: o.names.clone(),
            not_before: 1000,
            not_after: 2000,
            revoked: None,
        };
        assert!(may_revoke(&e, key(1), None).is_ok());
        assert!(may_revoke(&e, key(1), Some(1)).is_ok());
        assert_eq!(
            may_revoke(&e, key(1), Some(2)).unwrap_err().kind,
            ErrorType::BadRevocationReason
        );
        assert_eq!(
            may_revoke(&e, key(2), None).unwrap_err().kind,
            ErrorType::Unauthorized
        );
        e.revoked = Some((1500, 1));
        assert_eq!(
            may_revoke(&e, key(1), None).unwrap_err().kind,
            ErrorType::AlreadyRevoked
        );
    }
}
