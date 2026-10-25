//! Anchoring an issuer by witnesses (spec §2): when the verifier cannot
//! check the chain in the issuer's claim, `k` of its configured witnesses
//! attesting the key in the `fips-ca` role for the domain will do, as
//! NIP-DB's `Attested` method. The chain check itself is
//! `pubdom_resolve::proof`; this is the counting rule, with NIP-DB's
//! freshness limits.

use crate::SERVICE_CA;
use pubdom_core::claim::Attestation;
use pubdom_core::{ATTESTATION_MAX_AGE_SECS, MAX_FUTURE_SECS, Method, Npub};

/// The configured `witnesses` whose **newest** attestation for `domain`
/// names `issuer` as a `fips-ca` key: verified by DNSSEC or several
/// resolvers, within the last 30 days, not from the future. A witness's
/// older attestation counts for nothing once a newer one is in hand (it
/// may have withdrawn the key); the caller filters out what is older than
/// its anti-rollback table has seen, and compares the length with `k`.
pub fn attesting_witnesses(
    domain: &str,
    issuer: &Npub,
    attestations: &[Attestation],
    witnesses: &[Npub],
    now: u64,
) -> Vec<Npub> {
    let mut newest: Vec<&Attestation> = Vec::new();
    for a in attestations {
        if a.domain != domain
            || !witnesses.contains(&a.witness)
            || a.witness == *issuer
            || a.created_at > now + MAX_FUTURE_SECS
            || a.verified_at > now + MAX_FUTURE_SECS
        {
            continue;
        }
        match newest.iter_mut().find(|n| n.witness == a.witness) {
            Some(have) if have.created_at < a.created_at => *have = a,
            Some(_) => {}
            None => newest.push(a),
        }
    }
    newest
        .into_iter()
        .filter(|a| {
            a.method >= Method::Dns
                && a.verified_at + ATTESTATION_MAX_AGE_SECS >= now
                && a.others
                    .iter()
                    .any(|(role, k)| role == SERVICE_CA && k == issuer)
        })
        .map(|a| a.witness)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;

    fn key(n: u8) -> Npub {
        Npub::from_bytes([n; 32])
    }

    fn att(
        witness: u8,
        domain: &str,
        role: &str,
        issuer: u8,
        method: Method,
        verified_at: u64,
    ) -> Attestation {
        Attestation {
            witness: key(witness),
            domain: domain.into(),
            servers: vec![key(9)],
            others: vec![(role.into(), key(issuer))],
            method,
            verified_at,
            created_at: verified_at,
        }
    }

    #[test]
    fn counts_fresh_strong_configured_witnesses_once() {
        let witnesses = [key(10), key(11), key(12)];
        let atts = vec![
            att(10, "example.org", SERVICE_CA, 1, Method::Dns, NOW - 5), // the same witness, older
            att(10, "example.org", SERVICE_CA, 1, Method::Dnssec, NOW - 10), // and newer by created_at below
            att(
                11,
                "example.org",
                SERVICE_CA,
                1,
                Method::Dns,
                NOW - ATTESTATION_MAX_AGE_SECS + 1,
            ),
            att(
                12,
                "example.org",
                SERVICE_CA,
                1,
                Method::Dns,
                NOW - ATTESTATION_MAX_AGE_SECS - 1,
            ), // stale
            att(13, "example.org", SERVICE_CA, 1, Method::Dnssec, NOW), // not configured
            att(10, "example.org", SERVICE_CA, 2, Method::Dnssec, NOW - 100), // another issuer, older
            att(11, "example.net", SERVICE_CA, 1, Method::Dnssec, NOW),       // another domain
            att(
                11,
                "example.org",
                "fips-dns",
                1,
                Method::Dnssec,
                NOW - ATTESTATION_MAX_AGE_SECS - 10,
            ), // another role, older than the counting one
        ];
        assert_eq!(
            attesting_witnesses("example.org", &key(1), &atts, &witnesses, NOW),
            vec![key(10), key(11)]
        );
        // A witness that re-published without the key has withdrawn it:
        // its older attestation counts for nothing, even if fresher by
        // verified_at.
        let mut withdrawn = att(10, "example.org", "fips-dns", 1, Method::Dnssec, NOW - 20);
        withdrawn.created_at = NOW;
        let mut both = atts.clone();
        both.push(withdrawn);
        assert_eq!(
            attesting_witnesses("example.org", &key(1), &both, &witnesses, NOW),
            vec![key(11)]
        );
        // And a newer attestation that is too weak or stale withdraws too.
        let mut weak_newer = att(11, "example.org", SERVICE_CA, 1, Method::DnsSingle, NOW);
        weak_newer.created_at = NOW;
        let mut both = atts.clone();
        both.push(weak_newer);
        assert_eq!(
            attesting_witnesses("example.org", &key(1), &both, &witnesses, NOW),
            vec![key(10)]
        );
        let weak = [att(
            10,
            "example.org",
            SERVICE_CA,
            1,
            Method::DnsSingle,
            NOW,
        )];
        assert!(attesting_witnesses("example.org", &key(1), &weak, &witnesses, NOW).is_empty());
        let future = [att(
            10,
            "example.org",
            SERVICE_CA,
            1,
            Method::Dnssec,
            NOW + MAX_FUTURE_SECS + 1,
        )];
        assert!(attesting_witnesses("example.org", &key(1), &future, &witnesses, NOW).is_empty());
        // The issuer vouching for itself is no witness.
        let selfie = [att(1, "example.org", SERVICE_CA, 1, Method::Dnssec, NOW)];
        assert!(attesting_witnesses("example.org", &key(1), &selfie, &[key(1)], NOW).is_empty());
        assert!(attesting_witnesses("example.org", &key(1), &atts, &[], NOW).is_empty());
    }
}
