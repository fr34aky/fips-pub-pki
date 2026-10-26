//! The X.509 side (spec §8a): the CA's root (P-256, separate from the
//! Nostr issuer key: browsers do not accept secp256k1), CSR inspection,
//! issuing a leaf for exactly the approved names, and the check a client
//! runs on a published root statement. rcgen builds and signs,
//! x509-parser reads back. No I/O.

use crate::{ErrorType, MAX_ROOT_DER, MIN_RSA_BITS, NOT_BEFORE_SKEW_SECS, Problem};
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
    SerialNumber,
};
use rustls_pki_types::{CertificateDer, CertificateSigningRequestDer};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

type OffsetDateTime = ::time::OffsetDateTime;

#[derive(Debug, thiserror::Error)]
pub enum X509Error {
    #[error("{0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("root certificate: {0}")]
    Root(String),
    #[error("time out of range")]
    Time,
}

/// The CA root: key and self-signed certificate.
pub struct Root {
    key: KeyPair,
    cert_der: Vec<u8>,
    cert_pem: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootInfo {
    pub subject: String,
    pub not_before: u64,
    pub not_after: u64,
    pub der_sha256: [u8; 32],
}

fn ts(secs: u64) -> Result<OffsetDateTime, X509Error> {
    OffsetDateTime::from_unix_timestamp(secs as i64).map_err(|_| X509Error::Time)
}

/// 128 random bits with the top bit clear: a positive INTEGER of at most
/// 16 bytes, as RFC 5280 wants it.
pub fn random_serial() -> [u8; 16] {
    let mut s: [u8; 16] = rand::random();
    s[0] &= 0x7f;
    s
}

impl Root {
    /// A fresh root for `domain`: CA, key-signing usages, `validity_secs`
    /// from `now`. Returns the root and the two PEM texts to store.
    pub fn generate(
        domain: &str,
        now: u64,
        validity_secs: u64,
    ) -> Result<(Self, String, String), X509Error> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("{domain} fips root"));
        dn.push(DnType::OrganizationName, domain.to_string());
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = ts(now)?;
        params.not_after = ts(now + validity_secs)?;
        params.serial_number = Some(SerialNumber::from_slice(&random_serial()));
        let cert = params.self_signed(&key)?;
        let key_pem = key.serialize_pem();
        let cert_pem = cert.pem();
        Ok((
            Self {
                key,
                cert_der: cert.der().to_vec(),
                cert_pem,
            },
            key_pem,
            cert.pem(),
        ))
    }

    /// From the stored PEMs; the key must be the certificate's.
    pub fn load(key_pem: &str, cert_pem: &str) -> Result<Self, X509Error> {
        let key = KeyPair::from_pem(key_pem)?;
        let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| X509Error::Root(format!("not a PEM certificate: {e}")))?;
        let (_, cert) = parse_x509_certificate(&pem.contents)
            .map_err(|e| X509Error::Root(format!("not a certificate: {e}")))?;
        if !cert.is_ca() {
            return Err(X509Error::Root("not a CA certificate".into()));
        }
        if cert.public_key().raw != key.subject_public_key_info() {
            return Err(X509Error::Root("the key is not the certificate's".into()));
        }
        Ok(Self {
            key,
            cert_der: pem.contents.clone(),
            cert_pem: cert_pem.to_string(),
        })
    }

    pub fn der(&self) -> &[u8] {
        &self.cert_der
    }

    pub fn pem(&self) -> &str {
        &self.cert_pem
    }

    fn issuer(&self) -> Result<rcgen::Issuer<'_, &KeyPair>, X509Error> {
        let der = CertificateDer::from(self.cert_der.clone());
        Ok(rcgen::Issuer::from_ca_cert_der(&der, &self.key)?)
    }

    pub fn info(&self) -> Result<RootInfo, X509Error> {
        info_of(&self.cert_der)
    }
}

fn info_of(der: &[u8]) -> Result<RootInfo, X509Error> {
    let (_, cert) = parse_x509_certificate(der)
        .map_err(|e| X509Error::Root(format!("not a certificate: {e}")))?;
    Ok(RootInfo {
        subject: cert.subject().to_string(),
        not_before: cert.validity().not_before.timestamp().max(0) as u64,
        not_after: cert.validity().not_after.timestamp().max(0) as u64,
        der_sha256: Sha256::digest(der).into(),
    })
}

/// What the CSR says, for the policy to judge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrFacts {
    pub sans: Vec<String>,
    pub cn: Option<String>,
    pub key_alg: &'static str,
}

/// Parse and verify a CSR. rcgen checks the signature and accepts only
/// SAN, key usage, extended key usage and basic constraints; anything
/// else is `badCSR`, as is a key this CA will not certify.
pub fn inspect_csr(der: &[u8]) -> Result<(CertificateSigningRequestParams, CsrFacts), Problem> {
    let bad = |d: String| Problem::new(ErrorType::BadCsr, d);
    let csr = CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(
        der.to_vec(),
    ))
    .map_err(|e| match e {
        rcgen::Error::UnsupportedExtension => bad(
            "unsupported extension in the CSR (must-staple and custom extensions are not accepted)"
                .into(),
        ),
        other => bad(format!("CSR does not parse or verify: {other}")),
    })?;
    let mut sans = Vec::new();
    for san in &csr.params.subject_alt_names {
        match san {
            SanType::DnsName(n) => sans.push(n.as_str().to_ascii_lowercase()),
            other => {
                return Err(bad(format!(
                    "unsupported subject alternative name {other:?}"
                )));
            }
        }
    }
    let cn = csr
        .params
        .distinguished_name
        .get(&DnType::CommonName)
        .and_then(|v| match v {
            rcgen::DnValue::PrintableString(s) => Some(s.as_str().to_string()),
            rcgen::DnValue::Utf8String(s) => Some(s.clone()),
            rcgen::DnValue::Ia5String(s) => Some(s.as_str().to_string()),
            _ => None,
        });
    let alg = csr.public_key.algorithm();
    let key_alg = if *alg == rcgen::PKCS_ECDSA_P256_SHA256 {
        "P-256"
    } else if *alg == rcgen::PKCS_ECDSA_P384_SHA384 {
        "P-384"
    } else if *alg == rcgen::PKCS_ED25519 {
        "Ed25519"
    } else if *alg == rcgen::PKCS_RSA_SHA256 {
        let (_, req) = X509CertificationRequest::from_der(der)
            .map_err(|e| bad(format!("CSR does not parse: {e}")))?;
        let bits = req
            .certification_request_info
            .subject_pki
            .parsed()
            .map(|k| k.key_size())
            .unwrap_or(0);
        if bits < MIN_RSA_BITS {
            return Err(bad(format!(
                "RSA key of {bits} bits; at least {MIN_RSA_BITS}"
            )));
        }
        "RSA"
    } else {
        return Err(bad(format!("unsupported key algorithm {alg:?}")));
    };
    Ok((csr, CsrFacts { sans, cn, key_alg }))
}

/// An issued certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub der: Vec<u8>,
    /// Leaf then root, PEM, as `application/pem-certificate-chain`.
    pub chain_pem: String,
    pub serial: String,
    pub not_before: u64,
    pub not_after: u64,
}

/// Sign the CSR's key for exactly `names` (the order's, never the CSR's
/// SANs), every other parameter set here: CN = the first name, no CA,
/// serverAuth only, authority key identifier, `validity_secs` from `now`
/// with a little skew before.
pub fn issue(
    root: &Root,
    mut csr: CertificateSigningRequestParams,
    names: &[String],
    now: u64,
    validity_secs: u64,
    serial: [u8; 16],
) -> Result<Leaf, X509Error> {
    let p = &mut csr.params;
    // rcgen parses the names into DNS SANs; its string type is private.
    p.subject_alt_names = CertificateParams::new(names.to_vec())?.subject_alt_names;
    if p.subject_alt_names.len() != names.len()
        || p.subject_alt_names
            .iter()
            .any(|s| !matches!(s, SanType::DnsName(_)))
    {
        return Err(X509Error::Root("a name is not a DNS name".into()));
    }
    // A common name only when X.520's 64-character bound allows it; an
    // overlay name (`<npub>.fips`, 68 characters) does not fit, and the
    // SANs carry the names anyway.
    let mut dn = DistinguishedName::new();
    if let Some(first) = names.iter().find(|n| n.len() <= 64) {
        dn.push(DnType::CommonName, first.clone());
    }
    p.distinguished_name = dn;
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    if *csr.public_key.algorithm() == rcgen::PKCS_RSA_SHA256 {
        csr.params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
    }
    let p = &mut csr.params;
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.custom_extensions.clear();
    p.name_constraints = None;
    p.crl_distribution_points.clear();
    p.use_authority_key_identifier_extension = true;
    let not_before = now.saturating_sub(NOT_BEFORE_SKEW_SECS);
    let not_after = now + validity_secs;
    p.not_before = ts(not_before)?;
    p.not_after = ts(not_after)?;
    p.serial_number = Some(SerialNumber::from_slice(&serial));
    let cert = csr.signed_by(&root.issuer()?)?;
    // The serial as the certificate carries it (DER drops leading zero
    // bytes), so the index, the URL and the certificate agree.
    let (_, parsed) = parse_x509_certificate(cert.der())
        .map_err(|e| X509Error::Root(format!("the leaf does not parse back: {e}")))?;
    let serial = hex(parsed.raw_serial());
    Ok(Leaf {
        der: cert.der().to_vec(),
        chain_pem: format!("{}{}", cert.pem(), root.pem()),
        serial,
        not_before,
        not_after,
    })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum TrustError {
    #[error("content is not base64")]
    Base64,
    #[error("root larger than {MAX_ROOT_DER} bytes")]
    TooLarge,
    #[error("the content's SHA-256 does not match the x tag")]
    Digest,
    #[error("content is not an X.509 certificate: {0}")]
    NotACertificate(String),
    #[error("not a CA certificate")]
    NotCa,
    #[error("not self-signed, or the signature does not verify")]
    NotSelfSigned,
    #[error("expired")]
    Expired,
}

/// What `fips-pubpki trust` runs on the content of a validated
/// `_x509@<domain>` statement: the digest, the DER, a self-signed CA
/// certificate, unexpired. Returns the facts and the PEM to install.
pub fn check_root_content(
    content: &str,
    expected_sha256: &[u8; 32],
    now: u64,
) -> Result<(RootInfo, String), TrustError> {
    if content.len() > MAX_ROOT_DER * 2 {
        return Err(TrustError::TooLarge);
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(content.trim())
        .map_err(|_| TrustError::Base64)?;
    if der.len() > MAX_ROOT_DER {
        return Err(TrustError::TooLarge);
    }
    let digest: [u8; 32] = Sha256::digest(&der).into();
    if digest != *expected_sha256 {
        return Err(TrustError::Digest);
    }
    let (rest, cert) =
        parse_x509_certificate(&der).map_err(|e| TrustError::NotACertificate(e.to_string()))?;
    if !rest.is_empty() {
        return Err(TrustError::NotACertificate("trailing bytes".into()));
    }
    if !cert.is_ca() {
        return Err(TrustError::NotCa);
    }
    if cert.subject() != cert.issuer() || cert.verify_signature(None).is_err() {
        return Err(TrustError::NotSelfSigned);
    }
    let info = info_of(&der).map_err(|e| TrustError::NotACertificate(e.to_string()))?;
    if now >= info.not_after {
        return Err(TrustError::Expired);
    }
    Ok((info, pem_of(&der)))
}

/// PEM-encode a certificate DER.
pub fn pem_of(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;

    fn csr_for(names: &[&str], key: &KeyPair) -> Vec<u8> {
        let params =
            CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        params.serialize_request(key).unwrap().der().to_vec()
    }

    #[test]
    fn root_round_trips_and_issues_for_the_approved_names_only() {
        let (root, key_pem, cert_pem) =
            Root::generate("example.org", NOW, 10 * 365 * 86_400).unwrap();
        let info = root.info().unwrap();
        assert!(info.subject.contains("example.org fips root"));
        assert_eq!(info.not_before, NOW);
        let again = Root::load(&key_pem, &cert_pem).unwrap();
        assert_eq!(again.der(), root.der());
        let (other, _, _) = Root::generate("example.net", NOW, 3600).unwrap();
        assert!(
            Root::load(&key_pem, other.pem()).is_err(),
            "key of another root"
        );
        assert!(Root::load("nope", &cert_pem).is_err());

        let leaf_key = KeyPair::generate().unwrap();
        let names = vec!["www.example.org".to_string(), "npub1x.fips".to_string()];
        // The CSR asks for more and for a CA; the order decides.
        let mut asked = CertificateParams::new(vec![
            "www.example.org".to_string(),
            "evil.example.org".to_string(),
        ])
        .unwrap();
        asked.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        asked.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        let csr_der = asked.serialize_request(&leaf_key).unwrap().der().to_vec();
        let (csr, facts) = inspect_csr(&csr_der).unwrap();
        assert_eq!(facts.sans, ["www.example.org", "evil.example.org"]);
        assert_eq!(facts.key_alg, "P-256");
        let leaf = issue(&root, csr, &names, NOW, 30 * 86_400, [0x7f; 16]).unwrap();
        let (_, cert) = parse_x509_certificate(&leaf.der).unwrap();
        let sans: Vec<String> = cert
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .filter_map(|g| match g {
                GeneralName::DNSName(n) => Some(n.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(sans, names, "the order's names, not the CSR's");
        assert!(cert.subject().to_string().contains("www.example.org"));
        assert!(!cert.is_ca());
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth && !eku.code_signing);
        assert_eq!(
            cert.validity().not_before.timestamp() as u64,
            NOW - NOT_BEFORE_SKEW_SECS
        );
        assert_eq!(
            cert.validity().not_after.timestamp() as u64,
            NOW + 30 * 86_400
        );
        let (_, root_cert) = parse_x509_certificate(root.der()).unwrap();
        cert.verify_signature(Some(root_cert.public_key())).unwrap();
        assert_eq!(leaf.serial, "7f".repeat(16));
        let zero_led = issue(
            &root,
            inspect_csr(&csr_for(&["www.example.org"], &leaf_key))
                .unwrap()
                .0,
            &["www.example.org".to_string()],
            NOW,
            3600,
            [0, 0, 0x5a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
        )
        .unwrap();
        assert_eq!(
            zero_led.serial, "5a0102030405060708090a0b0c0d",
            "as the DER has it"
        );
        assert!(leaf.chain_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(leaf.chain_pem.matches("BEGIN CERTIFICATE").count(), 2);
        assert!(
            cert.extensions()
                .iter()
                .any(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        );
        // A bare-key node's only name is 68 characters: no CN, SAN alone.
        let overlay = pubpki_core::pubdom_core::Npub::from_bytes([5; 32]).fips_name();
        let (csr, _) = inspect_csr(&csr_for(&[&overlay], &leaf_key)).unwrap();
        let leaf = issue(
            &root,
            csr,
            std::slice::from_ref(&overlay),
            NOW,
            3600,
            [2; 16],
        )
        .unwrap();
        let (_, cert) = parse_x509_certificate(&leaf.der).unwrap();
        assert!(cert.subject().iter_common_name().next().is_none());
        let sans: Vec<String> = cert
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .filter_map(|g| match g {
                GeneralName::DNSName(n) => Some(n.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(sans, [overlay]);
    }

    #[test]
    fn csrs_with_other_extensions_or_weak_keys_are_bad_csrs() {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["www.example.org".to_string()]).unwrap();
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                vec![0x30, 0x03, 0x02, 0x01, 0x05],
            ));
        let der = params.serialize_request(&key).unwrap().der().to_vec();
        let e = inspect_csr(&der).unwrap_err();
        assert_eq!(e.kind, ErrorType::BadCsr);
        assert!(e.detail.contains("unsupported extension"));
        assert!(inspect_csr(b"not a csr").is_err());
        let plain = csr_for(&["a.example.org"], &key);
        let (_, facts) = inspect_csr(&plain).unwrap();
        assert_eq!(
            facts.cn.as_deref(),
            Some("rcgen self signed cert"),
            "rcgen's default DN; the order's names decide, never this"
        );
        assert_eq!(facts.sans, ["a.example.org"]);
        let mut tampered = plain.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 1;
        assert!(inspect_csr(&tampered).is_err(), "signature");
    }

    #[test]
    fn a_published_root_is_checked_before_it_is_trusted() {
        let (root, _, _) = Root::generate("example.org", NOW, 3600 * 24).unwrap();
        let content = base64::engine::general_purpose::STANDARD.encode(root.der());
        let digest: [u8; 32] = Sha256::digest(root.der()).into();
        let (info, pem) = check_root_content(&content, &digest, NOW + 10).unwrap();
        assert_eq!(info.der_sha256, digest);
        assert!(
            pem.starts_with("-----BEGIN CERTIFICATE-----\n")
                && pem.ends_with("-----END CERTIFICATE-----\n")
        );
        assert_eq!(
            pem,
            root.pem().replace("\r\n", "\n"),
            "rcgen writes CRLF on Windows; ours is LF everywhere"
        );
        assert_eq!(
            check_root_content(&content, &[0; 32], NOW).unwrap_err(),
            TrustError::Digest
        );
        assert_eq!(
            check_root_content("!!", &digest, NOW).unwrap_err(),
            TrustError::Base64
        );
        assert_eq!(
            check_root_content(&content, &digest, NOW + 3600 * 24).unwrap_err(),
            TrustError::Expired
        );
        // A leaf is not a root.
        let key = KeyPair::generate().unwrap();
        let (csr, _) = inspect_csr(&csr_for(&["www.example.org"], &key)).unwrap();
        let leaf = issue(&root, csr, &["www.example.org".into()], NOW, 3600, [1; 16]).unwrap();
        let lc = base64::engine::general_purpose::STANDARD.encode(&leaf.der);
        let ld: [u8; 32] = Sha256::digest(&leaf.der).into();
        assert_eq!(
            check_root_content(&lc, &ld, NOW).unwrap_err(),
            TrustError::NotCa
        );
        let big = base64::engine::general_purpose::STANDARD.encode(vec![0u8; MAX_ROOT_DER + 1]);
        assert_eq!(
            check_root_content(&big, &digest, NOW).unwrap_err(),
            TrustError::TooLarge
        );
    }
}
