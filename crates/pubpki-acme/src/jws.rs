//! The signature on every ACME request (RFC 8555 §6.2): a JWS in the
//! flattened JSON serialization, `protected` header with `alg`, `nonce`,
//! `url` and either `jwk` or `kid`, the signature over
//! `<protected>.<payload>`. ES256, RS256 and EdDSA, which is what
//! certbot, lego, acme.sh, Caddy and instant-acme send. No I/O.

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The account key as the client presents it (RFC 7517). Members this
/// crate does not know are ignored; only the canonical ones matter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Jwk {
    #[serde(rename = "EC")]
    Ec { crv: String, x: String, y: String },
    #[serde(rename = "RSA")]
    Rsa { n: String, e: String },
    #[serde(rename = "OKP")]
    Okp { crv: String, x: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alg {
    ES256,
    RS256,
    EdDSA,
}

/// The protected header, after the checks `parse` makes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Protected {
    pub alg: Alg,
    pub nonce: String,
    pub url: String,
    #[serde(default)]
    pub jwk: Option<Jwk>,
    #[serde(default)]
    pub kid: Option<String>,
}

/// The wire body: exactly these three members (RFC 8555 §6.2 forbids
/// the unprotected `header`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flattened {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum JwsError {
    #[error("malformed JWS: {0}")]
    Malformed(&'static str),
    #[error("unsupported signature algorithm")]
    BadSignatureAlgorithm,
    #[error("bad public key: {0}")]
    BadPublicKey(&'static str),
    #[error("both jwk and kid")]
    JwkAndKid,
    #[error("neither jwk nor kid")]
    NeitherJwkNorKid,
    #[error("signature does not verify")]
    Signature,
}

/// Parse the body and decode the protected header. The signature is not
/// checked here: the key may still have to be looked up by `kid`.
pub fn parse(body: &[u8]) -> Result<(Flattened, Protected), JwsError> {
    let f: Flattened =
        serde_json::from_slice(body).map_err(|_| JwsError::Malformed("not a flattened JWS"))?;
    let header = B64
        .decode(&f.protected)
        .map_err(|_| JwsError::Malformed("protected header is not base64url"))?;
    let raw: serde_json::Value = serde_json::from_slice(&header)
        .map_err(|_| JwsError::Malformed("protected header is not JSON"))?;
    if raw.get("crit").is_some() {
        return Err(JwsError::Malformed("crit is not supported"));
    }
    if raw.get("alg").and_then(|a| a.as_str()).is_none() {
        return Err(JwsError::Malformed("no alg"));
    }
    let p: Protected = match serde_json::from_value(raw.clone()) {
        Ok(p) => p,
        Err(_) => {
            // Everything else present but the alg unknown: say so (§6.2).
            if raw.get("nonce").is_some() && raw.get("url").is_some() {
                return Err(JwsError::BadSignatureAlgorithm);
            }
            return Err(JwsError::Malformed("protected header lacks nonce or url"));
        }
    };
    match (&p.jwk, &p.kid) {
        (Some(_), Some(_)) => return Err(JwsError::JwkAndKid),
        (None, None) => return Err(JwsError::NeitherJwkNorKid),
        _ => {}
    }
    Ok((f, p))
}

/// Verify `f.signature` over `<protected>.<payload>` with `key`, whose
/// type must match `p.alg`.
pub fn verify(f: &Flattened, p: &Protected, key: &Jwk) -> Result<(), JwsError> {
    let msg = format!("{}.{}", f.protected, f.payload);
    let sig = B64
        .decode(&f.signature)
        .map_err(|_| JwsError::Malformed("signature is not base64url"))?;
    match (p.alg, key) {
        (Alg::ES256, Jwk::Ec { crv, x, y }) => {
            if crv != "P-256" {
                return Err(JwsError::BadPublicKey("ES256 needs crv P-256"));
            }
            let x = b64_fixed::<32>(x).ok_or(JwsError::BadPublicKey("x"))?;
            let y = b64_fixed::<32>(y).ok_or(JwsError::BadPublicKey("y"))?;
            let point =
                p256::EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false);
            let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
                .map_err(|_| JwsError::BadPublicKey("not a P-256 point"))?;
            let sig = p256::ecdsa::Signature::from_slice(&sig).map_err(|_| JwsError::Signature)?;
            signature::Verifier::verify(&vk, msg.as_bytes(), &sig).map_err(|_| JwsError::Signature)
        }
        (Alg::RS256, Jwk::Rsa { n, e }) => {
            let n = B64.decode(n).map_err(|_| JwsError::BadPublicKey("n"))?;
            let e = B64.decode(e).map_err(|_| JwsError::BadPublicKey("e"))?;
            let n = num_bigint_dig::BigUint::from_bytes_be(&n);
            let e = num_bigint_dig::BigUint::from_bytes_be(&e);
            if n.bits() < crate::MIN_RSA_BITS {
                return Err(JwsError::BadPublicKey("RSA key shorter than 2048 bits"));
            }
            let pk = rsa::RsaPublicKey::new(n, e).map_err(|_| JwsError::BadPublicKey("RSA key"))?;
            let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pk);
            let sig = rsa::pkcs1v15::Signature::try_from(sig.as_slice())
                .map_err(|_| JwsError::Signature)?;
            signature::Verifier::verify(&vk, msg.as_bytes(), &sig).map_err(|_| JwsError::Signature)
        }
        (Alg::EdDSA, Jwk::Okp { crv, x }) => {
            if crv != "Ed25519" {
                return Err(JwsError::BadPublicKey("EdDSA needs crv Ed25519"));
            }
            let x = b64_fixed::<32>(x).ok_or(JwsError::BadPublicKey("x"))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&x)
                .map_err(|_| JwsError::BadPublicKey("not an Ed25519 point"))?;
            let sig =
                ed25519_dalek::Signature::from_slice(&sig).map_err(|_| JwsError::Signature)?;
            vk.verify_strict(msg.as_bytes(), &sig)
                .map_err(|_| JwsError::Signature)
        }
        _ => Err(JwsError::BadSignatureAlgorithm),
    }
}

/// RFC 7638: the SHA-256 of the canonical JSON of the key's required
/// members, base64url. The account id.
pub fn thumbprint(key: &Jwk) -> String {
    let canonical = match key {
        Jwk::Ec { crv, x, y } => format!(
            r#"{{"crv":{},"kty":"EC","x":{},"y":{}}}"#,
            json_str(crv),
            json_str(x),
            json_str(y)
        ),
        Jwk::Rsa { n, e } => format!(r#"{{"e":{},"kty":"RSA","n":{}}}"#, json_str(e), json_str(n)),
        Jwk::Okp { crv, x } => format!(
            r#"{{"crv":{},"kty":"OKP","x":{}}}"#,
            json_str(crv),
            json_str(x)
        ),
    };
    B64.encode(Sha256::digest(canonical.as_bytes()))
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// The payload as JSON; an empty payload is a POST-as-GET (`None`).
pub fn payload_json(f: &Flattened) -> Result<Option<serde_json::Value>, JwsError> {
    if f.payload.is_empty() {
        return Ok(None);
    }
    let bytes = B64
        .decode(&f.payload)
        .map_err(|_| JwsError::Malformed("payload is not base64url"))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| JwsError::Malformed("payload is not JSON"))
}

fn b64_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    B64.decode(s).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flattened(
        protected: &serde_json::Value,
        payload: &[u8],
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) -> Vec<u8> {
        let protected = B64.encode(serde_json::to_vec(protected).unwrap());
        let payload = B64.encode(payload);
        let sig = sign(format!("{protected}.{payload}").as_bytes());
        serde_json::to_vec(&serde_json::json!({
            "protected": protected, "payload": payload, "signature": B64.encode(sig)
        }))
        .unwrap()
    }

    fn p256_key() -> (p256::ecdsa::SigningKey, Jwk) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let jwk = Jwk::Ec {
            crv: "P-256".into(),
            x: B64.encode(point.x().unwrap()),
            y: B64.encode(point.y().unwrap()),
        };
        (sk, jwk)
    }

    #[test]
    fn es256_round_trip_and_tampering() {
        let (sk, jwk) = p256_key();
        let header = serde_json::json!({"alg":"ES256","nonce":"n1","url":"http://[::1]/acme/new-account","jwk":jwk});
        let body = flattened(&header, br#"{"termsOfServiceAgreed":true}"#, |m| {
            let s: p256::ecdsa::Signature = signature::Signer::sign(&sk, m);
            s.to_bytes().to_vec()
        });
        let (f, p) = parse(&body).unwrap();
        assert_eq!(p.alg, Alg::ES256);
        assert_eq!(p.nonce, "n1");
        assert_eq!(p.jwk.as_ref(), Some(&jwk));
        verify(&f, &p, &jwk).unwrap();
        assert_eq!(
            payload_json(&f).unwrap().unwrap()["termsOfServiceAgreed"],
            true
        );
        // A changed payload or a changed header breaks the signature.
        let mut t = f.clone();
        t.payload = B64.encode(br#"{"termsOfServiceAgreed":false}"#);
        assert_eq!(verify(&t, &p, &jwk), Err(JwsError::Signature));
        let (other, other_jwk) = {
            let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
            let pt = sk.verifying_key().to_encoded_point(false);
            (
                sk,
                Jwk::Ec {
                    crv: "P-256".into(),
                    x: B64.encode(pt.x().unwrap()),
                    y: B64.encode(pt.y().unwrap()),
                },
            )
        };
        let _ = other;
        assert_eq!(verify(&f, &p, &other_jwk), Err(JwsError::Signature));
        // Wrong key type for the alg.
        let okp = Jwk::Okp {
            crv: "Ed25519".into(),
            x: B64.encode([1u8; 32]),
        };
        assert_eq!(verify(&f, &p, &okp), Err(JwsError::BadSignatureAlgorithm));
        // POST-as-GET.
        let header = serde_json::json!({"alg":"ES256","nonce":"n2","url":"u","kid":"http://[::1]/acme/acct/x"});
        let body = flattened(&header, b"", |m| {
            let s: p256::ecdsa::Signature = signature::Signer::sign(&sk, m);
            s.to_bytes().to_vec()
        });
        let (f, p) = parse(&body).unwrap();
        assert_eq!(p.kid.as_deref(), Some("http://[::1]/acme/acct/x"));
        verify(&f, &p, &jwk).unwrap();
        assert_eq!(payload_json(&f).unwrap(), None);
    }

    #[test]
    fn eddsa_and_rs256_verify() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let jwk = Jwk::Okp {
            crv: "Ed25519".into(),
            x: B64.encode(sk.verifying_key().to_bytes()),
        };
        let header = serde_json::json!({"alg":"EdDSA","nonce":"n","url":"u","jwk":jwk});
        let body = flattened(&header, b"{}", |m| {
            let s: ed25519_dalek::Signature = signature::Signer::sign(&sk, m);
            s.to_bytes().to_vec()
        });
        let (f, p) = parse(&body).unwrap();
        verify(&f, &p, &jwk).unwrap();
        let mut t = f.clone();
        t.signature = B64.encode([0u8; 64]);
        assert_eq!(verify(&t, &p, &jwk), Err(JwsError::Signature));

        let mut rng = rand::thread_rng();
        let rsa_sk = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pk = rsa::traits::PublicKeyParts::n(&rsa_sk).to_bytes_be();
        let e = rsa::traits::PublicKeyParts::e(&rsa_sk).to_bytes_be();
        let jwk = Jwk::Rsa {
            n: B64.encode(pk),
            e: B64.encode(e),
        };
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_sk);
        let header = serde_json::json!({"alg":"RS256","nonce":"n","url":"u","jwk":jwk});
        let body = flattened(&header, b"{}", |m| {
            let s: rsa::pkcs1v15::Signature = signature::Signer::sign(&signer, m);
            signature::SignatureEncoding::to_vec(&s)
        });
        let (f, p) = parse(&body).unwrap();
        verify(&f, &p, &jwk).unwrap();
        let short = Jwk::Rsa {
            n: B64.encode([1u8; 128]),
            e: B64.encode([1, 0, 1]),
        };
        assert_eq!(
            verify(&f, &p, &short),
            Err(JwsError::BadPublicKey("RSA key shorter than 2048 bits"))
        );
    }

    #[test]
    fn refuses_what_acme_forbids() {
        let (sk, jwk) = p256_key();
        let sign = |m: &[u8]| {
            let s: p256::ecdsa::Signature = signature::Signer::sign(&sk, m);
            s.to_bytes().to_vec()
        };
        let both = serde_json::json!({"alg":"ES256","nonce":"n","url":"u","jwk":jwk,"kid":"k"});
        assert_eq!(
            parse(&flattened(&both, b"", sign)).unwrap_err(),
            JwsError::JwkAndKid
        );
        let neither = serde_json::json!({"alg":"ES256","nonce":"n","url":"u"});
        assert_eq!(
            parse(&flattened(&neither, b"", sign)).unwrap_err(),
            JwsError::NeitherJwkNorKid
        );
        let hs = serde_json::json!({"alg":"HS256","nonce":"n","url":"u","kid":"k"});
        assert_eq!(
            parse(&flattened(&hs, b"", sign)).unwrap_err(),
            JwsError::BadSignatureAlgorithm
        );
        let none = serde_json::json!({"alg":"none","nonce":"n","url":"u","kid":"k"});
        assert_eq!(
            parse(&flattened(&none, b"", sign)).unwrap_err(),
            JwsError::BadSignatureAlgorithm
        );
        let crit = serde_json::json!({"alg":"ES256","nonce":"n","url":"u","kid":"k","crit":["x"]});
        assert!(matches!(
            parse(&flattened(&crit, b"", sign)),
            Err(JwsError::Malformed(_))
        ));
        let no_url = serde_json::json!({"alg":"ES256","nonce":"n","kid":"k"});
        assert!(matches!(
            parse(&flattened(&no_url, b"", sign)),
            Err(JwsError::Malformed(_))
        ));
        let mut with_header: serde_json::Value = serde_json::from_slice(&flattened(
            &serde_json::json!({"alg":"ES256","nonce":"n","url":"u","kid":"k"}),
            b"",
            sign,
        ))
        .unwrap();
        with_header["header"] = serde_json::json!({"kid": "x"});
        assert!(matches!(
            parse(&serde_json::to_vec(&with_header).unwrap()),
            Err(JwsError::Malformed(_))
        ));
        assert!(matches!(parse(b"[1,2]"), Err(JwsError::Malformed(_))));
    }

    #[test]
    fn thumbprint_matches_rfc_7638() {
        let key = Jwk::Rsa {
            n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".into(),
            e: "AQAB".into(),
        };
        assert_eq!(
            thumbprint(&key),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }
}
