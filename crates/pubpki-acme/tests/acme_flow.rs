//! The server driven by a real ACME client (instant-acme) over plain
//! HTTP on loopback, with the test hook that makes the loopback peer
//! count as an allowed node. No network beyond `[::1]`.

use bytes::Bytes;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AuthorizationStatus, BodyWrapper, BytesResponse, HttpClient, Identifier, NewAccount,
    NewOrder, OrderStatus, RevocationRequest,
};
use pubpki_acme::policy::Allowlist;
use pubpki_acme::server::{AppState, ServeConfig, bind, serve};
use pubpki_acme::store::AcmeStore;
use pubpki_acme::x509::Root;
use pubpki_acme::zone::{ZoneCache, ZoneSource};
use pubpki_core::pubdom_core::Npub;
use rustls_pki_types::CertificateDer;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use x509_parser::prelude::*;

struct Plain(Client<HttpConnector, BodyWrapper<Bytes>>);

impl HttpClient for Plain {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let fut = self.0.request(req);
        Box::pin(async move {
            fut.await
                .map(BytesResponse::from)
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))
        })
    }
}

fn client() -> Box<dyn HttpClient> {
    Box::new(Plain(
        Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
    ))
}

struct Harness {
    base: String,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

/// The scratch directory, removed however the test ends.
struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn start(dir: &std::path::Path, peer: Option<Npub>) -> Harness {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let listen: SocketAddr = "[::1]:0".parse().unwrap();
    let mut cfg = ServeConfig::new(listen, "example.org");
    cfg.peer_override = peer;
    let listener = bind(&cfg, 0).await.unwrap();
    let addr = listener.local_addr().unwrap();
    cfg.listen = addr;
    cfg.base_url = format!("http://{addr}");
    let key_pem = std::fs::read_to_string(dir.join("root.key")).unwrap();
    let cert_pem = std::fs::read_to_string(dir.join("root.crt")).unwrap();
    let root = Root::load(&key_pem, &cert_pem).unwrap();
    let store = AcmeStore::new(dir.join("acme"));
    let zone = ZoneCache::new(
        ZoneSource::File {
            path: dir.join("example.org.yaml"),
            author: Npub::from_bytes([9; 32]),
        },
        300,
    );
    let state = Arc::new(AppState::new(cfg.clone(), root, store, zone).unwrap());
    tokio::spawn(serve(state, listener, async move {
        let _ = rx.await;
    }));
    Harness {
        base: cfg.base_url,
        _shutdown: tx,
    }
}

fn setup() -> (Scratch, Root, Npub, Npub) {
    let dir = std::env::temp_dir().join(format!(
        "pubpki-acme-flow-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("acme")).unwrap();
    let (root, key_pem, cert_pem) =
        Root::generate("example.org", pubpki::now(), 3650 * 86_400).unwrap();
    std::fs::write(dir.join("root.key"), key_pem).unwrap();
    std::fs::write(dir.join("root.crt"), cert_pem).unwrap();
    let peer = Npub::from_bytes([7; 32]);
    let other = Npub::from_bytes([8; 32]);
    let mut allow = Allowlist::default();
    allow.allow(peer, "test node", 1);
    AcmeStore::new(dir.join("acme"))
        .save_allowlist(&allow)
        .unwrap();
    std::fs::write(
        dir.join("example.org.yaml"),
        format!("domain: example.org\nnames:\n  \"@\": self\n  www: {peer}\n  mail: {other}\n  \"*\": legacy\n"),
    )
    .unwrap();
    (Scratch(dir), root, peer, other)
}

fn rand_suffix() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// A CSR as real clients make one: the names as SANs, the first one that
/// fits as the common name (certbot, lego) or no common name at all.
fn csr_for(names: &[String]) -> (rcgen::KeyPair, Vec<u8>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(names.to_vec()).unwrap();
    let mut dn = rcgen::DistinguishedName::new();
    if let Some(cn) = names.iter().find(|n| n.len() <= 64) {
        dn.push(rcgen::DnType::CommonName, cn.clone());
    }
    params.distinguished_name = dn;
    let der = params.serialize_request(&key).unwrap().der().to_vec();
    (key, der)
}

fn dns_sans(der: &[u8]) -> Vec<String> {
    let (_, cert) = parse_x509_certificate(der).unwrap();
    cert.subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .iter()
        .filter_map(|g| match g {
            GeneralName::DNSName(n) => Some(n.to_string()),
            _ => None,
        })
        .collect()
}

fn pem_blocks(pem: &str) -> Vec<Vec<u8>> {
    let mut rest = pem.as_bytes();
    let mut out = Vec::new();
    while let Ok((r, p)) = parse_x509_pem(rest) {
        out.push(p.contents);
        rest = r;
        if rest.is_empty() {
            break;
        }
    }
    out
}

/// `unwrap_err` for results whose success type has no Debug.
fn err<T>(r: Result<T, instant_acme::Error>) -> instant_acme::Error {
    match r {
        Err(e) => e,
        Ok(_) => panic!("expected an ACME error"),
    }
}

fn problem_type(e: &instant_acme::Error) -> String {
    match e {
        instant_acme::Error::Api(p) => p.r#type.clone().unwrap_or_default(),
        other => panic!("not an ACME problem: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_real_acme_client_gets_a_certificate_and_revokes_it() {
    let (scratch, root, peer, other) = setup();
    let dir = scratch.0.clone();
    let h = start(&dir, Some(peer)).await;
    let directory = format!("{}/directory", h.base);

    // 1. Account.
    let (account, creds) = Account::builder_with_http(client())
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.clone(),
            None,
        )
        .await
        .unwrap();
    assert!(account.id().starts_with(&h.base));

    // 2. An order for the two names the policy approves; ready at birth.
    let names = vec!["www.example.org".to_string(), peer.fips_name()];
    let ids: Vec<Identifier> = names.iter().map(|n| Identifier::Dns(n.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&ids)).await.unwrap();
    assert_eq!(order.state().status, OrderStatus::Ready);
    let mut seen = 0;
    {
        let mut authzs = order.authorizations();
        while let Some(a) = authzs.next().await {
            let mut a = a.unwrap();
            let st = a.refresh().await.unwrap();
            assert_eq!(st.status, AuthorizationStatus::Valid);
            assert_eq!(st.challenges.len(), 1);
            seen += 1;
        }
    }
    assert_eq!(seen, 2);
    let status = order
        .poll_ready(&instant_acme::RetryPolicy::default())
        .await
        .unwrap();
    assert_eq!(status, OrderStatus::Ready);

    // 3. Finalize with a CSR and download the chain.
    let (_, csr) = csr_for(&names);
    order.finalize_csr(&csr).await.unwrap();
    assert_eq!(order.state().status, OrderStatus::Valid);
    let chain = order.certificate().await.unwrap().expect("certificate");
    let blocks = pem_blocks(&chain);
    assert_eq!(blocks.len(), 2, "leaf and root");
    assert_eq!(dns_sans(&blocks[0]), names);
    let (_, leaf) = parse_x509_certificate(&blocks[0]).unwrap();
    let (_, root_cert) = parse_x509_certificate(&blocks[1]).unwrap();
    leaf.verify_signature(Some(root_cert.public_key())).unwrap();
    assert!(!leaf.is_ca());
    assert!(
        leaf.extended_key_usage()
            .unwrap()
            .unwrap()
            .value
            .server_auth
    );
    assert_eq!(
        root_cert.subject().to_string(),
        root.info().unwrap().subject
    );
    let validity = leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp();
    assert_eq!(validity as u64, 30 * 86_400 + 300);

    // 4. Refusals, each named.
    for (bad, expect) in [
        ("mail.example.org", "rejectedIdentifier"),
        ("example.net", "rejectedIdentifier"),
        (other.fips_name().as_str(), "rejectedIdentifier"),
        ("*.example.org", "rejectedIdentifier"),
        ("old.example.org", "rejectedIdentifier"),
    ] {
        let e = err(account
            .new_order(&NewOrder::new(&[Identifier::Dns(bad.to_string())]))
            .await);
        assert!(problem_type(&e).ends_with(expect), "{bad}: {e}");
    }
    let e = err(account
        .new_order(&NewOrder::new(&[Identifier::Ip("::1".parse().unwrap())]))
        .await);
    assert!(problem_type(&e).ends_with("unsupportedIdentifier"));
    // A CSR asking for more than the order, or less.
    let mut o2 = account.new_order(&NewOrder::new(&ids)).await.unwrap();
    let (_, more) = csr_for(&[
        "www.example.org".into(),
        peer.fips_name(),
        "extra.example.org".into(),
    ]);
    let e = o2.finalize_csr(&more).await.unwrap_err();
    assert!(problem_type(&e).ends_with("badCSR"), "{e}");
    let mut o3 = account.new_order(&NewOrder::new(&ids)).await.unwrap();
    let (_, fewer) = csr_for(&["www.example.org".into()]);
    assert!(problem_type(&o3.finalize_csr(&fewer).await.unwrap_err()).ends_with("badCSR"));

    // 5. Revocation, once.
    account
        .revoke(&RevocationRequest {
            certificate: &CertificateDer::from(blocks[0].clone()),
            reason: None,
        })
        .await
        .unwrap();
    let e = account
        .revoke(&RevocationRequest {
            certificate: &CertificateDer::from(blocks[0].clone()),
            reason: None,
        })
        .await
        .unwrap_err();
    assert!(problem_type(&e).ends_with("alreadyRevoked"));
    let index = AcmeStore::new(dir.join("acme")).load_index().unwrap();
    assert_eq!(index.len(), 1);
    assert!(index[0].revoked.is_some());
    assert_eq!(index[0].names, names);

    // 6. The same state after a restart: the account persists, nonces do not.
    let old_base = h.base.clone();
    drop(h);
    let h2 = start(&dir, Some(peer)).await;
    let creds_json = serde_json::to_string(&creds).unwrap();
    // The directory moved with the port; point the credentials at it.
    let mut v: serde_json::Value = serde_json::from_str(&creds_json).unwrap();
    v["directory"] = serde_json::json!(format!("{}/directory", h2.base));
    v["id"] = serde_json::json!(account.id().replace(&old_base, &h2.base));
    let creds: instant_acme::AccountCredentials = serde_json::from_value(v).unwrap();
    let account2 = Account::builder_with_http(client())
        .from_credentials(creds)
        .await
        .unwrap();
    let mut o4 = account2.new_order(&NewOrder::new(&ids)).await.unwrap();
    assert_eq!(o4.state().status, OrderStatus::Ready);

    // 7. Nobody allowed on this listener: no account, no nonce.
    drop(h2);
    let h3 = start(&dir, None).await;
    let e = err(Account::builder_with_http(client())
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            format!("{}/directory", h3.base),
            None,
        )
        .await);
    assert!(problem_type(&e).ends_with("unauthorized"), "{e}");
    drop(h3);
    // 8. An account may hold only so many live orders.
    let h4 = start(&dir, Some(peer)).await;
    let mut v: serde_json::Value = serde_json::from_str(&creds_json).unwrap();
    v["directory"] = serde_json::json!(format!("{}/directory", h4.base));
    v["id"] = serde_json::json!(account.id().replace(&old_base, &h4.base));
    let creds: instant_acme::AccountCredentials = serde_json::from_value(v).unwrap();
    let account4 = Account::builder_with_http(client())
        .from_credentials(creds)
        .await
        .unwrap();
    let mut made = 0;
    let mut limited = false;
    for _ in 0..40 {
        match account4.new_order(&NewOrder::new(&ids)).await {
            Ok(_) => made += 1,
            Err(e) => {
                assert!(problem_type(&e).ends_with("rateLimited"), "{e}");
                limited = true;
                break;
            }
        }
    }
    assert!(limited, "{made} orders without a limit");
    assert!(made <= 16);
}
