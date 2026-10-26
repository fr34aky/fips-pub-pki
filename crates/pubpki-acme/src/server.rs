//! The ACME endpoints (RFC 8555 §7) over the policy modules. One
//! listener on the CA node's fips address, one lock over the live
//! tables, the peer's source address as the proof, files saved from
//! under the lock after every change.

use crate::jws::{self, Jwk, JwsError};
use crate::nonce::NoncePool;
use crate::policy::{
    self, Account, AccountStatus, Allowlist, Authz, CertEntry, Order, OrderStatus, Peer,
};
use crate::store::AcmeStore;
use crate::x509::{self, Root};
use crate::zone::ZoneCache;
use crate::{
    DEFAULT_LEAF_VALIDITY_SECS, ErrorType, Identifier, MAX_BODY, MAX_CONTACTS, MAX_NONCES,
    NONCE_TTL_SECS, Problem, rfc3339,
};
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use base64::Engine;
use pubpki_core::pubdom_core::Npub;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// What `acme serve` decides once.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub listen: SocketAddr,
    /// `http://[fd…]:8555`, what every URL the server hands out starts with.
    pub base_url: String,
    pub ca_domain: String,
    /// Whom a loopback peer counts as; honoured on a loopback listener only.
    pub peer_override: Option<Npub>,
    pub leaf_validity_secs: u64,
    /// Linux: bind the listening socket to this interface (the fips tun),
    /// so nothing arriving through another interface reaches it.
    pub interface: Option<String>,
}

impl ServeConfig {
    pub fn new(listen: SocketAddr, ca_domain: &str) -> Self {
        Self {
            listen,
            base_url: format!("http://{listen}"),
            ca_domain: ca_domain.to_string(),
            peer_override: None,
            leaf_validity_secs: DEFAULT_LEAF_VALIDITY_SECS,
            interface: None,
        }
    }
}

pub struct AppState {
    cfg: ServeConfig,
    root: Root,
    store: AcmeStore,
    inner: Mutex<Inner>,
}

struct Inner {
    allow: Allowlist,
    allow_mtime: Option<SystemTime>,
    addresses: HashMap<Ipv6Addr, Npub>,
    nonces: NoncePool,
    accounts: Vec<Account>,
    orders: Vec<Order>,
    index: Vec<CertEntry>,
    zone: ZoneCache,
}

impl AppState {
    /// Load the tables from the store. The override is refused off
    /// loopback; `base_url` must be absolute.
    pub fn new(
        cfg: ServeConfig,
        root: Root,
        store: AcmeStore,
        zone: ZoneCache,
    ) -> Result<Self, String> {
        if cfg.peer_override.is_some() && !cfg.listen.ip().is_loopback() {
            return Err("acme_peer_override is for a loopback listener only".into());
        }
        if !cfg.listen.ip().is_loopback() && !policy::is_mesh(&cfg.listen.ip()) {
            return Err(format!(
                "{}: the ACME server listens on the node's fips address (or loopback for tests), nowhere else",
                cfg.listen
            ));
        }
        if !cfg.base_url.starts_with("http://") {
            return Err("base_url must start with http://".into());
        }
        let (allow, allow_mtime) = store.load_allowlist()?;
        let addresses = allow.addresses();
        let accounts = store.load_accounts()?;
        let orders = store.load_orders()?;
        let index = store.load_index()?;
        Ok(Self {
            cfg,
            root,
            store,
            inner: Mutex::new(Inner {
                allow,
                allow_mtime,
                addresses,
                nonces: NoncePool::new(NONCE_TTL_SECS, MAX_NONCES),
                accounts,
                orders,
                index,
                zone,
            }),
        })
    }

    pub fn config(&self) -> &ServeConfig {
        &self.cfg
    }
}

fn now() -> u64 {
    pubpki::now()
}

fn random_id() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
}

/// Bind the listener; on Linux, to `interface` too. `retries` times a
/// second apart, since the fips address exists only once the tun is up.
pub async fn bind(cfg: &ServeConfig, retries: u32) -> Result<TcpListener, String> {
    let mut attempt = 0;
    loop {
        match try_bind(cfg) {
            Ok(l) => return Ok(l),
            Err(e) if attempt < retries => {
                attempt += 1;
                tracing::warn!(listen = %cfg.listen, %e, attempt, "bind failed; the fips address may not be up yet");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Err(e) => return Err(format!("{}: {e}", cfg.listen)),
        }
    }
}

fn try_bind(cfg: &ServeConfig) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if cfg.listen.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if let Some(iface) = &cfg.interface {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        socket.bind_device(Some(iface.as_bytes()))?;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = iface;
            return Err(std::io::Error::other(
                "binding to an interface is Linux only",
            ));
        }
    }
    socket.set_nonblocking(true)?;
    socket.bind(&cfg.listen.into())?;
    socket.listen(128)?;
    TcpListener::from_std(socket.into())
}

/// Serve until `shutdown` completes.
pub async fn serve(
    state: Arc<AppState>,
    listener: TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .map_err(|e| e.to_string())
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/directory", get(directory))
        .route("/acme/new-nonce", get(new_nonce).head(new_nonce))
        .route("/acme/new-account", post(new_account))
        .route("/acme/acct/{id}", post(account))
        .route("/acme/acct/{id}/orders", post(account_orders))
        .route("/acme/new-order", post(new_order))
        .route("/acme/order/{id}", post(order))
        .route("/acme/order/{id}/finalize", post(finalize))
        .route("/acme/authz/{id}", post(authz))
        .route("/acme/chall/{id}", post(challenge))
        .route("/acme/cert/{serial}", post(certificate))
        .route("/acme/revoke-cert", post(revoke))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(state.clone(), gate))
        .with_state(state)
}

/// Every request: nothing off the mesh is served at all; the directory
/// and a nonce, which reveal nothing, go to any mesh peer (so a client
/// that is not allowed gets a proper problem document at new-account
/// instead of unparsable refusals); every POST needs an allowed node.
async fn gate(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let mut inner = state.inner.lock().await;
    inner.reload_allowlist(&state.store);
    let override_ = state
        .cfg
        .peer_override
        .filter(|_| state.cfg.listen.ip().is_loopback());
    let peer = policy::peer_of(addr.ip(), &inner.addresses, override_);
    drop(inner);
    let open = matches!(req.uri().path(), "/directory" | "/acme/new-nonce");
    let on_mesh = policy::is_mesh(&addr.ip())
        || (addr.ip().is_loopback() && state.cfg.listen.ip().is_loopback());
    match peer {
        Peer::Allowed(npub) => {
            req.extensions_mut().insert(PeerKey(npub));
            next.run(req).await
        }
        Peer::Unknown if open => next.run(req).await,
        Peer::NotMesh if open && on_mesh => next.run(req).await,
        other => {
            tracing::info!(peer = %addr.ip(), ?other, path = req.uri().path(), "refused");
            Problem::new(
                ErrorType::Unauthorized,
                "this address is not an allowed node",
            )
            .into_response()
        }
    }
}

#[derive(Clone, Copy)]
struct PeerKey(Npub);

impl Inner {
    fn reload_allowlist(&mut self, store: &AcmeStore) {
        let mtime = store.allowlist_mtime();
        if mtime != self.allow_mtime
            && let Ok((allow, m)) = store.load_allowlist()
        {
            self.addresses = allow.addresses();
            self.allow = allow;
            self.allow_mtime = m;
        }
    }

    fn account(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_REQUEST);
        let body = serde_json::to_vec(&self).unwrap_or_default();
        let mut r = Response::new(Body::from(body));
        *r.status_mut() = status;
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        r
    }
}

/// What a handler produced, before the common headers go on.
struct Reply {
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
    headers: Vec<(&'static str, String)>,
}

impl Reply {
    fn json(status: StatusCode, v: &serde_json::Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(v).unwrap_or_default(),
            headers: Vec::new(),
        }
    }

    fn location(mut self, url: String) -> Self {
        self.headers.push(("location", url));
        self
    }
}

/// Finish a reply or a problem with `Replay-Nonce`, the index link and
/// no caching (RFC 8555 §6.5, §7.1).
fn finish(state: &AppState, inner: &mut Inner, r: Result<Reply, Problem>) -> Response {
    let nonce = inner.nonces.issue(now(), rand::random());
    let mut resp = match r {
        Ok(reply) => {
            let mut resp = Response::new(Body::from(reply.body));
            *resp.status_mut() = reply.status;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(reply.content_type),
            );
            for (k, v) in reply.headers {
                if let Ok(v) = HeaderValue::from_str(&v) {
                    resp.headers_mut().insert(k, v);
                }
            }
            resp
        }
        Err(p) => p.into_response(),
    };
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&nonce) {
        h.insert("replay-nonce", v);
    }
    if let Ok(v) =
        HeaderValue::from_str(&format!("<{}/directory>;rel=\"index\"", state.cfg.base_url))
    {
        h.append(header::LINK, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

async fn directory(State(state): State<Arc<AppState>>) -> Response {
    let b = &state.cfg.base_url;
    let v = serde_json::json!({
        "newNonce": format!("{b}/acme/new-nonce"),
        "newAccount": format!("{b}/acme/new-account"),
        "newOrder": format!("{b}/acme/new-order"),
        "revokeCert": format!("{b}/acme/revoke-cert"),
        "meta": {
            "website": "https://github.com/fr34aky/fips-pub-pki",
            "caaIdentities": [state.cfg.ca_domain],
        }
    });
    let mut inner = state.inner.lock().await;
    finish(&state, &mut inner, Ok(Reply::json(StatusCode::OK, &v)))
}

async fn new_nonce(State(state): State<Arc<AppState>>, req: axum::extract::Request) -> Response {
    let status = if req.method() == axum::http::Method::HEAD {
        StatusCode::OK
    } else {
        StatusCode::NO_CONTENT
    };
    let mut inner = state.inner.lock().await;
    let mut r = finish(
        &state,
        &mut inner,
        Ok(Reply {
            status,
            content_type: "application/json",
            body: Vec::new(),
            headers: Vec::new(),
        }),
    );
    r.headers_mut().remove(header::CONTENT_TYPE);
    r
}

/// A verified POST: with which key, as which account, saying what.
struct Posted {
    account: Option<Account>,
    jwk: Jwk,
    payload: Option<serde_json::Value>,
}

fn jws_problem(e: JwsError) -> Problem {
    match e {
        JwsError::BadSignatureAlgorithm => {
            let mut p = Problem::new(
                ErrorType::BadSignatureAlgorithm,
                "use ES256, RS256 or EdDSA",
            );
            p.detail.push_str(" (algorithms: ES256, RS256, EdDSA)");
            p
        }
        JwsError::BadPublicKey(why) => Problem::new(ErrorType::BadPublicKey, why),
        JwsError::Signature => {
            Problem::new(ErrorType::Malformed, "the JWS signature does not verify")
        }
        other => Problem::new(ErrorType::Malformed, other.to_string()),
    }
}

/// RFC 8555 §6.2–§6.5: parse, nonce, url, key, signature.
fn authenticate(
    state: &AppState,
    inner: &mut Inner,
    peer: Npub,
    uri: &Uri,
    body: &[u8],
    allow_jwk: bool,
) -> Result<Posted, Problem> {
    let (f, p) = jws::parse(body).map_err(jws_problem)?;
    if !inner.nonces.consume(&p.nonce, now()) {
        return Err(Problem::new(
            ErrorType::BadNonce,
            "nonce unknown or used; retry with the one in this reply",
        ));
    }
    let expected = format!("{}{}", state.cfg.base_url, uri.path());
    if p.url != expected {
        return Err(Problem::new(
            ErrorType::Malformed,
            format!("the JWS url {} is not this request's {expected}", p.url),
        ));
    }
    let (jwk, account) = match (&p.jwk, &p.kid) {
        (Some(jwk), None) => {
            if !allow_jwk {
                return Err(Problem::new(
                    ErrorType::Malformed,
                    "this request needs kid, not jwk",
                ));
            }
            let id = jws::thumbprint(jwk);
            (jwk.clone(), inner.account(&id).cloned())
        }
        (None, Some(kid)) => {
            let prefix = format!("{}/acme/acct/", state.cfg.base_url);
            let id = kid.strip_prefix(&prefix).ok_or_else(|| {
                Problem::new(
                    ErrorType::Malformed,
                    "kid is not an account URL of this server",
                )
            })?;
            let acct = inner
                .account(id)
                .cloned()
                .ok_or_else(|| Problem::new(ErrorType::AccountDoesNotExist, "no such account"))?;
            policy::same_peer(&acct, peer)?;
            (acct.key.clone(), Some(acct))
        }
        _ => return Err(Problem::new(ErrorType::Malformed, "jwk or kid")),
    };
    jws::verify(&f, &p, &jwk).map_err(jws_problem)?;
    if let Some(a) = &account {
        policy::same_peer(a, peer)?;
    }
    let payload = jws::payload_json(&f).map_err(jws_problem)?;
    Ok(Posted {
        account,
        jwk,
        payload,
    })
}

fn account_json(state: &AppState, a: &Account) -> serde_json::Value {
    serde_json::json!({
        "status": a.status,
        "contact": a.contact,
        "orders": format!("{}/acme/acct/{}/orders", state.cfg.base_url, a.id),
    })
}

fn order_json(state: &AppState, o: &Order) -> serde_json::Value {
    let b = &state.cfg.base_url;
    let mut v = serde_json::json!({
        "status": o.status,
        "expires": rfc3339(o.expires),
        "identifiers": o.identifiers,
        "authorizations": o.authzs.iter().map(|a| format!("{b}/acme/authz/{}", a.id)).collect::<Vec<_>>(),
        "finalize": format!("{b}/acme/order/{}/finalize", o.id),
    });
    if let Some(serial) = &o.serial {
        v["certificate"] = serde_json::json!(format!("{b}/acme/cert/{serial}"));
    }
    if let Some(e) = &o.error {
        v["error"] =
            serde_json::json!({ "type": "urn:ietf:params:acme:error:badCSR", "detail": e });
    }
    v
}

fn challenge_json(state: &AppState, a: &Authz) -> serde_json::Value {
    serde_json::json!({
        "type": "fips-peer-01",
        "url": format!("{}/acme/chall/{}", state.cfg.base_url, a.challenge_id),
        "status": "valid",
        "validated": rfc3339(a.validated_at),
        "token": a.token,
    })
}

fn authz_json(state: &AppState, a: &Authz) -> serde_json::Value {
    serde_json::json!({
        "identifier": a.identifier,
        "status": "valid",
        "expires": rfc3339(a.expires),
        "challenges": [challenge_json(state, a)],
    })
}

fn peer_of(req_ext: &axum::http::Extensions) -> Result<Npub, Problem> {
    req_ext
        .get::<PeerKey>()
        .map(|p| p.0)
        .ok_or_else(|| Problem::new(ErrorType::ServerInternal, "no peer"))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct NewAccountPayload {
    contact: Vec<String>,
    terms_of_service_agreed: bool,
    only_return_existing: bool,
}

async fn new_account(State(state): State<Arc<AppState>>, req: axum::extract::Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return Problem::new(ErrorType::Malformed, "body").into_response(),
    };
    let mut inner = state.inner.lock().await;
    let r = (|| {
        let peer = peer_of(&parts.extensions)?;
        let posted = authenticate(&state, &mut inner, peer, &parts.uri, &body, true)?;
        let payload: NewAccountPayload = match posted.payload {
            Some(v) => serde_json::from_value(v)
                .map_err(|e| Problem::new(ErrorType::Malformed, e.to_string()))?,
            None => NewAccountPayload::default(),
        };
        let id = jws::thumbprint(&posted.jwk);
        let url = format!("{}/acme/acct/{id}", state.cfg.base_url);
        if let Some(existing) = &posted.account {
            policy::same_peer(existing, peer)?;
            return Ok(Reply::json(StatusCode::OK, &account_json(&state, existing)).location(url));
        }
        if payload.only_return_existing {
            return Err(Problem::new(
                ErrorType::AccountDoesNotExist,
                "no account for this key",
            ));
        }
        if payload.contact.len() > MAX_CONTACTS {
            return Err(Problem::new(
                ErrorType::Malformed,
                format!("at most {MAX_CONTACTS} contacts"),
            ));
        }
        if let Some(c) = payload.contact.iter().find(|c| !c.starts_with("mailto:")) {
            return Err(Problem::new(
                ErrorType::UnsupportedContact,
                format!("{c}: only mailto: contacts"),
            ));
        }
        let acct = Account {
            id: id.clone(),
            key: posted.jwk.clone(),
            npub: peer,
            status: AccountStatus::Valid,
            contact: payload.contact,
            created_at: now(),
        };
        inner.accounts.push(acct.clone());
        state
            .store
            .save_accounts(&inner.accounts)
            .map_err(|e| internal(&e))?;
        tracing::info!(account = %id, node = %peer, "account created");
        Ok(Reply::json(StatusCode::CREATED, &account_json(&state, &acct)).location(url))
    })();
    finish(&state, &mut inner, r)
}

fn internal(e: &str) -> Problem {
    tracing::error!(error = %e, "state not saved");
    Problem::new(ErrorType::ServerInternal, "state could not be saved")
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AccountUpdate {
    contact: Option<Vec<String>>,
    status: Option<String>,
}

async fn account(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return Problem::new(ErrorType::Malformed, "body").into_response(),
    };
    let mut inner = state.inner.lock().await;
    let r = (|| {
        let peer = peer_of(&parts.extensions)?;
        let posted = authenticate(&state, &mut inner, peer, &parts.uri, &body, false)?;
        let acct = posted
            .account
            .ok_or_else(|| Problem::new(ErrorType::Malformed, "kid"))?;
        if acct.id != id {
            return Err(Problem::new(ErrorType::Unauthorized, "not your account"));
        }
        if let Some(v) = posted.payload {
            let update: AccountUpdate = serde_json::from_value(v)
                .map_err(|e| Problem::new(ErrorType::Malformed, e.to_string()))?;
            let a = inner
                .accounts
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or_else(|| Problem::new(ErrorType::AccountDoesNotExist, "gone"))?;
            if let Some(c) = update.contact {
                if c.len() > MAX_CONTACTS || c.iter().any(|c| !c.starts_with("mailto:")) {
                    return Err(Problem::new(
                        ErrorType::UnsupportedContact,
                        "only mailto: contacts, at most 8",
                    ));
                }
                a.contact = c;
            }
            if update.status.as_deref() == Some("deactivated") {
                a.status = AccountStatus::Deactivated;
                tracing::info!(account = %id, "account deactivated");
            }
            let a = a.clone();
            state
                .store
                .save_accounts(&inner.accounts)
                .map_err(|e| internal(&e))?;
            return Ok(Reply::json(StatusCode::OK, &account_json(&state, &a)));
        }
        Ok(Reply::json(StatusCode::OK, &account_json(&state, &acct)))
    })();
    finish(&state, &mut inner, r)
}

async fn account_orders(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return Problem::new(ErrorType::Malformed, "body").into_response(),
    };
    let mut inner = state.inner.lock().await;
    let r = (|| {
        let peer = peer_of(&parts.extensions)?;
        let posted = authenticate(&state, &mut inner, peer, &parts.uri, &body, false)?;
        let acct = posted
            .account
            .ok_or_else(|| Problem::new(ErrorType::Malformed, "kid"))?;
        if acct.id != id {
            return Err(Problem::new(ErrorType::Unauthorized, "not your account"));
        }
        let urls: Vec<String> = inner
            .orders
            .iter()
            .filter(|o| o.account == id)
            .map(|o| format!("{}/acme/order/{}", state.cfg.base_url, o.id))
            .collect();
        Ok(Reply::json(
            StatusCode::OK,
            &serde_json::json!({ "orders": urls }),
        ))
    })();
    finish(&state, &mut inner, r)
}

#[derive(Deserialize)]
struct RawIdentifier {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

#[derive(Deserialize)]
struct NewOrderPayload {
    identifiers: Vec<RawIdentifier>,
}

async fn new_order(State(state): State<Arc<AppState>>, req: axum::extract::Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return Problem::new(ErrorType::Malformed, "body").into_response(),
    };
    let mut inner = state.inner.lock().await;
    // The zone first: it may fetch, and must not hold the request's
    // authentication state meanwhile.
    let zone = inner.zone.get(&state.cfg.ca_domain, now()).await;
    let r = (|| {
        let peer = peer_of(&parts.extensions)?;
        let posted = authenticate(&state, &mut inner, peer, &parts.uri, &body, false)?;
        let acct = posted
            .account
            .ok_or_else(|| Problem::new(ErrorType::Malformed, "kid"))?;
        let payload: NewOrderPayload = serde_json::from_value(
            posted
                .payload
                .ok_or_else(|| Problem::new(ErrorType::Malformed, "no payload"))?,
        )
        .map_err(|e| Problem::new(ErrorType::Malformed, e.to_string()))?;
        let mut ids = Vec::new();
        for raw in payload.identifiers {
            if raw.kind != "dns" {
                return Err(Problem::new(
                    ErrorType::UnsupportedIdentifier,
                    format!("identifier type {} is not supported; only dns", raw.kind),
                ));
            }
            ids.push(Identifier::Dns(raw.value));
        }
        let names = policy::approve(&ids, peer, &state.cfg.ca_domain, zone.as_ref())
            .map_err(|r| policy::rejected(&r))?;
        let t = now();
        let order = Order::new(random_id(), &acct, ids, names, t, random_id);
        let url = format!("{}/acme/order/{}", state.cfg.base_url, order.id);
        let v = order_json(&state, &order);
        inner.orders.retain(|o| !o.is_expired(t));
        inner.orders.push(order);
        state
            .store
            .save_orders(&inner.orders, t)
            .map_err(|e| internal(&e))?;
        Ok(Reply::json(StatusCode::CREATED, &v).location(url))
    })();
    finish(&state, &mut inner, r)
}

/// The order `id` of this account, live.
fn own_order<'a>(inner: &'a Inner, acct: &Account, id: &str) -> Result<&'a Order, Problem> {
    inner
        .orders
        .iter()
        .find(|o| o.id == id && o.account == acct.id)
        .ok_or_else(|| Problem::new(ErrorType::Malformed, "no such order"))
}

async fn order(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return Problem::new(ErrorType::Malformed, "body").into_response(),
    };
    let mut inner = state.inner.lock().await;
    let r = (|| {
        let peer = peer_of(&parts.extensions)?;
        let posted = authenticate(&state, &mut inner, peer, &parts.uri, &body, false)?;
        let acct = posted
            .account
            .ok_or_else(|| Problem::new(ErrorType::Malformed, "kid"))?;
        let o = own_order(&inner, &acct, &id)?;
        Ok(Reply::json(StatusCode::OK, &order_json(&state, o)))
    })();
    finish(&state, &mut inner, r)
}

#[derive(Deserialize)]
struct FinalizePayload {
    csr: String,
}

async fn finalize(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return Problem::new(ErrorType::Malformed, "body").into_response(),
    };
    let mut inner = state.inner.lock().await;
    let r = (|| {
        let peer = peer_of(&parts.extensions)?;
        let posted = authenticate(&state, &mut inner, peer, &parts.uri, &body, false)?;
        let acct = posted
            .account
            .ok_or_else(|| Problem::new(ErrorType::Malformed, "kid"))?;
        let payload: FinalizePayload = serde_json::from_value(
            posted
                .payload
                .ok_or_else(|| Problem::new(ErrorType::Malformed, "no payload"))?,
        )
        .map_err(|e| Problem::new(ErrorType::Malformed, e.to_string()))?;
        let t = now();
        let o = own_order(&inner, &acct, &id)?.clone();
        if o.is_expired(t) {
            return Err(Problem::new(ErrorType::OrderNotReady, "order expired"));
        }
        if o.status != OrderStatus::Ready {
            return Err(Problem::new(
                ErrorType::OrderNotReady,
                format!("order is {:?}", o.status),
            ));
        }
        let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&payload.csr)
            .map_err(|_| Problem::new(ErrorType::BadCsr, "csr is not base64url"))?;
        let outcome = (|| -> Result<(x509::Leaf, Vec<String>), Problem> {
            let (csr, facts) = x509::inspect_csr(&der)?;
            policy::csr_matches(&o.names, &facts.sans, facts.cn.as_deref())?;
            let leaf = x509::issue(
                &state.root,
                csr,
                &o.names,
                t,
                state.cfg.leaf_validity_secs,
                x509::random_serial(),
            )
            .map_err(|e| Problem::new(ErrorType::ServerInternal, e.to_string()))?;
            Ok((leaf, o.names.clone()))
        })();
        let idx = inner
            .orders
            .iter()
            .position(|x| x.id == id)
            .ok_or_else(|| Problem::new(ErrorType::Malformed, "no such order"))?;
        match outcome {
            Ok((leaf, names)) => {
                // Chain and index first; only then does the order say valid.
                state
                    .store
                    .write_chain(&leaf.serial, &leaf.chain_pem)
                    .map_err(|e| internal(&e))?;
                inner.index.push(CertEntry {
                    serial: leaf.serial.clone(),
                    npub: peer,
                    account: acct.id.clone(),
                    names: names.clone(),
                    not_before: leaf.not_before,
                    not_after: leaf.not_after,
                    revoked: None,
                });
                state
                    .store
                    .save_index(&inner.index)
                    .map_err(|e| internal(&e))?;
                inner.orders[idx].finalize(Ok(leaf.serial.clone()))?;
                state
                    .store
                    .save_orders(&inner.orders, t)
                    .map_err(|e| internal(&e))?;
                tracing::info!(serial = %leaf.serial, node = %peer, names = ?names, "certificate issued");
                Ok(
                    Reply::json(StatusCode::OK, &order_json(&state, &inner.orders[idx]))
                        .location(format!("{}/acme/order/{id}", state.cfg.base_url)),
                )
            }
            Err(p) => {
                let _ = inner.orders[idx].finalize(Err(p.clone()));
                let _ = state.store.save_orders(&inner.orders, t);
                tracing::info!(order = %id, node = %peer, problem = %p, "finalize refused");
                Err(p)
            }
        }
    })();
    finish(&state, &mut inner, r)
}

fn find_authz<'a>(inner: &'a Inner, acct: &Account, id: &str) -> Option<&'a Authz> {
    inner
        .orders
        .iter()
        .filter(|o| o.account == acct.id)
        .flat_map(|o| o.authzs.iter())
        .find(|a| a.id == id)
}

async fn authz(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return Problem::new(ErrorType::Malformed, "body").into_response(),
    };
    let mut inner = state.inner.lock().await;
    let r = (|| {
        let peer = peer_of(&parts.extensions)?;
        let posted = authenticate(&state, &mut inner, peer, &parts.uri, &body, false)?;
        let acct = posted
            .account
            .ok_or_else(|| Problem::new(ErrorType::Malformed, "kid"))?;
        let a = find_authz(&inner, &acct, &id)
            .ok_or_else(|| Problem::new(ErrorType::Malformed, "no such authorization"))?;
        // A deactivation request is acknowledged by returning the
        // authorization: it was valid by construction and expires with
        // its order; nothing else is issued from it.
        Ok(Reply::json(StatusCode::OK, &authz_json(&state, a)))
    })();
    finish(&state, &mut inner, r)
}

async fn challenge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return Problem::new(ErrorType::Malformed, "body").into_response(),
    };
    let mut inner = state.inner.lock().await;
    let r = (|| {
        let peer = peer_of(&parts.extensions)?;
        let posted = authenticate(&state, &mut inner, peer, &parts.uri, &body, false)?;
        let acct = posted
            .account
            .ok_or_else(|| Problem::new(ErrorType::Malformed, "kid"))?;
        let a = inner
            .orders
            .iter()
            .filter(|o| o.account == acct.id)
            .flat_map(|o| o.authzs.iter())
            .find(|a| a.challenge_id == id)
            .ok_or_else(|| Problem::new(ErrorType::Malformed, "no such challenge"))?;
        let mut reply = Reply::json(StatusCode::OK, &challenge_json(&state, a));
        reply.headers.push((
            "link",
            format!("<{}/acme/authz/{}>;rel=\"up\"", state.cfg.base_url, a.id),
        ));
        Ok(reply)
    })();
    finish(&state, &mut inner, r)
}

async fn certificate(
    State(state): State<Arc<AppState>>,
    Path(serial): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return Problem::new(ErrorType::Malformed, "body").into_response(),
    };
    let mut inner = state.inner.lock().await;
    let r = (|| {
        let peer = peer_of(&parts.extensions)?;
        let _ = authenticate(&state, &mut inner, peer, &parts.uri, &body, false)?;
        let entry = inner
            .index
            .iter()
            .find(|e| e.serial == serial)
            .ok_or_else(|| Problem::new(ErrorType::Malformed, "no such certificate"))?;
        if entry.npub != peer {
            return Err(Problem::new(
                ErrorType::Unauthorized,
                "issued to another node",
            ));
        }
        let pem = state.store.read_chain(&serial).map_err(|e| internal(&e))?;
        Ok(Reply {
            status: StatusCode::OK,
            content_type: "application/pem-certificate-chain",
            body: pem.into_bytes(),
            headers: Vec::new(),
        })
    })();
    finish(&state, &mut inner, r)
}

#[derive(Deserialize)]
struct RevokePayload {
    certificate: String,
    #[serde(default)]
    reason: Option<u32>,
}

/// The serial of a DER certificate, as the index spells it (hex, no
/// leading zero bytes).
fn serial_of(der: &[u8]) -> Result<String, Problem> {
    use x509_parser::prelude::*;
    let (_, cert) = parse_x509_certificate(der)
        .map_err(|e| Problem::new(ErrorType::Malformed, format!("certificate: {e}")))?;
    Ok(crate::x509::hex(cert.raw_serial()))
}

fn same_serial(a: &str, b: &str) -> bool {
    a.trim_start_matches("00") == b.trim_start_matches("00")
}

async fn revoke(State(state): State<Arc<AppState>>, req: axum::extract::Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return Problem::new(ErrorType::Malformed, "body").into_response(),
    };
    let mut inner = state.inner.lock().await;
    let r = (|| {
        let peer = peer_of(&parts.extensions)?;
        let posted = authenticate(&state, &mut inner, peer, &parts.uri, &body, true)?;
        if posted.account.is_none() {
            return Err(Problem::new(
                ErrorType::Unauthorized,
                "no account for this key",
            ));
        }
        let payload: RevokePayload = serde_json::from_value(
            posted
                .payload
                .ok_or_else(|| Problem::new(ErrorType::Malformed, "no payload"))?,
        )
        .map_err(|e| Problem::new(ErrorType::Malformed, e.to_string()))?;
        let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&payload.certificate)
            .map_err(|_| Problem::new(ErrorType::Malformed, "certificate is not base64url"))?;
        let serial = serial_of(&der)?;
        let t = now();
        let entry = inner
            .index
            .iter_mut()
            .find(|e| same_serial(&e.serial, &serial))
            .ok_or_else(|| Problem::new(ErrorType::Unauthorized, "not a certificate of this CA"))?;
        policy::may_revoke(entry, peer, payload.reason)?;
        entry.revoked = Some((t, payload.reason.unwrap_or(0)));
        let serial = entry.serial.clone();
        state
            .store
            .save_index(&inner.index)
            .map_err(|e| internal(&e))?;
        tracing::info!(serial = %serial, node = %peer, reason = ?payload.reason, "certificate revoked");
        Ok(Reply {
            status: StatusCode::OK,
            content_type: "application/json",
            body: Vec::new(),
            headers: Vec::new(),
        })
    })();
    finish(&state, &mut inner, r)
}

/// For the CLI's `acme status`: what the tables hold.
pub struct Summary {
    pub accounts: usize,
    pub live_orders: usize,
    pub certificates: usize,
    pub revoked: usize,
}

impl AppState {
    pub async fn summary(&self) -> Summary {
        let inner = self.inner.lock().await;
        let t = now();
        Summary {
            accounts: inner.accounts.len(),
            live_orders: inner.orders.iter().filter(|o| !o.is_expired(t)).count(),
            certificates: inner.index.len(),
            revoked: inner.index.iter().filter(|e| e.revoked.is_some()).count(),
        }
    }
}
