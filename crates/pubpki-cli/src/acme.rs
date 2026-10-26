//! `fips-pubpki acme …` and `fips-pubpki trust` (docs/acme.md): the
//! issuer's side of TLS on the mesh, and the client's.

use crate::{
    in_days, open_issuer, parse_npub, print_path, record_and_publish, write_out, write_secret,
};
use anyhow::{Context, Result, anyhow, bail};
use clap::Subcommand;
use pubpki::pubdom_resolve::RelayClient;
use pubpki::pubdom_resolve::txt::TxtVerifier;
use pubpki::pubpki_core::Name;
use pubpki::pubpki_core::name::overlay_key;
use pubpki::pubpki_core::pubdom_core::policy::TxtLookup;
use pubpki::pubpki_core::pubdom_core::{Npub, SERVICE_DNS};
use pubpki::{Config, Issuer, Request, Verifier, now};
use pubpki_acme::DEFAULT_PORT;
use pubpki_acme::policy::Allowlist;
use pubpki_acme::server::{AppState, ServeConfig, bind, serve};
use pubpki_acme::store::AcmeStore;
use pubpki_acme::x509::{Root, check_root_content, hex};
use pubpki_acme::zone::{ZoneCache, ZoneSource};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Subcommand, Debug)]
pub enum AcmeCmd {
    /// Create the X.509 root if missing and publish it as the domain's
    /// `_x509@<domain>` statement
    Init {
        /// The CA node's npub (where the ACME server listens)
        #[arg(long)]
        node: Option<String>,
        /// Validity of the statement in days (default: ca_validity_days)
        #[arg(long)]
        days: Option<u64>,
        #[arg(long)]
        no_publish: bool,
    },
    /// Run the ACME server on the node's fips address
    Serve,
    /// Allow a node (by npub) to request certificates
    Allow {
        npub: String,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Withdraw a node
    Deny { npub: String },
    /// The allowed nodes
    List,
    /// The root, the listener, the allowlist, what was issued
    Status,
}

/// The root, when both files exist; neither is "no root yet"; one of
/// the two is a broken installation to say so about, never something to
/// paper over by generating a new root (clients trusted the old one).
fn root_files(cfg: &Config) -> Result<Option<Root>> {
    let (key, cert) = (&cfg.acme_root_key, &cfg.acme_root_cert);
    match (key.exists(), cert.exists()) {
        (false, false) => Ok(None),
        (true, true) => {
            let key_pem =
                std::fs::read_to_string(key).with_context(|| key.display().to_string())?;
            let cert_pem =
                std::fs::read_to_string(cert).with_context(|| cert.display().to_string())?;
            Ok(Some(
                Root::load(&key_pem, &cert_pem).map_err(|e| anyhow!("{}: {e}", cert.display()))?,
            ))
        }
        (have_key, _) => bail!(
            "{} exists but {} does not: restore the missing file, or move both aside to start a new root (every machine that ran `trust` would have to run it again)",
            if have_key {
                key.display()
            } else {
                cert.display()
            },
            if have_key {
                cert.display()
            } else {
                key.display()
            }
        ),
    }
}

fn directory_url(listen: SocketAddr) -> String {
    format!("http://{listen}/directory")
}

fn node_of(cfg: &Config, flag: Option<&str>) -> Result<Npub> {
    match (flag, cfg.acme_node) {
        (Some(s), _) => parse_npub(s),
        (None, Some(n)) => Ok(n),
        (None, None) => bail!(
            "which node runs the ACME server? `--node <npub>` once, or `acme_node:` in the configuration"
        ),
    }
}

pub async fn run(cmd: AcmeCmd, cfg: &Config, json: bool) -> Result<()> {
    match cmd {
        AcmeCmd::Init {
            node,
            days,
            no_publish,
        } => {
            let node = node_of(cfg, node.as_deref())?;
            let (issuer, mut issued) = open_issuer(cfg)?;
            let root = match root_files(cfg)? {
                Some(r) => {
                    eprintln!("root certificate present: {}", cfg.acme_root_cert.display());
                    r
                }
                None => {
                    let (root, key_pem, cert_pem) =
                        Root::generate(&issuer.domain, now(), cfg.acme_root_validity())
                            .map_err(|e| anyhow!("root: {e}"))?;
                    write_secret(&cfg.acme_root_key, key_pem.as_bytes())?;
                    if let Some(dir) = cfg.acme_root_cert.parent() {
                        std::fs::create_dir_all(dir)?;
                    }
                    std::fs::write(&cfg.acme_root_cert, cert_pem)
                        .with_context(|| cfg.acme_root_cert.display().to_string())?;
                    eprintln!(
                        "wrote {} and {}",
                        cfg.acme_root_key.display(),
                        cfg.acme_root_cert.display()
                    );
                    root
                }
            };
            let info = root.info().map_err(|e| anyhow!("{e}"))?;
            let mut req = Request::x509_root(&issuer.domain, vec![node], root.der())
                .ok_or_else(|| anyhow!("{}: not a domain", issuer.domain))?;
            req.validity_secs = days.map(|d| d.max(1) * 86_400).unwrap_or(cfg.ca_validity());
            let mut at = now();
            if let Some(prev) = issued.get(&req.name) {
                let prev = pubpki::pubpki_core::Certificate::parse(&pubpki::core_event(prev))
                    .map_err(|e| {
                        anyhow!("the previous {} on file does not parse: {e}", req.name)
                    })?;
                at = Issuer::after(&prev, at);
            }
            let ev = issuer.issue(&req, at).map_err(anyhow::Error::msg)?;
            let listen = SocketAddr::new(node.fips_address().into(), cfg.acme_port);
            if !json {
                println!("root:       {}", info.subject);
                println!("sha256:     {}", hex(&info.der_sha256));
                println!("expires:    {}", in_days(info.not_after, now()));
                println!("node:       {node}");
                println!("directory:  {}", directory_url(listen));
            }
            record_and_publish(cfg, &mut issued, &[ev], no_publish, json).await?;
            if !json {
                println!(
                    "\nNext: `fips-pubpki acme allow <npub>` for each node that may ask, then\n`systemctl enable --now fips-pubpki-acme` (or `fips-pubpki acme serve`); clients use\n  --server {}\nand `fips-pubpki trust {}` on the machines that should trust the root.",
                    directory_url(listen),
                    issuer.domain
                );
            }
        }
        AcmeCmd::Serve => {
            let (issuer, _) = open_issuer(cfg)?;
            let root = root_files(cfg)?
                .ok_or_else(|| anyhow!("no root certificate; `fips-pubpki acme init` first"))?;
            let listen = cfg.acme_listen_addr().map_err(anyhow::Error::msg)?;
            let mut sc = ServeConfig::new(listen, &issuer.domain);
            sc.peer_override = cfg.acme_peer_override;
            sc.leaf_validity_secs = cfg.acme_validity();
            sc.interface = cfg.acme_interface.clone();
            let zone = zone_source(cfg, &issuer.domain).await?;
            let store = AcmeStore::new(&cfg.acme_state);
            let state =
                Arc::new(AppState::new(sc.clone(), root, store, zone).map_err(anyhow::Error::msg)?);
            let listener = bind(&sc, 60).await.map_err(anyhow::Error::msg)?;
            tracing::info!(listen = %listen, domain = %issuer.domain, "ACME server up");
            eprintln!("listening on {listen}; directory {}", directory_url(listen));
            serve(state, listener, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
            .map_err(anyhow::Error::msg)?;
        }
        AcmeCmd::Allow { npub, note } => {
            let key = parse_npub(&npub)?;
            let store = AcmeStore::new(&cfg.acme_state);
            let (mut allow, _) = store.load_allowlist().map_err(anyhow::Error::msg)?;
            if !allow.allow(key, &note, now()) {
                bail!("{key} is already allowed");
            }
            store.save_allowlist(&allow).map_err(anyhow::Error::msg)?;
            println!("allowed {key} ({})", key.fips_address());
        }
        AcmeCmd::Deny { npub } => {
            let key = parse_npub(&npub)?;
            let store = AcmeStore::new(&cfg.acme_state);
            let (mut allow, _) = store.load_allowlist().map_err(anyhow::Error::msg)?;
            if !allow.deny(&key) {
                bail!("{key} was not allowed");
            }
            store.save_allowlist(&allow).map_err(anyhow::Error::msg)?;
            println!(
                "denied {key}; its certificates run out on their own, or revoke them from the node"
            );
        }
        AcmeCmd::List => {
            let store = AcmeStore::new(&cfg.acme_state);
            let (allow, _) = store.load_allowlist().map_err(anyhow::Error::msg)?;
            print_allowlist(&allow, json)?;
        }
        AcmeCmd::Status => {
            let (issuer, _) = open_issuer(cfg)?;
            if json {
                let store = AcmeStore::new(&cfg.acme_state);
                let (allow, _) = store.load_allowlist().map_err(anyhow::Error::msg)?;
                let index = store.load_index().map_err(anyhow::Error::msg)?;
                let root = root_files(cfg)?
                    .map(|r| r.info())
                    .transpose()
                    .map_err(|e| anyhow!("{e}"))?;
                let listen = cfg.acme_listen_addr().ok();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "domain": issuer.domain,
                        "root": root.map(|i| serde_json::json!({"subject": i.subject, "sha256": hex(&i.der_sha256), "not_after": i.not_after})),
                        "listen": listen,
                        "directory": listen.map(directory_url),
                        "state": cfg.acme_state,
                        "allowed": allow.peers,
                        "certificates": index,
                    }))?
                );
                return Ok(());
            }
            println!("domain:     {}", issuer.domain);
            match root_files(cfg)? {
                Some(root) => {
                    let info = root.info().map_err(|e| anyhow!("{e}"))?;
                    println!("root:       {}", info.subject);
                    println!("sha256:     {}", hex(&info.der_sha256));
                    println!("expires:    {}", in_days(info.not_after, now()));
                }
                None => println!("root:       none (`fips-pubpki acme init`)"),
            }
            match cfg.acme_listen_addr() {
                Ok(l) => {
                    println!("listen:     {l}");
                    println!("directory:  {}", directory_url(l));
                }
                Err(e) => println!("listen:     {e}"),
            }
            println!("state:      {}", cfg.acme_state.display());
            let store = AcmeStore::new(&cfg.acme_state);
            let (allow, _) = store.load_allowlist().map_err(anyhow::Error::msg)?;
            println!("\n{} node(s) allowed:", allow.peers.len());
            print_allowlist(&allow, false)?;
            let index = store.load_index().map_err(anyhow::Error::msg)?;
            let t = now();
            println!(
                "\n{} certificate(s) issued, {} revoked, {} live:",
                index.len(),
                index.iter().filter(|e| e.revoked.is_some()).count(),
                index
                    .iter()
                    .filter(|e| e.revoked.is_none() && t < e.not_after)
                    .count()
            );
            for e in &index {
                println!(
                    "  {}  {:<10} expires {:>6}  {}",
                    &e.serial[..8.min(e.serial.len())],
                    if e.revoked.is_some() {
                        "revoked"
                    } else if t >= e.not_after {
                        "expired"
                    } else {
                        "live"
                    },
                    in_days(e.not_after, t),
                    e.names.join(", ")
                );
            }
        }
    }
    Ok(())
}

fn print_allowlist(allow: &Allowlist, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&allow.peers)?);
    } else {
        for p in &allow.peers {
            println!("  {}  {}  {}", p.npub, p.npub.fips_address(), p.note);
        }
    }
    Ok(())
}

/// Where the zone comes from, in order: the configured file, the
/// server's default zone file, the configured servers' records, the
/// servers the `_fips-dns` record names (the issuer's DNS use, as `ca
/// status --dns`), else none (overlay names only).
async fn zone_source(cfg: &Config, domain: &str) -> Result<ZoneCache> {
    let ttl = cfg.acme_zone_ttl_secs.max(10);
    if overlay_key(domain).is_some() {
        eprintln!("bare-key CA: only <npub>.fips names are issued");
        return Ok(ZoneCache::new(ZoneSource::None, ttl));
    }
    let default = Path::new("/etc/fips-pubdom/zones").join(format!("{domain}.yaml"));
    // An explicit file may be a copy from another node: its `self`
    // entries mean that node, so its author must be named. The server's
    // own default file is served by this node by construction.
    let file = match &cfg.acme_zone_file {
        Some(path) => Some((
            path.clone(),
            cfg.acme_zone_author.ok_or_else(|| {
                anyhow!("acme_zone_file is set: acme_zone_author must name the node that serves that zone (its `self`)")
            })?,
        )),
        None if default.exists() => Some((
            default,
            cfg.acme_zone_author.or(cfg.acme_node).ok_or_else(|| {
                anyhow!("acme_node (or acme_zone_author) is needed to read the zone file as its server")
            })?,
        )),
        None => None,
    };
    if let Some((path, author)) = file {
        eprintln!("zone: {} (as {author})", path.display());
        return Ok(ZoneCache::new(ZoneSource::File { path, author }, ttl));
    }
    let mut servers = cfg.acme_zone_servers.clone();
    if servers.is_empty() {
        // The one DNS question, the issuer's: which nodes serve the
        // domain. A denial means no zone; no answer means try again later
        // (the unit restarts), never a silently narrower policy.
        let v = TxtVerifier::new(&cfg.upstreams, true, cfg.budget()).map_err(anyhow::Error::msg)?;
        match v.lookup_service(SERVICE_DNS, domain).await.0 {
            TxtLookup::Hit { records, .. } => servers = records.iter().map(|r| r.npub).collect(),
            TxtLookup::Miss { .. } => {}
            other => bail!(
                "the _fips-dns record of {domain} could not be looked up ({other:?}); set acme_zone_servers or acme_zone_file, or start again when DNS answers"
            ),
        }
    }
    if servers.is_empty() {
        eprintln!(
            "no zone source (no file, no acme_zone_servers, no _fips-dns record): only <npub>.fips names are issued"
        );
        return Ok(ZoneCache::new(ZoneSource::None, ttl));
    }
    let client = RelayClient::new(&cfg.public_relays, &cfg.mesh_relays, cfg.budget()).await;
    eprintln!(
        "zone: from the relays, records by {}",
        servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(ZoneCache::new(
        ZoneSource::Relays {
            client: Box::new(client),
            servers,
        },
        ttl,
    ))
}

/// `fips-pubpki trust <domain> [--bundle FILE]`: the domain's `_x509`
/// statement, validated through the PKI (from the relays, or from a
/// bundle file handed over by any means), the root inside it checked,
/// the PEM written.
pub async fn trust(
    cfg: &Config,
    domain: &str,
    bundle: Option<&Path>,
    out: Option<&Path>,
    json: bool,
) -> Result<()> {
    let name = Name::x509(domain).ok_or_else(|| anyhow!("{domain}: not a domain"))?;
    let mut v = Verifier::open(cfg.clone())
        .await
        .map_err(anyhow::Error::msg)?;
    let (path, ev) = if let Some(file) = bundle {
        let text = std::fs::read_to_string(file).with_context(|| file.display().to_string())?;
        let events = crate::read_events(&text)?;
        let r = v.verify_bundle(&events, now());
        crate::finish(v).await;
        let path = r.map_err(|e| anyhow!("{}: not verified: {e}", file.display()))?;
        if path.cert().name != name {
            bail!(
                "{}: the bundle is for {}, not {name}",
                file.display(),
                path.cert().name
            );
        }
        (path, events[0].clone())
    } else {
        // One fetch: the events of the validated path, then validation
        // again on exactly those events, so the hash is checked against
        // the certificate the content belongs to.
        let events = v.bundle_for(&name, now()).await;
        let events = match events {
            Ok(e) => e,
            Err(e) => {
                crate::finish(v).await;
                bail!(
                    "{domain}: {e}; with no relay in reach, `--bundle` takes the statement's event from a file"
                );
            }
        };
        let r = v.verify_bundle(&events, now());
        crate::finish(v).await;
        let path = r.map_err(|e| anyhow!("{domain}: the root statement does not verify: {e}"))?;
        let ev = events
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("{name}: the statement's event was not fetched"))?;
        (path, ev)
    };
    let cert = path.cert().clone();
    if !cert.is_x509() {
        bail!("{name}: the certificate is not an X.509 root statement (no usage x509)");
    }
    if ev.created_at.as_secs() != cert.created_at {
        bail!("{name}: the event in hand is not the certificate the path validated");
    }
    let digest = cert.digest.ok_or_else(|| anyhow!("{name}: no digest"))?;
    let (info, pem) = check_root_content(&ev.content, &digest, now())
        .map_err(|e| anyhow!("{name}: the published root is not acceptable: {e}"))?;
    let directories: Vec<String> = cert
        .subjects
        .iter()
        .map(|p| directory_url(SocketAddr::new(p.fips_address().into(), DEFAULT_PORT)))
        .collect();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "domain": domain,
                "subject": info.subject,
                "sha256": hex(&info.der_sha256),
                "not_after": info.not_after,
                "issuer_path": path,
                "directories": directories,
                "pem": pem,
            }))?
        );
        return Ok(());
    }
    eprintln!("{domain}: X.509 root verified through the PKI");
    print_path(&path);
    eprintln!("  root:      {}", info.subject);
    eprintln!("  sha256:    {}", hex(&info.der_sha256));
    eprintln!("  expires:   {}", in_days(info.not_after, now()));
    for d in &directories {
        eprintln!("  ACME:      {d}");
    }
    write_out(out, pem.as_bytes())?;
    if let Some(p) = out {
        eprintln!(
            "wrote {}; install it in the trust store of what should trust {domain}",
            p.display()
        );
    }
    Ok(())
}
