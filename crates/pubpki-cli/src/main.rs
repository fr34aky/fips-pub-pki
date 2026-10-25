//! `fips-pubpki`: the issuer's and the user's tool (docs/issuer.md,
//! docs/users.md). Everything it knows comes from
//! `/etc/fips-pubpki/config.yaml`; everything it decides is `pubpki`'s.

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use pubpki::nostr_sdk::{Event, Keys};
use pubpki::pubdom_resolve::proof::{build_chain_any_for, default_upstreams};
use pubpki::pubdom_resolve::txt::TxtVerifier;
use pubpki::pubpki_core::pubdom_core::Npub;
use pubpki::pubpki_core::pubdom_core::policy::TxtLookup;
use pubpki::pubpki_core::{Certificate, Name, Path as CertPath, Resolution, SERVICE_CA, Usage};
use pubpki::{Config, Issued, Issuer, Request, Verifier, load_keys, now, publish_signed};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "fips-pubpki",
    version,
    about = "Certificates for name@domain as Nostr events, anchored in fips public domains"
)]
struct Cli {
    /// Configuration file
    #[arg(long, default_value = "/etc/fips-pubpki/config.yaml", global = true)]
    config: PathBuf,
    /// Machine-readable output where there is one
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Issuer operations
    Ca {
        #[command(subcommand)]
        cmd: CaCmd,
    },
    /// The issuers this machine trusts by hand (the verifier's pins)
    Issuer {
        #[command(subcommand)]
        cmd: IssuerCmd,
    },
    /// Resolve a name@domain to its keys, with the path that proves it
    Resolve { name: String },
    /// The names a key validly holds
    Names { npub: String },
    /// Verify an offline bundle (or a single certificate event) from a file
    Verify { file: PathBuf },
    /// Export the offline bundle for a name
    Bundle {
        name: String,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Sign a file: a detached signature event for its hash
    Sign {
        file: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Media type hint
        #[arg(long)]
        media: Option<String>,
    },
    /// Verify a detached signature and resolve the signer's names
    VerifySig {
        file: PathBuf,
        #[arg(long)]
        sig: PathBuf,
    },
    /// Encrypt a file (or stdin) to a name, NIP-44
    Encrypt { name: String, file: Option<PathBuf> },
    /// Decrypt a NIP-44 payload (file or stdin) sent by a key
    Decrypt {
        #[arg(long)]
        from: String,
        file: Option<PathBuf>,
    },
    /// Emit /.well-known/nostr.json from what this issuer has issued
    NostrJson {
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Print the effective configuration
    Config,
}

#[derive(Subcommand, Debug)]
enum CaCmd {
    /// Create the issuer key if missing and print what to publish
    Init {
        /// The domain to issue for; omitted: a bare key, <npub>.fips
        #[arg(long)]
        domain: Option<String>,
    },
    /// Issue a certificate for a name
    Issue {
        name: String,
        /// Subject key(s): npub or hex; several for several devices
        #[arg(long = "subject", required = true)]
        subjects: Vec<String>,
        /// sign, encrypt (default: both)
        #[arg(long = "usage")]
        usages: Vec<Usage>,
        #[arg(long)]
        days: Option<u64>,
        /// Relay hint(s) where the subject reads
        #[arg(long = "relay")]
        relays: Vec<String>,
        #[arg(long)]
        no_publish: bool,
    },
    /// Issue a sub-issuer certificate (_@domain, usage ca)
    IssueCa {
        domain: String,
        #[arg(long = "subject", required = true)]
        subjects: Vec<String>,
        /// How many further sub-issuer certificates may follow (0: none)
        #[arg(long)]
        pathlen: Option<u32>,
        #[arg(long)]
        days: Option<u64>,
        #[arg(long)]
        no_publish: bool,
    },
    /// Renew what is past half its validity (or one name now)
    Renew {
        name: Option<String>,
        /// Keep running: renew as certificates come due
        #[arg(long)]
        watch: bool,
        /// Renew everything live, due or not
        #[arg(long)]
        force: bool,
        #[arg(long)]
        no_publish: bool,
    },
    /// Publish a revocation marker for a name
    Revoke {
        name: String,
        #[arg(long, default_value = "")]
        reason: String,
        #[arg(long)]
        no_publish: bool,
    },
    /// Publish the issuer's claim (with its DNSSEC chain) and every unexpired event
    Publish {
        #[arg(long)]
        claim_only: bool,
        #[arg(long)]
        certs_only: bool,
        /// Fail instead of publishing a claim without a chain
        #[arg(long)]
        require_chain: bool,
    },
    /// The key, the domain, the record, what is issued
    Status {
        /// Also look the _fips-ca record up in the legacy DNS
        #[arg(long)]
        dns: bool,
    },
}

#[derive(Subcommand, Debug)]
enum IssuerCmd {
    Add { domain: String, npub: String },
    Remove { domain: String, npub: String },
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let cfg = Config::load_or_default(&cli.config).map_err(anyhow::Error::msg)?;
    match cli.cmd {
        Cmd::Config => print!("{}", cfg.render().map_err(anyhow::Error::msg)?),
        Cmd::Ca { cmd } => ca(cmd, &cfg, cli.json).await?,
        Cmd::Issuer { cmd } => {
            let mut v = Verifier::open(cfg.clone())
                .await
                .map_err(anyhow::Error::msg)?;
            match cmd {
                IssuerCmd::Add { domain, npub } => {
                    let key = parse_npub(&npub)?;
                    if v.pin(&domain, key, now()) {
                        println!("pinned {key} for {domain}");
                    } else {
                        bail!("{domain}: not pinned (already there, or not a domain)");
                    }
                }
                IssuerCmd::Remove { domain, npub } => {
                    let key = parse_npub(&npub)?;
                    if !v.unpin(&domain, &key) {
                        bail!("{domain}: {key} was not pinned");
                    }
                    println!("forgot {key} for {domain}");
                }
                IssuerCmd::List => {
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&v.snapshot().issuers)?);
                    } else {
                        for p in &v.snapshot().issuers {
                            println!(
                                "{}\t{}\t{:?}\t{}",
                                p.domain, p.npub, p.method, p.verified_at
                            );
                        }
                    }
                }
            }
            v.save(now()).map_err(anyhow::Error::msg)?;
            v.shutdown().await;
        }
        Cmd::Resolve { name } => {
            let name = parse_name(&name)?;
            let mut v = Verifier::open(cfg.clone())
                .await
                .map_err(anyhow::Error::msg)?;
            let r = v.resolve(&name, now()).await;
            v.save(now()).map_err(anyhow::Error::msg)?;
            v.shutdown().await;
            print_resolution(&name, &r, cli.json)?;
        }
        Cmd::Names { npub } => {
            let key = parse_npub(&npub)?;
            let mut v = Verifier::open(cfg.clone())
                .await
                .map_err(anyhow::Error::msg)?;
            let paths = v.names_of(&key, now()).await;
            v.save(now()).map_err(anyhow::Error::msg)?;
            v.shutdown().await;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&paths)?);
            } else if paths.is_empty() {
                println!("{key}: no valid certificate names this key");
            } else {
                for p in &paths {
                    print_path(p);
                }
            }
        }
        Cmd::Verify { file } => {
            let text =
                std::fs::read_to_string(&file).with_context(|| file.display().to_string())?;
            let events = read_events(&text)?;
            let mut v = Verifier::open(cfg.clone())
                .await
                .map_err(anyhow::Error::msg)?;
            let r = v.verify_bundle(&events, now());
            v.save(now()).map_err(anyhow::Error::msg)?;
            v.shutdown().await;
            let path = r.map_err(|e| anyhow!("{}: not verified: {e}", file.display()))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&path)?);
            } else {
                println!("verified");
                print_path(&path);
            }
        }
        Cmd::Bundle { name, out } => {
            let name = parse_name(&name)?;
            let mut v = Verifier::open(cfg.clone())
                .await
                .map_err(anyhow::Error::msg)?;
            let r = v.bundle_for(&name, now()).await;
            v.save(now()).map_err(anyhow::Error::msg)?;
            v.shutdown().await;
            let events = r.map_err(anyhow::Error::msg)?;
            let json = pubpki::bundle::render(&events).map_err(anyhow::Error::msg)?;
            write_out(out.as_deref(), json.as_bytes())?;
            eprintln!("{} event(s) in the bundle", events.len());
        }
        Cmd::Sign { file, out, media } => {
            let keys = user_keys(&cfg)?;
            let data = std::fs::read(&file).with_context(|| file.display().to_string())?;
            let ev = pubpki::sig::sign_detached(&keys, &data, media.as_deref())
                .map_err(anyhow::Error::msg)?;
            let json = serde_json::to_string_pretty(&ev)?;
            let out = out.unwrap_or_else(|| {
                let mut p = file.clone().into_os_string();
                p.push(".sig.json");
                PathBuf::from(p)
            });
            std::fs::write(&out, json).with_context(|| out.display().to_string())?;
            eprintln!(
                "signed as {}: {}",
                pubpki::crypto::npub_of(&keys),
                out.display()
            );
        }
        Cmd::VerifySig { file, sig } => {
            let data = std::fs::read(&file).with_context(|| file.display().to_string())?;
            let text = std::fs::read_to_string(&sig).with_context(|| sig.display().to_string())?;
            let ev: Event = serde_json::from_str(&text).context("the signature file")?;
            let s = pubpki::sig::verify_detached(&ev, &data).map_err(anyhow::Error::msg)?;
            let mut v = Verifier::open(cfg.clone())
                .await
                .map_err(anyhow::Error::msg)?;
            let names: Vec<CertPath> = v
                .names_of(&s.signer, now())
                .await
                .into_iter()
                .filter(|p| p.cert().allows(Usage::Sign))
                .collect();
            v.save(now()).map_err(anyhow::Error::msg)?;
            v.shutdown().await;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({ "signer": s.signer, "created_at": s.created_at, "names": names })
                );
            } else {
                println!("signature valid; signer {}", s.signer);
                if names.is_empty() {
                    println!("no certificate allowing sign names this key");
                }
                for p in &names {
                    println!("  {}  (issuer {})", p.cert().name, p.anchor.issuer);
                }
            }
        }
        Cmd::Encrypt { name, file } => {
            let keys = user_keys(&cfg)?;
            let name = parse_name(&name)?;
            let data = read_in(file.as_deref())?;
            let mut v = Verifier::open(cfg.clone())
                .await
                .map_err(anyhow::Error::msg)?;
            let r = v.resolve(&name, now()).await;
            v.save(now()).map_err(anyhow::Error::msg)?;
            v.shutdown().await;
            let path = match r {
                Resolution::Verified(p) => p,
                other => {
                    print_resolution(&name, &other, false)?;
                    bail!("{name}: not resolved to a key");
                }
            };
            if !path.cert().allows(Usage::Encrypt) {
                bail!("{name}: the certificate does not allow encrypt");
            }
            let mut out = Vec::new();
            for key in &path.cert().subjects {
                let payload =
                    pubpki::crypto::encrypt(&keys, key, &data).map_err(anyhow::Error::msg)?;
                out.push(serde_json::json!({ "to": key, "payload": payload }));
            }
            if out.len() == 1 && !cli.json {
                println!("{}", out[0]["payload"].as_str().unwrap_or_default());
            } else {
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        }
        Cmd::Decrypt { from, file } => {
            let keys = user_keys(&cfg)?;
            let from = parse_npub(&from)?;
            let payload = String::from_utf8(read_in(file.as_deref())?)?;
            let plain = pubpki::crypto::decrypt(&keys, &from, payload.trim())
                .map_err(anyhow::Error::msg)?;
            std::io::stdout().write_all(&plain)?;
        }
        Cmd::NostrJson { out } => {
            let (issuer, issued) = open_issuer(&cfg)?;
            let json = serde_json::to_string_pretty(&issuer.nostr_json(&issued, now()))?;
            write_out(out.as_deref(), json.as_bytes())?;
        }
    }
    Ok(())
}

async fn ca(cmd: CaCmd, cfg: &Config, json: bool) -> Result<()> {
    match cmd {
        CaCmd::Init { domain } => {
            let keys = if cfg.ca_key.exists() {
                load_keys(&cfg.ca_key.display().to_string()).map_err(anyhow::Error::msg)?
            } else {
                let keys = Keys::generate();
                write_secret(&cfg.ca_key, &keys)?;
                eprintln!("wrote {}", cfg.ca_key.display());
                keys
            };
            let domain = domain.or_else(|| cfg.ca_domain.clone());
            let issuer = Issuer::new(keys, domain.as_deref()).map_err(anyhow::Error::msg)?;
            println!("issuer key: {}", issuer.npub());
            println!("domain:     {}", issuer.domain);
            match issuer.txt_record() {
                Some((owner, text)) => {
                    println!(
                        "\nPublish this record in the legacy DNS, then `fips-pubpki ca publish`:\n"
                    );
                    println!("  {owner}.  TXT  \"{text}\"\n");
                    if cfg.ca_domain.as_deref() != Some(issuer.domain.as_str()) {
                        println!(
                            "and set `ca_domain: {}` in the configuration",
                            issuer.domain
                        );
                    }
                }
                None => println!(
                    "\nA bare-key issuer: no DNS record, no claim. Verifiers pin it with\n  fips-pubpki issuer add {} {}",
                    issuer.domain,
                    issuer.npub()
                ),
            }
        }
        CaCmd::Issue {
            name,
            subjects,
            usages,
            days,
            relays,
            no_publish,
        } => {
            let (issuer, mut issued) = open_issuer(cfg)?;
            let mut req = Request::new(parse_name(&name)?, parse_npubs(&subjects)?);
            req.usages = usages;
            req.validity_secs = days.map(|d| d.max(1) * 86_400).unwrap_or(cfg.ca_validity());
            req.relays = relays;
            if let Some(prev) = issued.get(&req.name) {
                let prev =
                    Certificate::parse(&pubpki::core_event(prev)).map_err(anyhow::Error::msg)?;
                if prev.is_live_at(now()) {
                    bail!(
                        "{} is already issued (expires {}); use `ca renew {}` or `ca revoke` first",
                        req.name,
                        prev.expiration,
                        req.name
                    );
                }
            }
            let ev = issuer.issue(&req, now()).map_err(anyhow::Error::msg)?;
            record_and_publish(cfg, &mut issued, &[ev], no_publish, json).await?;
        }
        CaCmd::IssueCa {
            domain,
            subjects,
            pathlen,
            days,
            no_publish,
        } => {
            let (issuer, mut issued) = open_issuer(cfg)?;
            let name = Name::apex(&domain).ok_or_else(|| anyhow!("{domain}: not a domain"))?;
            let mut req = Request::new(name, parse_npubs(&subjects)?);
            req.usages = vec![Usage::Ca];
            req.pathlen = pathlen;
            req.validity_secs = days.map(|d| d.max(1) * 86_400).unwrap_or(cfg.ca_validity());
            let ev = issuer.issue(&req, now()).map_err(anyhow::Error::msg)?;
            record_and_publish(cfg, &mut issued, &[ev], no_publish, json).await?;
        }
        CaCmd::Renew {
            name,
            watch,
            force,
            no_publish,
        } => {
            let (issuer, mut issued) = open_issuer(cfg)?;
            let only = name.map(|n| parse_name(&n)).transpose()?;
            loop {
                let t = now();
                let due: Vec<Certificate> = issued
                    .certificates()
                    .into_iter()
                    .map(|(c, _)| c)
                    .filter(|c| c.revoked.is_none() && c.issuer == issuer.npub())
                    .filter(|c| match &only {
                        Some(n) => &c.name == n,
                        None => force || is_due(c, t),
                    })
                    .collect();
                if let Some(n) = &only
                    && due.is_empty()
                {
                    bail!("{n}: nothing live to renew");
                }
                let mut events = Vec::new();
                for c in &due {
                    events.push(issuer.renew(c, t).map_err(anyhow::Error::msg)?);
                }
                if !events.is_empty() {
                    record_and_publish(cfg, &mut issued, &events, no_publish, json).await?;
                } else if !watch {
                    eprintln!("nothing due");
                }
                if !watch || only.is_some() {
                    break;
                }
                let next = issued
                    .certificates()
                    .into_iter()
                    .map(|(c, _)| c)
                    .filter(|c| c.revoked.is_none() && now() < c.expiration)
                    .map(halfway)
                    .min()
                    .unwrap_or(now() + 6 * 3600);
                let wait = next.saturating_sub(now()).clamp(60, 6 * 3600);
                tracing::info!(seconds = wait, "next renewal check");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
        }
        CaCmd::Revoke {
            name,
            reason,
            no_publish,
        } => {
            let (issuer, mut issued) = open_issuer(cfg)?;
            let name = parse_name(&name)?;
            let ev = issued
                .get(&name)
                .ok_or_else(|| anyhow!("{name}: never issued here"))?;
            let cert = Certificate::parse(&pubpki::core_event(ev)).map_err(anyhow::Error::msg)?;
            if cert.revoked.is_some() {
                bail!("{name}: already revoked");
            }
            let marker = issuer
                .revoke(&cert, &reason, now())
                .map_err(anyhow::Error::msg)?;
            record_and_publish(cfg, &mut issued, &[marker], no_publish, json).await?;
        }
        CaCmd::Publish {
            claim_only,
            certs_only,
            require_chain,
        } => {
            let (issuer, issued) = open_issuer(cfg)?;
            let mut events = Vec::new();
            if !certs_only && !issuer.is_overlay() {
                let upstreams = if cfg.upstreams.is_empty() {
                    default_upstreams()
                } else {
                    cfg.upstreams.clone()
                };
                let chain = match build_chain_any_for(
                    SERVICE_CA,
                    &issuer.domain,
                    &upstreams,
                    cfg.budget(),
                )
                .await
                {
                    Ok((chain, proven)) => {
                        if proven.records.iter().any(|r| r.npub == issuer.npub()) {
                            eprintln!(
                                "DNSSEC chain for _fips-ca.{} built; it names this key",
                                issuer.domain
                            );
                            Some(chain)
                        } else {
                            let msg = format!(
                                "_fips-ca.{} is signed but does not name {}",
                                issuer.domain,
                                issuer.npub()
                            );
                            if require_chain {
                                bail!("{msg}");
                            }
                            eprintln!("warning: {msg}; publishing the claim without a chain");
                            None
                        }
                    }
                    Err(e) => {
                        if require_chain {
                            bail!("no DNSSEC chain for _fips-ca.{}: {e}", issuer.domain);
                        }
                        eprintln!(
                            "warning: no DNSSEC chain for _fips-ca.{} ({e}); the claim goes out without one, so only witnesses or pins can anchor this issuer",
                            issuer.domain
                        );
                        None
                    }
                };
                events.push(issuer.claim(chain.as_deref()).map_err(anyhow::Error::msg)?);
            }
            if !claim_only {
                let t = now();
                for (c, ev) in issued.certificates() {
                    if t < c.expiration {
                        events.push(ev.clone());
                    }
                }
            }
            if events.is_empty() {
                bail!("nothing to publish");
            }
            publish_all(cfg, &events).await?;
        }
        CaCmd::Status { dns } => {
            let (issuer, issued) = open_issuer(cfg)?;
            println!("issuer key: {}", issuer.npub());
            println!("domain:     {}", issuer.domain);
            println!("key file:   {}", cfg.ca_key.display());
            println!("issued:     {}", cfg.ca_issued.display());
            println!("relays:     {}", cfg.ca_relays().join(", "));
            if let Some((owner, text)) = issuer.txt_record() {
                println!("record:     {owner}.  TXT  \"{text}\"");
                if dns {
                    let v = TxtVerifier::new(&cfg.upstreams, true, cfg.budget())
                        .map_err(anyhow::Error::msg)?;
                    let (lookup, _) = v.lookup_service(SERVICE_CA, &issuer.domain).await;
                    match lookup {
                        TxtLookup::Hit { records, method } => {
                            let named = records.iter().any(|r| r.npub == issuer.npub());
                            println!(
                                "dns:        {} record(s), {:?}; this key {}",
                                records.len(),
                                method,
                                if named { "is named" } else { "is NOT named" }
                            );
                        }
                        TxtLookup::Miss { method } => {
                            println!("dns:        no record ({method:?})")
                        }
                        other => println!("dns:        {other:?}"),
                    }
                }
            } else {
                println!(
                    "record:     none (bare key); verifiers pin {} for {}",
                    issuer.npub(),
                    issuer.domain
                );
            }
            let t = now();
            let certs = issued.certificates();
            println!("\n{} event(s) issued:", certs.len());
            for (c, _) in certs {
                let state = if c.revoked.is_some() {
                    "revoked"
                } else if t >= c.expiration {
                    "expired"
                } else if is_due(&c, t) {
                    "due for renewal"
                } else {
                    "live"
                };
                let usages: Vec<String> = c.usages.iter().map(|u| u.to_string()).collect();
                println!(
                    "  {:<40} {:<16} expires {:>8}  {} key(s) {}",
                    c.name.to_string(),
                    state,
                    in_days(c.expiration, t),
                    c.subjects.len(),
                    usages.join(",")
                );
            }
        }
    }
    Ok(())
}

fn halfway(c: Certificate) -> u64 {
    c.created_at + (c.expiration.saturating_sub(c.created_at)) / 2
}

fn is_due(c: &Certificate, now: u64) -> bool {
    now < c.expiration && now >= halfway(c.clone())
}

fn in_days(at: u64, now: u64) -> String {
    if at <= now {
        return "past".into();
    }
    let secs = at - now;
    if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

fn open_issuer(cfg: &Config) -> Result<(Issuer, Issued)> {
    let keys = load_keys(&cfg.ca_key.display().to_string())
        .map_err(|e| anyhow!("{e}; `fips-pubpki ca init` creates the key"))?;
    let issuer = Issuer::new(keys, cfg.ca_domain.as_deref()).map_err(anyhow::Error::msg)?;
    let issued = Issued::load(&cfg.ca_issued).map_err(anyhow::Error::msg)?;
    Ok((issuer, issued))
}

async fn record_and_publish(
    cfg: &Config,
    issued: &mut Issued,
    events: &[Event],
    no_publish: bool,
    json: bool,
) -> Result<()> {
    for ev in events {
        issued.put(ev.clone());
    }
    issued.save(&cfg.ca_issued).map_err(anyhow::Error::msg)?;
    for ev in events {
        if json {
            println!("{}", serde_json::to_string(ev)?);
        } else if let Ok(c) = Certificate::parse(&pubpki::core_event(ev)) {
            println!(
                "{} {} -> {} key(s), until {}{}",
                if c.revoked.is_some() {
                    "revoked"
                } else {
                    "issued"
                },
                c.name,
                c.subjects.len(),
                c.expiration,
                if c.is_ca() { " (sub-issuer)" } else { "" }
            );
        }
    }
    if no_publish {
        eprintln!("not published (--no-publish); `fips-pubpki ca publish --certs-only` later");
        return Ok(());
    }
    publish_all(cfg, events).await
}

async fn publish_all(cfg: &Config, events: &[Event]) -> Result<()> {
    let relays = cfg.ca_relays();
    let mut failed = 0;
    for ev in events {
        match publish_signed(ev, &relays, cfg.budget()).await {
            Ok(o) => {
                eprintln!(
                    "kind {} {}: accepted by {}{}",
                    ev.kind.as_u16(),
                    d_of(ev),
                    o.accepted.len(),
                    if o.rejected.is_empty() {
                        String::new()
                    } else {
                        format!(
                            ", rejected by {}",
                            o.rejected
                                .iter()
                                .map(|(u, why)| format!("{u} ({why})"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                );
                if o.none_accepted() {
                    failed += 1;
                }
            }
            Err(e) => {
                eprintln!("kind {} {}: {e}", ev.kind.as_u16(), d_of(ev));
                failed += 1;
            }
        }
    }
    if failed > 0 {
        bail!("{failed} event(s) reached no relay; `fips-pubpki ca publish` retries");
    }
    Ok(())
}

fn d_of(ev: &Event) -> String {
    ev.tags
        .iter()
        .map(|t| t.clone().to_vec())
        .find(|t| t.len() >= 2 && t[0] == "d")
        .map(|t| t[1].clone())
        .unwrap_or_default()
}

fn user_keys(cfg: &Config) -> Result<Keys> {
    let path = cfg
        .key
        .as_ref()
        .ok_or_else(|| anyhow!("no `key` in the configuration (this user's key file or nsec)"))?;
    load_keys(&path.display().to_string()).map_err(anyhow::Error::msg)
}

fn write_secret(path: &std::path::Path, keys: &Keys) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
    }
    let hex = keys.secret_key().to_secret_hex();
    std::fs::write(path, format!("{hex}\n")).with_context(|| path.display().to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn parse_name(s: &str) -> Result<Name> {
    Name::parse(s).ok_or_else(|| anyhow!("{s}: not a name (local@domain, _@domain for the domain)"))
}

fn parse_npub(s: &str) -> Result<Npub> {
    Npub::parse_any(s).map_err(|e| anyhow!("{s}: {e}"))
}

fn parse_npubs(v: &[String]) -> Result<Vec<Npub>> {
    v.iter().map(|s| parse_npub(s)).collect()
}

fn read_events(text: &str) -> Result<Vec<Event>> {
    if text.trim_start().starts_with('[') {
        return pubpki::bundle::parse(text).map_err(anyhow::Error::msg);
    }
    let ev: Event = serde_json::from_str(text).context("not a bundle nor an event")?;
    ev.verify().map_err(|e| anyhow!("bad signature: {e}"))?;
    Ok(vec![ev])
}

fn read_in(file: Option<&std::path::Path>) -> Result<Vec<u8>> {
    match file {
        Some(p) => std::fs::read(p).with_context(|| p.display().to_string()),
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn write_out(out: Option<&std::path::Path>, bytes: &[u8]) -> Result<()> {
    match out {
        Some(p) => std::fs::write(p, bytes).with_context(|| p.display().to_string()),
        None => {
            std::io::stdout().write_all(bytes)?;
            println!();
            Ok(())
        }
    }
}

fn print_resolution(name: &Name, r: &Resolution, json: bool) -> Result<()> {
    if json {
        let v = match r {
            Resolution::Verified(p) => serde_json::json!({ "status": "verified", "path": p }),
            Resolution::Disputed(paths) => {
                serde_json::json!({ "status": "disputed", "paths": paths })
            }
            Resolution::Refused(r) => serde_json::json!({
                "status": "refused",
                "certificates": r.iter().map(|(c, e)| serde_json::json!({ "certificate": c, "error": e.to_string() })).collect::<Vec<_>>()
            }),
            Resolution::Unknown => serde_json::json!({ "status": "unknown" }),
        };
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    match r {
        Resolution::Verified(p) => {
            for k in &p.cert().subjects {
                println!("{name} = {k}");
            }
            print_path(p);
        }
        Resolution::Disputed(paths) => {
            println!(
                "{name}: DISPUTED, {} issuers disagree; using none",
                paths.len()
            );
            for p in paths {
                print_path(p);
            }
        }
        Resolution::Refused(list) => {
            println!("{name}: refused");
            for (c, e) in list {
                println!("  issuer {}: {e}", c.issuer);
            }
        }
        Resolution::Unknown => println!("{name}: no certificate found"),
    }
    Ok(())
}

fn print_path(p: &CertPath) {
    let t = now();
    for (i, c) in p.certs.iter().enumerate() {
        let usages: Vec<String> = c.usages.iter().map(|u| u.to_string()).collect();
        println!(
            "  {}{} by {}  expires in {}{}",
            "  ".repeat(i),
            c.name,
            c.issuer,
            in_days(c.expiration, t),
            if usages.is_empty() {
                String::new()
            } else {
                format!("  [{}]", usages.join(","))
            }
        );
    }
    println!(
        "  {}anchor: {} for {} ({:?})",
        "  ".repeat(p.certs.len()),
        p.anchor.issuer,
        p.anchor.domain,
        p.anchor.kind
    );
}
