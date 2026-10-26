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
use pubpki::{Config, Issued, Issuer, Request, Verifier, load_keys, now, publish_events};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

mod acme;

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
    /// TLS certificates for services on the mesh: the ACME server
    Acme {
        #[command(subcommand)]
        cmd: acme::AcmeCmd,
    },
    /// Fetch and check a domain's published X.509 root; write the PEM to install
    Trust {
        domain: String,
        /// The statement's event (or a bundle) from a file instead of the relays
        #[arg(long)]
        bundle: Option<PathBuf>,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
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
    /// Renew what is past half its validity (or one name now), and retry what no relay took
    Renew {
        name: Option<String>,
        /// Keep running: renew as certificates come due, hourly at least
        #[arg(long)]
        watch: bool,
        /// Renew everything not revoked, expired included
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
        Cmd::Acme { cmd } => acme::run(cmd, &cfg, cli.json).await?,
        Cmd::Trust {
            domain,
            bundle,
            out,
        } => acme::trust(&cfg, &domain, bundle.as_deref(), out.as_deref(), cli.json).await?,
        Cmd::Ca { cmd } => ca(cmd, &cfg, cli.json).await?,
        Cmd::Issuer { cmd } => {
            let mut v = Verifier::open(cfg.clone())
                .await
                .map_err(anyhow::Error::msg)?;
            let r = match cmd {
                IssuerCmd::Add { domain, npub } => {
                    let key = parse_npub(&npub)?;
                    if v.pin(&domain, key, now()) {
                        println!("pinned {key} for {domain}");
                        Ok(())
                    } else {
                        Err(anyhow!(
                            "{domain}: not pinned (already there, or not a domain)"
                        ))
                    }
                }
                IssuerCmd::Remove { domain, npub } => {
                    let key = parse_npub(&npub)?;
                    if v.unpin(&domain, &key) {
                        println!("forgot {key} for {domain}");
                        Ok(())
                    } else {
                        Err(anyhow!("{domain}: {key} was not pinned"))
                    }
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
                    Ok(())
                }
            };
            // A pin that could not be written is an error, not a warning.
            v.save(now()).map_err(anyhow::Error::msg)?;
            v.shutdown().await;
            r?;
        }
        Cmd::Resolve { name } => {
            let name = parse_name(&name)?;
            let mut v = Verifier::open(cfg.clone())
                .await
                .map_err(anyhow::Error::msg)?;
            let r = v.resolve(&name, now()).await;
            finish(v).await;
            print_resolution(&name, &r, cli.json)?;
            if !matches!(r, Resolution::Verified(_)) {
                std::process::exit(1);
            }
        }
        Cmd::Names { npub } => {
            let key = parse_npub(&npub)?;
            let mut v = Verifier::open(cfg.clone())
                .await
                .map_err(anyhow::Error::msg)?;
            let paths = v.names_of(&key, now()).await;
            finish(v).await;
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
            // What was learnt (a marker above all) is saved whether or not
            // the path held, and before anything is printed.
            finish(v).await;
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
            finish(v).await;
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
            finish(v).await;
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
            finish(v).await;
            let path = match r {
                Resolution::Verified(p) => p,
                other => {
                    print_resolution(&name, &other, false)?;
                    bail!("{name}: not resolved to a key");
                }
            };
            if name.is_reserved() && !name.is_apex() {
                bail!("{name}: a reserved name is the domain's statement, not someone to write to");
            }
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

/// Save what a user command learnt and close the relays, before the
/// answer is printed (a closed pipe must not cost what was learnt). A
/// file that cannot be written (a plain user with the system default
/// path) is a warning, not a lost answer.
pub(crate) async fn finish(mut v: Verifier) {
    if let Err(e) = v.save(now()) {
        eprintln!("warning: not saved: {e} (set `issuers:` to a writable path)");
    }
    v.shutdown().await;
}

async fn ca(cmd: CaCmd, cfg: &Config, json: bool) -> Result<()> {
    match cmd {
        CaCmd::Init { domain } => {
            let keys = if cfg.ca_key.exists() {
                load_keys(&cfg.ca_key.display().to_string()).map_err(anyhow::Error::msg)?
            } else {
                let keys = Keys::generate();
                write_secret(
                    &cfg.ca_key,
                    format!("{}\n", keys.secret_key().to_secret_hex()).as_bytes(),
                )?;
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
            // Dated after whatever the name had before (a marker, an expired
            // certificate), or relays and verifiers would keep the old one.
            let mut at = now();
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
                at = Issuer::after(&prev, at);
            }
            let ev = issuer.issue(&req, at).map_err(anyhow::Error::msg)?;
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
            let mut at = now();
            if let Some(prev) = issued.get(&req.name) {
                let prev =
                    Certificate::parse(&pubpki::core_event(prev)).map_err(anyhow::Error::msg)?;
                at = Issuer::after(&prev, at);
            }
            let ev = issuer.issue(&req, at).map_err(anyhow::Error::msg)?;
            record_and_publish(cfg, &mut issued, &[ev], no_publish, json).await?;
        }
        CaCmd::Renew {
            name,
            watch,
            force,
            no_publish,
        } => {
            let (issuer, _) = open_issuer(cfg)?;
            let only = name.map(|n| parse_name(&n)).transpose()?;
            loop {
                // Reloaded every round: the operator's commands write the
                // same file while the loop runs.
                let mut issued = Issued::load(&cfg.ca_issued).map_err(anyhow::Error::msg)?;
                let t = now();
                let due: Vec<Event> = issued
                    .certificates()
                    .into_iter()
                    .filter(|(c, _)| c.revoked.is_none() && c.issuer == issuer.npub())
                    .filter(|(c, _)| match &only {
                        Some(n) => &c.name == n,
                        None => force || renewable(c, t),
                    })
                    .map(|(_, ev)| ev.clone())
                    .collect();
                if let Some(n) = &only
                    && due.is_empty()
                {
                    bail!("{n}: nothing live to renew");
                }
                let mut events = Vec::new();
                for ev in &due {
                    events.push(issuer.renew(ev, t).map_err(anyhow::Error::msg)?);
                }
                let r = if !events.is_empty() {
                    record_and_publish(cfg, &mut issued, &events, no_publish, json).await
                } else if !no_publish && !issued.pending(t).is_empty() {
                    publish_pending(cfg, &mut issued).await
                } else {
                    if !watch {
                        eprintln!("nothing due");
                    }
                    Ok(())
                };
                if !watch || only.is_some() {
                    return r;
                }
                if let Err(e) = r {
                    // Not fatal in the loop: what reached no relay stays
                    // pending and is retried next round.
                    tracing::warn!(error = %e, "renewal round incomplete");
                }
                let next = issued
                    .certificates()
                    .into_iter()
                    .map(|(c, _)| c)
                    .filter(|c| c.revoked.is_none() && now() < c.expiration)
                    .map(|c| halfway(&c))
                    .min()
                    .unwrap_or(now() + 3600);
                let wait = next.saturating_sub(now()).clamp(60, 3600);
                tracing::info!(seconds = wait, "next renewal check");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
                    _ = tokio::signal::ctrl_c() => return Ok(()),
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
                .revoke(ev, &reason, now())
                .map_err(anyhow::Error::msg)?;
            record_and_publish(cfg, &mut issued, &[marker], no_publish, json).await?;
        }
        CaCmd::Publish {
            claim_only,
            certs_only,
            require_chain,
        } => {
            let (issuer, mut issued) = open_issuer(cfg)?;
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
            let failed = publish(cfg, &events, &mut issued).await?;
            issued.save(&cfg.ca_issued).map_err(anyhow::Error::msg)?;
            if failed > 0 {
                bail!(
                    "{failed} event(s) reached no relay; `ca publish` or the renewal loop retries"
                );
            }
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
            let pending = issued.pending(t).len();
            println!(
                "\n{} event(s) issued{}:",
                certs.len(),
                if pending > 0 {
                    format!(", {pending} not yet on any relay")
                } else {
                    String::new()
                }
            );
            for (c, ev) in certs {
                let state = if c.revoked.is_some() {
                    "revoked"
                } else if t >= c.expiration {
                    "expired"
                } else if is_due(&c, t) {
                    "due for renewal"
                } else {
                    "live"
                };
                let usages = usages_of(&c);
                println!(
                    "  {:<40} {:<16} expires {:>8}  {} key(s) {}{}",
                    c.name.to_string(),
                    state,
                    in_days(c.expiration, t),
                    c.subjects.len(),
                    usages.join(","),
                    if issued.unpublished.contains(&ev.id.to_hex()) {
                        "  (unpublished)"
                    } else {
                        ""
                    }
                );
            }
        }
    }
    Ok(())
}

/// Every usage, the unknown ones included, so an operator sees why a
/// certificate allows nothing.
fn usages_of(c: &Certificate) -> Vec<String> {
    c.usages
        .iter()
        .map(|u| u.to_string())
        .chain(c.other_usages.iter().cloned())
        .collect()
}

fn halfway(c: &Certificate) -> u64 {
    c.created_at + (c.expiration.saturating_sub(c.created_at)) / 2
}

/// Past half its validity and not yet expired.
fn is_due(c: &Certificate, now: u64) -> bool {
    now < c.expiration && now >= halfway(c)
}

/// What the loop and a plain `renew` take on: due, or expired for less
/// than its own validity (the node was down over the expiry). Expired
/// for longer is abandoned on purpose; `--force` or `issue` revives it.
fn renewable(c: &Certificate, now: u64) -> bool {
    let length = c.expiration.saturating_sub(c.created_at);
    is_due(c, now) || (now >= c.expiration && now < c.expiration + length)
}

pub(crate) fn in_days(at: u64, now: u64) -> String {
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

pub(crate) fn open_issuer(cfg: &Config) -> Result<(Issuer, Issued)> {
    let keys = load_keys(&cfg.ca_key.display().to_string())
        .map_err(|e| anyhow!("{e}; `fips-pubpki ca init` creates the key"))?;
    let issuer = Issuer::new(keys, cfg.ca_domain.as_deref()).map_err(anyhow::Error::msg)?;
    let issued = Issued::load(&cfg.ca_issued).map_err(anyhow::Error::msg)?;
    Ok((issuer, issued))
}

/// Record the events (refusing one the file would not take), save, print,
/// publish what is pending.
pub(crate) async fn record_and_publish(
    cfg: &Config,
    issued: &mut Issued,
    events: &[Event],
    no_publish: bool,
    json: bool,
) -> Result<()> {
    for ev in events {
        if !issued.put(ev.clone()) {
            bail!(
                "{}: not newer than what is on file; nothing recorded",
                Issued::d_of(ev).unwrap_or_default()
            );
        }
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
        eprintln!(
            "not published (--no-publish); `fips-pubpki ca publish --certs-only` or the renewal loop will"
        );
        return Ok(());
    }
    publish_pending(cfg, issued).await
}

/// Publish every pending event, mark what a relay accepted, save.
async fn publish_pending(cfg: &Config, issued: &mut Issued) -> Result<()> {
    let pending = issued.pending(now());
    if pending.is_empty() {
        return Ok(());
    }
    let failed = publish(cfg, &pending, issued).await?;
    issued.save(&cfg.ca_issued).map_err(anyhow::Error::msg)?;
    if failed > 0 {
        bail!("{failed} event(s) reached no relay; `ca publish` or the renewal loop retries");
    }
    Ok(())
}

/// One connection round for all `events`; what a relay accepted is marked
/// published in `issued` (the caller saves). Returns how many reached no
/// relay.
async fn publish(cfg: &Config, events: &[Event], issued: &mut Issued) -> Result<usize> {
    let relays = cfg.ca_relays();
    let results = publish_events(events, &relays, cfg.budget())
        .await
        .map_err(anyhow::Error::msg)?;
    let mut failed = 0;
    for (ev, r) in events.iter().zip(results) {
        let label = format!(
            "kind {} {}",
            ev.kind.as_u16(),
            Issued::d_of(ev).unwrap_or_default()
        );
        match r {
            Ok(o) if !o.none_accepted() => {
                issued.mark_published(&ev.id.to_hex());
                eprintln!(
                    "{label}: accepted by {}{}",
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
            }
            Ok(o) => {
                failed += 1;
                eprintln!(
                    "{label}: no relay accepted it ({})",
                    o.rejected
                        .iter()
                        .map(|(u, why)| format!("{u}: {why}"))
                        .collect::<Vec<_>>()
                        .join("; ")
                );
            }
            Err(e) => {
                failed += 1;
                eprintln!("{label}: {e}");
            }
        }
    }
    Ok(failed)
}

fn user_keys(cfg: &Config) -> Result<Keys> {
    let path = cfg
        .key
        .as_ref()
        .ok_or_else(|| anyhow!("no `key` in the configuration (this user's key file or nsec)"))?;
    load_keys(&path.display().to_string()).map_err(anyhow::Error::msg)
}

/// The key file is created with its final mode: never readable by others,
/// not even for an instant.
/// A secret file (the issuer key, the X.509 root key) created with its
/// final mode: never readable by others, not even for an instant.
pub(crate) fn write_secret(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| path.display().to_string())?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn parse_name(s: &str) -> Result<Name> {
    Name::parse(s).ok_or_else(|| anyhow!("{s}: not a name (local@domain, _@domain for the domain)"))
}

pub(crate) fn parse_npub(s: &str) -> Result<Npub> {
    Npub::parse_any(s).map_err(|e| anyhow!("{s}: {e}"))
}

fn parse_npubs(v: &[String]) -> Result<Vec<Npub>> {
    v.iter().map(|s| parse_npub(s)).collect()
}

pub(crate) fn read_events(text: &str) -> Result<Vec<Event>> {
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

pub(crate) fn write_out(out: Option<&std::path::Path>, bytes: &[u8]) -> Result<()> {
    match out {
        Some(p) => std::fs::write(p, bytes).with_context(|| p.display().to_string()),
        None => {
            std::io::stdout().write_all(bytes)?;
            println!();
            Ok(())
        }
    }
}

pub(crate) fn print_resolution(name: &Name, r: &Resolution, json: bool) -> Result<()> {
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

pub(crate) fn print_path(p: &CertPath) {
    let t = now();
    for (i, c) in p.certs.iter().enumerate() {
        let usages = usages_of(c);
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
