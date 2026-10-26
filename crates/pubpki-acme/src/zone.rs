//! Where a human-readable name is bound to a node key: fips-pub-domains's
//! zone record (kind 37199), read from the operator's zone file (the
//! pubdom-server format) or fetched from the relays as published by the
//! domain's servers. The legacy DNS has nothing to say about it.

use pubpki::pubdom_resolve::RelayClient;
use pubpki::pubdom_resolve::relay::RelayScope;
use pubpki_core::pubdom_core::claim::{Target, ZoneRecord};
use pubpki_core::pubdom_core::domain::{is_claimable, is_valid_zone_label, normalize};
use pubpki_core::pubdom_core::{MAX_FUTURE_SECS, Npub};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::SystemTime;

/// `/etc/fips-pubdom/zones/<domain>.yaml` as fips-pubdom-server reads it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneFile {
    domain: String,
    #[serde(default)]
    #[allow(dead_code)]
    port: Option<u16>,
    #[serde(default)]
    names: BTreeMap<String, String>,
}

/// Parse a zone file; `author` is the node that serves it (`self`).
/// Mirrors the server's private parser (a few lines; the server crate
/// has no library).
pub fn parse_zone_file(text: &str, author: Npub) -> Result<ZoneRecord, String> {
    let zf: ZoneFile = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    let domain = normalize(&zf.domain).ok_or_else(|| format!("{}: invalid domain", zf.domain))?;
    if !is_claimable(&domain) {
        return Err(format!("{domain}: a public suffix or not registrable"));
    }
    let mut names = Vec::new();
    for (name, target) in &zf.names {
        let name = name.to_ascii_lowercase();
        if name != "@" && !is_valid_zone_label(&name) {
            return Err(format!("invalid label {name:?}"));
        }
        let target = match target.as_str() {
            "self" => Target::Author,
            "legacy" => Target::Legacy,
            s => Target::Node(Npub::parse_any(s).map_err(|e| format!("{name}: {e}"))?),
        };
        names.push((name, target));
    }
    Ok(ZoneRecord {
        author,
        domain,
        created_at: 0,
        names,
    })
}

/// Where the zone comes from.
pub enum ZoneSource {
    /// The operator's zone file, re-read when it changes.
    File { path: PathBuf, author: Npub },
    /// The domain's servers' records on the relays, newest per author.
    Relays {
        client: Box<RelayClient>,
        servers: Vec<Npub>,
    },
    /// No zone: only `<npub>.fips` identifiers are ever approved.
    None,
}

/// The zone, cached: a file by mtime, relays for `ttl` seconds.
pub struct ZoneCache {
    source: ZoneSource,
    ttl: u64,
    cached: Option<(u64, Option<ZoneRecord>)>,
    mtime: Option<SystemTime>,
}

impl ZoneCache {
    pub fn new(source: ZoneSource, ttl: u64) -> Self {
        Self {
            source,
            ttl,
            cached: None,
            mtime: None,
        }
    }

    /// The current zone record for `domain`, or `None` when there is
    /// none (the policy then approves overlay names only).
    pub async fn get(&mut self, domain: &str, now: u64) -> Option<ZoneRecord> {
        match &self.source {
            ZoneSource::None => None,
            ZoneSource::File { path, author } => {
                let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
                if let Some((_, z)) = &self.cached
                    && mtime.is_some()
                    && mtime == self.mtime
                {
                    return z.clone();
                }
                let z = match std::fs::read_to_string(path) {
                    Ok(text) => match parse_zone_file(&text, *author) {
                        Ok(z) => Some(z),
                        Err(e) => {
                            tracing::error!(path = %path.display(), %e, "zone file not parsed; only .fips names are approved");
                            None
                        }
                    },
                    Err(e) => {
                        tracing::error!(path = %path.display(), %e, "zone file not read");
                        None
                    }
                };
                self.mtime = mtime;
                self.cached = Some((now, z.clone()));
                z
            }
            ZoneSource::Relays { client, servers } => {
                if let Some((at, z)) = &self.cached
                    && at + self.ttl > now
                {
                    return z.clone();
                }
                let mut newest: Option<ZoneRecord> = None;
                for server in servers {
                    for ev in client.fetch_zone(domain, server, RelayScope::Offline).await {
                        let Ok(z) = ZoneRecord::parse(&ev) else {
                            continue;
                        };
                        if z.author != *server
                            || z.domain != domain
                            || z.created_at > now + MAX_FUTURE_SECS
                        {
                            continue;
                        }
                        if newest.as_ref().is_none_or(|n| n.created_at < z.created_at) {
                            newest = Some(z);
                        }
                    }
                }
                if newest.is_none() {
                    tracing::warn!(
                        domain,
                        "no zone record from the domain's servers; only .fips names are approved"
                    );
                }
                self.cached = Some((now, newest.clone()));
                newest
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Npub {
        Npub::from_bytes([n; 32])
    }

    #[test]
    fn parses_the_server_s_zone_file_format() {
        let text = format!(
            "domain: Example.org.\nport: 5355\nnames:\n  \"@\": self\n  www: {}\n  mail: legacy\n  \"*\": self\n",
            key(1)
        );
        let z = parse_zone_file(&text, key(9)).unwrap();
        assert_eq!(z.domain, "example.org");
        assert_eq!(z.author, key(9));
        assert_eq!(z.lookup("@"), Some(key(9)));
        assert_eq!(z.lookup("www"), Some(key(1)));
        assert_eq!(z.lookup("mail"), None);
        assert_eq!(z.lookup("anything"), Some(key(9)), "wildcard");
        assert!(
            parse_zone_file("domain: org\nnames: {}\n", key(9)).is_err(),
            "not registrable"
        );
        assert!(parse_zone_file("domain: example.org\nnames:\n  _bad: self\n", key(9)).is_err());
        assert!(parse_zone_file("domain: example.org\nnames:\n  www: nope\n", key(9)).is_err());
        assert!(
            parse_zone_file("domain: example.org\nextra: 1\n", key(9)).is_err(),
            "unknown key"
        );
    }

    #[tokio::test]
    async fn a_zone_file_is_reread_when_it_changes_and_none_means_no_zone() {
        let dir = std::env::temp_dir().join(format!("pubpki-acme-zone-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("example.org.yaml");
        std::fs::write(&path, "domain: example.org\nnames:\n  www: self\n").unwrap();
        let mut cache = ZoneCache::new(
            ZoneSource::File {
                path: path.clone(),
                author: key(9),
            },
            300,
        );
        assert_eq!(
            cache.get("example.org", 1).await.unwrap().lookup("www"),
            Some(key(9))
        );
        std::fs::write(&path, "domain: example.org\nnames:\n  www: legacy\n").unwrap();
        // A changed mtime (or an unchanged one within the same second)
        // either way yields the file's current content.
        let now = std::time::SystemTime::now();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(now + std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            cache.get("example.org", 2).await.unwrap().lookup("www"),
            None
        );
        std::fs::write(&path, "nonsense: [").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(now + std::time::Duration::from_secs(4))
            .unwrap();
        assert!(
            cache.get("example.org", 3).await.is_none(),
            "a broken file approves nothing beyond .fips"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let mut none = ZoneCache::new(ZoneSource::None, 300);
        assert!(none.get("example.org", 1).await.is_none());
    }
}
