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

/// The zone, cached: a file by mtime (a `metadata` call per lookup and a
/// read when it changed; the file is small and the server's traffic
/// tiny, so this stays on the request path), relays for `ttl` seconds
/// with a high-water mark, so a relay serving an older record after a
/// newer one was seen cannot roll the policy back.
pub struct ZoneCache {
    source: ZoneSource,
    ttl: u64,
    cached: Option<(u64, Option<ZoneRecord>)>,
    mtime: Option<SystemTime>,
    newest_seen: u64,
}

impl ZoneCache {
    pub fn new(source: ZoneSource, ttl: u64) -> Self {
        Self {
            source,
            ttl,
            cached: None,
            mtime: None,
            newest_seen: 0,
        }
    }

    /// What a relay fetch yielded, folded into the cache with the
    /// high-water mark: the newest record not older than what was seen,
    /// else what was in hand. Separated from the fetch so it is testable.
    fn take_fetched(&mut self, fetched: Vec<ZoneRecord>, now: u64) -> Option<ZoneRecord> {
        let newest = fetched
            .into_iter()
            .filter(|z| z.created_at >= self.newest_seen)
            .max_by_key(|z| z.created_at);
        match newest {
            Some(z) => {
                self.newest_seen = z.created_at;
                self.cached = Some((now, Some(z.clone())));
                Some(z)
            }
            None => {
                let kept = self.cached.as_ref().and_then(|(_, z)| z.clone());
                self.cached = Some((now, kept.clone()));
                kept
            }
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
                        Ok(z) if z.domain == domain => Some(z),
                        Ok(z) => {
                            tracing::error!(path = %path.display(), file_domain = %z.domain, domain, "zone file is for another domain; only .fips names are approved");
                            None
                        }
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
                let mut fetched = Vec::new();
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
                        fetched.push(z);
                    }
                }
                let z = self.take_fetched(fetched, now);
                if z.is_none() {
                    tracing::warn!(
                        domain,
                        "no zone record from the domain's servers; only .fips names are approved"
                    );
                }
                z
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
        std::fs::write(&path, "domain: example.net\nnames:\n  www: self\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(now + std::time::Duration::from_secs(6))
            .unwrap();
        assert!(
            cache.get("example.org", 4).await.is_none(),
            "another domain's zone is not this domain's"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let mut none = ZoneCache::new(ZoneSource::None, 300);
        assert!(none.get("example.org", 1).await.is_none());
    }

    #[test]
    fn relay_records_never_roll_the_zone_back() {
        let rec = |created_at: u64, target: Target| ZoneRecord {
            author: key(9),
            domain: "example.org".into(),
            created_at,
            names: vec![("www".into(), target)],
        };
        let mut cache = ZoneCache::new(ZoneSource::None, 300);
        let v1 = rec(100, Target::Node(key(1)));
        let v2 = rec(200, Target::Node(key(2)));
        assert_eq!(
            cache
                .take_fetched(vec![v1.clone(), v2.clone()], 1000)
                .unwrap()
                .lookup("www"),
            Some(key(2))
        );
        // A relay still holding v1 after v2 was seen changes nothing.
        assert_eq!(
            cache
                .take_fetched(vec![v1.clone()], 1400)
                .unwrap()
                .lookup("www"),
            Some(key(2))
        );
        assert_eq!(
            cache.take_fetched(vec![], 1800).unwrap().lookup("www"),
            Some(key(2)),
            "nothing fetched: what is in hand stays"
        );
        let v3 = rec(300, Target::Legacy);
        assert_eq!(
            cache
                .take_fetched(vec![v1, v3], 2200)
                .unwrap()
                .lookup("www"),
            None
        );
    }
}
