//! `/etc/fips-pubpki/config.yaml`, all keys optional:
//!
//! ```yaml
//! public_relays: ["wss://relay.example.org"]   # asked after the mesh relays
//! mesh_relays: ["ws://npub1….fips:80"]          # by .fips name, as fips-pubdom's
//! issuers: /var/lib/fips-pubpki/issuers.json    # the verifier's file (spec §6)
//! witnesses: ["npub1…"]                         # whose fips-ca attestations count
//! attestation_threshold: 2                      # k; 0 turns attestations off
//! budget_ms: 4500                               # per relay fetch
//! key: /etc/fips/fips.key                       # this user's key: sign, decrypt
//! upstreams: ["9.9.9.9"]                        # the issuer's chain building only; empty: the system's
//! ca_key: /etc/fips-pubpki/ca.key               # the issuer key (`ca init` writes it)
//! ca_domain: example.org                        # null: a bare key, <npub>.fips
//! ca_issued: /var/lib/fips-pubpki/issued.json   # what this issuer has issued
//! ca_relays: []                                 # where it publishes; empty: mesh then public
//! ca_validity_days: 90
//! ```
//!
//! The `ca_*` keys matter to the `ca` commands only; a machine that only
//! resolves never sets them.

use pubpki_core::pubdom_core::Npub;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub public_relays: Vec<String>,
    pub mesh_relays: Vec<String>,
    pub issuers: PathBuf,
    pub witnesses: Vec<Npub>,
    pub attestation_threshold: usize,
    pub budget_ms: u64,
    pub key: Option<PathBuf>,
    pub upstreams: Vec<IpAddr>,
    pub ca_key: PathBuf,
    pub ca_domain: Option<String>,
    pub ca_issued: PathBuf,
    pub ca_relays: Vec<String>,
    pub ca_validity_days: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            public_relays: Vec::new(),
            mesh_relays: Vec::new(),
            issuers: PathBuf::from("/var/lib/fips-pubpki/issuers.json"),
            witnesses: Vec::new(),
            attestation_threshold: 2,
            budget_ms: 4500,
            key: None,
            upstreams: Vec::new(),
            ca_key: PathBuf::from("/etc/fips-pubpki/ca.key"),
            ca_domain: None,
            ca_issued: PathBuf::from("/var/lib/fips-pubpki/issued.json"),
            ca_relays: Vec::new(),
            ca_validity_days: 90,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Unknown keys are errors: a typo must not silently mean a default.
    pub fn parse(text: &str) -> Result<Self, String> {
        serde_yaml::from_str(text).map_err(|e| e.to_string())
    }

    pub fn render(&self) -> Result<String, String> {
        serde_yaml::to_string(self).map_err(|e| e.to_string())
    }

    /// Load if present, defaults otherwise.
    pub fn load_or_default(path: &Path) -> Result<Self, String> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self::default())
        }
    }

    pub fn budget(&self) -> Duration {
        Duration::from_millis(self.budget_ms.max(100))
    }

    /// Where the issuer publishes: its own list, or the mesh relays then
    /// the public ones.
    pub fn ca_relays(&self) -> Vec<String> {
        if !self.ca_relays.is_empty() {
            return self.ca_relays.clone();
        }
        self.mesh_relays
            .iter()
            .chain(self.public_relays.iter())
            .cloned()
            .collect()
    }

    pub fn ca_validity(&self) -> u64 {
        self.ca_validity_days.max(1) * 86_400
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_defaults_and_refuses_typos() {
        let c = Config::parse("").unwrap();
        assert_eq!(c, Config::default());
        assert_eq!(c.attestation_threshold, 2);
        let c = Config::parse(
            "mesh_relays: [\"ws://relay.fips:80\"]\nattestation_threshold: 0\nbudget_ms: 10\n",
        )
        .unwrap();
        assert_eq!(c.mesh_relays, ["ws://relay.fips:80"]);
        assert_eq!(c.budget(), Duration::from_millis(100), "floor");
        assert!(Config::parse("mesh_relay: []").is_err(), "unknown key");
        let back = Config::parse(&c.render().unwrap()).unwrap();
        assert_eq!(back, c);
        assert_eq!(c.ca_relays(), ["ws://relay.fips:80"], "mesh first");
        let c = Config::parse("ca_relays: [\"wss://x\"]\nca_validity_days: 0\n").unwrap();
        assert_eq!(c.ca_relays(), ["wss://x"]);
        assert_eq!(c.ca_validity(), 86_400, "at least a day");
    }
}
