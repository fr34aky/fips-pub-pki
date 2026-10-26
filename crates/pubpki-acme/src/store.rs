//! The ACME state directory, `/var/lib/fips-pubpki/acme/`: the
//! allowlist, accounts, orders, the certificate index and the chains.
//! Plain JSON, written atomically like the verifier's file; nonces
//! live in memory.

use crate::policy::{Account, Allowlist, CertEntry, Order};
use pubpki::store::write_atomic;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub struct AcmeStore {
    dir: PathBuf,
}

fn read_json<T: Default + serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    write_atomic(path, &bytes).map_err(|e| format!("{}: {e}", path.display()))
}

impl AcmeStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn allow_path(&self) -> PathBuf {
        self.dir.join("allow.json")
    }

    /// The allowlist and the file's modification time, so a running
    /// server notices `acme allow` without a restart.
    pub fn load_allowlist(&self) -> Result<(Allowlist, Option<SystemTime>), String> {
        let path = self.allow_path();
        let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        Ok((read_json(&path)?, mtime))
    }

    pub fn allowlist_mtime(&self) -> Option<SystemTime> {
        std::fs::metadata(self.allow_path())
            .and_then(|m| m.modified())
            .ok()
    }

    pub fn save_allowlist(&self, a: &Allowlist) -> Result<(), String> {
        write_json(&self.allow_path(), a)
    }

    pub fn load_accounts(&self) -> Result<Vec<Account>, String> {
        read_json(&self.dir.join("accounts.json"))
    }

    pub fn save_accounts(&self, a: &[Account]) -> Result<(), String> {
        write_json(&self.dir.join("accounts.json"), &a)
    }

    pub fn load_orders(&self) -> Result<Vec<Order>, String> {
        read_json(&self.dir.join("orders.json"))
    }

    /// Expired orders are dropped on the way out.
    pub fn save_orders(&self, orders: &[Order], now: u64) -> Result<(), String> {
        let live: Vec<&Order> = orders.iter().filter(|o| !o.is_expired(now)).collect();
        write_json(&self.dir.join("orders.json"), &live)
    }

    pub fn load_index(&self) -> Result<Vec<CertEntry>, String> {
        read_json(&self.dir.join("certs").join("index.json"))
    }

    pub fn save_index(&self, index: &[CertEntry]) -> Result<(), String> {
        write_json(&self.dir.join("certs").join("index.json"), &index)
    }

    pub fn write_chain(&self, serial: &str, pem: &str) -> Result<(), String> {
        let path = self.chain_path(serial)?;
        write_atomic(&path, pem.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn read_chain(&self, serial: &str) -> Result<String, String> {
        let path = self.chain_path(serial)?;
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn chain_path(&self, serial: &str) -> Result<PathBuf, String> {
        if serial.is_empty() || !serial.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("{serial:?}: not a serial"));
        }
        Ok(self.dir.join("certs").join(format!("{serial}.pem")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AccountStatus, OrderStatus};
    use pubpki_core::pubdom_core::Npub;

    #[test]
    fn every_file_round_trips_and_expired_orders_are_dropped() {
        let dir = std::env::temp_dir().join(format!("pubpki-acme-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = AcmeStore::new(&dir);
        let (empty, mtime) = store.load_allowlist().unwrap();
        assert!(empty.peers.is_empty() && mtime.is_none());
        let mut a = Allowlist::default();
        a.allow(Npub::from_bytes([1; 32]), "web", 1);
        store.save_allowlist(&a).unwrap();
        let (back, mtime) = store.load_allowlist().unwrap();
        assert_eq!(back, a);
        assert!(mtime.is_some());
        let acct = Account {
            id: "t".into(),
            key: crate::jws::Jwk::Okp {
                crv: "Ed25519".into(),
                x: "AA".into(),
            },
            npub: Npub::from_bytes([1; 32]),
            status: AccountStatus::Valid,
            contact: vec!["mailto:ops@example.org".into()],
            created_at: 1,
        };
        store.save_accounts(std::slice::from_ref(&acct)).unwrap();
        assert_eq!(store.load_accounts().unwrap(), vec![acct.clone()]);
        let mut n = 0;
        let fresh = Order::new("o1".into(), &acct, vec![], vec![], 1000, || {
            n += 1;
            n.to_string()
        });
        let mut old = fresh.clone();
        old.id = "o0".into();
        old.expires = 500;
        store.save_orders(&[fresh.clone(), old], 900).unwrap();
        let loaded = store.load_orders().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, OrderStatus::Ready);
        let e = CertEntry {
            serial: "0a".into(),
            npub: acct.npub,
            account: "t".into(),
            names: vec!["www.example.org".into()],
            not_before: 1,
            not_after: 2,
            revoked: None,
        };
        store.save_index(std::slice::from_ref(&e)).unwrap();
        assert_eq!(store.load_index().unwrap(), vec![e]);
        store.write_chain("0a", "PEM").unwrap();
        assert_eq!(store.read_chain("0a").unwrap(), "PEM");
        assert!(
            store.read_chain("../etc/passwd").is_err(),
            "serials are hex"
        );
        assert!(store.read_chain("zz").is_err());
        std::fs::write(dir.join("accounts.json"), b"{").unwrap();
        assert!(
            store.load_accounts().is_err(),
            "a corrupt file is an error, not an empty store"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
