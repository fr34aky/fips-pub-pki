//! The verifier's file (spec §6): `pubpki_core::Snapshot` as pretty JSON,
//! written atomically (temp file + rename) like fips-pubdom's pin file. A
//! missing file is an empty store; a corrupt one is an error, since
//! silently dropping every issuer and floor is the worst outcome.

use pubpki_core::{IssuerStore, Snapshot};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct FileStore {
    path: PathBuf,
    saving: Mutex<()>,
    seq: AtomicU64,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            saving: Mutex::new(()),
            seq: AtomicU64::new(0),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> io::Result<Snapshot> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice::<Snapshot>(&bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", self.path.display()),
                )
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Snapshot::default()),
            Err(e) => Err(e),
        }
    }

    fn write(&self, snap: &Snapshot) -> io::Result<()> {
        let _serialized = self.saving.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .path
            .with_extension(format!("json.{}.{n}.tmp", std::process::id()));
        let bytes = serde_json::to_vec_pretty(snap).map_err(io::Error::other)?;
        let result = std::fs::write(&tmp, bytes).and_then(|_| std::fs::rename(&tmp, &self.path));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}

impl IssuerStore for FileStore {
    fn load(&self) -> Result<Snapshot, String> {
        self.read().map_err(|e| e.to_string())
    }

    fn save(&self, snap: &Snapshot) -> Result<(), String> {
        self.write(snap)
            .map_err(|e| format!("{}: {e}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubpki_core::pubdom_core::Npub;
    use pubpki_core::{IssuerMethod, IssuerPin};

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pubpki-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("sub").join("issuers.json")
    }

    #[test]
    fn missing_is_empty_saved_is_reloaded_corrupt_is_an_error() {
        let path = scratch("rt");
        let store = FileStore::new(&path);
        assert_eq!(store.load().unwrap(), Snapshot::default());
        let mut snap = Snapshot::default();
        snap.pin(IssuerPin {
            domain: "example.org".into(),
            npub: Npub::from_bytes([1; 32]),
            method: IssuerMethod::Pinned,
            verified_at: 1,
        });
        store.save(&snap).unwrap();
        assert_eq!(FileStore::new(&path).load().unwrap(), snap);
        assert!(
            std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")),
            "no temp file left"
        );
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(store.load().is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }
}
