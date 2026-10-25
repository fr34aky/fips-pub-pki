//! Policy core of fips-pub-pki (docs/spec.md, docs/nip.md): the rules by
//! which a key bound to a domain certifies other keys, with no I/O. The
//! issuer binding itself is `pubdom-core`'s (NIP-DB, the `fips-ca` role);
//! this crate adds names, certificates, the sub-issuer scope rule, path
//! validation with revocation and anti-rollback, the verifier's store
//! and the offline bundle.
//!
//! Signature checking is the relay client's job (nostr-sdk verifies on
//! receipt); here we trust `pubkey`, as `pubdom-core` does.

pub mod anchoring;
pub mod bundle;
pub mod cert;
pub mod name;
pub mod path;
pub mod sig;
pub mod store;

pub use anchoring::attesting_witnesses;
pub use bundle::{Bundle, BundleError, MAX_BUNDLE_EVENTS};
pub use cert::{CertError, Certificate, Usage};
pub use name::Name;
pub use path::{
    Anchor, AnchorKind, Anchors, Certs, Ignored, Path, PathError, Resolution, certifies,
};
/// The crate this one builds on, re-exported so consumers use one version.
pub use pubdom_core;
pub use sig::{SigError, Signature, digest};
pub use store::{IssuerMethod, IssuerPin, IssuerStore, MemoryStore, PinChange, SeenKey, Snapshot};

/// Nostr kinds. Placeholders until registered (docs/nip.md).
pub const KIND_CERT: u16 = 37200;
/// A detached signature: a regular event that is never published.
pub const KIND_SIGNATURE: u16 = 9200;

/// The issuer role in a NIP-DB claim and its `_fips-ca` record.
pub const SERVICE_CA: &str = pubdom_core::SERVICE_CA;

/// Certificates in a path from an anchored issuer to the end entity,
/// the end entity included; longer paths are refused (spec §4).
pub const MAX_PATH: usize = 4;
/// What `fips-pubpki ca issue` puts in `expiration` unless told otherwise.
pub const DEFAULT_VALIDITY_SECS: u64 = 90 * 86_400;
/// Events dated further in the future than this are ignored (as NIP-DB).
pub const MAX_FUTURE_SECS: u64 = pubdom_core::MAX_FUTURE_SECS;

/// Limits enforced before anything is cached.
pub const MAX_TAGS: usize = pubdom_core::claim::MAX_TAGS;
pub const MAX_SUBJECTS: usize = 16;
pub const MAX_RELAY_HINTS: usize = 8;
