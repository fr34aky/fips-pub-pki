# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The repository: workspace of `pubpki-core`, `pubpki` and `pubpki-cli`
  (`fips-pubpki`), on `pubdom-core` and `pubdom-resolve` pinned by
  commit; CI as in fips-pub-domains (fmt, clippy, tests on three
  platforms, the Android check of the library crates).
- `docs/nip.md`: NIP-DC, Domain Certificates — kind 37200, names in the
  NIP-05 grammar, sub-issuers scoped by their `d`, revocation markers,
  the offline bundle, detached signatures as events, NIP-44.
- `pubpki_core::Name` (parsing, the apex `_@domain`, the bare-key
  overlay issuer, the "under a domain" rule) and
  `pubpki_core::Certificate` (parse and build, usages, the sub-issuer
  scope rule `may_issue_for`), under test.
- `pubpki_core::path`: path validation over the verifier's tables —
  `Anchors` (issuers pinned per domain, the `<npub>.fips` overlay rule),
  `Certs` (the newest certificate per issuer and name, the anti-rollback
  floor), `validate`, `resolve` (verified, disputed, refused, unknown)
  and `names_of`; revocation, expiry, rollback and `pathlen` are checked
  on every link and reported with the link's name. `prune_expired` and
  `retain_issuers` bound the tables.
- `pubpki_core::store`: the verifier's file (spec §6) — `IssuerPin` with
  `IssuerMethod` (`pinned` above every verification), `Snapshot` with
  pin and unpin by strength, floors to and from the certificate table,
  anti-rollback for the issuers' claims, and the trusted-author rule that
  keeps strangers' events out of the file; `IssuerStore` and
  `MemoryStore`.
- `pubpki_core::bundle`: the offline bundle (spec §7) — `Bundle` sorts
  certificates, `fips-ca` claims and attestations with the failing
  event's position in the error, validates against what the verifier
  already knows, and lists what the I/O crate must verify to anchor it.
