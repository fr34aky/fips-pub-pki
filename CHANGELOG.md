# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `pubpki_acme::server`: the ACME server (RFC 8555) over the crate's
  policy — one listener on the CA node's fips address (bound to the
  interface on Linux), the peer's source address as the proof, an
  allowlist reloaded without a restart, authorizations valid at birth,
  CSR inspection and issuing at finalize, PEM chains, revocation; driven
  end to end by a real ACME client (instant-acme) in the test suite.
- The `pubpki-acme` crate (desktop only): the policy and crypto of the
  ACME server — the flattened-JWS verifier (ES256, RS256,
  EdDSA, RFC 7638 thumbprints), the allowlist and the peer-address
  table, identifier approval against the domain's zone record, the
  order, account and revocation rules, the nonce pool, the P-256 root
  and leaf issuing with rcgen, the root check for `trust`, the zone-file
  reader and relay fetch, the state directory.
- Protocol: `usage x509` and the `x` tag (the content's SHA-256) for the
  domain's X.509 root statement under the reserved name
  `_x509@<domain>`; local parts starting with `_` are reserved
  (`Name::is_reserved`, `Name::x509`, `Certificate::is_x509`,
  `Certificate::digest`); `Request::x509_root` builds it, `root_digest`
  computes the tag from the content. Groundwork for the ACME server
  (docs/roadmap.md).

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
- `pubpki_core::sig` (detached signatures: the `x`/`m`/`size` tags and
  the match against the data) and `pubpki_core::anchoring`
  (`attesting_witnesses`, the witness-counting rule).
- The `pubpki` crate: `Verifier` (certificates from relays by name or
  key, issuers anchored from their claims' chains or from `k` witnesses,
  delegations followed by `#p`, `resolve`, `names_of`, offline bundle
  verification, retention and the issuers file), `Config`
  (`/etc/fips-pubpki/config.yaml`), `FileStore`, NIP-44 `encrypt`/
  `decrypt`, `sign_detached`/`verify_detached`, the bundle as JSON with
  every signature checked.
- `fips-pubpki`, the binary: `ca init|issue|issue-ca|renew [--watch]|
  revoke|publish|status [--dns]`, `issuer add|remove|list`, `resolve`,
  `names`, `verify <file>`, `bundle`, `sign`, `verify-sig`, `encrypt`,
  `decrypt`, `nostr-json`, `config`; `packaging/systemd/fips-pubpki-ca.service`
  for the renewal loop.
- `pubpki::issuer`: `Issuer` (issue from a `Request`, renew and revoke
  dated after what they replace, the claim with its chain, nostr.json),
  `Issued` (the issued file), `sign_at` (explicit timestamp, self-tagging
  allowed), `publish_signed`; `Verifier::bundle_for`; the `ca_*` and
  `upstreams` configuration keys.
- The verifier's file keeps the trusted issuers' newest certificates and
  markers (`certs`), so a name verified once resolves offline and a
  revocation seen once is refused after a restart; a bundle's
  certificates are learnt before validation, so a marker arriving in a
  failing bundle counts.
- Documentation: `docs/how-it-works.md`, `docs/install.md`,
  `docs/issuer.md`, `docs/users.md`.

### Changed

- A `usage` value the client does not know is kept
  (`Certificate::other_usages`) and counts as a usage: a certificate
  whose usages are all unknown allows nothing, instead of being read as
  a plain sign+encrypt key. Only a certificate with no `usage` tag at
  all implies `sign` and `encrypt`. `Issuer::renew` and `revoke` take
  the event and carry its content. A reserved name other than the apex
  is never a person: `names_of` does not list it, `nostr-json` does not
  emit it, `encrypt` refuses it. `ca status` and `resolve` print unknown
  usages too.
