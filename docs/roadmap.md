# Roadmap

What is done, what is next, what is undecided. The source of truth for
the state of the project; when something is finished or verified it is
recorded here and in [testing.md](testing.md). Dates are absolute.

## Done

- 2026-10-25: the decision and the issuer binding — fips-pub-domains
  PR #29 (the `fips-ca` role, per-role `dnssec` tags, role-aware
  attestations, `sign_event`/`publish_event`/`fetch_raw`).
- 2026-10-25: this repository; [nip.md](nip.md) (NIP-DC) drafted;
  `pubpki_core::Name` and `Certificate` with the sub-issuer scope rule,
  under test; CI as fips-pub-domains.
- 2026-10-25: `pubpki_core::path` — path validation over tables
  (`Anchors`, `Certs`): anchored and certified issuers, nearest `_@E`,
  `pathlen`, `MAX_PATH`, revocation and rollback along the path,
  disputes; thirteen table tests from spec §4 and nip.md.
- 2026-10-25: `pubpki_core::store` (the issuer file's types, pin and
  unpin by strength, floors to and from `Certs`, the trusted-author rule
  that bounds the file) and `pubpki_core::bundle` (sort, per-event
  errors, validation against what is known, what the I/O crate must
  verify); eight tests.
- 2026-10-25: `pubpki_core::sig` and `anchoring`; the `pubpki` crate —
  `Verifier` (relay fetch by `#d`/`#p`, anchoring from claims and
  witnesses, `ensure_anchor`, `resolve`, `names_of`, `verify_bundle`,
  retention and the file), `Config`, `FileStore`, NIP-44, detached
  signatures, the bundle as JSON; tested offline with signed events
  (bare key, pinned issuer with delegation and rollback, witnesses).
- 2026-10-25: `fips-pubpki` — `ca init|issue|issue-ca|renew [--watch]|
  revoke|publish|status`, `issuer add|remove|list`, `resolve`, `names`,
  `verify`, `bundle`, `sign`, `verify-sig`, `encrypt`, `decrypt`,
  `nostr-json`; the issuer side of `pubpki` (`Issuer`, `Issued`,
  `sign_at`, `publish_signed`); the renewal unit; the verifier's file
  keeps trusted certificates; install, issuer, user and how-it-works
  guides. Run end to end offline with a bare-key issuer
  ([testing.md](testing.md) level 1).

## Next, in order

0. **TLS on the mesh (the X.509 bridge)**, decided with the user
   2026-10-26, in four PRs: (1) the protocol pieces — `usage x509`, the
   `x` tag, the reserved name `_x509@<domain>`, the unknown-usage rule
   — **done**; (2) the `pubpki-acme` crate: JWS, allowlist and
   identifier policy, the X.509 root and issuing, the zone reader, the
   state store — **done**; (3) the ACME server listening on the CA node's fips
   address, the mesh connection as the proof, an integration test with
   a real ACME client on loopback; (4) `fips-pubpki acme init|serve|
   allow|deny|list|status`, `fips-pubpki trust`, the unit, `docs/acme.md`
   and the other guides.

1. **Live** (each on the user's word): a `_fips-ca` record for the demo
   domain and an issuer claim with its chain; certificates on the mesh
   relay; an offline verification on the second node with no Internet;
   a bare-key issuer with no domain.
2. **Phone**: `name@domain` in fips2go's contacts with its own issuer
   pins; no sign/encrypt tooling in the resolver.
3. **Registration and the NIP**: kind numbers and the NIP-DC submission,
   on the user's word, after the reference implementation.

## Later

- **Enrolment requests** (ACME's model, over Nostr and fips only): a
  signed request event from the subject — proof of key possession, as
  ACME's key authorization — naming the wanted `d` and keys, gift-wrapped
  (NIP-59) to the issuer; the issuer applies policy (renewal of a live,
  unrevoked certificate is mechanical; first issuance stays the domain
  owner's decision, there being no HTTP-01 analogue for a person's key)
  and publishes. A request kind as a section of NIP-DC, after path
  validation ships. The `relay` hints already give the reply path.

## Open questions

- Whether `fips-pubdom-server` should publish the domain's `fips-ca`
  claim on the issuer's behalf, or the issuer tooling alone; today
  `ca publish` does it once, and nothing refreshes the chain in the
  claim before its RRSIGs expire (a `--watch` for the claim, or the
  domain server's loop).
- A release workflow and archives, as fips-pub-domains has; until
  then [install.md](install.md) builds from source.
- Whether `nostr.json` emission belongs in the CLI or in the domain
  server's web root.
- Multi-recipient encryption: leave to applications (NIP-59) or offer a
  helper.
