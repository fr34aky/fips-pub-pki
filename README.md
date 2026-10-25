# fips-pub-pki

A decentralized PKI on top of [fips](https://github.com/jmcorgan/fips)
public domains: the owner of `example.org` certifies that
`alice@example.org` is a given Nostr key, that a service of the domain is
a given key, or that a department's key may certify names under
`sales.example.org`. Certificates are signed Nostr events. They are
verified with nothing but the issuer's binding to the domain — which
[fips-pub-domains](https://github.com/fr34aky/fips-pub-domains) provides
(NIP-DB, the `fips-ca` role), offline from the DNSSEC chain carried in the
issuer's claim — and need no domain at all when the issuer is a bare key
on the mesh.

- **Nostr carries the certificates**, on relays the subjects and their
  correspondents can reach without the Internet.
- **The verifier never queries DNS.** It trusts its own issuer pins, then
  the chain inside the issuer's claim, then configured witnesses on mesh
  relays, and refuses the rest.
- **Sub-issuers are structural.** A sub-issuer certificate is for
  `_@<domain>` with `usage ca`, and its holder may issue only names at or
  under that domain. An offline root certifying an online issuer, or a
  department's key, needs no DNS change.
- **Revocation is short validity plus an explicit marker**, both
  addressable events; nothing depends on a relay honouring a deletion.
- **No X.509, no web PKI.** Signatures are event signatures (never raw
  bytes), encryption is NIP-44.

Not a goal: a global registry of names, TLS certificates, or long-term
validation after expiry.

## Status

2026-10-25: the protocol is drafted in [docs/nip.md](docs/nip.md)
(NIP-DC, Domain Certificates); the issuer binding is live in
fips-pub-domains (its `fips-ca` role); `pubpki-core` has path validation,
revocation, anti-rollback, the store and the bundle under table tests;
`pubpki` fetches, anchors and verifies; `fips-pubpki` issues, renews,
revokes, resolves, verifies bundles, signs and encrypts, and has run end
to end offline with a bare-key issuer. Not yet done: the live tests on
the mesh with a public domain, the phone, kind registration and the NIP
submission ([docs/roadmap.md](docs/roadmap.md)).

## Components

| crate / binary | runs on | does |
|---|---|---|
| `pubpki-core` | everywhere (no I/O) | names, certificates, sub-issuer scope, path validation, revocation, anti-rollback, the bundle format |
| `pubpki` | desktop and phone | relays, issuer proofs and keys through `pubdom-resolve`; NIP-44 |
| `pubpki-cli` → `fips-pubpki` | desktop | `ca init\|issue\|issue-ca\|renew\|revoke\|publish\|status`, `resolve`, `verify`, `sign`, `verify-sig`, `encrypt`, `decrypt`, `bundle`, `nostr-json` |

## Quick start

```bash
git clone https://github.com/fr34aky/fips-pub-pki.git
cd fips-pub-pki
cargo test --workspace      # no network needed
cargo build --release       # target/release/fips-pubpki
```

Then [docs/install.md](docs/install.md) for an issuer or a user machine.
A bare-key issuer needs no domain and no relay to try it out:

```bash
fips-pubpki --config ca.yaml ca init                       # prints <npub>.fips
fips-pubpki --config ca.yaml ca issue alice@<npub>.fips --subject npub1alice… --no-publish
fips-pubpki --config user.yaml verify alice.json           # the event from issued.json
```

## Documents

- [docs/how-it-works.md](docs/how-it-works.md) — from a name to a key,
  every trust step named; what DNS and relays can and cannot do.
- [docs/install.md](docs/install.md) — install, configure, upgrade,
  uninstall; the renewal unit.
- [docs/issuer.md](docs/issuer.md) — running an issuer: key, record,
  claim, issuing, sub-issuers, renewal, revocation, witnesses.
- [docs/users.md](docs/users.md) — resolving, pins, offline bundles,
  signing, encrypting, the file, troubleshooting.
- [docs/nip.md](docs/nip.md) — the protocol as a NIP draft.
- [docs/spec.md](docs/spec.md) — the protocol as this implementation
  applies it: precedence, path validation, storage, the bundle.
- [docs/architecture.md](docs/architecture.md) — the code.
- [docs/design-history.md](docs/design-history.md) — what was decided and
  what was rejected, so it stays rejected.
- [docs/roadmap.md](docs/roadmap.md) and [docs/testing.md](docs/testing.md)
  — state, next steps, the live test ladder.
- [CONTRIBUTING.md](CONTRIBUTING.md), [PR-REVIEW.md](PR-REVIEW.md).

## License

MIT.
