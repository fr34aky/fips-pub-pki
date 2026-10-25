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

Day one (2026-10-25). The protocol is drafted in [docs/nip.md](docs/nip.md)
(NIP-DC, Domain Certificates), the issuer binding is live in
fips-pub-domains (its `fips-ca` role), and `pubpki-core` parses names and
certificates with the sub-issuer scope rule under test. Path validation,
revocation, the offline bundle, the CLI and the live tests follow in
[docs/roadmap.md](docs/roadmap.md)'s order.

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
```

## Documents

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
