# Contributing to fips-pub-pki

<!-- markdownlint-disable MD013 -->

fips-pub-pki lets a key bound to a domain certify other keys:
`alice@example.org`, the domain's services, and sub-issuers for names
under part of the domain. Certificates are Nostr events, verified from
the issuer's binding, which
[fips-pub-domains](https://github.com/fr34aky/fips-pub-domains) provides.
The code is cut so that the part that can be wrong is testable without a
network:

- **`pubpki-core`** — the policy, no I/O: names, certificates, the
  sub-issuer scope rule, path validation, revocation, anti-rollback, the
  bundle format. Every rule in [docs/spec.md](docs/spec.md) has a test
  here.
- **`pubpki`** — the I/O: relays, the issuer's proof and keys through
  `pubdom-resolve`, NIP-44.
- **`pubpki-cli`** — `fips-pubpki`, the issuer's and the user's tool.

Three invariants shape every change, and reviewers check them first:

1. **A certificate alone binds nothing.** Its issuer must be anchored
   (a verified NIP-DB `fips-ca` binding, a pinned or configured key) or
   certified by one along a valid path.
2. **The verifier never queries DNS.** The issuer's DNSSEC chain travels
   inside the issuer's claim; pins and witnesses do the rest.
3. **A sub-issuer issues only at or under its own domain.** The scope is
   the `d` of its certificate, never a separate claim.

## Quick start

```bash
git clone https://github.com/fr34aky/fips-pub-pki.git
cd fips-pub-pki
cargo test --workspace      # no network needed
```

Requirements: Rust 1.88 or newer. The pinned `pubdom-*` crates are
fetched from GitHub on the first build.

## Branches

One long-lived branch, `main`. Open PRs against it. Tags mark releases
and [CHANGELOG.md](CHANGELOG.md) records what changed between them.

## Submitting pull requests

### Scope discipline

Every PR makes one logical change. No drive-by reformatting, no unrelated
refactors, no "while I was in there" cleanups outside the change's
footprint.

### Required before opening any PR

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs the same on Linux, macOS and Windows, checks that the two
library crates build for `aarch64-linux-android`, and greps them for
`cfg(target_os)`.

### Self-review against the review checklist

[PR-REVIEW.md](PR-REVIEW.md) is run against every incoming PR, once. Run
your change through it before opening.

### Changes to the protocol

Anything that changes an event's shape or how a certificate is judged
must update [docs/nip.md](docs/nip.md) and [docs/spec.md](docs/spec.md)
in the same PR, add the case to the `pubpki-core` tests *before* the
behaviour changes, and say what a client running the old version does
when it meets the new event.

### Changes that need fips-pub-domains

If the issuer binding, the relay client or the proof code must change,
that is a PR to fips-pub-domains first; this repository then bumps the
`rev` of both `pubdom-*` pins in `Cargo.toml` together.

### Merge mechanics

PRs are squash-merged; the commit message says *why*, in the style of the
existing history.

## Releasing

Changes collect under `[Unreleased]` until the maintainer releases: bump
`version` in `[workspace.package]`, commit, annotated tag `vX.Y.Z` on
`main`, push both. Versions follow Semantic Versioning; all crates share
the workspace version.

## AI coding assistant policy

Use of AI coding assistants in preparing a contribution is welcome. The
contributor does a thorough manual review and editorial pass over the
output before submission: verify the code does what it claims, verify the
documentation matches the behaviour, spot-check the diff, do not include
coding-assistant attribution trailers in commit messages or PR
descriptions, and be ready to discuss the design choices as if you wrote
every line. Submissions that show signs of being unreviewed agent output
will be closed without human review.

## Further reading

- [PR-REVIEW.md](PR-REVIEW.md) — the review checklist.
- [docs/nip.md](docs/nip.md) — the protocol; [docs/architecture.md](docs/architecture.md) — the code.
- [docs/design-history.md](docs/design-history.md) — what was rejected and why.
