# CLAUDE.md

Guidance for Claude Code in this repository.

## What this is

`fips-pub-pki`: a decentralized PKI on top of fips public domains — an
issuer key bound to `example.org` (or a bare key on the mesh) certifies
`alice@example.org`, the domain's services, and sub-issuers for names
under part of the domain; certificates are Nostr events verifiable
offline. Read [README.md](README.md) first, then [docs/nip.md](docs/nip.md)
(the protocol), [docs/spec.md](docs/spec.md) (how this implementation
applies it) and [docs/architecture.md](docs/architecture.md) (the code).
[docs/design-history.md](docs/design-history.md) records the decisions
and what was rejected; do not re-litigate them without new information.

The repository **depends on** [fips-pub-domains](https://github.com/fr34aky/fips-pub-domains)
(`~/fips-pub-domains`): `pubdom-core` and `pubdom-resolve` are pinned by
commit in `Cargo.toml`, as fips2go pins them. The issuer binding (NIP-DB,
the `fips-ca` role), the DNSSEC proof, the TXT verifier and the relay
client live there and are not duplicated here. A change they need goes
as a PR to that repository first; then the pins are bumped here. Nothing
of this repository moves into fips-pub-domains, fips2go or fips.

## Working rules

- Public repo `fr34aky/fips-pub-pki`. Commit and push only as
  `fr34aky <162515565+fr34aky@users.noreply.github.com>`.
- **No Claude attribution anywhere**: no `Co-Authored-By: Claude`, no
  `Claude-Session:` trailer, no claude.ai links, no "Generated with Claude
  Code" in commits or PR bodies.
- Commit messages explain *why*, as in fips-pub-domains.
  [CONTRIBUTING.md](CONTRIBUTING.md) and [PR-REVIEW.md](PR-REVIEW.md) are
  the rules for PRs and reviews; every user-visible change gets a line
  under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
- Releases: bump `version` in `[workspace.package]`, annotated tag
  `vX.Y.Z` on `main`. Never tag without the user asking.
- Nothing gets published outside this repository without the user saying
  so: no kind registration, no NIP submission, no DNS record for the demo
  domain, no certificate on a public relay.
- No `cfg(target_os)` in `pubpki-core` or `pubpki` (CI enforces).
- `cargo test --workspace` must stay green; the policy tests in
  `pubpki-core` are the place to add a case before changing behaviour.
- **Every PR gets one code review before it merges** (`/code-review high`
  on the branch). Real bugs it finds are fixed on the branch; everything
  else — polish, docs, deliberate trade-offs, pre-existing issues — is
  listed in the PR body as deferred or declined. Then merge when the
  checks are green and the PR head is the pushed commit. No
  review-fix-review loop.

## Layout

```
crates/pubpki-core   policy, no I/O: names, certificates, scope, path validation
crates/pubpki        I/O through pubdom-resolve; NIP-44
crates/pubpki-acme    the ACME server for TLS on the mesh (desktop only, not portable-checked)
crates/pubpki-cli    fips-pubpki
docs/                nip, spec, architecture, design-history, roadmap, testing
```

Config `/etc/fips-pubpki/`, issuer pins `/var/lib/fips-pubpki/issuers.json`
(its own file: the fips-pubdom pin file is shared with the phone and is
not touched).

## Environment notes

- The demo domain, the serving node and the mesh relay used for live
  tests are private; they are in Claude's memory for the fips-pub-domains
  project, not in any repository. Documents use `example.org`.
- The rustup proxies on the reference machine have no default toolchain;
  use `/usr/bin/cargo`, `/usr/bin/cargo-fmt` and `/usr/bin/cargo-clippy`.

## State and next steps

[docs/roadmap.md](docs/roadmap.md) is the source of truth; keep it and
[docs/testing.md](docs/testing.md) current when something is done or
verified, rather than adding status notes elsewhere.
