# PR Review Checklist

<!-- markdownlint-disable MD013 -->

The 13-criteria checklist run once against every incoming PR. Run it
yourself before opening; the document is written so it can be handed to
a coding agent with "review my branch against this checklist".

This project tells applications which key *is* `alice@example.org`, and
which keys may say so. A wrong decision here binds a name to a key that
merely claimed it, or lets a department key certify the whole company.
The criteria are weighted accordingly.

## Step 1 — Should this even be reviewed?

Skip (and say so) if the PR is closed, merged or draft; automated and
trivially OK — except a bump of `pubdom-*`, `nostr-sdk`, `hickory-*` or
`psl`, which change what is validated, signed or parsed; or so small that
a one-paragraph informal review is better.

## Step 2 — Gather context

Read before analyzing the diff: the PR metadata and diff (`gh pr view`,
`gh pr diff`); base freshness; [CONTRIBUTING.md](CONTRIBUTING.md); the
sections of [docs/nip.md](docs/nip.md) and [docs/spec.md](docs/spec.md)
the diff touches; [docs/design-history.md](docs/design-history.md) —
rejected ideas come back looking like improvements; and the invariants:
a certificate alone binds nothing; the verifier never queries DNS; a
sub-issuer issues only at or under its own domain; anti-rollback per
(kind, issuer, `d`); a revocation marker outlives what it revokes.

## Step 3 — The 13 criteria

### Group A — PR hygiene

1. **PR body.** Accurate, matches the diff, says how the change was
   exercised (unit tests, an offline bundle, a live issuer on the demo
   domain, the mesh relay, the phone).
2. **Commit hygiene and base freshness.**
3. **Commit message quality.** Subject plus a body that says *why*; no
   coding-assistant attribution trailers.

### Group B — Diff content

4. **Does it do what it says it does.** Each claimed behaviour against
   the diff, each changed decision against the spec section.
5. **Coherent whole.** No drive-by changes.
6. **Fits the codebase.** Policy in `pubpki-core`, I/O in `pubpki`,
   nothing platform-specific in either; the issuer binding, the proof
   and the relay client through `pubdom-*`, never re-implemented; one
   `nostr-sdk`, the one `pubdom-resolve` re-exports.

### Group C — Cross-cutting concerns

7. **New dependency surface.** A stated reason; builds for
   `aarch64-linux-android` if it enters a library crate; no second
   secp256k1 or nostr implementation.
8. **Verification.** A `pubpki-core` test for every policy change; the
   live level the PR reached ([docs/testing.md](docs/testing.md)).
9. **Documentation impact.** `docs/nip.md` and `docs/spec.md` for
   protocol changes, `docs/roadmap.md` when a gap opens or closes, a
   CHANGELOG entry.
10. **Security and the invariants.** Can a certificate be accepted whose
    issuer is neither anchored nor certified along a valid path? Can a
    sub-issuer reach outside its domain, or a non-apex certificate with
    `usage ca` delegate anything? Can an old certificate be accepted by
    a verifier that has seen its revocation or renewal? Does any code
    path query DNS on the verifier's side? Does a raw BIP-340 signature
    over arbitrary bytes ever exist? Is anything but NIP-44 used to
    encrypt? Are private keys ever logged, bundled or published?
    Untrusted input — relay events, bundles — parsed with the size limits.
11. **Rust practices.** No `unwrap` on data from the network; timeouts on
    every I/O; no `cfg(target_os)` in the libraries; errors logged with
    the fields a support request needs (name, issuer, reason).
12. **Overlap with existing work.** Issues, PRs, roadmap items.
13. **Other concerns.** A verifier with no Internet and no pin; a bare-key
    issuer; several issuer keys for one domain; the phone. Compatibility
    of the issuer pin file across upgrades.

## Step 4 — Compose the review

Prose, ordered by what matters most, all 13 criteria addressed without
naming their numbers; a closing disposition: *land*,
*land-with-followups*, *request-changes*, or *hold*.

## Step 5 — Filter aggressively

Do not flag pre-existing issues on untouched lines, anything `cargo fmt`,
`clippy` or the build would catch, pedantic style, or likely intentional
changes. For every issue surfaced, include a concrete fix.

## Step 6 — Citation discipline

Reference code by full-SHA permalink:
`https://github.com/fr34aky/fips-pub-pki/blob/<full-40-char-sha>/<path>#L<start>-L<end>`.
