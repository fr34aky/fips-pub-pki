# Design history

Decisions and what was rejected, so it stays rejected without new
information. Dates are absolute.

## Starting point (2026-10-25)

Asked for a decentralized PKI/CA on fips public domains — a domain owner
announces signing keys, issues, verifies and revokes certificates for
keys it verified, sub-CAs included, with sign/encrypt tooling — and
whether to build it into fips-pub-domains or beside it.

- **A separate project, the issuer binding in NIP-DB.** The two share one
  question, which keys does `example.org` vouch for, and NIP-DB answers
  it; so the issuer key became one more role of a claim (`fips-ca`, its
  own `_fips-ca` record and chain) in fips-pub-domains, and everything
  about certificates lives here. Rejected: making NIP-DB's `decide`
  service-generic (welded to DNS serving; the phone pins that crate); a
  parallel claim kind for issuer keys; the serving node's key as the
  issuer key (keeps the issuing key on the server; a separate record lets
  the TXT name an offline root and an online issuer).
- **Rely on Nostr and fips, not on public centralized services** (the
  user's constraint). The verifier never queries DNS: the issuer's chain
  travels inside the claim, pins and mesh-relay witnesses do the rest; an
  issuer may be a bare key with no domain at all.
- **`d` is the name, `p` the subject.** Relays index single-letter tags
  only, so with `d = pubkey` the name → key lookup would be impossible by
  filter. `d = alice@example.org` makes both directions queryable;
  renames are a new `d`; several keys of one person are several `p`.
  Rejected: `d = subject pubkey`; certifying hostnames here (NIP-DB's
  zone record does that).
- **Sub-CAs are structural** (the user's requirement). A sub-issuer
  certificate is `_@<domain>` with `usage ca`, scoped to names at or under
  that domain — NIP-DB's "a publisher defines names under itself", one
  level further. Covers an offline root certifying an online issuer with
  no DNS change. Rejected: name constraints as separate tags (two
  sources of truth); `ca` on a person's certificate meaning anything.
- **Revocation: short validity and an explicit marker, both.**
  Replacement alone cannot reach a verifier that never saw the newer
  event; expiry bounds that window for everyone. The marker's
  `expiration` equals the revoked certificate's so it outlives the threat
  and no longer. NIP-09 is a courtesy. Rejected: a CRL event (one more
  thing to fetch, same reachability problem); relying on deletion.
- **A signature is an event.** A raw BIP-340 signature over arbitrary
  bytes with the Nostr key is a cross-protocol risk (a file whose hash is
  an event id); the detached signature is an unpublished event carrying
  the data's hash. Rejected: raw Schnorr over bytes.
- **NIPs.** NIP-05's grammar adopted, and `nostr.json` emitted as a
  bridge; NIP-40, NIP-44 used. NIP-26 avoided (deprecated, delegates
  authorship not identity); NIP-58 (regular events, irrevocable); kind 0
  as a security input; NIP-85 maybe mirrored later.
- **No X.509 bridge.** fips authenticates the far key; browsers' trust
  stores are a different problem. Revisit only with a concrete need.
