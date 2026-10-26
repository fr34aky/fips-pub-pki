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

## TLS on the mesh through ACME (2026-10-26)

The request: a web server or relay on a fips node should get a TLS
certificate for its service from the domain's CA with an ordinary ACME
client, the certificate naming both the human-readable name and the
node's `<npub>.fips`, and only nodes the CA knows should be able to ask.
The PKI so far had scoped X.509 out; browsers made it necessary.

**No challenge round.** On fips a packet from `fd…` can only come from
the node holding the key the address is derived from: the mesh
authenticates the source cryptographically. An HTTP-01 or DNS-01 round
would therefore prove less than the transport already proves, and the
operator's allowlist plus the zone's binding of the name to the node is
the actual authorization. The ACME server listens on the CA node's fips
address only and, on Linux, on the fips interface only; the peer's
address names the requester; authorizations are valid at birth, which
RFC 8555 permits and every targeted client handles. Rejected: External
Account Binding (a shared secret duplicating the allowlist, and a
weaker binding than the key); a custom `fips-01` challenge type (every
client would need a plugin for nothing new); HTTPS on the ACME endpoint
(nothing to authenticate it with before the root exists; the mesh
encrypts the hop). The premise, and its limit, are written down: the
listener must never be reachable through another interface or a proxy.

**A P-256 root, separate from the issuer key.** Browsers and TLS stacks
do not accept secp256k1 or Schnorr; the Nostr issuer key signs events,
the X.509 key signs certificates, and compromise of one does not cost
the other. Rejected: deriving one key from the other (couples what
should stay apart); an RSA root (size, on a mesh with small MTUs).
Leaves are short-lived (30 days) and clients renew; no CRL, no OCSP:
revocation infrastructure for certificates that die in a month is
weight without benefit.

**The root published through the PKI, under a reserved name.** "Is this
the root of `example.org`" is the question NIP-DC already answers for
keys, so the root's DER rides in a certificate for `_x509@<domain>`
with `usage x509` and its SHA-256 in an `x` tag; `fips-pubpki trust` is
path validation plus a hash check. The name is reserved rather than the
apex `_@<domain>` because relays keep one event per issuer and name,
and the apex already carries the domain's service keys and delegations;
an `x509` statement there would have replaced them or been replaced by
the next renewal. Rejected: shipping the root over HTTP from the ACME
server (nothing authenticates it); a new event kind (one more thing to
fetch, pin and register); putting the root in the zone record
(fips-pub-domains's concern is names, not keys). Two rules came with
it: local parts starting with `_` are the domain's statements, never
people, and a usage a client does not know allows nothing; the
compatibility note in nip.md says what 0.1.0 would have done instead.

**What the first offline run changed.** nostr-sdk's builder drops a
`p` tag naming the author unless told otherwise, which silently broke a
bare key certifying its own name; a revocation marker arrives in a
bundle that fails validation, so learning only from validated bundles
left the old certificate verifiable; a verifier that kept floors but no
certificates could not encrypt to a name it had just verified after a
restart. All three are in the code now because the tool was run, not
because they were foreseen.
