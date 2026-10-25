# fips-pub-pki: the protocol as this implementation applies it

The protocol is [nip.md](nip.md) (NIP-DC, Domain Certificates). This
document is what the code does with it: the trust model and precedence,
path validation as implemented, storage, the bundle, and the decisions.
Section numbers are referenced from the code.

## 1. Goals and non-goals

Goals:

- Bind `alice@example.org` (and the domain's services, and sub-issuers)
  to Nostr keys by signed events, verifiable offline, anchored either in
  a public domain through NIP-DB's `fips-ca` role or in a bare key on the
  mesh.
- Rely on Nostr and fips, not on public centralized services: the
  verifier never queries DNS; relays on the mesh come first.
- Make delegation safe by structure: a sub-issuer's reach is the `d` of
  its certificate.

Non-goals: a global registry of names; TLS or X.509; validation of
signatures after the certificate's expiry; multi-recipient encryption
below the application (NIP-59 is the application's choice).

## 2. Trust model

An **anchored issuer** for domain `D` is:

- a key named by `_fips-ca.D TXT` whose kind 37197 claim with
  `["service","fips-ca"]` the verifier accepts per NIP-DB: by its own
  issuer pin, by the chain in the claim's `fips-ca` `dnssec` tag, or by
  `k` configured witnesses whose attestations carry `["p", key, "fips-ca"]`;
  or
- the key `<npub>` of the overlay domain `<npub>.fips`, when the verifier
  has pinned or configured it.

A **certified issuer** holds a live sub-issuer certificate (`_@E`,
`usage ca`) from an anchored or certified issuer, and may issue for names
under `E` (§4).

Precedence for the issuer binding, as NIP-DB: pin ≥ chain in the claim ≥
witnesses; unverified is refused. Live DNS is never consulted by the
verifier. The issuer tooling uses DNS only to collect the chain it
publishes (`pubdom_resolve::proof::build_chain_for("fips-ca", …)`).

As implemented (`pubpki::Verifier::anchor_from`): for each `fips-ca`
claim of the domain not older than the newest seen for (37197, author,
domain), the chain is checked with `DnssecProofs::check_service` and
earns `dnssec`; failing that, `pubpki_core::attesting_witnesses` counts
the configured witnesses whose **newest** attestation for the domain
names the key in the `fips-ca` role (method `dns` or better, verified
within 30 days, not from the future, the issuer itself no witness): a
witness that re-published without the key has withdrawn it. `k` or more
earn `attested`; `k = 0` turns attestations off. Claims and attestations
dated beyond `MAX_FUTURE_SECS` are ignored, and both have anti-rollback
in the file: the newest `created_at` seen per (37197, issuer, domain) and
per (37198, witness, domain), so neither a claim nor an attestation can
be replayed from before what the verifier has seen. The pin goes through
`Snapshot::pin` (§6), so a weaker result never replaces a stronger pin.
Online, `ensure_anchor` places a certificate's issuer by asking for the
claims of the name's domain and its ancestors first (a directly
anchorable issuer must not depend on whatever delegations strangers
publish for it), then for the sub-issuer certificates naming it (`#p`)
and their issuers in turn, up to `MAX_PATH` deep, each domain and key
asked for once per lookup; an overlay domain `<npub>.fips` fetches
nothing. Relays are asked mesh first (`RelayScope::Offline`), the public
ones only when the mesh had nothing.

## 3. Names and certificates

Names: `<local>@<domain>`, `local` in `a-z0-9-_.` (≤ 64), `_` the apex;
domain normalized as NIP-DB's (`pubpki_core::Name`). Certificates: kind
37200 as nip.md, parsed by `pubpki_core::Certificate` with the limits
`MAX_TAGS` (300), `MAX_SUBJECTS` (16), `MAX_RELAY_HINTS` (8). `d` must be
canonical. Absent `usage` means `sign` and `encrypt`; `ca` is never
implied, and only on an apex certificate makes a sub-issuer.

## 4. Path validation

Given certificate `C` for name `N` (domain `D`) at `now`:

1. `C` parses, `now < expiration`, no `revoked` tag, and `created_at` is
   not below the newest seen for (37200, issuer, `d`) (§6).
2. If `C.issuer` is an anchored issuer for `D` or a domain above `D`:
   done.
3. Else find a live sub-issuer certificate `S` with `p ∋ C.issuer`,
   `d = _@E`, `is_under(D, E)`, preferring the nearest `E`; validate `S`
   recursively with `D := E`; honour `S.pathlen` against the count of
   sub-issuer certificates below `S`.
4. At most `MAX_PATH` = 4 certificates in the path.

Conflicting live certificates for one `d` from different issuers of the
same domain: **disputed**, neither used. A revoked, expired or rolled-back
link invalidates everything below it.

As implemented (`pubpki_core::path`): the verifier's knowledge is two
tables, `Anchors` (issuer pins per domain, normalized, never a single
label; the key of `<npub>.fips` is anchored for that domain by structure,
reported as `Overlay`, and the walk up the domain stops there) and
`Certs` (the newest certificate per (issuer, `d`), with the floor of §6;
`prune_expired` and `retain_issuers` let the store bound what untrusted
relay traffic can grow: nothing from an issuer that is neither anchored
nor certified needs remembering).
`validate` walks up: a link fails as `Future`, `Revoked` (also when the
newer event known is the marker), `Superseded`, `Expired`, `NoIssuer`,
`TooLong` or `Pathlen`, and a failure above the certificate is reported
as `Via(<sub-issuer d>, …)`. Sub-issuer candidates are tried nearest `E`
first, then newest, then by issuer key and name, so equal inputs give
equal paths on every verifier; the first that validates wins; a key's
delegation to itself is no candidate and no (issuer, `d`) appears twice
in a path. `resolve`
validates every issuer's newest certificate for the name: `Verified`
(the shortest valid path, then the newest, then the lower issuer key; all
valid paths name the same subject keys), `Disputed` (valid paths disagree), `Refused` (none
validates; the errors, newest first) or `Unknown`. `names_of` lists the
valid certificates naming a key.

## 5. Revocation

Short validity (`DEFAULT_VALIDITY_SECS` = 90 days) plus renewal; the
explicit marker (same `d`, same `p`, later `created_at`, `revoked`,
`expiration` = the revoked certificate's); NIP-09 as a courtesy. An
anchored issuer is withdrawn by the TXT record; a certified one by
revoking its sub-issuer certificate.

## 6. Freshness, anti-rollback, storage

Per (kind, issuer, `d`) the highest `created_at` seen is kept; older
events are ignored; events more than `MAX_FUTURE_SECS` (600 s) in the
future are ignored. Storage is `/var/lib/fips-pubpki/issuers.json`:

```jsonc
{
  "issuers": [ { "domain": "example.org", "npub": "npub1…", "method": "dnssec", "verified_at": 1790000000 } ],
  "seen":    [ [ { "kind": 37200, "author": "npub1…", "d": "alice@example.org" }, 1790000000 ] ],
  "certs":   [ { "issuer": "npub1…", "name": { "local": "alice", "domain": "example.org" }, "subjects": ["npub1…"],
                 "expiration": 1797776000, "usages": ["sign"], "revoked": null, "pathlen": null,
                 "relays": [], "created_at": 1790000000 } ]
}
```

`certs` holds the trusted authors' newest certificates and markers, so
that a name verified once resolves again with no relay in reach and a
revocation seen once is refused after a restart; it follows the same
retention as `seen` and is seeded after the floors.

Its own file: the fips-pubdom pin file is shared with the phone and not
touched. `method` ranks as NIP-DB's (`attested < dns-single < dns <
dnssec`), with `pinned` above them all for what the user configured by
hand (a bare key, a known issuer): an issuer pin is replaced only by a
verification at least as strong (`Snapshot::pin`), and forgotten only on
a denial at least as strong (`Snapshot::unpin`), so unsigned DNS can
neither install nor withdraw a DNSSEC-verified issuer and no verification
touches a hand-configured one. Domains are normalized and a single label
is never pinned. The `seen` key's `d` is the certificate's name or the
claim's domain; entries for kind 37200 are rebuilt from `Certs::seen()`
at save time (`record`: timestamps move forward only, and entries the
running table does not know stay, so a short-lived run cannot erase the
floor), entries for the issuers' claims are kept with `note_seen`. The
file admits trusted authors only: issuers placed for some domain,
subjects of sub-issuer certificates that validate now, and authors
already in the file (trusted once, their floors stay, so what they
revoked stays revoked even after their delegation lapsed); a stranger's
self-signed `_@…` certificate makes nobody trusted, and neither does a
bare key's structural anchor for its own `<npub>.fips`, since anyone has
one (`is_trusted_author`). A bare-key issuer enters the file when the
user chooses it: the verifier pins it (`pinned`) when a name under it is
resolved or its bundle verifies, never from an unsolicited certificate
naming a key (`names_of`).
`Certs::retain_issuers` bounds the running table the same way, expired
certificates are pruned with their timestamps kept as floors, and
`retain_authors` is the operator's explicit forget, never routine.

## 7. The offline bundle

A JSON array of events: the certificate, the sub-issuer certificates up
the path, the anchored issuer's kind 37197 claim with its `fips-ca` chain,
optional kind 37198 attestations. `fips-pubpki verify --bundle` runs §4 on
it with no network; `fips-pubpki bundle <name>` produces it.

As implemented: the I/O crate checks every event's signature, reduces
them to `pubdom_core::Event` and calls `Bundle::from_events`, which
requires the first event to be a certificate, accepts at most
`MAX_BUNDLE_EVENTS` (32), refuses any other kind, and parses each event
with the error naming its position. `anchors_needed` lists the issuers no
certificate in the bundle certifies for its domain (the scope rule of
§4), with the domain the anchor must cover; for each, the I/O crate
verifies a `fips-ca` claim of that issuer for the domain or one above it
(`claims_of`: the chain through `pubdom_resolve::proof`, or
`attestations_of` against its configured witnesses) and, on success,
anchors the key for the claim's domain with the method earned. A
bare-key issuer (`<npub>.fips`) needs no claim. Every attestation of the
claim's domain goes into the count, not only those naming the issuer: a
witness's newer attestation without the key is its withdrawal. `validate`
then runs §4 over the bundle's certificates added to what the verifier
knows that can matter (the entries they collide with, and its sub-issuer
certificates, so a bundle that left the delegation out still validates
for a verifier holding it); what the verifier knows wins, so a bundle
cannot roll a certificate back below a marker or renewal it has seen,
and a link below a floor is named `Superseded` and passed over for the
next candidate rather than reported as a missing issuer. The size bound
is checked before any signature. A bundle teaches the verifier only once
it validated.

## 8. Signing and encryption

A detached signature is a kind 9200 event, never published, with
`["x", sha256(data)]`; verification hashes the data, checks the event,
and resolves the signer through a certificate allowing `sign`.
Encryption is NIP-44 v2 to each `p` of a certificate allowing `encrypt`.

As implemented: `pubpki::sig::sign_detached` writes `x`, the optional
`m` and `size` (`pubpki_core::Signature::tags`); `verify_detached` checks
the event signature, then `Signature::covers` (hash, and size if stated).
`pubpki::crypto::encrypt`/`decrypt` wrap nostr-sdk's NIP-44 v2 for one
recipient key.

## 9. Privacy

`#d` queries disclose the names a client looks up; prefer mesh relays
and relays one trusts; cache. Issuers publish where their subjects'
correspondents can read without the Internet.

## 10. Decisions and open questions

- Separate project on fips-pub-domains (2026-10-25); see
  [design-history.md](design-history.md).
- Kind numbers 37200 and 9200 are provisional; registration and the NIP
  submission happen on the maintainer's word.
- Open: whether `fips-pubdom-server` publishes a domain's `fips-ca` claim
  on the issuer's behalf (it keeps the `fips-dns` chain fresh already) or
  the issuer tooling does it alone; whether the phone should resolve
  names in contacts in v1.
