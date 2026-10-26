NIP-DC
======

Domain Certificates
-------------------

`draft` `optional`

This NIP defines addressable events by which a key that is *bound to a
domain* certifies other keys: that `alice@example.org` is a given public
key, that a service of the domain is a given key, or that a given key may
in turn certify names under a part of the domain. Certificates are signed
Nostr events, verifiable with nothing but the issuer's binding, which
[NIP-DB](https://github.com/nostr-protocol/nips/pull/2487) (Domain Service
Bindings) provides — including offline, from the DNSSEC chain carried in
the issuer's claim, and with no domain at all when the issuer is a bare
key on a key-addressed overlay.

It depends on NIP-DB for the issuer binding, on NIP-40 for expiry and on
NIP-44 for encryption. Kind numbers are provisional until registered.
Reference implementation: fips-pub-pki (library and CLI) on top of
fips-pub-domains.

## Terminology

- **Domain**: an Internet domain name in lowercase without trailing dot,
  or an overlay name `<npub>.fips` (the key-addressed form of NIP-DB's
  overlay; other overlays substitute their own).
- **Issuer**: a key authorised to sign certificates for names at or under
  a domain. An issuer is *anchored* (named by the domain's `fips-ca`
  record, or the bare key of `<npub>.fips`) or *certified* (holder of a
  sub-issuer certificate, see "Sub-issuers").
- **Name**: `<local>@<domain>`, with `<local>` in the NIP-05 grammar
  (`a-z0-9-_.`), or `_@<domain>` for the domain itself.
- **Subject**: the key(s) a certificate names.

## Issuer anchors

**A public domain.** The domain owner publishes, in the legacy DNS,

```
_fips-ca.example.org.  TXT  "v=fips1 npub=<issuer npub>"
```

one record per anchored issuer key (for instance an offline root key and
an online issuing key), and each anchored key publishes a NIP-DB claim
(kind 37197) for the domain with `["service", "fips-ca"]` and, if the
zone is signed, the `dnssec` tag for the `_fips-ca` record
(`["dnssec", "<chain>", "fips-ca"]`). The claim is verified as NIP-DB
prescribes; this NIP adds nothing to that verification, and a verifier
of certificates need never query DNS itself: it uses its own pins, the
chain in the claim, or `k` configured witnesses whose attestations carry
`["p", "<issuer>", "fips-ca"]`. Removing a key from the record withdraws
its authority; pins are forgotten on a denial at least as strong as the
pin, as in NIP-DB.

**A bare key.** For the domain `<npub>.fips` the issuer is that key. No
claim, no record: trust comes from the verifier having pinned or chosen
the key (a contact, a configured issuer). Everything below applies
unchanged.

## Kind 37200: Certificate

Addressable; `d` is the name.

```jsonc
{
  "kind": 37200,
  "pubkey": "<issuer pubkey>",
  "created_at": 1790000000,
  "tags": [
    ["d", "alice@example.org"],
    ["p", "<subject pubkey>"],              // one or more
    ["expiration", "1797776000"],           // NIP-40, REQUIRED
    ["usage", "sign"],                      // zero or more of sign, encrypt, ca, x509
    ["usage", "encrypt"],
    ["relay", "wss://relay.example.org"]    // optional hints, where the subject reads
  ],
  "content": ""                              // or a JSON object of display fields
}
```

- `d`: the name, lowercase. Several `p` tags are several keys of one
  subject (several devices); every one of them is the subject.
- `expiration` is REQUIRED. Relays and clients drop expired events
  (NIP-40). Issuers SHOULD keep validity short (90 days or less) and
  re-issue; a certificate is renewed by publishing a new event with a
  later `created_at`, which replaces the old one on conforming relays.
- `usage`: what the subject's keys may be used for. `sign` and `encrypt`
  are hints to applications; `ca` makes the certificate a sub-issuer
  certificate (below); `x509` makes it the domain's X.509 root statement
  (below). **No `usage` tag at all** means `sign` and `encrypt`. A client
  MUST treat a `usage` value it does not know as a usage it does not
  allow: a certificate whose usages are all unknown to the client allows
  nothing the client knows, and is never read as a plain key.
- `content`: empty, or a JSON object with display fields (`name`,
  `about`, `picture`); for `usage` `x509`, the base64 DER below. Never a
  security input except through the `x` tag.
- `x`: the SHA-256, hex, of the DER that `content` decodes to (the root
  certificate's usual fingerprint), REQUIRED with `usage` `x509`.
- **Reserved names.** A local part starting with `_` is a statement of
  the domain about itself, not a person: `_@<domain>` names the domain's
  own keys (its services) or, with `usage` `ca`, a sub-issuer for the
  domain; `_x509@<domain>` is its X.509 root statement. Issuers MUST NOT
  issue other `_…` names. A reserved name other than the apex is never a
  person: clients MUST NOT list it among the names a key holds, nor
  encrypt to it, nor present it as an identity.

Clients query `{"kinds":[37200], "#d":["alice@example.org"]}` to go from
name to key and `{"kinds":[37200], "#p":["<pubkey>"]}` to go from key to
names. Hostnames are not certified here: NIP-DB's zone record (kind
37199) says which key serves `www.example.org`.

## Sub-issuers

A certificate with `d` = `_@<domain>` and `["usage", "ca"]` makes each of
its `p` keys an issuer for **names whose domain is equal to or under
`<domain>`**, and for nothing else. The constraint follows from `d`: an
issuer can only delegate what it holds. Examples:

- An offline root listed in `_fips-ca.example.org` certifies
  `_@example.org` `ca` for an online issuing key. The online key issues
  `alice@example.org` without the root ever coming online, and without a
  DNS change.
- `example.org` certifies `_@sales.example.org` `ca` for the sales
  department's key, which issues `bob@sales.example.org` and may certify
  `_@emea.sales.example.org` `ca` further down.

An optional `["pathlen", "<n>"]` on a sub-issuer certificate limits how
many further sub-issuer certificates may follow below it (`0`: none).

## The X.509 root statement

A domain that runs TLS services on the overlay publishes the root of
its own X.509 CA as a certificate for `_x509@<domain>` with
`["usage", "x509"]`, the base64 (RFC 4648) DER of the self-signed root
certificate as `content`, and `["x", <sha256 of the DER, hex>]`. Its `p`
keys are the nodes operating the CA (where its ACME endpoint listens).
A client that validates this certificate's path as for any other has
the domain's word that this X.509 root is the domain's: it decodes the
content, checks its SHA-256 against the `x` tag, parses the DER,
requires a self-signed CA certificate, and may install it in a TLS
trust store. How the CA issues TLS certificates is outside this NIP; the
reference implementation runs an ACME server reachable over the overlay
only.

Compatibility: a client written to this revision meets the event as a
certificate with a usage it may not know, which allows nothing, under a
reserved name, which is not a person; the event is inert to it. A client
of the reference implementation's 0.1.0, which predates both rules,
reads it as a plain sign+encrypt certificate for the operating node's
key under the name `_x509@<domain>`; no such verifier was deployed, and
the rules above exist so that it cannot happen again.

## Path validation

To accept a certificate `C` for name `N` under domain `D` at time `now`:

1. `C` is unexpired, not revoked (below), and the newest the client has
   seen for (37200, author, `d`) — see "Freshness".
2. Let `A` be `C`'s author. If `A` is an anchored issuer for `D` or for
   a domain above `D` (a `fips-ca` binding verified per NIP-DB, or the
   bare key of `<npub>.fips`), the path is complete.
3. Otherwise find a sub-issuer certificate `S` with `usage` `ca`, a `p`
   equal to `A`, and `d` = `_@E` where `E` is `D` or a domain above `D`.
   Prefer the nearest such `E`. Validate `S` by this same procedure
   (steps 1–3) with `D := E`, and check `S`'s `pathlen` against the
   number of sub-issuer certificates already below it.
4. At most `MAX_PATH` = 4 certificates in a path; longer paths are
   refused.

A path is only as fresh as its weakest link: a revoked or expired
sub-issuer certificate invalidates every certificate below it. When two
issuers of the same domain publish live, conflicting certificates for one
name (different subjects), the name is **disputed** and clients MUST NOT
use either, mirroring NIP-DB's rule for conflicting claims.

## Revocation

- **Short validity plus renewal** is the first line: an issuer that stops
  renewing lets a certificate lapse within its validity.
- **Explicit revocation** replaces the addressable event: the issuer
  publishes kind 37200 with the same `d`, the same `p` keys, a later
  `created_at`, `["revoked", "<reason>"]`, and an `expiration` equal to
  the revoked certificate's (the marker must outlive the threat, no
  longer). Clients that have seen the marker MUST refuse the earlier
  certificate even if presented out of band.
- NIP-09 deletion of the revoked event MAY be sent as a courtesy. It is
  never relied upon.
- An **issuer key** is revoked by removing it from the `_fips-ca` record
  (anchored) or by revoking its sub-issuer certificate (certified).
- Validation after expiry (long-term signatures) is out of scope.
- Renewal is the issuer's: it re-publishes the same `d` with a later
  `created_at` and a fresh `expiration`, typically halfway through the
  remaining validity, and typically from an online issuing key certified
  by an offline root (see "Sub-issuers"). A request protocol by which a
  subject asks for issuance or renewal is left to a later revision; the
  `relay` hints give the issuer a reply path.

## Freshness and anti-rollback

Relays can withhold a newer event but cannot forge one. Clients keep the
highest `created_at` seen per (37200, author, `d`), ignore anything older,
and ignore events dated more than 10 minutes in the future. A verifier
that has seen a revocation marker or a renewal keeps that knowledge across
restarts.

## Offline bundle

A subject can present everything a verifier needs with no network:

```jsonc
[
  { "kind": 37200, ... },          // the certificate
  { "kind": 37200, ... },          // sub-issuer certificates up the path, if any
  { "kind": 37197, ... },          // the anchored issuer's claim with its dnssec chain
  { "kind": 37198, ... }           // attestations, optional
]
```

The verifier runs path validation on the bundle exactly as on events
fetched from relays; the claim's chain is verified against the DNS root
trust anchor offline, as NIP-DB describes. A bundle carries no secret and
may be handed over in band by any protocol.

## Signing

A signature over arbitrary data is itself a Nostr event, so that a key
never signs raw bytes that another protocol might interpret:

```jsonc
{
  "kind": 9200,                      // regular, provisional; never published
  "pubkey": "<signer pubkey>",
  "created_at": 1790000000,
  "tags": [
    ["x", "<sha256 of the data, hex>"],
    ["m", "<media type>"],           // optional
    ["size", "<bytes>"]              // optional
  ],
  "content": ""
}
```

The verifier hashes the data, checks the event's signature and `x`, then
resolves the signer's name through a certificate whose `p` includes the
signer and whose `usage` allows `sign`. Timestamps are the signer's claim,
nothing more.

## Encryption

To encrypt to a name, resolve it to its subject key(s) through a
certificate whose `usage` allows `encrypt`, and encrypt with NIP-44 (v2)
to each key. Several `p` keys of one subject receive the same message.
Multi-recipient wrapping (NIP-59) is an application's choice above this.

## Privacy

Queries by `#d` reveal which names a client looks up to the relay asked.
Clients SHOULD prefer relays they trust, including relays reachable only
over the overlay, and SHOULD cache. An issuer SHOULD publish its
certificates to relays its subjects and their correspondents can reach
without the Internet.

## Relationship to other NIPs

- **NIP-05**: a certificate is a signed, offline-verifiable statement of
  what a NIP-05 `nostr.json` says over HTTPS. The identifier grammar is
  NIP-05's; an issuer MAY also serve `/.well-known/nostr.json` generated
  from its certificates, so that clients without this NIP benefit.
- **NIP-DB**: the issuer binding; this NIP adds the `fips-ca` role's
  meaning and nothing to NIP-DB's verification.
- **NIP-40**: expiry. **NIP-44**: encryption. **NIP-09**: courtesy only.
- **NIP-26** (delegation) is not used: it delegates event authorship, not
  identity, and is deprecated. **NIP-58** badges are regular events and
  cannot be replaced or revoked. Kind 0 `nip05` fields are a display
  cross-check, never a security input. **NIP-85** trusted assertions could
  mirror a certificate's existence; this NIP keeps a dedicated kind so
  that name → key lookup stays a single `#d` query.

## Security considerations

- A certificate alone binds nothing: the issuer's authority comes from a
  verified binding (NIP-DB) or the verifier's own choice of key. Clients
  MUST NOT accept a certificate whose issuer they cannot place.
- The verifier never queries DNS; the legacy DNS is involved only where
  the issuer proves its binding, and that proof travels inside the
  claim. A verifier with no Internet and no pin still verifies a bundle.
- Name constraints are structural (`d` of the sub-issuer certificate), so
  a compromised department key cannot certify names outside its
  department, and a compromised online issuing key is withdrawn by the
  offline root re-issuing `_@<domain>` `ca` with a revocation marker.
- Anti-rollback protects only verifiers that have seen the newer event;
  short validity bounds the window for everyone else.
