# How it works

A walk from a name to a key, and back, with every trust step named.
The normative text is [nip.md](nip.md); what the code does with it is
[spec.md](spec.md); this is the explanation.

## The problem

`alice@example.org` should mean one Nostr key, and anyone should be able
to check that, including a node on a fips mesh with no Internet, without
asking a central party, and without trusting whatever relay happens to
answer. NIP-05 answers it over HTTPS from a web server: online only, and
the web PKI underneath. This project answers it with signed events and
one binding: the domain's owner says which keys speak for the domain.

## Three kinds of statement

Everything is a Nostr event, signed by its author, replaceable by a
newer one from the same author with the same `d` tag (addressable).

| who signs | event | says |
|---|---|---|
| a `fips-ca` key of `example.org` | **claim**, kind 37197 (NIP-DB, from fips-pub-domains) | "I am an issuer for example.org", with the DNSSEC proof of the `_fips-ca.example.org` TXT record inside |
| an issuer | **certificate**, kind 37200 (NIP-DC, this project) | "`alice@example.org` is key K until T", or "key K may issue names under `sales.example.org`" |
| a witness | **attestation**, kind 37198 (NIP-DB) | "I looked example.org up in DNS and its `fips-ca` keys were …" |

A certificate for `_@example.org` with `usage ca` is a **sub-issuer
certificate**: a delegation. A certificate with a `revoked` tag is a
**revocation marker**: the same name and keys, later timestamp.

## From name to key

`fips-pubpki resolve alice@example.org` does this:

```
1. ask the relays for kind 37200 with d = alice@example.org
   → one or more certificates, each by some issuer key A
2. for each: can A be placed for example.org?
   a. A is pinned for example.org or a domain above     → anchored (pin)
   b. A's claim for example.org carries a DNSSEC chain
      proving _fips-ca.example.org names A              → anchored (dnssec)
   c. k of my witnesses attest A as fips-ca for it      → anchored (attested)
   d. some live sub-issuer certificate _@E, E at or above
      example.org, names A as subject                   → climb: place ITS issuer (back to 2)
   e. none of that                                      → not placed
3. a certificate whose chain of delegations ends in an anchor,
   with no link expired, revoked or rolled back, is valid
4. all valid ones agree on the keys → answer; disagree → DISPUTED;
   none valid → refused with the reason; none at all → unknown
```

The domain above matters in 2a and 2d: `bob@sales.example.org` may be
issued by a key anchored for `example.org`, and a key certified for
`_@example.org` may issue anything below. The scope of a delegation is
its name, nothing else: that is what makes delegation safe.

A bare key needs no step 2b or 2c: for the domain `<npub>.fips` the key
`npub` is anchored by structure. Its names are
`alice@npub1….fips`, and you trust it because you chose to (you pinned
it, or you asked for a name under it).

## What DNS is for, and who asks it

Only the issuer's tooling talks to the legacy DNS: `ca publish` fetches
the DNSSEC chain for `_fips-ca.example.org` and puts it inside the
claim. A verifier validates that chain against the DNS root key it
carries, offline. A verifier **never queries DNS** itself: no DNS
answer, signed or not, can reach it except through the issuer's claim or
a witness's attestation, and nothing in the system depends on the
verifier having Internet. When the zone is unsigned the chain does not
exist; then witnesses (nodes that did look it up, repeatedly, and signed
what they saw) or a pin carry the trust.

## What a relay can and cannot do

A relay can withhold an event or serve an old one. It cannot forge one.
So the verifier keeps, per issuer and name, the newest timestamp it has
ever seen (and for claims and attestations likewise), on disk. An older
event than that is a replay and is refused, whether it came from a
relay, a file or a friend. A revocation marker, once seen, therefore
stays effective even if every relay later serves the pre-revocation
certificate. The window of exposure is "verifiers that have not yet
seen the marker", bounded by the certificate's short validity.

## Revocation

Two mechanisms, both cheap:

- **Short validity.** Certificates default to 90 days and are renewed
  halfway through by the issuer's loop. An issuer that stops renewing
  lets a certificate lapse; a sub-issuer that lapses takes everything
  below it along.
- **The marker.** The issuer re-publishes the name with `revoked`, the
  same expiration, a later timestamp. Verifiers refuse the old one from
  then on. No deletion is relied upon.

An issuer key itself is retired by removing it from the `_fips-ca`
record (anchored) or revoking its delegation (certified).

## Offline

A **bundle** is the list of events a verifier needs: the certificate,
the delegations above it, the anchored issuer's claim with its chain,
attestations if any. `fips-pubpki bundle` gathers it; `fips-pubpki
verify` runs exactly the steps above on it, with the relay replaced by
the file and DNS replaced by the chain inside. A bundle made on a
connected machine verifies on one that never had a network, and what it
taught (the certificate, a revocation) is kept, so the name keeps
resolving there.

## Signing and encrypting with a name

A key named by a certificate is used like any Nostr key, with two rules:

- A **signature over data** is itself an event (kind 9200, never
  published) over the data's SHA-256. The key never signs raw bytes that
  another protocol could interpret. `verify-sig` checks the event, then
  resolves the signer's names.
- **Encryption** is NIP-44 v2 to each of the subject's keys. The
  certificate's `usage` says whether a key is for signing, encryption or
  both.

## What is where

| | the issuer's machine | a user's machine |
|---|---|---|
| configuration | `/etc/fips-pubpki/config.yaml` (`ca_*` keys) | `/etc/fips-pubpki/config.yaml` |
| secret | `/etc/fips-pubpki/ca.key` | the user's own key (`key:`) |
| state | `/var/lib/fips-pubpki/issued.json`: what was issued | `/var/lib/fips-pubpki/issuers.json`: pins, newest-seen, kept certificates |
| service | `fips-pubpki-ca.service`: renew and re-publish | none |
| talks to | relays (publish), DNS (the chain, at publish time) | relays (fetch); never DNS |

## Behaviour in one table

| situation | what happens |
|---|---|
| name issued by a key the TXT record names, zone signed | verified anywhere, offline included, from the chain in the claim |
| same, zone unsigned | verified where `k` witnesses attest the key or the key is pinned; refused elsewhere |
| name issued by a department key | verified through the delegation `_@sales.example.org`, if that is live and its issuer is placed |
| department key issues `alice@example.org` | refused: outside its scope |
| two anchored keys issue different keys for one name | disputed, nobody wins |
| relay serves a pre-revocation certificate | refused where the marker was seen; lapses within the validity elsewhere |
| bundle with an older delegation than the verifier has seen | that link is named superseded; a newer delegation the verifier holds is used instead |
| bare key issues names under its own `<npub>.fips` | verified by anyone who pinned the key or asked for a name under it; a stranger's unsolicited certificate is answered and forgotten |
| claim or attestation dated in the future, or older than one seen | ignored |
