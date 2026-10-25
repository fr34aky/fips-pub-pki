# Roadmap

What is done, what is next, what is undecided. The source of truth for
the state of the project; when something is finished or verified it is
recorded here and in [testing.md](testing.md). Dates are absolute.

## Done

- 2026-10-25: the decision and the issuer binding — fips-pub-domains
  PR #29 (the `fips-ca` role, per-role `dnssec` tags, role-aware
  attestations, `sign_event`/`publish_event`/`fetch_raw`).
- 2026-10-25: this repository; [nip.md](nip.md) (NIP-DC) drafted;
  `pubpki_core::Name` and `Certificate` with the sub-issuer scope rule,
  under test; CI as fips-pub-domains.

## Next, in order

1. **`pubpki-core::path`** — path validation (spec §4) over tables of
   certificates and anchored issuers: nearest `_@E`, `pathlen`,
   `MAX_PATH`, disputes, revocation and rollback along the path. Tests
   first, from the cases in spec §4 and nip.md.
2. **`pubpki-core::store` and `bundle`** — the issuer pin file's types,
   the anti-rollback table, the offline bundle's parse and validation.
3. **`pubpki`** — relay fetch of kind 37200 by `#d` and `#p` through
   `fetch_raw`, the issuer's claim and chain through `pubdom-resolve`,
   the issuer pin file on disk, NIP-44 helpers, detached signatures.
4. **`fips-pubpki`** — `ca init|issue|issue-ca|renew|revoke|publish|status`,
   `resolve`, `verify [--bundle]`, `bundle`, `sign`, `verify-sig`,
   `encrypt`, `decrypt`, `nostr-json`. `ca renew --watch` re-issues
   every live certificate halfway through its remaining validity, the
   loop `fips-pubdom-server` runs for its chain: automatic renewal is
   issuer-driven and needs no protocol change (an addressable event
   re-published with a later `created_at`).
5. **Live** (each on the user's word): a `_fips-ca` record for the demo
   domain and an issuer claim with its chain; certificates on the mesh
   relay; an offline verification on the second node with no Internet;
   a bare-key issuer with no domain.
6. **Phone**: `name@domain` in fips2go's contacts with its own issuer
   pins; no sign/encrypt tooling in the resolver.
7. **Registration and the NIP**: kind numbers and the NIP-DC submission,
   on the user's word, after the reference implementation.

## Later

- **Enrolment requests** (ACME's model, over Nostr and fips only): a
  signed request event from the subject — proof of key possession, as
  ACME's key authorization — naming the wanted `d` and keys, gift-wrapped
  (NIP-59) to the issuer; the issuer applies policy (renewal of a live,
  unrevoked certificate is mechanical; first issuance stays the domain
  owner's decision, there being no HTTP-01 analogue for a person's key)
  and publishes. A request kind as a section of NIP-DC, after path
  validation ships. The `relay` hints already give the reply path.

## Open questions

- Whether `fips-pubdom-server` should publish the domain's `fips-ca`
  claim on the issuer's behalf, or the issuer tooling alone.
- Whether `nostr.json` emission belongs in the CLI or in the domain
  server's web root.
- Multi-recipient encryption: leave to applications (NIP-59) or offer a
  helper.
