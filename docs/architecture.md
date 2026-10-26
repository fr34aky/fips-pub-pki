# Architecture

Three crates, cut like fips-pub-domains: the part that can be wrong is
policy with no I/O and is tested with tables.

### pubpki-core

| module | what |
|---|---|
| `name` | `Name`: `<local>@<domain>` parsing and display, the apex `_@domain`, the bare-key overlay issuer (`<npub>.fips`), `is_under(domain, scope)` — the sub-issuer scope rule |
| `cert` | `Certificate`: kind 37200 parse and build with the size limits, `Usage`, `allows`, `is_ca`, `is_live_at`, `may_issue_for` |
| `path` | path validation (spec §4): `Anchors` (pinned issuers by domain, the overlay rule), `Certs` (newest per (issuer, name), the anti-rollback floor, `seen()` for the store), `validate`, `resolve` (`Verified`/`Disputed`/`Refused`/`Unknown`), `names_of`; nearest `_@E`, `pathlen`, `MAX_PATH`, errors named up the path (`PathError::Via`) |
| `store` | the issuer file's types (spec §6): `IssuerMethod` (`attested < dns-single < dns < dnssec < pinned`), `IssuerPin`, `SeenKey`, `Snapshot` (`pin`/`unpin` by strength, `anchors()`, `seed`/`record` to and from `Certs` with floors moving forward only, `note_seen` for claims, `is_trusted_author`, `retain_authors` as the explicit forget), the `IssuerStore` trait and `MemoryStore`; the file store lives in `pubpki` |
| `bundle` | the offline bundle (spec §7): `Bundle::from_events` sorts certificates, `fips-ca` claims and attestations with per-event errors; `validate` runs §4 over the bundle's certificates added to what is known (what is known wins); `anchors_needed`, `claims_of`, `attestations_of` tell the I/O crate what to verify |
| `sig` | detached signature events (spec §8): `Signature` parse and tags, `digest`, `covers` |
| `anchoring` | `attesting_witnesses`: the witness-counting rule for a `fips-ca` key (NIP-DB's freshness limits, each witness once, the issuer no witness for itself) |

No `cfg(target_os)`; the phone embeds it. `pubdom_core` is re-exported so
consumers use one version.

### pubpki

I/O through `pubdom-resolve`, in modules:

| module | what |
|---|---|
| `verifier` | `Verifier`: the core tables fed from relays (`fetch_raw` with `#d`/`#p` filters, `RelayScope::Offline`: mesh first) or from a bundle; `anchor_from` (a claim's chain through `DnssecProofs::check_service` earns `Dnssec`, `k` witnesses `Attested`; future-dated and rolled-back claims and attestations ignored), `fetch_anchor`, `ensure_anchor` (the domain's ancestors first, then `#p` delegations, bounded by `MAX_PATH`, one fetch per domain and key per call), `resolve` and `verify_bundle` (adopt a bare-key issuer by pinning it), `names_of` (adopts nothing), `pin`/`unpin`, `learn`, `save` (prune, trusted authors only, write) |
| `config` | `/etc/fips-pubpki/config.yaml`: relays, the issuers file, witnesses and `k`, budget, this user's key |
| `store` | `FileStore`: `Snapshot` as pretty JSON, atomic write, corrupt file an error |
| `sig` | `sign_detached` / `verify_detached` around `pubpki_core::Signature` |
| `crypto` | NIP-44 v2 `encrypt` / `decrypt` to a key, `npub_of` |
| `bundle` | the bundle as a JSON array of events; every signature verified on parse |
| `issuer` | `Issuer` (key and domain; `issue` from a `Request`, `renew` and `revoke` dated after what they replace, `claim` with the chain, `nostr_json`, the TXT record text), `Issued` (the issued file, newest per name), `sign_at` (explicit timestamp, self-tagging allowed: nostr-sdk drops a `p` naming the author otherwise), `publish_signed` (the exact stored event) |

`core_event` reduces a relay event to the core crates' view. The verifier
never queries DNS; `TxtVerifier::lookup_service` and `build_chain_for`
are for the issuer tooling (the `ca` commands), which comes next.

### pubpki-acme

Desktop only, outside the portability checks: the ACME server for TLS
certificates on the mesh (spec §8a, docs/acme.md when it lands). The
policy's premise is that a `fd…` source address was authenticated by the
mesh; that holds only for connections that arrived over the fips
interface, so the server (next PR) binds the node's fips address and,
on Linux, the interface itself, and the service is never to sit behind
a proxy or a host route from another interface.

| module | what |
|---|---|
| `lib` | the limits, `Problem` (RFC 7807 with `urn:ietf:params:acme:error:*`), `Identifier`, `rfc3339` |
| `jws` | the request signature: flattened JWS, `Jwk`, `Protected`, `parse`, `verify` (ES256, RS256, EdDSA), `thumbprint` (RFC 7638), `payload_json` — no I/O |
| `policy` | `Allowlist` and its address table, `peer_of` (the mesh address is the proof; a loopback override for tests only), `approve` (the peer's `.fips` name and zone-mapped names under the CA's domain, all or nothing), `Order`/`Authz`/`Account`/`CertEntry`, `csr_matches`, `same_peer`, `may_revoke` — no I/O, table-tested |
| `nonce` | `NoncePool`: single use, TTL, cap |
| `x509` | `Root` (P-256, generate/load), `inspect_csr` (rcgen: signature verified, only SAN/KU/EKU/BC extensions, key algorithm and RSA size), `issue` (the order's names, serverAuth, AKI, short validity), `check_root_content` and `pem_of` for `trust` |
| `zone` | `parse_zone_file` (the pubdom-server format), `ZoneSource::{File, Relays, None}`, `ZoneCache` |
| `store` | `AcmeStore`: `allow.json`, `accounts.json`, `orders.json` (expired dropped), `certs/index.json`, `certs/<serial>.pem`, through `write_atomic` |
| `server` | `ServeConfig`, `AppState` (the tables under one lock, the zone cache under its own, every change saved and rolled back if the save fails), `bind` (the fips address and, on Linux, the interface; retries until the tun is up), `serve` (hyper-util's connection builder with a header deadline, a body deadline per handler, a deadline per connection), `router`; the `gate` middleware (nothing off the mesh; `/directory` and `/acme/new-nonce` for any mesh peer; every POST for an allowed node, the loopback override on a loopback listener only); `authenticate` (JWS, nonce, `url`, `jwk` or `kid`, the account's node); the RFC 8555 endpoints: `/directory`, `new-nonce`, `new-account`, `acct/{id}` and its `orders`, `new-order` (authorizations valid at birth, one synthetic `fips-peer-01` challenge, at most `MAX_ORDERS_PER_ACCOUNT` live orders per account), `order/{id}`, `finalize` (CSR inspected and matched, the leaf issued and recorded before the order says valid), `authz/{id}`, `chall/{id}`, `cert/{serial}` (`application/pem-certificate-chain`), `revoke-cert`; `Replay-Nonce` (remembered for allowed peers only), `Link rel=index`, `Cache-Control: no-store` on every reply, `application/problem+json` errors |

### pubpki-cli

`fips-pubpki`, one file over `pubpki`: `ca init|issue|issue-ca|renew
[--watch]|revoke|publish|status [--dns]`, `issuer add|remove|list`,
`resolve`, `names`, `verify <file>` (a bundle or one event), `bundle`,
`sign`, `verify-sig`, `encrypt`, `decrypt`, `nostr-json`, `config`.
Config `/etc/fips-pubpki/config.yaml`; the issuer key is its own file
(`ca_key`, written by `ca init` with mode 0600), never the node key.
`ca status --dns` and `ca publish` are the only commands that touch the
legacy DNS, and they are the issuer's. The renewal unit is
`packaging/systemd/fips-pubpki-ca.service`.

### Dependencies

`pubdom-core` and `pubdom-resolve` pinned by commit in the workspace
manifest; bumped together. One `nostr-sdk`, through `pubdom-resolve`.
