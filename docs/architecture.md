# Architecture

Three crates, cut like fips-pub-domains: the part that can be wrong is
policy with no I/O and is tested with tables.

### pubpki-core

| module | what |
|---|---|
| `name` | `Name`: `<local>@<domain>` parsing and display, the apex `_@domain`, the bare-key overlay issuer (`<npub>.fips`), `is_under(domain, scope)` — the sub-issuer scope rule |
| `cert` | `Certificate`: kind 37200 parse and build with the size limits, `Usage`, `allows`, `is_ca`, `is_live_at`, `may_issue_for` |
| *(next)* `path` | path validation (spec §4): anchored and certified issuers, nearest `_@E`, `pathlen`, `MAX_PATH`, disputes |
| *(next)* `store` | the issuer pin file's types and the anti-rollback table (spec §6), a trait like `pubdom_core::PinStore` |
| *(next)* `bundle` | the offline bundle (spec §7): parse, order, validate |
| *(next)* `sig` | detached signature events (spec §8) |

No `cfg(target_os)`; the phone embeds it. `pubdom_core` is re-exported so
consumers use one version.

### pubpki

I/O through `pubdom-resolve`: `RelayClient::fetch_raw` for kind 37200
with `#d`/`#p` filters and the NIP-DB scopes, `publish_event` for
issuing, `proof::verify_chain_for("fips-ca", …)` and
`DnssecProofs::check_service` for the issuer's chain, `load_keys` for the
issuer key, `TxtVerifier::lookup_service` for the issuer tooling only.
NIP-44 through the re-exported `nostr_sdk`. `core_event` reduces a relay
event to the core crates' view. The issuer pin file is written atomically
like `FilePinStore`.

### pubpki-cli

`fips-pubpki`: `ca init|issue|issue-ca|renew|revoke|publish|status`,
`resolve`, `verify [--bundle]`, `sign`, `verify-sig`, `encrypt`,
`decrypt`, `bundle`, `nostr-json`. Config `/etc/fips-pubpki/`. The issuer
key is its own file (not `/etc/fips/fips.key` by default), group `fips`.

### Dependencies

`pubdom-core` and `pubdom-resolve` pinned by commit in the workspace
manifest; bumped together. One `nostr-sdk`, through `pubdom-resolve`.
