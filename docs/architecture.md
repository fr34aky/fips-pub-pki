# Architecture

Three crates, cut like fips-pub-domains: the part that can be wrong is
policy with no I/O and is tested with tables.

### pubpki-core

| module | what |
|---|---|
| `name` | `Name`: `<local>@<domain>` parsing and display, the apex `_@domain`, the bare-key overlay issuer (`<npub>.fips`), `is_under(domain, scope)` — the sub-issuer scope rule |
| `cert` | `Certificate`: kind 37200 parse and build with the size limits, `Usage`, `allows`, `is_ca`, `is_live_at`, `may_issue_for` |
| `path` | path validation (spec §4): `Anchors` (pinned issuers by domain, the overlay rule), `Certs` (newest per (issuer, name), the anti-rollback floor, `seen()` for the store), `validate`, `resolve` (`Verified`/`Disputed`/`Refused`/`Unknown`), `names_of`; nearest `_@E`, `pathlen`, `MAX_PATH`, errors named up the path (`PathError::Via`) |
| `store` | the issuer file's types (spec §6): `IssuerMethod` (`attested < dns-single < dns < dnssec < pinned`), `IssuerPin`, `SeenKey`, `Snapshot` (`pin`/`unpin` by strength, `anchors()`, `seed`/`record` to and from `Certs`, `note_seen` for claims, `retain_authors`, `is_trusted_author`), the `IssuerStore` trait and `MemoryStore`; the file store lives in `pubpki` |
| `bundle` | the offline bundle (spec §7): `Bundle::from_events` sorts certificates, `fips-ca` claims and attestations with per-event errors; `validate` runs §4 over the bundle's certificates added to what is known (what is known wins); `anchors_needed`, `claims_of`, `attestations_of` tell the I/O crate what to verify |
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
