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
| `verifier` | `Verifier`: the core tables fed from relays (`fetch_raw` with `#d`/`#p` filters, `RelayScope::Offline`: mesh first) or from a bundle; `anchor_from` (a claim's chain through `DnssecProofs::check_service` earns `Dnssec`, `k` witnesses `Attested`), `fetch_anchor`, `ensure_anchor` (walks `#p` delegations and the domain's ancestors, bounded by `MAX_PATH`), `resolve`, `names_of`, `verify_bundle`, `pin`/`unpin`, `learn`, `save` (prune, trusted authors only, write) |
| `config` | `/etc/fips-pubpki/config.yaml`: relays, the issuers file, witnesses and `k`, budget, this user's key |
| `store` | `FileStore`: `Snapshot` as pretty JSON, atomic write, corrupt file an error |
| `sig` | `sign_detached` / `verify_detached` around `pubpki_core::Signature` |
| `crypto` | NIP-44 v2 `encrypt` / `decrypt` to a key, `npub_of` |
| `bundle` | the bundle as a JSON array of events; every signature verified on parse |

`core_event` reduces a relay event to the core crates' view. The verifier
never queries DNS; `TxtVerifier::lookup_service` and `build_chain_for`
are for the issuer tooling (the `ca` commands), which comes next.

### pubpki-cli

`fips-pubpki`: `ca init|issue|issue-ca|renew|revoke|publish|status`,
`resolve`, `verify [--bundle]`, `sign`, `verify-sig`, `encrypt`,
`decrypt`, `bundle`, `nostr-json`. Config `/etc/fips-pubpki/`. The issuer
key is its own file (not `/etc/fips/fips.key` by default), group `fips`.

### Dependencies

`pubdom-core` and `pubdom-resolve` pinned by commit in the workspace
manifest; bumped together. One `nostr-sdk`, through `pubdom-resolve`.
