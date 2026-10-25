# Testing

The ladder of checks, from what needs no network to what needs the mesh.
Each level records the commands and the output they produced when it was
last run. Nothing above level 0 has run yet.

| level | what | needs | last run |
|---|---|---|---|
| 0 | `cargo test --workspace`: names, certificates, scope rule, path validation tables, the store's pin rules and file shape, the bundle; `pubpki` with signed events and no relays: bare-key bundle, pinned issuer with delegation and rollback across a restart, witnesses anchoring a chainless claim, NIP-44, detached signatures, the file store, the config | nothing | 2026-10-25, green (41 tests) |
| 1 | offline bundle: `fips-pubpki verify --bundle` on a bundle made by `fips-pubpki bundle`, machine with no network | the CLI | — |
| 2 | issuer on the demo domain: `_fips-ca` record, claim with chain, `ca issue` for a name, `resolve` from a second node online | the user's word for the DNS record | — |
| 3 | mesh only: the second node with no Internet resolves the name from the mesh relay and the chain in the claim | the mesh relay | — |
| 4 | bare-key issuer: a `<npub>.fips` issuer with no domain, pinned on the verifier | two nodes | — |
| 5 | sub-issuer: an offline root, an online `_@example.org` `ca`, a department `_@sales.example.org`; revocation of the department key withdraws everything below | levels 2–3 | — |
| 6 | phone: `name@domain` resolved in fips2go contacts | the phone | — |
