# Testing

The ladder of checks, from what needs no network to what needs the mesh.
Each level records the commands and the output they produced when it was
last run. Nothing above level 0 has run yet.

| level | what | needs | last run |
|---|---|---|---|
| 0 | `cargo test --workspace`: names, certificates, scope rule, path validation tables, the store's pin rules and file shape, the bundle; `pubpki-acme`: JWS vectors for the three algorithms and the RFC 7638 thumbprint, the allowlist and peer table, identifier approval against a zone, order and revocation rules, the nonce pool, root generation and reload, issuing against a CSR that asks for more, CSR rejection, the root check, the zone file, the state directory, and the server driven by instant-acme over plain HTTP on loopback (account, a ready order with valid authorizations, finalize, the chain checked against the root, every refusal type, revocation once, a restart with the same state, an unallowed peer refused at new-account); `pubpki` with signed events and no relays: bare-key bundle, pinned issuer with delegation and rollback across a restart, witnesses anchoring a chainless claim, NIP-44, detached signatures, the file store, the config | nothing | 2026-10-26, green (64 tests) |
| 1 | the CLI offline: a bare-key issuer `ca init`, `ca issue` (a person, a self-named key, a department delegation), the user's `verify` of the issued events, `encrypt`/`decrypt` and `sign`/`verify-sig` from what was learnt, `ca revoke` then `verify` of the old certificate refused across runs, `ca renew --force`; no relay configured | the CLI | 2026-10-25, green (scratch directory, see the PR) |
| 1c | the ACME commands offline: a bare-key CA's `acme init` (root files, the `_x509` statement in `issued.json`), `acme allow|list|status`, `trust --bundle` on the statement's event (a PEM OpenSSL reads), `acme serve` on loopback answering the directory and a nonce | the CLI | 2026-10-26, green (scratch directory, see PR 4) |
| 1d | certbot against `acme serve` on loopback with `acme_peer_override` | certbot in a venv | — |
| 1b | offline bundle: `fips-pubpki verify` on a bundle made by `fips-pubpki bundle` on a connected machine | a relay | — |
| 2 | issuer on the demo domain: `_fips-ca` record, claim with chain, `ca issue` for a name, `resolve` from a second node online | the user's word for the DNS record | — |
| 3 | mesh only: the second node with no Internet resolves the name from the mesh relay and the chain in the claim | the mesh relay | — |
| 4 | bare-key issuer: a `<npub>.fips` issuer with no domain, pinned on the verifier | two nodes | — |
| 5 | sub-issuer: an offline root, an online `_@example.org` `ca`, a department `_@sales.example.org`; revocation of the department key withdraws everything below | levels 2–3 | — |
| 5b | TLS on the mesh: `acme init` on the CA node publishing `_x509@<domain>`, a second node allowed with `acme allow` running certbot against `http://[fd…]:8555/directory` for its `relay.<domain>` and `<npub>.fips`, `fips-pubpki trust <domain>` on a third machine, a browser with the PEM installed opening `https://relay.<domain>` over the mesh | three nodes, the user's word | — |
| 6 | phone: `name@domain` resolved in fips2go contacts | the phone | — |
