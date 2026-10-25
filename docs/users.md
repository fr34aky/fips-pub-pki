# Resolving, verifying, signing and encrypting

The user side of `fips-pubpki`: turning `alice@example.org` into a key
you can trust, with or without a network, and using that key.
[install.md](install.md) puts the binary and the configuration in place;
[how-it-works.md](how-it-works.md) is the why.

## Configuration

`/etc/fips-pubpki/config.yaml` (or `--config` anywhere), every key
optional, unknown keys refused:

```yaml
mesh_relays: ["ws://npub1….fips:80"]      # asked first, by .fips name
public_relays: ["wss://relay.example.org"] # asked when the mesh had nothing; learns your lookups
issuers: /var/lib/fips-pubpki/issuers.json # pins, anti-rollback, kept certificates
witnesses: ["npub1…", "npub1…"]            # whose fips-ca attestations count
attestation_threshold: 2                   # k; 0 turns attestations off
budget_ms: 4500                            # per relay fetch
key: /etc/fips/fips.key                    # this user's key: sign, decrypt, encrypt-from
```

`fips-pubpki config` prints the effective configuration, defaults
included. The verifier never queries DNS, whatever the configuration;
`upstreams:` and the `ca_*` keys are the issuer's.

## Resolving

```bash
$ fips-pubpki resolve alice@example.org
alice@example.org = npub1alice…
  alice@example.org by npub1online…  expires in 89d  [sign,encrypt]
    _@example.org by npub1root…  expires in 300d  [ca]
      anchor: npub1root… for example.org (Pinned)
```

The first line is the answer (one per device key). Below it, the path:
the certificate, the delegations above it, and the anchor that ends it.
Four outcomes:

| printed | meaning | what to do |
|---|---|---|
| `name = npub…` | one subject, through a valid path | use the key |
| `DISPUTED` | two issuers of the domain disagree on the keys | use neither; ask the domain's owner |
| `refused`, with the reason per issuer | certificates exist but none validates (`issuer not anchored`, `expired`, `revoked: …`, `through _@…: …`) | see below |
| `no certificate found` | nothing on the relays you asked | check `mesh_relays`; the issuer may publish elsewhere |

`issuer not anchored` is the one to understand. The verifier places an
issuer by, in order: your own pin, the DNSSEC chain inside the issuer's
claim, `k` of your witnesses. If none applies the name is refused, not
guessed. `--json` gives the same as data.

The other direction:

```bash
fips-pubpki names npub1alice…        # every name a key validly holds
```

## Pins

```bash
fips-pubpki issuer add npub1….fips npub1…    # a bare-key issuer a friend gave you
fips-pubpki issuer add example.org npub1…    # trust this key for the domain by hand
fips-pubpki issuer list
fips-pubpki issuer remove example.org npub1…
```

A pin made by hand outranks every verification: no DNS answer, signed
or not, replaces or removes it. Pins the verifier made itself show
their method (`dnssec`, `attested`) and are replaced only by a
verification at least as strong. Resolving a name under a bare-key
issuer, or verifying its bundle, pins that key for you: you chose it by
asking.

## Offline

A bundle is a JSON file with everything a verifier needs: the
certificate, the delegations above it, the issuer's claim with its
DNSSEC chain, attestations. Anyone can hand it over by any means.

```bash
fips-pubpki bundle alice@example.org -o alice.json    # on a machine that reaches the relays
fips-pubpki verify alice.json                         # on one that does not
```

`verify` checks every signature, places the issuer from the bundle's own
claim (chain, or your witnesses' attestations, or your pin), runs the
same path validation as `resolve`, and remembers what it learnt:
afterwards `resolve`, `encrypt` and `verify-sig` work for that name
with no relay in reach. A bundle cannot roll you back: a revocation or
renewal you have seen wins over an older copy in a bundle, and a
revocation marker arriving in a bundle is learnt even though that
bundle "fails".

`verify` also takes a single certificate event (`{...}` instead of
`[...]`), which is what an issuer's `issued.json` holds per name.

## Signing

```bash
fips-pubpki sign release.tar                      # writes release.tar.sig.json
fips-pubpki verify-sig release.tar --sig release.tar.sig.json
signature valid; signer npub1alice…
  alice@example.org  (issuer npub1root…)
```

A signature is a Nostr event (kind 9200, never published) over the
file's SHA-256, signed by your `key:`; the key never signs raw bytes
another protocol might interpret. `verify-sig` checks the event, then
lists the names the signer validly holds whose certificate allows
`sign`. A valid signature from a key that holds no name is still
printed as valid: the binding to a name is a separate statement.

## Encrypting

```bash
echo "meet at the relay" | fips-pubpki encrypt alice@example.org > msg.txt
fips-pubpki decrypt --from npub1bob… msg.txt
```

`encrypt` resolves the name, requires a certificate allowing `encrypt`,
and encrypts (NIP-44 v2) from your key to each of the subject's keys;
one payload for one key, a JSON list for several devices. `decrypt`
needs the sender's key (`--from`). Transport is yours: a Nostr DM, a
file, anything. Multi-recipient wrapping (NIP-59) is an application's
choice above this.

## The file

`issuers.json` (spec §6) is written before a command prints its answer;
if it cannot be (a plain user with the system default path), the answer
is printed anyway with a warning, and `issuers:` should point somewhere
writable. It holds three things, all for authors you trust:
the issuer pins with their method, the newest timestamp seen per
certificate and claim (so a relay cannot roll an event back), and the
trusted issuers' newest certificates and markers (so a name verified
once resolves offline, and a revocation seen once stays seen). Strangers'
events are answered and forgotten at exit; the file grows only with
issuers you placed. It is plain JSON; edit it only to remove.

## Troubleshooting

- **`no certificate found` for a name you know exists**: your relays do
  not have it. The issuer publishes to its relays (`ca status` there
  shows which); add one of them to `mesh_relays` or `public_relays`.
  A `.fips` relay name resolves only on a node with fips running.
- **`issuer not anchored`** for a public domain: its claim carries no
  usable chain (unsigned zone, chain expired) and you have no witnesses
  or pin for it. `fips-pubpki issuer add example.org npub1…` after
  checking the key out of band is the manual answer; witnesses are the
  automatic one.
- **`through _@example.org: expired`**: a delegation above the name
  lapsed; the issuer must renew it. Nothing you can do locally.
- **`DISPUTED`**: two anchored keys of the domain issued different keys
  for one name. The protocol refuses to pick; the domain's owner must
  revoke one.
- **A pin you did not make** (`dnssec`, `attested` in `issuer list`):
  the verifier made it from a verification. `issuer remove` forgets it.
- **Lookups are slow**: each relay fetch waits up to `budget_ms`, mesh
  relays first, then public ones. Drop relays that never answer.
