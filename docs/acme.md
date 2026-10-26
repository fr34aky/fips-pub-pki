# TLS certificates for services on the mesh

How a web server, a relay or any TLS service on a fips node gets a
certificate for `https://relay.example.org` and `https://<npub>.fips`
from the domain's own CA, with an ordinary ACME client, and how the
browsers on the mesh come to trust it. The protocol pieces are in
[spec.md](spec.md) §8a and [nip.md](nip.md) "The X.509 root statement";
the design and what was rejected is in
[design-history.md](design-history.md).

## The idea in four sentences

The domain's CA runs an ACME server (RFC 8555) that listens **only on
the CA node's fips address**. On fips a packet from the address `fd…`
can only come from the node holding the key that address is derived
from, so **the connection itself proves which node is asking**; there
is no challenge round, and an operator allowlist says which nodes may
ask at all. A certificate may carry the node's own `<npub>.fips` name
and the names under the domain that the domain's zone maps to that node.
The X.509 root is **published through the PKI** as the domain's
`_x509@<domain>` statement, so `fips-pubpki trust example.org` can fetch
it, verify it the way any certificate is verified, and hand you the PEM
to install.

## Prerequisites

- The issuer side of [issuer.md](issuer.md): `ca init`, and for a public
  domain the `_fips-ca` record and `ca publish`. A bare-key CA
  (`<npub>.fips`) works too, for `<npub>.fips` names only.
- fips on the CA node, so that it has a fips address to listen on.
- For human-readable names: the domain's zone, as
  fips-pub-domains's server has it (`/etc/fips-pubdom/zones/<domain>.yaml`,
  `relay: npub1…`), on the CA node or published by the domain's servers
  on the relays. No zone means `<npub>.fips` names only.

## Setting up the CA side

```bash
# the CA node's npub: the key of the node whose fips address serves ACME
# (fips prints it; or `fips-pubpki ca status` if the issuer key is the node key)
sudo fips-pubpki acme init --node npub1…
```

`acme init` creates `/etc/fips-pubpki/x509-root.key` (P-256, mode 0600)
and `/etc/fips-pubpki/x509-root.crt` if they do not exist, then issues
and publishes the `_x509@<domain>` statement with the root inside, the
node as subject, so that every verifier of the domain can find the root
and the ACME directory. It prints the directory URL,
`http://[fd…]:8555/directory`. Put `acme_node: npub1…` in the
configuration so the server and `acme status` know it without the flag.

```bash
sudo fips-pubpki acme allow npub1web…   --note "www node"
sudo fips-pubpki acme allow npub1relay… --note "relay"
sudo systemctl enable --now fips-pubpki-acme.service
sudo fips-pubpki acme status
```

The unit runs `fips-pubpki acme serve`: it binds the node's fips address
(waiting up to a minute for the tun to come up) and, on Linux with
`acme_interface: fips0` set, the interface itself; it re-reads the
allowlist when it changes, so `acme allow` needs no restart. It decides
where the zone comes from at start: the configured file (whose
`acme_zone_author` must then name the node serving that zone), the
server's own `/etc/fips-pubdom/zones/<domain>.yaml`, the configured
`acme_zone_servers`, or the servers the `_fips-dns` record names; when
that record cannot be looked up at all the server exits so the unit
retries, rather than quietly issuing `.fips` names only. `acme deny`
withdraws a node; what it already holds runs out within the
certificate's validity (30 days by default), or the node revokes it.

Configuration keys ([users.md](users.md#configuration) has the rest):

```yaml
acme_node: npub1…                      # the listener is its fd… address
acme_port: 8555                        # the port clients expect; another one is not discoverable
acme_interface: fips0                  # Linux: accept from the fips tun only
acme_validity_days: 30                 # leaves; clients renew
acme_zone_file: /etc/fips-pubdom/zones/example.org.yaml   # default if present
acme_zone_servers: []                  # else: fetch the zone from these fips-dns nodes
```

**Never expose the ACME endpoint on another interface or behind a
proxy.** The whole authorization rests on the source address having
come over fips. There is no HTTPS on the endpoint and nothing to
authenticate it with before the root exists; the mesh encrypts and
authenticates the hop.

## On a node that wants a certificate

Any ACME client. The server offers no challenge: the authorization is
valid the moment the order is created, and the clients below all skip
straight to finalizing. The names you ask for must be your own
`<npub>.fips` and names the zone maps to you; anything else is refused
with a `rejectedIdentifier` that names the identifier and the reason.

certbot (an authenticator must be named even though none runs):

```bash
sudo certbot certonly --server 'http://[fd…]:8555/directory' \
     --standalone --register-unsafely-without-email \
     -d relay.example.org -d npub1relay….fips
```

lego:

```bash
lego --server 'http://[fd…]:8555/directory' --email you@example.org \
     --domains relay.example.org --domains npub1relay….fips --http run
```

acme.sh:

```bash
acme.sh --server 'http://[fd…]:8555/directory' --issue --standalone \
        -d relay.example.org -d npub1relay….fips
```

Caddy, in the global options:

```
{
    acme_ca http://[fd…]:8555/directory
}
```

In Rust, instant-acme with a plain HTTP client, exactly as the
repository's integration test does (`crates/pubpki-acme/tests/acme_flow.rs`).

What comes back is a two-certificate PEM chain: the leaf (30 days,
`serverAuth`, the names as SANs, a common name only where one fits) and
the root. The client renews on its own schedule; the server keeps no
state a renewal depends on beyond the allowlist.

A CSR with extensions the server does not know (must-staple, custom
OIDs) is refused as `badCSR`; so is a CSR whose names differ from the
order's, or an RSA key under 2048 bits.

## Trusting the root

On every machine that should accept these certificates:

```bash
fips-pubpki trust example.org -o fips-example-org.crt
```

resolves `_x509@example.org` through the PKI (your pins, the chain in the
issuer's claim, your witnesses, as for any name), checks that the
content's SHA-256 is the statement's `x` tag and that it is a
self-signed, unexpired CA certificate, prints the path and the ACME
directory, and writes the PEM. With no relay in reach, `--bundle FILE`
takes the statement's event from a file handed over by any means.

Then install it:

- Debian/Ubuntu: `sudo cp fips-example-org.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`
- Fedora/RHEL/Arch: `sudo cp fips-example-org.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust`
  (Arch: `/etc/ca-certificates/trust-source/anchors/` and `trust extract-compat`)
- Firefox: its own store; Settings → Certificates → Import, or an
  enterprise policy that imports from the system store.
- Android: Settings → Security → Install a certificate → CA certificate
  (user store; apps that pin the system store will not see it).

The root expires after ten years by default; `trust` says when.

## Revocation

```bash
certbot revoke --server 'http://[fd…]:8555/directory' --cert-path …   # from the node that holds it
```

Only the node a certificate was issued to can revoke it. Revocation is
recorded in the CA's index; there is no CRL and no OCSP, and the
validity is short instead. `fips-pubpki acme status` lists what is
live and what is revoked.

## What it does not do

- No challenges, no External Account Binding, no path for clients off
  the mesh: the connection is the proof, and the allowlist the
  authorization.
- No wildcard certificates (`*.example.org` is refused; the zone's own
  `*` entry still lets a node obtain explicit names under it).
- No HTTPS on the ACME endpoint, no CRL, no OCSP, no must-staple.
- No IP identifiers; `<npub>.fips` is the name a node has.

## Troubleshooting

- **Client: connection refused or timeout**: the client is not on the
  mesh, or the server is not up (`systemctl status fips-pubpki-acme`,
  `journalctl -u fips-pubpki-acme`). `fips-pubpki acme status` on the CA
  prints the listen address; compare with `ip -6 addr` on the CA node.
- **`unauthorized` at account creation**: the node's npub is not
  allowed. `fips-pubpki acme allow <npub>` on the CA. The npub must be
  the key of the node the client runs on; the log on the CA shows the
  refused address.
- **`rejectedIdentifier`**: the subproblem says why: the zone does not
  map the name to your node, maps it to another, the name is outside
  the domain, or it is another key's `.fips` name. Fix the zone on the
  domain's server (and let it publish) or ask for the right name.
- **`badCSR`**: the client asked for an extension the server does not
  take (Caddy's `must_staple`, custom OIDs), or the CSR's names differ
  from the order's.
- **`fips-pubpki trust`: no X.509 root statement found**: the CA has
  not run `acme init`, or your relays do not have the statement; with
  the event in a file, `--bundle`.
