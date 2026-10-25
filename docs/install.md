# Installing

One binary comes out of this repository, `fips-pubpki`, and a machine
holds one of two roles with it, or both:

| role | what runs | section | then |
|---|---|---|---|
| an **issuer**: the owner of a domain (or of a bare key) certifying names | `fips-pubpki ca …` and the renewal unit | [The issuer](#the-issuer) | [issuer.md](issuer.md) |
| a **user**: resolving, verifying, signing and encrypting with names | `fips-pubpki` commands, no service | [The user side](#the-user-side) | [users.md](users.md) |

Both read `/etc/fips-pubpki/config.yaml` and keep their state under
`/var/lib/fips-pubpki/`. Nothing here touches fips's own files, the
fips-pubdom resolver's, or the OS resolver: the verifier never queries
DNS, so there is nothing to wire into the system. [how-it-works.md](how-it-works.md)
explains what the pieces are before you install them.

## Getting the binary

Until there is a release archive, build from source. Rust 1.85 or newer
(edition 2024); a C toolchain is not needed.

```bash
git clone https://github.com/fr34aky/fips-pub-pki.git
cd fips-pub-pki
cargo build --release
ls -l target/release/fips-pubpki
```

`cargo test --workspace` runs the whole test ladder's level 0 with no
network ([testing.md](testing.md)). The two library crates build for
Android too; the phone does not take the binary.

Where things go, either role:

| what | where |
|---|---|
| the binary | `/usr/bin/fips-pubpki` (a user alone may use `~/.local/bin/`) |
| configuration | `/etc/fips-pubpki/config.yaml`, all keys optional ([users.md](users.md#configuration)) |
| the verifier's file: pinned issuers, anti-rollback, kept certificates | `/var/lib/fips-pubpki/issuers.json` |
| the issuer key | `/etc/fips-pubpki/ca.key` (`ca init` writes it, mode 0600) |
| what the issuer has issued | `/var/lib/fips-pubpki/issued.json` |
| the renewal unit | `/etc/systemd/system/fips-pubpki-ca.service` |

## The issuer

A node (any Linux machine with the mesh reachable, usually the one that
already runs `fips-pubdom-server` for the domain) that issues and renews
certificates. The key never has to be online for issuing: see
[issuer.md](issuer.md) for an offline root and an online issuing key.

### Install

```bash
# from a source build, in the repository:
sudo install -m 0755 target/release/fips-pubpki /usr/bin/
sudo install -m 0644 packaging/systemd/fips-pubpki-ca.service /etc/systemd/system/
sudo install -d -m 0755 /etc/fips-pubpki /var/lib/fips-pubpki

# configuration: relays to publish to, the domain, the paths (defaults shown)
sudo tee /etc/fips-pubpki/config.yaml >/dev/null <<'YAML'
mesh_relays: ["ws://npub1….fips:80"]      # your relay on the mesh, by .fips name
public_relays: []                          # optional; a public relay learns your names
ca_domain: example.org                     # omit for a bare-key issuer (<npub>.fips)
ca_key: /etc/fips-pubpki/ca.key
ca_issued: /var/lib/fips-pubpki/issued.json
ca_validity_days: 90
YAML

# the key, and what to publish in DNS
sudo fips-pubpki ca init
```

`ca init` prints the issuer's npub and, for a public domain, the TXT
record to publish:

```
_fips-ca.example.org.  TXT  "v=fips1 npub=npub1…"
```

Publish it at your DNS hoster (DNSSEC-signed zones let verifiers accept
the issuer offline; unsigned zones need witnesses, see
[issuer.md](issuer.md#witnesses)). Then publish the claim and start the
renewal loop:

```bash
sudo fips-pubpki ca publish            # the claim with its DNSSEC chain, and anything issued
sudo groupadd -f fips-pubpki
sudo chgrp fips-pubpki /etc/fips-pubpki/ca.key && sudo chmod 0640 /etc/fips-pubpki/ca.key
sudo chgrp -R fips-pubpki /var/lib/fips-pubpki && sudo chmod 0775 /var/lib/fips-pubpki
sudo systemctl daemon-reload
sudo systemctl enable --now fips-pubpki-ca.service
systemctl status fips-pubpki-ca.service
```

The unit runs `fips-pubpki ca renew --watch` as a dynamic user in group
`fips-pubpki`: it reads the key, re-issues every live certificate halfway
through its validity, writes `issued.json`, and publishes. Issue and
revoke by hand with `sudo -g fips-pubpki fips-pubpki ca issue …` or as
root; the loop picks the new certificates up at its next check (within
an hour at most; `systemctl restart fips-pubpki-ca` makes it now).

### Upgrade

```bash
cd fips-pub-pki && git pull && cargo build --release
sudo install -m 0755 target/release/fips-pubpki /usr/bin/
sudo install -m 0644 packaging/systemd/fips-pubpki-ca.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart fips-pubpki-ca.service
fips-pubpki --version
```

Configuration and state files are read by every version; a key the new
version does not know is an error on purpose (a typo must not silently
mean a default), and the [CHANGELOG](../CHANGELOG.md) names any new key.
`issued.json` and `issuers.json` only ever gain fields.

### Uninstall

```bash
sudo systemctl disable --now fips-pubpki-ca.service
sudo rm /etc/systemd/system/fips-pubpki-ca.service /usr/bin/fips-pubpki
sudo systemctl daemon-reload
# the key and what was issued: keep them unless the issuer is retired for good
# sudo rm -r /etc/fips-pubpki /var/lib/fips-pubpki
```

Retiring an issuer for good is a protocol act, not a file removal:
remove its key from the `_fips-ca` record (or revoke its sub-issuer
certificate) so verifiers stop trusting it, and let what it issued
expire ([issuer.md](issuer.md#retiring-a-key)).

## The user side

A machine that resolves names, verifies bundles, signs and encrypts. No
service, no firewall change, no OS resolver change.

### Install

```bash
# from a source build, in the repository:
sudo install -m 0755 target/release/fips-pubpki /usr/bin/      # or: install -m 0755 … ~/.local/bin/
sudo install -d -m 0755 /etc/fips-pubpki

sudo tee /etc/fips-pubpki/config.yaml >/dev/null <<'YAML'
mesh_relays: ["ws://npub1….fips:80"]      # relays on the mesh, asked first
public_relays: []                          # optional, asked when the mesh had nothing
issuers: /var/lib/fips-pubpki/issuers.json # or a path in your home for a single user
key: /etc/fips/fips.key                    # this node's key, for sign/decrypt (group fips reads it)
witnesses: []                              # npubs whose fips-ca attestations count
attestation_threshold: 2
YAML
```

A single user keeps everything under the home directory instead:
`fips-pubpki --config ~/.config/fips-pubpki/config.yaml …` with
`issuers: ~/.local/state/fips-pubpki/issuers.json` and `key:` pointing at
an `nsec` or key file of their own. Then:

```bash
fips-pubpki resolve alice@example.org
fips-pubpki issuer add npub1….fips npub1…     # trust a bare-key issuer a friend gave you
fips-pubpki verify bundle.json                 # with no network at all
```

[users.md](users.md) has every command.

### Upgrade

```bash
cd fips-pub-pki && git pull && cargo build --release
sudo install -m 0755 target/release/fips-pubpki /usr/bin/
fips-pubpki --version
```

### Uninstall

```bash
sudo rm /usr/bin/fips-pubpki
# sudo rm -r /etc/fips-pubpki /var/lib/fips-pubpki   # the pins and what was verified
```

## Android

Nothing from here is installed on a phone. The two library crates
(`pubpki-core`, `pubpki`) build for Android and are meant to be embedded
by fips2go, which is [roadmap.md](roadmap.md)'s phone item; CI checks the
Android build on every change.

## Other platforms

The binary builds and its tests pass on Linux, macOS and Windows (CI).
The systemd unit is Linux's; on another platform run
`fips-pubpki ca renew --watch` under that platform's service manager, or
`fips-pubpki ca renew` from a daily scheduled task: renewal is idempotent
and only touches what is past half its validity.
