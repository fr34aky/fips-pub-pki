# Packaging

Mirrors fips-pub-domains's `packaging/` layout; the two never touch each
other's files.

- `systemd/fips-pubpki-ca.service` — the issuer's renewal loop,
  `fips-pubpki ca renew --watch`: every live certificate is re-issued
  halfway through its validity and re-published. Needs
  `/etc/fips-pubpki/config.yaml` with the `ca_*` keys and the issuer key
  readable by group `fips-pubpki` ([../docs/install.md](../docs/install.md),
  [../docs/issuer.md](../docs/issuer.md)).

- `systemd/fips-pubpki-acme.service` — the ACME server for TLS on the
  mesh, `fips-pubpki acme serve`, on the CA node's fips address. Needs
  `acme init` done and the root key readable by group `fips-pubpki`
  ([../docs/acme.md](../docs/acme.md)).

No unit for the user side: `fips-pubpki resolve|verify|sign|encrypt|…` are
commands, not a service. A firewall drop-in is not needed: the tool opens
outbound connections to relays only.
