# Running an issuer

How the owner of `example.org` (or of a bare key) certifies that
`alice@example.org` is a given Nostr key, keeps that true, and takes it
back. The commands are `fips-pubpki ca …`; [install.md](install.md) puts
the binary, the configuration and the renewal unit in place. What the
verifier does with all this is [how-it-works.md](how-it-works.md).

## Prerequisites

- A relay the people who will resolve your names can reach: one on the
  mesh (`ws://npub1….fips:80`, the strfry-over-fips relay fips-pub-domains
  documents) is the normal case; a public relay is optional and learns
  which names you issue.
- For a public domain: control of its DNS. A DNSSEC-signed zone lets
  every verifier accept you offline from the chain in your claim; an
  unsigned zone needs [witnesses](#witnesses).
- For a bare key: nothing. Your issuer name is `<npub>.fips`, and the
  people who trust you pin your key.

## 1. The key

```bash
sudo fips-pubpki ca init                 # with ca_domain in the configuration
sudo fips-pubpki ca init --domain example.org
```

Writes `/etc/fips-pubpki/ca.key` if it does not exist (64 hex characters,
mode 0600; an existing file, or an `nsec`, is used as is) and prints the
issuer npub. The issuer key is deliberately **not** the node's fips key:
the node key signs claims and serves names, the issuer key certifies
people; keep them apart so that losing one does not cost the other.

## 2. The record, or the pin

**Public domain.** `ca init` printed the record:

```
_fips-ca.example.org.  TXT  "v=fips1 npub=npub1…"
```

Publish it at the hoster. Several records name several issuer keys
(an offline root and an online issuing key, or two administrators);
each key publishes its own claim. Removing a record withdraws that key.

**Bare key.** There is no record. Give your issuer name
`<npub>.fips` and your npub to the people who should trust you, in
person or over a channel you trust; they run
`fips-pubpki issuer add <npub>.fips <npub>`. Everything below works the
same, except that `ca publish` publishes certificates only.

## 3. The claim

```bash
sudo fips-pubpki ca publish
```

Builds the DNSSEC chain for `_fips-ca.example.org` from your upstream
resolvers (`upstreams:` in the configuration, or the system's), checks
that it names your key, and publishes your NIP-DB claim (kind 37197,
role `fips-ca`) with the chain inside, then every unexpired certificate
you have issued. A verifier anywhere, online or not, can then place your
key from the claim alone.

If the zone is not signed, the claim goes out without a chain and the
command says so: verifiers then need `k` witnesses, or a pin. With
`--require-chain` it refuses instead. `ca status --dns` shows what the
legacy DNS currently says about your record.

The chain expires with its RRSIGs (days to weeks); re-run `ca publish`
after rotating keys at the hoster or when `ca status --dns` shows a
problem. A refresh loop for the claim is an open item
([roadmap.md](roadmap.md)); the renewal unit handles certificates.

## 4. Issuing

```bash
sudo fips-pubpki ca issue alice@example.org --subject npub1alice… \
     --usage sign --usage encrypt --days 90 --relay wss://relay.example.org
sudo fips-pubpki ca issue bob@example.org --subject npub1phone… --subject npub1laptop…
```

- `--subject` once per key: several keys are several devices of one
  person, all equally the subject.
- `--usage` absent means `sign` and `encrypt`. `ca` is not for people.
- `--days` defaults to `ca_validity_days` (90). Short is right: a
  certificate that stops being renewed lapses on its own.
- `--relay` hints where the subject reads, for correspondents.
- `--no-publish` signs and records without publishing;
  `ca publish --certs-only` later.

Verify a subject's key the way you verify anything that matters: in
person, over a channel you trust. The tool cannot do that part for you,
and there is no HTTP challenge to replace it for a person's key.

A name already live is refused by `issue`: renew it, or revoke it first.
What is issued is recorded in `/var/lib/fips-pubpki/issued.json` and
shown by `ca status`:

```
2 event(s) issued:
  alice@example.org                        live             expires      89d  1 key(s) sign,encrypt
  _@sales.example.org                      live             expires      89d  1 key(s) ca
```

`fips-pubpki nostr-json` renders `/.well-known/nostr.json` from the
same file for clients that only know NIP-05; serve it from the domain's
web root if you have one.

## 5. Sub-issuers

A sub-issuer certificate is `_@<domain>` with `usage ca`. Its holder may
issue names at or under `<domain>` and nothing else; that is all the
constraint there is, and it comes from the name.

**An offline root and an online issuing key.** Generate the root on a
machine that stays offline, list its npub in `_fips-ca.example.org`,
and let it certify the key that does the daily work:

```bash
# on the offline machine, as the root:
fips-pubpki --config root.yaml ca issue-ca example.org --subject npub1online… --pathlen 1 --days 365 --no-publish
# carry issued.json (or the printed event) to the online machine and publish it there:
fips-pubpki ca publish --certs-only
```

The online key then issues `alice@example.org` with its own
`ca issue`; the root never comes online again until the delegation
needs renewing or revoking. No DNS change for either.

**A department.** `example.org` certifies `_@sales.example.org` for the
department's key; that key issues `bob@sales.example.org` and, if
`--pathlen` allows, further sub-issuers below it:

```bash
sudo fips-pubpki ca issue-ca sales.example.org --subject npub1sales… --pathlen 0
```

`--pathlen 0` means no further delegation below; `1` allows one more
level. Paths are at most four certificates long, the person's included.

The department runs its own `fips-pubpki` with `ca_domain:
sales.example.org` and its own key; its `ca init` prints no DNS record,
because its authority is the delegation, not a record.

## 6. Renewal

```bash
sudo fips-pubpki ca renew              # everything past half its validity
sudo fips-pubpki ca renew alice@example.org   # this one now
sudo fips-pubpki ca renew --force      # everything live
```

A renewal is the same certificate with a fresh validity of the same
length and a later timestamp; relays keep the newest. The unit from
[install.md](install.md) (`ca renew --watch`) does this on its own,
checking at least hourly and sleeping until the next one is due; it
re-reads `issued.json` every round, so what you issue or revoke by hand
while it runs is picked up within the hour.

A certificate that expired while the node was down is renewed too, as
long as it has not been expired for longer than its own validity; past
that it counts as abandoned on purpose, and only `--force` (everything
not revoked, expired included) or a fresh `ca issue` revives it. Revoked
names are never renewed.

What no relay accepted stays recorded as unpublished (`ca status` marks
it) and is retried by the loop every round and by `ca publish`; a relay
outage therefore delays a renewal, never loses it.

## 7. Revocation

```bash
sudo fips-pubpki ca revoke alice@example.org --reason "lost phone"
```

Publishes a marker: the same name and keys, the same expiration, a
`revoked` tag, a later timestamp. Verifiers that have seen it refuse
the certificate even when it is presented out of band, and keep that
knowledge across restarts. Nothing is deleted from relays (a deletion
might not be honoured); the marker expires when the certificate would
have. To give the person a new key, `ca issue` the name again
afterwards.

Revoking a sub-issuer certificate (`ca revoke _@sales.example.org`)
invalidates everything issued below it, at every verifier that sees
the marker.

## 8. Retiring a key

- An **anchored** key (listed in `_fips-ca`): remove its record. Verifiers
  forget a pin on a denial at least as strong as the pin, so a
  DNSSEC-verified pin needs the signed denial, which the next verifier
  that looks will get. Anything the key issued expires on its own; revoke
  what must die sooner while you still hold the key.
- A **certified** key: revoke its sub-issuer certificate.
- A **bare key**: tell the people who pinned it (`fips-pubpki issuer
  remove`); there is nobody else to tell.

## Witnesses

A verifier with no DNSSEC chain to check (unsigned zone, or a client
that cannot validate) accepts your key when `k` witnesses it trusts have
attested it. Witnesses are nodes running fips-pub-domains's
`fips-pubdom attest` for your domain: from its `e6da51e` on, an
attestation carries the `fips-ca` keys of the domain next to its DNS
servers (`["p", <issuer>, "fips-ca"]`), re-verified by the witness from
the legacy DNS each time it re-publishes. Ask the operators of nodes
your users already trust to attest your domain; your users list those
nodes under `witnesses:` with `attestation_threshold: k`.

## Checking from another node

On any machine with the mesh relay configured:

```bash
fips-pubpki resolve alice@example.org
alice@example.org = npub1alice…
  alice@example.org by npub1online…  expires in 89d  [sign,encrypt]
    _@example.org by npub1root…  expires in 300d  [ca]
      anchor: npub1root… for example.org (Pinned)
```

`Pinned` here is the issuer pin the verifier made from your claim's
chain (`fips-pubpki issuer list` shows the method: `dnssec`,
`attested`, or `pinned` by hand). `fips-pubpki bundle alice@example.org
-o alice.json` exports what a machine with no network needs to verify
the same thing ([users.md](users.md#offline)).

## What the issuer does not do

- Verify a person's key for you.
- Issue names outside its domain: the tool refuses, and so would every
  verifier.
- Delete anything from a relay, or depend on a relay honouring a
  deletion.
- Touch the fips-pubdom pin file, the node key, or the OS resolver.
