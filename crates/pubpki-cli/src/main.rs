//! `fips-pubpki`: the issuer's and the user's tool. The command set is
//! the one docs/roadmap.md lists; each lands with the module behind it.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "fips-pubpki",
    version,
    about = "Certificates for name@domain as Nostr events, anchored in fips public domains"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Issuer operations: init, issue, issue-ca, renew, revoke, publish, status
    Ca {
        #[command(subcommand)]
        cmd: CaCmd,
    },
    /// Resolve a name@domain to its subject keys, with the path that proves it
    Resolve,
    /// Verify a certificate or an offline bundle
    Verify,
    /// Sign data: a detached signature event for the data's hash
    Sign,
    /// Verify a detached signature and resolve the signer's name
    VerifySig,
    /// Encrypt to a name (NIP-44)
    Encrypt,
    /// Decrypt with this node's key
    Decrypt,
    /// Export the offline bundle for a name
    Bundle,
    /// Emit /.well-known/nostr.json from the issuer's certificates
    NostrJson,
}

#[derive(Subcommand, Debug)]
enum CaCmd {
    Init,
    Issue,
    IssueCa,
    Renew,
    Revoke,
    Publish,
    Status,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    anyhow::bail!("{:?}: not implemented yet (docs/roadmap.md)", cli.cmd)
}
