#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "be",
    version,
    about = "Reliable, interoperable file encryption using the age v1 format",
    after_help = "key.key, key.pub, input, and output are located beside the executable.\n\
                  File arguments must be bare names. Existing files are never overwritten."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new age-compatible key.key and key.pub.
    #[command(name = "keygen")]
    Keygen,

    /// Encrypt INPUT to OUTPUT using key.pub.
    #[command(name = "E", visible_aliases = ["e", "encrypt"])]
    Encrypt { input: PathBuf, output: PathBuf },

    /// Authenticate, then decrypt INPUT to OUTPUT using key.key.
    #[command(name = "D", visible_aliases = ["d", "decrypt"])]
    Decrypt { input: PathBuf, output: PathBuf },

    /// Authenticate an encrypted file without writing plaintext.
    #[command(name = "verify")]
    Verify { input: PathBuf },

    /// Print the public recipient derived from key.key.
    #[command(name = "pubkey")]
    PublicKey,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let executable = std::env::current_exe().context("could not locate the executable")?;
    let directory = executable
        .parent()
        .context("the executable has no parent directory")?;

    match cli.command {
        Command::Keygen => {
            let recipient = be::keygen_in(directory)?;
            println!("created {}", directory.join(be::SECRET_KEY_FILE).display());
            println!("created {}", directory.join(be::PUBLIC_KEY_FILE).display());
            println!("public key: {recipient}");
            println!("Back up key.key securely. It is required for decryption.");
        }
        Command::Encrypt { input, output } => {
            let bytes = be::encrypt_in(directory, &input, &output)?;
            println!(
                "encrypted {} -> {} ({bytes} bytes)",
                input.display(),
                output.display()
            );
        }
        Command::Decrypt { input, output } => {
            let bytes = be::decrypt_in(directory, &input, &output)?;
            println!(
                "decrypted {} -> {} ({bytes} bytes)",
                input.display(),
                output.display()
            );
        }
        Command::Verify { input } => {
            let bytes = be::verify_in(directory, &input)?;
            println!("verified {} ({bytes} plaintext bytes)", input.display());
        }
        Command::PublicKey => println!("{}", be::public_key_in(directory)?),
    }
    Ok(())
}
