use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use x3x::x4x::{
    Error, decrypt_file, default_decrypted_path, default_encrypted_path, encrypt_file, password,
};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "x4x",
    version,
    about = "Password-based authenticated file encryption",
    long_about = "Encrypt and decrypt files with Argon2id and XChaCha20-Poly1305.\n\
                  Passwords are prompted for without echo by default; use --password-file for automation."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Encrypt a file. The source file is never modified.
    Encrypt(FileArgs),
    /// Decrypt and authenticate a file. No output is committed unless all data verifies.
    Decrypt(FileArgs),
}

#[derive(Debug, Args)]
struct FileArgs {
    /// Input file
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Output file (defaults to INPUT.x4x when encrypting)
    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// Read the password from a file instead of prompting (one trailing CRLF/LF is removed)
    #[arg(long, value_name = "PASSWORD_FILE")]
    password_file: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Error> {
    match cli.command {
        Command::Encrypt(args) => {
            let output = args
                .output
                .unwrap_or_else(|| default_encrypted_path(&args.input));
            let password = acquire_password(args.password_file.as_deref(), true)?;
            encrypt_file(&args.input, &output, &password)?;
            println!(
                "Encrypted '{}' to '{}'.",
                args.input.display(),
                output.display()
            );
        }
        Command::Decrypt(args) => {
            let output = args
                .output
                .unwrap_or_else(|| default_decrypted_path(&args.input));
            let password = acquire_password(args.password_file.as_deref(), false)?;
            decrypt_file(&args.input, &output, &password)?;
            println!(
                "Decrypted '{}' to '{}'.",
                args.input.display(),
                output.display()
            );
        }
    }
    Ok(())
}

fn acquire_password(path: Option<&Path>, confirm: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
    if let Some(path) = path {
        return password::read_password_file(path);
    }

    let first = password::prompt("Password: ")?;
    if confirm {
        let second = password::prompt("Confirm password: ")?;
        if first.as_slice() != second.as_slice() {
            return Err(Error::PasswordsDoNotMatch);
        }
    }
    Ok(first)
}
