//! Command-line interface. Passwords are read from a terminal or a named file,
//! never from command-line values or environment variables.
use crate::{
    Decryption, Encryption, Operation,
    error::{Error, IoContext, Result},
    secret,
};
use age::secrecy::{ExposeSecret, SecretString};
use clap::{Args, Parser, Subcommand};
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    sync::atomic::Ordering,
};

#[derive(Parser, Debug)]
#[command(
    name = "best",
    version,
    about = "Streaming, authenticated file encryption using age",
    long_about = "Encrypt, decrypt, and verify regular files using the interoperable binary age v1 format. Originals are kept. Existing outputs are never overwritten. Decrypted files are published only after complete authentication.",
    after_help = "EXAMPLES:\n  best encrypt report.pdf\n  best decrypt report.pdf.age -o restored.pdf\n  best keygen -o personal.key\n  best encrypt report.pdf -r age1...\n  best decrypt report.pdf.age -i personal.key -o restored.pdf\n  best verify report.pdf.age -i personal.key\n\nUse --password-file for automation. Keep password files and private keys protected.\nPassword encryption uses scrypt N=2^18 (about 256 MiB). No password recovery exists."
)]
pub(crate) struct Cli {
    /// Suppress success messages on stderr (public keys are still printed)
    #[arg(short, long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Encrypt a file; prompts for a password unless recipients are supplied
    Encrypt(EncryptArgs),
    /// Decrypt a file and publish output only after full authentication
    Decrypt(DecryptArgs),
    /// Authenticate an entire encrypted file without saving plaintext
    Verify(VerifyArgs),
    /// Generate a private X25519 identity; print its public recipient
    Keygen {
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Print public recipients from an X25519 identity file
    Recipients {
        #[arg(short, long)]
        identity: PathBuf,
    },
}

#[derive(Args, Debug)]
struct Limits {
    /// Refuse plaintext larger than this number of bytes
    #[arg(long)]
    max_bytes: Option<u64>,
}

#[derive(Args, Debug)]
struct EncryptArgs {
    input: PathBuf,
    /// Destination (default: INPUT.age); must not already exist
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// age X25519 recipient; repeat for multiple recipients (maximum 64)
    #[arg(short, long, conflicts_with = "password_file")]
    recipient: Vec<String>,
    /// Read one UTF-8 password line from a protected file instead of prompting
    #[arg(long, value_name = "FILE")]
    password_file: Option<PathBuf>,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Args, Debug)]
struct Unlock {
    /// X25519 identity file; repeat to try multiple files (maximum 4)
    #[arg(short, long, conflicts_with_all = ["password_file", "max_work_factor"])]
    identity: Vec<PathBuf>,
    /// Read one UTF-8 password line from a protected file instead of prompting
    #[arg(long, value_name = "FILE")]
    password_file: Option<PathBuf>,
    /// Maximum accepted scrypt log2(N), 1..20 (default 18; 20 uses about 1 GiB)
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=20))]
    max_work_factor: Option<u8>,
}

#[derive(Args, Debug)]
struct DecryptArgs {
    input: PathBuf,
    /// Destination (default: strip .age); must not already exist
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[command(flatten)]
    unlock: Unlock,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    input: PathBuf,
    #[command(flatten)]
    unlock: Unlock,
    #[command(flatten)]
    limits: Limits,
}

fn password(path: Option<&std::path::Path>, encrypting: bool) -> Result<SecretString> {
    if let Some(path) = path {
        return secret::password_file(path, encrypting);
    }
    let password = SecretString::from(
        rpassword::prompt_password("Password: ")
            .context("cannot read terminal password; for automation use --password-file")?,
    );
    secret::validate_password(&password, encrypting)?;
    if encrypting {
        let confirm = SecretString::from(
            rpassword::prompt_password("Confirm password: ")
                .context("cannot read password confirmation")?,
        );
        if password.expose_secret() != confirm.expose_secret() {
            return Err(Error::Invalid("passwords do not match"));
        }
    }
    Ok(password)
}

fn unlock(args: Unlock) -> Result<Decryption> {
    if args.identity.is_empty() {
        Ok(Decryption::Password {
            password: password(args.password_file.as_deref(), false)?,
            max_work_factor: args.max_work_factor.unwrap_or(crate::PASSWORD_WORK_FACTOR),
        })
    } else {
        if args.identity.len() > 4 {
            return Err(Error::Invalid("at most 4 identity files may be supplied"));
        }
        let mut identities = Vec::new();
        for path in args.identity {
            identities.extend(secret::identities_file(&path)?);
        }
        Ok(Decryption::Identities(identities))
    }
}

fn run(cli: Cli, mut op: Operation) -> Result<()> {
    let message = match cli.command {
        Command::Encrypt(args) => {
            op.max_bytes = args.limits.max_bytes;
            let output = args
                .output
                .unwrap_or_else(|| crate::files::encrypted_path(&args.input));
            let method = if args.recipient.is_empty() {
                Encryption::Password(password(args.password_file.as_deref(), true)?)
            } else {
                Encryption::Recipients(crate::recipients(&args.recipient)?)
            };
            let count = crate::encrypt_file(&args.input, &output, method, &op)?;
            format!("Encrypted {count} bytes -> {output:?}")
        }
        Command::Decrypt(args) => {
            op.max_bytes = args.limits.max_bytes;
            let output = match args.output {
                Some(path) => path,
                None => crate::files::decrypted_path(&args.input)?,
            };
            let count = crate::decrypt_file(&args.input, &output, unlock(args.unlock)?, &op)?;
            format!("Decrypted and authenticated {count} bytes -> {output:?}")
        }
        Command::Verify(args) => {
            op.max_bytes = args.limits.max_bytes;
            let count = crate::verify_file(&args.input, unlock(args.unlock)?, &op)?;
            format!("Verified: all {count} plaintext bytes authenticated")
        }
        Command::Keygen { output } => {
            let public = crate::keygen(&output)?;
            writeln!(io::stdout().lock(), "{public}")
                .context("identity saved, but cannot print public key")?;
            format!("Private identity saved -> {output:?}; back it up securely")
        }
        Command::Recipients { identity } => {
            let keys = secret::identities_file(&identity)?;
            let mut stdout = io::stdout().lock();
            for key in keys {
                writeln!(stdout, "{}", key.to_public()).context("cannot print public recipient")?;
            }
            return Ok(());
        }
    };
    if !cli.quiet {
        // Success diagnostics must not turn an already committed operation into
        // a reported failure merely because the caller closed stderr.
        let _ = writeln!(io::stderr().lock(), "{message}");
    }
    Ok(())
}

pub fn main_entry() -> ExitCode {
    let cli = Cli::parse();
    let op = Operation::default();
    let cancelled = op.cancelled.clone();
    if let Err(error) = ctrlc::set_handler(move || cancelled.store(true, Ordering::Relaxed)) {
        let _ = writeln!(
            io::stderr().lock(),
            "best: cannot install cancellation handler: {error}"
        );
        return ExitCode::FAILURE;
    }
    match run(cli, op) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "best: {error}");
            if matches!(error, Error::Cancelled) {
                ExitCode::from(130)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
