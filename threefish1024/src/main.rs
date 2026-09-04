use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use threefish1024::{DEFAULT_KEY_FILE, decrypt_file, encrypt_file, generate_key};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Authenticated file encryption using Threefish-1024",
    after_help = "The default key is ./key.key. Generate it once with `threefish1024 keygen`."
)]
struct Cli {
    /// Master-key file (defaults to key.key in the current directory).
    #[arg(long, global = true, default_value = DEFAULT_KEY_FILE, value_name = "FILE")]
    key: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new 1024-bit key without overwriting an existing key.
    #[command(visible_alias = "kegen")]
    Keygen,

    /// Encrypt `FILE_IN` into `FILE_OUT`.
    Encrypt {
        /// Plaintext input file.
        #[arg(value_name = "FILE_IN")]
        file_in: PathBuf,
        /// Authenticated encrypted output file.
        #[arg(value_name = "FILE_OUT")]
        file_out: PathBuf,
        /// Replace `FILE_OUT` if it already exists.
        #[arg(long, short)]
        force: bool,
    },

    /// Authenticate and decrypt `FILE_IN` into `FILE_OUT`.
    Decrypt {
        /// Encrypted input file.
        #[arg(value_name = "FILE_IN")]
        file_in: PathBuf,
        /// Plaintext output file.
        #[arg(value_name = "FILE_OUT")]
        file_out: PathBuf,
        /// Replace `FILE_OUT` if it already exists.
        #[arg(long, short)]
        force: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Keygen => generate_key(&cli.key),
        Command::Encrypt {
            file_in,
            file_out,
            force,
        } => encrypt_file(&file_in, &file_out, &cli.key, force),
        Command::Decrypt {
            file_in,
            file_out,
            force,
        } => decrypt_file(&file_in, &file_out, &cli.key, force),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
