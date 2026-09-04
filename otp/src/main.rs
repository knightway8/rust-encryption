use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgGroup, Args, Parser, Subcommand};
use otp::{
    OtpError, Result, create_pad_pair, decrypt_file_with_state, default_state_directory,
    destroy_pad, encrypt_file_with_state, file_length, inspect_pad, is_reserved_in, parse_size,
};

#[derive(Debug, Parser)]
#[command(
    name = "otp",
    version,
    about = "Misuse-resistant, authenticated one-time-pad file encryption",
    long_about = "Create a one-message sender/receiver pad pair, encrypt with the sender pad, \
and decrypt with the receiver pad. Pads are exact-length, authenticated, and permanently \
reserved on first valid use. Never copy, restore, or reuse a sender pad."
)]
struct Cli {
    /// Reuse-ledger directory; changing it creates a new, unsafe reuse namespace
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create, inspect, or explicitly destroy pad files
    Pad {
        #[command(subcommand)]
        command: PadCommand,
    },

    /// Encrypt one file with a fresh sender pad
    Encrypt(FileCommand),

    /// Authenticate and decrypt one file with a fresh receiver pad
    Decrypt(FileCommand),
}

#[derive(Debug, Subcommand)]
enum PadCommand {
    /// Create an exact-length sender/receiver pad pair
    Create(CreateCommand),

    /// Validate a pad and print only its non-secret metadata
    Info {
        /// Pad file to inspect
        #[arg(long, short = 'p', value_name = "FILE")]
        pad: PathBuf,
    },

    /// Best-effort overwrite and truncate a pad file
    Destroy {
        /// Pad file to destroy
        #[arg(long, short = 'p', value_name = "FILE")]
        pad: PathBuf,

        /// Confirm the irreversible operation
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("capacity")
        .required(true)
        .multiple(false)
        .args(["length", "for_file"])
))]
struct CreateCommand {
    /// Capacity in bytes or with a unit such as 10MiB or 2GB
    #[arg(long, value_name = "SIZE", value_parser = parse_size)]
    length: Option<u64>,

    /// Size the pad exactly for this existing file
    #[arg(long, value_name = "FILE")]
    for_file: Option<PathBuf>,

    /// Sender copy; used exactly once for encryption
    #[arg(long, value_name = "FILE")]
    sender: PathBuf,

    /// Receiver copy; used exactly once for decryption
    #[arg(long, value_name = "FILE")]
    receiver: PathBuf,
}

#[derive(Debug, Args)]
struct FileCommand {
    /// Input file
    #[arg(long, short = 'i', value_name = "FILE")]
    input: PathBuf,

    /// Managed sender or receiver pad
    #[arg(long, short = 'p', value_name = "FILE")]
    pad: PathBuf,

    /// New output file; existing paths are never overwritten
    #[arg(long, short = 'o', value_name = "FILE")]
    output: PathBuf,
}

fn resolve_state_directory(explicit: Option<PathBuf>) -> Result<PathBuf> {
    explicit.map_or_else(default_state_directory, Ok)
}

fn run(cli: Cli, stdout: &mut impl Write) -> Result<()> {
    let Cli { state_dir, command } = cli;
    match command {
        Command::Pad {
            command: PadCommand::Create(arguments),
        } => {
            let capacity = match (arguments.length, arguments.for_file) {
                (Some(length), None) => length,
                (None, Some(path)) => file_length(path)?,
                _ => unreachable!("clap enforces exactly one capacity source"),
            };
            create_pad_pair(capacity, &arguments.sender, &arguments.receiver)?;
            writeln!(
                stdout,
                "Created a {capacity}-byte one-message pad pair.\nSender: {}\nReceiver: {}",
                arguments.sender.display(),
                arguments.receiver.display()
            )
            .map_err(|source| OtpError::Io {
                action: "writing status",
                path: PathBuf::from("<stdout>"),
                source,
            })?;
            Ok(())
        }
        Command::Pad {
            command: PadCommand::Info { pad },
        } => {
            let information = inspect_pad(&pad)?;
            let state_directory = resolve_state_directory(state_dir)?;
            let reserved = is_reserved_in(state_directory, &information.id, information.role)?;
            let state = if information.consumed || reserved {
                "consumed"
            } else {
                "fresh"
            };
            writeln!(
                stdout,
                "Pad ID: {}\nRole: {}\nState: {state}\nCapacity: {} bytes",
                information.id_hex(),
                information.role,
                information.capacity
            )
            .map_err(|source| OtpError::Io {
                action: "writing pad information",
                path: PathBuf::from("<stdout>"),
                source,
            })?;
            Ok(())
        }
        Command::Pad {
            command: PadCommand::Destroy { pad, yes },
        } => {
            if !yes {
                return Err(OtpError::ConfirmationRequired);
            }
            destroy_pad(&pad)?;
            writeln!(stdout, "Destroyed and truncated pad: {}", pad.display()).map_err(
                |source| OtpError::Io {
                    action: "writing status",
                    path: PathBuf::from("<stdout>"),
                    source,
                },
            )?;
            Ok(())
        }
        Command::Encrypt(arguments) => {
            let state_directory = resolve_state_directory(state_dir)?;
            encrypt_file_with_state(
                &arguments.input,
                &arguments.pad,
                &arguments.output,
                state_directory,
            )?;
            writeln!(
                stdout,
                "Encrypted {} -> {}\nThe sender pad is now consumed and was retained for explicit destruction.",
                arguments.input.display(),
                arguments.output.display()
            )
            .map_err(|source| OtpError::Io {
                action: "writing status",
                path: PathBuf::from("<stdout>"),
                source,
            })?;
            Ok(())
        }
        Command::Decrypt(arguments) => {
            let state_directory = resolve_state_directory(state_dir)?;
            decrypt_file_with_state(
                &arguments.input,
                &arguments.pad,
                &arguments.output,
                state_directory,
            )?;
            writeln!(
                stdout,
                "Decrypted {} -> {}\nThe receiver pad is now consumed and was retained for explicit destruction.",
                arguments.input.display(),
                arguments.output.display()
            )
            .map_err(|source| OtpError::Io {
                action: "writing status",
                path: PathBuf::from("<stdout>"),
                source,
            })?;
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli, &mut io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
