#![forbid(unsafe_code)]

use std::process::ExitCode;

use cascade::cli::{Command, USAGE};

fn main() -> ExitCode {
    let command = match cascade::cli::parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("cascade: {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    match command {
        Command::Help => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("cascade {}", cascade::VERSION);
            ExitCode::SUCCESS
        }
        operation => match cascade::execute(operation) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("cascade: {error}");
                ExitCode::from(1)
            }
        },
    }
}
