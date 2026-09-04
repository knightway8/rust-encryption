#![forbid(unsafe_code)]

use std::process::ExitCode;

use secure::{
    Cancellation, Error, ParseOutcome, USAGE, execute_cancellable, harden_process, parse_args,
    read_password_from_terminal,
};

fn main() -> ExitCode {
    let parsed = match parse_args(std::env::args_os()) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("secure: {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let config = match parsed {
        ParseOutcome::Help => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        ParseOutcome::Version => {
            println!("secure {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        ParseOutcome::Run(config) => config,
    };

    if let Err(error) = harden_process() {
        eprintln!("secure: {error}");
        return ExitCode::FAILURE;
    }

    let cancellation = match Cancellation::install() {
        Ok(cancellation) => cancellation,
        Err(error) => {
            eprintln!("secure: {error}");
            return ExitCode::FAILURE;
        }
    };

    let password_result = read_password_from_terminal(config.operation, &cancellation);
    if cancellation.is_cancelled() {
        eprintln!("secure: {}", Error::Interrupted);
        return ExitCode::from(cancellation.exit_code().unwrap_or(1));
    }
    let password = match password_result {
        Ok(password) => password,
        Err(error) => {
            eprintln!("secure: {error}");
            return ExitCode::FAILURE;
        }
    };

    match execute_cancellable(&config, password, &cancellation) {
        Ok(()) => {
            println!("{} complete.", config.operation.completed_verb());
            ExitCode::SUCCESS
        }
        Err(Error::Interrupted) => {
            eprintln!("secure: {}", Error::Interrupted);
            ExitCode::from(cancellation.exit_code().unwrap_or(1))
        }
        Err(error) => {
            eprintln!("secure: {error}");
            ExitCode::FAILURE
        }
    }
}
