use ezcrypt::cli::{CliCommand, ConsolePrompter, USAGE, parse_args, request_password};
use ezcrypt::{plan_for_path, transform_file};
use std::process::ExitCode;

fn main() -> ExitCode {
    let command = match parse_args(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("error: {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    match command {
        CliCommand::Help => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        CliCommand::Version => {
            println!("ezcrypt {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        CliCommand::Transform(path) => {
            let plan = match plan_for_path(&path) {
                Ok(plan) => plan,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let password = match request_password(plan.operation(), &mut ConsolePrompter) {
                Ok(password) => password,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::FAILURE;
                }
            };
            match transform_file(plan.input(), password.as_bytes()) {
                Ok(outcome) => {
                    println!(
                        "{} {} -> {} ({} bytes)",
                        outcome.operation().past_tense(),
                        outcome.input().display(),
                        outcome.output().display(),
                        outcome.plaintext_bytes()
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
