fn main() {
    match multicrypt::run_cli() {
        Ok(message) => println!("{message}"),
        Err(error) => {
            eprintln!("error: {error}");
            if matches!(error, multicrypt::Error::Usage(_)) {
                eprintln!();
                eprintln!("{}", multicrypt::USAGE);
                std::process::exit(2);
            }
            std::process::exit(1);
        }
    }
}
