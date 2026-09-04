use crate::io_util::{ensure_absent, local_path, open_regular_file};
use crate::{
    Algorithm, MAX_KEY_SIZE, Mode, binary_key_to_text_in, generate_random_key_in,
    make_deterministic_key_in, process_file_in, process_password_file_in, text_to_binary_key_in,
    xor_file_in_place,
};
use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use zeroize::Zeroizing;

pub fn cipher_main(algorithm: Algorithm) {
    exit_on_error(cipher_command(algorithm));
}

fn cipher_command(algorithm: Algorithm) -> Result<()> {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    if arguments.len() != 4 {
        bail!(
            "usage: {} [E or D] [filename] [output-file]",
            algorithm.command()
        );
    }
    let operation = arguments[1]
        .to_str()
        .context("operation must be valid Unicode and exactly E or D")?;
    let mode = Mode::parse(operation)?;
    let directory = std::env::current_dir().context("cannot determine current directory")?;
    process_file_in(&directory, algorithm, mode, &arguments[2], &arguments[3])?;
    println!(
        "{algorithm} {} complete: '{}' -> '{}'",
        if mode == Mode::Encrypt {
            "encryption"
        } else {
            "decryption"
        },
        arguments[2].to_string_lossy(),
        arguments[3].to_string_lossy()
    );
    Ok(())
}

pub fn password_cipher_main(algorithm: Algorithm) {
    exit_on_error(password_cipher_command(algorithm));
}

fn password_cipher_command(algorithm: Algorithm) -> Result<()> {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    if arguments.len() != 4 {
        bail!(
            "usage: {} [E or D] [filename] [output-file]",
            algorithm.password_command()
        );
    }
    let operation = arguments[1]
        .to_str()
        .context("operation must be valid Unicode and exactly E or D")?;
    let mode = Mode::parse(operation)?;
    let directory = std::env::current_dir().context("cannot determine current directory")?;
    preflight_password_file_operation(&directory, &arguments[2], &arguments[3])?;

    let password =
        Zeroizing::new(rpassword::prompt_password("Password: ").context("cannot read password")?);
    if mode == Mode::Encrypt {
        let confirmation = Zeroizing::new(
            rpassword::prompt_password("Password again: ")
                .context("cannot read password confirmation")?,
        );
        if password.as_bytes() != confirmation.as_bytes() {
            bail!("passwords do not match");
        }
    }

    process_password_file_in(
        &directory,
        algorithm,
        mode,
        &arguments[2],
        &arguments[3],
        password.as_bytes(),
    )?;
    println!(
        "{algorithm} password-based {} complete: '{}' -> '{}'",
        if mode == Mode::Encrypt {
            "encryption"
        } else {
            "decryption"
        },
        arguments[2].to_string_lossy(),
        arguments[3].to_string_lossy()
    );
    Ok(())
}

fn preflight_password_file_operation(
    directory: &std::path::Path,
    input_name: &std::ffi::OsStr,
    output_name: &std::ffi::OsStr,
) -> Result<()> {
    let input_path = local_path(directory, input_name)?;
    let output_path = local_path(directory, output_name)?;
    ensure_absent(&output_path)?;
    drop(open_regular_file(&input_path)?);
    Ok(())
}

pub fn keygen_main() {
    exit_on_error(keygen_command());
}

fn keygen_command() -> Result<()> {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    if arguments.len() != 2 {
        bail!("usage: keygen [size in bytes]");
    }
    let size = parse_size(&arguments[1])?;
    let directory = std::env::current_dir().context("cannot determine current directory")?;
    generate_random_key_in(&directory, size)?;
    println!("created keygen.key with exactly {size} random bytes");
    Ok(())
}

pub fn keymake_main() {
    exit_on_error(keymake_command());
}

fn keymake_command() -> Result<()> {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    if arguments.len() != 2 {
        bail!("usage: keymake [size in bytes]");
    }
    let size = parse_size(&arguments[1])?;
    let directory = std::env::current_dir().context("cannot determine current directory")?;
    ensure_absent(&directory.join("keymake.key"))?;

    let password =
        Zeroizing::new(rpassword::prompt_password("Password: ").context("cannot read password")?);
    let confirmation = Zeroizing::new(
        rpassword::prompt_password("Password again: ")
            .context("cannot read password confirmation")?,
    );
    if password.as_bytes() != confirmation.as_bytes() {
        bail!("passwords do not match");
    }
    make_deterministic_key_in(&directory, size, password.as_bytes())?;
    println!("created deterministic keymake.key with exactly {size} bytes");
    Ok(())
}

pub fn key2txt_main() {
    exit_on_error(key2txt_command());
}

fn key2txt_command() -> Result<()> {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    if arguments.len() != 2 {
        bail!("usage: key2txt [binary key file]");
    }
    let directory = std::env::current_dir().context("cannot determine current directory")?;
    binary_key_to_text_in(&directory, &arguments[1])?;
    println!(
        "converted binary key '{}' to key2txt.txt",
        arguments[1].to_string_lossy()
    );
    Ok(())
}

pub fn txt2key_main() {
    exit_on_error(txt2key_command());
}

fn txt2key_command() -> Result<()> {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    if arguments.len() != 2 {
        bail!("usage: txt2key [decimal text file]");
    }
    let directory = std::env::current_dir().context("cannot determine current directory")?;
    text_to_binary_key_in(&directory, &arguments[1])?;
    println!(
        "restored decimal key text '{}' to txt2key.key",
        arguments[1].to_string_lossy()
    );
    Ok(())
}

pub fn otp_main() {
    exit_on_error(otp_command());
}

fn otp_command() -> Result<()> {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    if arguments.len() != 3 {
        bail!("usage: otp [file to process] [key file]");
    }
    let directory = std::env::current_dir().context("cannot determine current directory")?;
    xor_file_in_place(&directory, &arguments[1], &arguments[2])?;
    println!(
        "OTP processing complete: '{}'",
        arguments[1].to_string_lossy()
    );
    Ok(())
}

fn parse_size(value: &OsString) -> Result<u64> {
    let text = value
        .to_str()
        .context("size must be an ASCII decimal byte count")?;
    let size = text
        .parse::<u64>()
        .with_context(|| format!("invalid byte count '{text}'"))?;
    if !(1..=MAX_KEY_SIZE).contains(&size) {
        bail!("size must be an exact byte count from 1 through {MAX_KEY_SIZE}");
    }
    Ok(size)
}

fn exit_on_error(result: Result<()>) {
    if let Err(error) = result {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
