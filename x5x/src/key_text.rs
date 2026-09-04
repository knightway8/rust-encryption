use crate::io_util::{IO_BUFFER_SIZE, NewOutput, local_path, open_regular_file};
use anyhow::{Context, Result, bail};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const TEXT_OUTPUT: &str = "key2txt.txt";
const BINARY_OUTPUT: &str = "txt2key.key";

/// Convert every byte of a binary key to one decimal value per text line.
///
/// Commas follow every value except the final one, making them separators while
/// retaining the one-value-per-line format required by the reverse converter.
///
/// # Errors
///
/// Returns an error for an invalid or non-regular input, an existing output,
/// an input that changes while being read, or an I/O failure.
pub fn binary_key_to_text_in(directory: &Path, input_name: &OsStr) -> Result<()> {
    let input_path = local_path(directory, input_name)?;
    let output_path = directory.join(TEXT_OUTPUT);
    let mut input = open_regular_file(&input_path)?;
    let input_len = input
        .metadata()
        .with_context(|| format!("cannot inspect input '{}'", input_path.display()))?
        .len();

    let mut output = NewOutput::create(&output_path)?;
    let mut binary = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let text_capacity = IO_BUFFER_SIZE
        .checked_mul(5)
        .context("text conversion buffer size overflows")?;
    let mut text = Zeroizing::new(Vec::with_capacity(text_capacity));
    let mut remaining = input_len;
    let mut processed = 0_u64;

    while remaining != 0 {
        let length = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64))
            .context("input chunk length does not fit this platform")?;
        input
            .read_exact(&mut binary[..length])
            .context("binary key changed or ended while being converted")?;

        for byte in &binary[..length] {
            push_decimal_byte(&mut text, *byte);
            processed += 1;
            if processed == input_len {
                text.push(b'\n');
            } else {
                text.extend_from_slice(b",\n");
            }
        }
        output
            .writer()
            .write_all(&text)
            .context("cannot write decimal key text")?;
        text.as_mut_slice().zeroize();
        text.clear();
        binary[..length].zeroize();
        remaining -= length as u64;
    }

    let mut extra = [0_u8; 1];
    if input.read(&mut extra)? != 0 {
        bail!("binary key grew while being converted");
    }
    output.finish()
}

/// Parse one decimal byte per line and create txt2key.key.
///
/// Lines may contain surrounding ASCII spaces or tabs and an optional trailing
/// comma. Values must contain one to three decimal digits and be in 0..=255.
///
/// # Errors
///
/// Returns an error for an invalid or non-regular input, malformed text, a
/// value outside the byte range, an existing output, or an I/O failure.
pub fn text_to_binary_key_in(directory: &Path, input_name: &OsStr) -> Result<()> {
    let input_path = local_path(directory, input_name)?;
    let output_path = directory.join(BINARY_OUTPUT);
    let mut input = open_regular_file(&input_path)?;

    let mut output = NewOutput::create(&output_path)?;
    let mut input_buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let mut binary_buffer = Zeroizing::new(Vec::with_capacity(IO_BUFFER_SIZE));
    let mut parser = DecimalLineParser::new();

    loop {
        let length = input
            .read(&mut input_buffer)
            .context("cannot read decimal key text")?;
        if length == 0 {
            break;
        }
        for character in &input_buffer[..length] {
            if let Some(byte) = parser.consume(*character)? {
                binary_buffer.push(byte);
                if binary_buffer.len() == IO_BUFFER_SIZE {
                    output
                        .writer()
                        .write_all(&binary_buffer)
                        .context("cannot write restored binary key")?;
                    binary_buffer.as_mut_slice().zeroize();
                    binary_buffer.clear();
                }
            }
        }
        input_buffer[..length].zeroize();
    }

    if let Some(byte) = parser.finish_at_eof()? {
        binary_buffer.push(byte);
    }
    if !binary_buffer.is_empty() {
        output
            .writer()
            .write_all(&binary_buffer)
            .context("cannot write restored binary key")?;
        binary_buffer.as_mut_slice().zeroize();
        binary_buffer.clear();
    }
    output.finish()
}

fn push_decimal_byte(output: &mut Vec<u8>, value: u8) {
    if value >= 100 {
        output.push(b'0' + value / 100);
        output.push(b'0' + (value / 10) % 10);
    } else if value >= 10 {
        output.push(b'0' + value / 10);
    }
    output.push(b'0' + value % 10);
}

#[derive(Clone, Copy)]
enum LinePhase {
    Leading,
    Digits,
    AfterDigits,
    AfterComma,
}

struct DecimalLineParser {
    phase: LinePhase,
    value: u16,
    digits: u8,
    line: u64,
    line_started: bool,
}

impl DecimalLineParser {
    const fn new() -> Self {
        Self {
            phase: LinePhase::Leading,
            value: 0,
            digits: 0,
            line: 1,
            line_started: false,
        }
    }

    fn consume(&mut self, character: u8) -> Result<Option<u8>> {
        if character == b'\n' {
            return self.finish_line();
        }

        self.line_started = true;
        match self.phase {
            LinePhase::Leading => {
                if is_horizontal_space(character) {
                    Ok(None)
                } else if character.is_ascii_digit() {
                    self.push_digit(character)?;
                    self.phase = LinePhase::Digits;
                    Ok(None)
                } else {
                    bail!("line {}: expected one unsigned decimal byte", self.line)
                }
            }
            LinePhase::Digits => {
                if character.is_ascii_digit() {
                    self.push_digit(character)?;
                    Ok(None)
                } else if is_horizontal_space(character) {
                    self.phase = LinePhase::AfterDigits;
                    Ok(None)
                } else if character == b',' {
                    self.phase = LinePhase::AfterComma;
                    Ok(None)
                } else {
                    bail!(
                        "line {}: each line must contain exactly one decimal byte",
                        self.line
                    )
                }
            }
            LinePhase::AfterDigits => {
                if is_horizontal_space(character) {
                    Ok(None)
                } else if character == b',' {
                    self.phase = LinePhase::AfterComma;
                    Ok(None)
                } else {
                    bail!("line {}: unexpected data after decimal byte", self.line)
                }
            }
            LinePhase::AfterComma => {
                if is_horizontal_space(character) {
                    Ok(None)
                } else {
                    bail!(
                        "line {}: comma must be the final non-space character",
                        self.line
                    )
                }
            }
        }
    }

    fn push_digit(&mut self, character: u8) -> Result<()> {
        if self.digits == 3 {
            bail!("line {}: byte has more than three digits", self.line);
        }
        self.digits += 1;
        self.value = self
            .value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u16::from(character - b'0')))
            .context("decimal byte value overflows")?;
        if self.value > u16::from(u8::MAX) {
            bail!(
                "line {}: value {} is greater than 255",
                self.line,
                self.value
            );
        }
        Ok(())
    }

    fn finish_line(&mut self) -> Result<Option<u8>> {
        if matches!(self.phase, LinePhase::Leading) {
            bail!("line {}: blank lines are not allowed", self.line);
        }
        let byte = u8::try_from(self.value).context("validated byte does not fit in u8")?;
        self.reset_for_next_line();
        Ok(Some(byte))
    }

    fn finish_at_eof(&mut self) -> Result<Option<u8>> {
        if matches!(self.phase, LinePhase::Leading) {
            if self.line_started {
                bail!("line {}: line does not contain a decimal byte", self.line);
            }
            return Ok(None);
        }
        let byte = u8::try_from(self.value).context("validated byte does not fit in u8")?;
        Ok(Some(byte))
    }

    fn reset_for_next_line(&mut self) {
        self.phase = LinePhase::Leading;
        self.value = 0;
        self.digits = 0;
        self.line = self.line.saturating_add(1);
        self.line_started = false;
    }
}

const fn is_horizontal_space(character: u8) -> bool {
    matches!(character, b' ' | b'\t' | b'\r')
}
