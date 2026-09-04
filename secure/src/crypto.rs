use std::io::{self, BufRead, Cursor, Read, Write};

use age::{Decryptor, Encryptor, Identity, Recipient, secrecy::SecretString};

use crate::Error;

/// `N = 2^18`, `r = 8`, `p = 1`: approximately 256 MiB of memory.
pub(crate) const SCRYPT_WORK_FACTOR: u8 = 18;
pub(crate) const MAX_HEADER_BYTES: usize = 64 * 1024;

pub(crate) fn encrypt_stream<R: Read, W: Write>(
    input: &mut R,
    output: W,
    password: SecretString,
) -> Result<u64, Error> {
    let mut recipient = age::scrypt::Recipient::new(password);
    recipient.set_work_factor(SCRYPT_WORK_FACTOR);
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn Recipient))
        .map_err(|_| Error::EncryptionFailed)?;
    encrypt_with_encryptor(input, output, encryptor)
}

fn encrypt_with_encryptor<R: Read, W: Write>(
    input: &mut R,
    output: W,
    encryptor: Encryptor,
) -> Result<u64, Error> {
    let mut encrypted = encryptor.wrap_output(output).map_err(Error::EncryptionIo)?;
    let copied = io::copy(input, &mut encrypted).map_err(Error::EncryptionIo)?;
    encrypted.finish().map_err(Error::EncryptionIo)?;
    Ok(copied)
}

#[cfg(test)]
pub(crate) fn encrypt_stream_with_recipient<R: Read, W: Write>(
    input: &mut R,
    output: W,
    recipient: &dyn Recipient,
) -> Result<u64, Error> {
    let encryptor = Encryptor::with_recipients(std::iter::once(recipient))
        .map_err(|_| Error::EncryptionFailed)?;
    encrypt_with_encryptor(input, output, encryptor)
}

pub(crate) fn decrypt_stream<R: BufRead, W: Write>(
    input: R,
    mut output: W,
    password: SecretString,
) -> Result<u64, Error> {
    let input = bounded_header_replay(input)?;
    let decryptor = Decryptor::new_buffered(input).map_err(|_| Error::DecryptionFailed)?;
    if !decryptor.is_scrypt() {
        return Err(Error::DecryptionFailed);
    }

    let mut identity = age::scrypt::Identity::new(password);
    identity.set_max_work_factor(SCRYPT_WORK_FACTOR);
    let mut plaintext = decryptor
        .decrypt(std::iter::once(&identity as &dyn Identity))
        .map_err(|_| Error::DecryptionFailed)?;

    io::copy(&mut plaintext, &mut output).map_err(|_| Error::DecryptionFailed)
}

fn bounded_header_replay<R: BufRead>(mut input: R) -> Result<io::Chain<Cursor<Vec<u8>>, R>, Error> {
    let mut prefix = Vec::with_capacity(1024);
    let mut found_end = false;

    while prefix.len() <= MAX_HEADER_BYTES {
        let line_start = prefix.len();
        let remaining = MAX_HEADER_BYTES + 1 - prefix.len();
        let read = {
            let mut limited = (&mut input).take(remaining as u64);
            limited
                .read_until(b'\n', &mut prefix)
                .map_err(|_| Error::DecryptionFailed)?
        };

        if read == 0 {
            break;
        }
        if prefix.len() > MAX_HEADER_BYTES {
            return Err(Error::DecryptionFailed);
        }

        let line = &prefix[line_start..];
        if line.starts_with(b"--- ") && line.ends_with(b"\n") {
            found_end = true;
            break;
        }
    }

    if !found_end {
        return Err(Error::DecryptionFailed);
    }

    Ok(Cursor::new(prefix).chain(input))
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        collections::BTreeSet,
        io::{BufReader, BufWriter, ErrorKind},
        rc::Rc,
    };

    use age::{DecryptError, secrecy::SecretString};
    use proptest::prelude::*;

    use super::*;

    const TEST_WORK_FACTOR: u8 = 10;
    const AGE_CHUNK_BYTES: usize = 64 * 1024;

    fn secret(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    fn test_recipient(password: &str) -> age::scrypt::Recipient {
        let mut recipient = age::scrypt::Recipient::new(secret(password));
        recipient.set_work_factor(TEST_WORK_FACTOR);
        recipient
    }

    fn encrypt_for_test(plaintext: &[u8], password: &str) -> Vec<u8> {
        let recipient = test_recipient(password);
        let mut input = Cursor::new(plaintext);
        let mut ciphertext = Vec::new();
        let copied = encrypt_stream_with_recipient(&mut input, &mut ciphertext, &recipient)
            .expect("low-work-factor test encryption succeeds");
        assert_eq!(copied, plaintext.len() as u64);
        ciphertext
    }

    fn decrypt_for_test(ciphertext: &[u8], password: &str) -> Result<Vec<u8>, Error> {
        let mut plaintext = Vec::new();
        let copied = decrypt_stream(Cursor::new(ciphertext), &mut plaintext, secret(password))?;
        assert_eq!(copied, plaintext.len() as u64);
        Ok(plaintext)
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn header_end(ciphertext: &[u8]) -> usize {
        let final_line = find_subslice(ciphertext, b"\n--- ")
            .expect("test ciphertext has an age header terminator")
            + 1;
        final_line
            + ciphertext[final_line..]
                .iter()
                .position(|byte| *byte == b'\n')
                .expect("age header terminator is newline-terminated")
            + 1
    }

    fn replace_scrypt_work_factor(ciphertext: &mut [u8], expected: u8, replacement: u8) {
        let stanza_start =
            find_subslice(ciphertext, b"-> scrypt ").expect("test ciphertext has a scrypt stanza");
        let line_end = stanza_start
            + ciphertext[stanza_start..]
                .iter()
                .position(|byte| *byte == b'\n')
                .expect("scrypt stanza is newline-terminated");
        let factor_start = stanza_start
            + ciphertext[stanza_start..line_end]
                .iter()
                .rposition(|byte| *byte == b' ')
                .expect("scrypt stanza has a work-factor argument")
            + 1;
        let expected = expected.to_string();
        let replacement = replacement.to_string();
        assert_eq!(expected.len(), replacement.len());
        assert_eq!(
            &ciphertext[factor_start..line_end],
            expected.as_bytes(),
            "test ciphertext used the expected work factor"
        );
        ciphertext[factor_start..line_end].copy_from_slice(replacement.as_bytes());
    }

    fn patterned_bytes(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| {
                u8::try_from((index.wrapping_mul(131) + 17) % 251)
                    .expect("a value reduced modulo 251 fits in u8")
            })
            .collect()
    }

    fn synthetic_header_input(header_length: usize, payload: &[u8]) -> Vec<u8> {
        let terminator = b"--- test-mac\n";
        let filler_length = header_length
            .checked_sub(terminator.len())
            .expect("synthetic header is long enough for its terminator");
        assert!(filler_length >= 1);

        let mut input = vec![b'x'; filler_length - 1];
        input.push(b'\n');
        input.extend_from_slice(terminator);
        input.extend_from_slice(payload);
        input
    }

    #[test]
    fn round_trips_exact_age_chunk_boundaries() {
        let sizes = [
            0,
            1,
            AGE_CHUNK_BYTES - 1,
            AGE_CHUNK_BYTES,
            AGE_CHUNK_BYTES + 1,
            2 * AGE_CHUNK_BYTES - 1,
            2 * AGE_CHUNK_BYTES,
            2 * AGE_CHUNK_BYTES + 1,
        ];

        for size in sizes {
            let plaintext = patterned_bytes(size);
            let ciphertext = encrypt_for_test(&plaintext, "boundary-test-password");
            let decrypted = decrypt_for_test(&ciphertext, "boundary-test-password")
                .expect("boundary-sized ciphertext decrypts");
            assert_eq!(decrypted, plaintext, "failed at plaintext size {size}");
        }
    }

    #[test]
    fn wrong_password_is_rejected_before_plaintext_output() {
        let ciphertext = encrypt_for_test(b"authenticated secret", "correct password");
        let mut output = Vec::new();
        let result = decrypt_stream(
            Cursor::new(ciphertext),
            &mut output,
            secret("incorrect password"),
        );

        assert!(matches!(result, Err(Error::DecryptionFailed)));
        assert!(output.is_empty());
    }

    #[test]
    fn unicode_passwords_are_not_normalized() {
        let composed = "Caf\u{e9} \u{79d8}\u{5bc6} \u{1f510}";
        let decomposed = "Cafe\u{301} \u{79d8}\u{5bc6} \u{1f510}";
        assert_ne!(composed.as_bytes(), decomposed.as_bytes());

        let plaintext = b"normalization must not change a passphrase";
        let composed_ciphertext = encrypt_for_test(plaintext, composed);
        let decomposed_ciphertext = encrypt_for_test(plaintext, decomposed);

        assert_eq!(
            decrypt_for_test(&composed_ciphertext, composed).unwrap(),
            plaintext
        );
        assert_eq!(
            decrypt_for_test(&decomposed_ciphertext, decomposed).unwrap(),
            plaintext
        );
        assert!(decrypt_for_test(&composed_ciphertext, decomposed).is_err());
        assert!(decrypt_for_test(&decomposed_ciphertext, composed).is_err());
    }

    #[test]
    fn encryption_is_randomized_for_identical_inputs() {
        let plaintext = patterned_bytes(AGE_CHUNK_BYTES + 123);
        let first = encrypt_for_test(&plaintext, "same password");
        let second = encrypt_for_test(&plaintext, "same password");

        assert_ne!(first, second);
        assert_eq!(
            decrypt_for_test(&first, "same password").unwrap(),
            plaintext
        );
        assert_eq!(
            decrypt_for_test(&second, "same password").unwrap(),
            plaintext
        );
    }

    #[test]
    fn authenticated_header_nonce_and_payload_corruptions_are_rejected() {
        let plaintext = patterned_bytes(2 * AGE_CHUNK_BYTES + 37);
        let ciphertext = encrypt_for_test(&plaintext, "corruption password");
        let header_end = header_end(&ciphertext);
        let mac_line_start = find_subslice(&ciphertext[..header_end], b"\n--- ")
            .expect("test ciphertext has a MAC line")
            + 1;

        let positions = BTreeSet::from([
            0,
            mac_line_start + 4,
            header_end,
            header_end + 15,
            header_end + 16,
            header_end + 16 + AGE_CHUNK_BYTES / 2,
            header_end + 16 + AGE_CHUNK_BYTES + 16,
            ciphertext.len() - 1,
        ]);

        for position in positions {
            assert!(position < ciphertext.len());
            let mut corrupted = ciphertext.clone();
            corrupted[position] ^= 1;
            assert!(
                decrypt_for_test(&corrupted, "corruption password").is_err(),
                "corruption at ciphertext offset {position} was accepted"
            );
        }
    }

    #[test]
    fn truncation_is_rejected_at_header_nonce_tag_and_chunk_boundaries() {
        let plaintext = patterned_bytes(2 * AGE_CHUNK_BYTES + 37);
        let ciphertext = encrypt_for_test(&plaintext, "truncation password");
        let header_end = header_end(&ciphertext);
        let first_chunk_end = header_end + 16 + AGE_CHUNK_BYTES + 16;
        assert!(first_chunk_end < ciphertext.len());

        let cuts = BTreeSet::from([
            0,
            1,
            header_end - 1,
            header_end,
            header_end + 1,
            header_end + 15,
            header_end + 16,
            header_end + 17,
            first_chunk_end - 1,
            first_chunk_end,
            first_chunk_end + 1,
            ciphertext.len() - 17,
            ciphertext.len() - 16,
            ciphertext.len() - 1,
        ]);

        for cut in cuts {
            assert!(
                decrypt_for_test(&ciphertext[..cut], "truncation password").is_err(),
                "truncation at ciphertext offset {cut} was accepted"
            );
        }
    }

    #[test]
    fn trailing_garbage_is_rejected_for_partial_and_full_final_chunks() {
        for size in [
            0,
            1,
            AGE_CHUNK_BYTES - 1,
            AGE_CHUNK_BYTES,
            AGE_CHUNK_BYTES + 1,
        ] {
            let mut ciphertext =
                encrypt_for_test(&patterned_bytes(size), "trailing-garbage password");
            ciphertext.extend_from_slice(b"unauthenticated trailing bytes");

            assert!(
                decrypt_for_test(&ciphertext, "trailing-garbage password").is_err(),
                "trailing bytes were accepted after plaintext size {size}"
            );
        }
    }

    #[test]
    fn concatenated_age_ciphertexts_are_rejected() {
        // An exact full chunk exercises age's special last-chunk retry path.
        let first_plaintext = patterned_bytes(AGE_CHUNK_BYTES);
        let second_plaintext = patterned_bytes(257);
        let mut concatenated =
            encrypt_for_test(&first_plaintext, "concatenated ciphertext password");
        concatenated.extend_from_slice(&encrypt_for_test(
            &second_plaintext,
            "concatenated ciphertext password",
        ));

        assert!(decrypt_for_test(&concatenated, "concatenated ciphertext password").is_err());
    }

    #[test]
    fn dropping_stream_writer_without_finish_produces_rejected_ciphertext() {
        let recipient = test_recipient("unfinished password");
        let encryptor =
            Encryptor::with_recipients(std::iter::once(&recipient as &dyn Recipient)).unwrap();
        let mut ciphertext = Vec::new();
        {
            let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
            writer
                .write_all(&patterned_bytes(AGE_CHUNK_BYTES + 1))
                .unwrap();
        }

        assert!(decrypt_for_test(&ciphertext, "unfinished password").is_err());
    }

    #[test]
    fn recipient_encrypted_age_input_is_rejected_as_non_scrypt() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let plaintext = b"recipient-encrypted rather than passphrase-encrypted";
        let mut input = Cursor::new(plaintext);
        let mut ciphertext = Vec::new();
        encrypt_stream_with_recipient(&mut input, &mut ciphertext, &recipient).unwrap();

        let mut output = Vec::new();
        let result = decrypt_stream(
            Cursor::new(ciphertext),
            &mut output,
            secret("irrelevant password"),
        );
        assert!(matches!(result, Err(Error::DecryptionFailed)));
        assert!(output.is_empty());
    }

    #[test]
    fn bounded_header_accepts_exact_limit_and_replays_every_byte() {
        let payload = b"payload bytes after the synthetic header";
        let input = synthetic_header_input(MAX_HEADER_BYTES, payload);
        let mut replayed = bounded_header_replay(Cursor::new(input.clone())).unwrap();
        let mut actual = Vec::new();
        replayed.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, input);
    }

    #[test]
    fn bounded_header_rejects_one_byte_over_limit() {
        let input = synthetic_header_input(MAX_HEADER_BYTES + 1, b"payload");
        assert!(bounded_header_replay(Cursor::new(input)).is_err());
    }

    #[test]
    fn oversized_one_line_input_consumes_only_limit_plus_one() {
        let consumed = Rc::new(Cell::new(0));
        let input = CountingBufRead::new(
            Cursor::new(vec![b'x'; 8 * MAX_HEADER_BYTES]),
            Rc::clone(&consumed),
        );
        let mut output = Vec::new();
        let result = decrypt_stream(input, &mut output, secret("unused password"));

        assert!(matches!(result, Err(Error::DecryptionFailed)));
        assert_eq!(consumed.get(), MAX_HEADER_BYTES + 1);
        assert!(output.is_empty());
    }

    #[test]
    fn work_factor_above_cap_is_rejected_before_kdf() {
        let mut ciphertext = encrypt_for_test(b"bounded KDF work", "work-factor password");
        replace_scrypt_work_factor(&mut ciphertext, TEST_WORK_FACTOR, SCRYPT_WORK_FACTOR + 1);

        let decryptor = Decryptor::new_buffered(Cursor::new(ciphertext.as_slice())).unwrap();
        assert!(decryptor.is_scrypt());
        let mut identity = age::scrypt::Identity::new(secret("work-factor password"));
        identity.set_max_work_factor(SCRYPT_WORK_FACTOR);
        let Err(error) = decryptor.decrypt(std::iter::once(&identity as &dyn Identity)) else {
            panic!("an excessive work factor was accepted");
        };
        assert!(matches!(
            error,
            DecryptError::ExcessiveWork {
                required,
                target: _
            } if required == SCRYPT_WORK_FACTOR + 1
        ));

        assert!(matches!(
            decrypt_stream(
                Cursor::new(ciphertext),
                Vec::new(),
                secret("work-factor password")
            ),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn short_and_interrupted_io_still_round_trips() {
        let plaintext = patterned_bytes(2 * AGE_CHUNK_BYTES + 333);
        let recipient = test_recipient("choppy I/O password");
        let mut input = ChoppyReader::new(Cursor::new(plaintext.as_slice()), 37, 4);
        let input_interruptions = Rc::clone(&input.interruptions);
        let mut encrypted_output = ChoppyWriter::new(Vec::new(), 29, 5).delay_interrupts_until(64);

        let copied = {
            // Production wraps the destination file in a `BufWriter`; this also
            // absorbs short writes while the age header is being serialized.
            let mut buffered_output = BufWriter::with_capacity(257, &mut encrypted_output);
            let copied =
                encrypt_stream_with_recipient(&mut input, &mut buffered_output, &recipient)
                    .unwrap();
            buffered_output.flush().unwrap();
            copied
        };
        assert_eq!(copied, plaintext.len() as u64);
        assert!(input_interruptions.get() > 0);
        assert!(encrypted_output.interruptions.get() > 0);
        let ciphertext = encrypted_output.into_inner();

        let decrypt_reader = ChoppyReader::new(Cursor::new(ciphertext), 31, 3);
        let decrypt_interruptions = Rc::clone(&decrypt_reader.interruptions);
        let decrypt_reader = BufReader::with_capacity(43, decrypt_reader);
        let mut plaintext_output = ChoppyWriter::new(Vec::new(), 23, 4);
        let copied = decrypt_stream(
            decrypt_reader,
            &mut plaintext_output,
            secret("choppy I/O password"),
        )
        .unwrap();

        assert_eq!(copied, plaintext.len() as u64);
        assert_eq!(plaintext_output.inner, plaintext);
        assert!(decrypt_interruptions.get() > 0);
        assert!(plaintext_output.interruptions.get() > 0);
    }

    #[test]
    fn hard_io_failures_are_mapped_to_public_errors() {
        let plaintext = patterned_bytes(2 * AGE_CHUNK_BYTES + 333);
        let recipient = test_recipient("I/O failure password");

        let mut failing_input = FailAfterReader::new(Cursor::new(plaintext.as_slice()), 1_337);
        let mut ciphertext_sink = Vec::new();
        assert!(matches!(
            encrypt_stream_with_recipient(
                &mut failing_input,
                &mut ciphertext_sink,
                &recipient
            ),
            Err(Error::EncryptionIo(error)) if error.kind() == ErrorKind::Other
        ));

        let mut header_failure = FailAfterWriter::new(0);
        let mut input = Cursor::new(plaintext.as_slice());
        assert!(matches!(
            encrypt_stream_with_recipient(&mut input, &mut header_failure, &recipient),
            Err(Error::EncryptionIo(error)) if error.kind() == ErrorKind::Other
        ));

        let ciphertext = encrypt_for_test(&plaintext, "I/O failure password");
        let mut failing_encryption_output = FailAfterWriter::new(ciphertext.len() / 2);
        let mut input = Cursor::new(plaintext.as_slice());
        assert!(matches!(
            encrypt_stream_with_recipient(
                &mut input,
                &mut failing_encryption_output,
                &recipient
            ),
            Err(Error::EncryptionIo(error)) if error.kind() == ErrorKind::Other
        ));

        let fail_after = header_end(&ciphertext) + 16 + 1_337;
        let failing_ciphertext =
            FailAfterReader::new(Cursor::new(ciphertext.as_slice()), fail_after);
        let failing_ciphertext = BufReader::with_capacity(257, failing_ciphertext);
        assert!(matches!(
            decrypt_stream(
                failing_ciphertext,
                Vec::new(),
                secret("I/O failure password")
            ),
            Err(Error::DecryptionFailed)
        ));

        let mut failing_plaintext_output = FailAfterWriter::new(1_337);
        assert!(matches!(
            decrypt_stream(
                Cursor::new(ciphertext),
                &mut failing_plaintext_output,
                secret("I/O failure password")
            ),
            Err(Error::DecryptionFailed)
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        #[test]
        fn property_round_trip_and_authentication(
            plaintext in prop::collection::vec(any::<u8>(), 0..(2 * AGE_CHUNK_BYTES + 2)),
            password in "[A-Za-z0-9 ._!@#-]{1,40}",
            mutation_selector in any::<usize>(),
            bit in 0_u8..8,
            truncation_selector in any::<usize>(),
        ) {
            let ciphertext = encrypt_for_test(&plaintext, &password);
            let decrypted = decrypt_for_test(&ciphertext, &password)
                .expect("property-generated ciphertext decrypts");
            prop_assert_eq!(decrypted.as_slice(), plaintext.as_slice());

            let authenticated_start = header_end(&ciphertext);
            let mut corrupted = ciphertext.clone();
            let position = authenticated_start
                + mutation_selector % (corrupted.len() - authenticated_start);
            corrupted[position] ^= 1_u8 << bit;
            prop_assert!(decrypt_for_test(&corrupted, &password).is_err());

            let cut = truncation_selector % ciphertext.len();
            prop_assert!(decrypt_for_test(&ciphertext[..cut], &password).is_err());
        }
    }

    struct CountingBufRead<R> {
        inner: R,
        consumed: Rc<Cell<usize>>,
    }

    impl<R> CountingBufRead<R> {
        fn new(inner: R, consumed: Rc<Cell<usize>>) -> Self {
            Self { inner, consumed }
        }
    }

    impl<R: Read> Read for CountingBufRead<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read = self.inner.read(buffer)?;
            self.consumed.set(self.consumed.get() + read);
            Ok(read)
        }
    }

    impl<R: BufRead> BufRead for CountingBufRead<R> {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            self.inner.fill_buf()
        }

        fn consume(&mut self, amount: usize) {
            self.inner.consume(amount);
            self.consumed.set(self.consumed.get() + amount);
        }
    }

    struct ChoppyReader<R> {
        inner: R,
        maximum: usize,
        interrupt_every: usize,
        calls: usize,
        interruptions: Rc<Cell<usize>>,
    }

    impl<R> ChoppyReader<R> {
        fn new(inner: R, maximum: usize, interrupt_every: usize) -> Self {
            assert!(maximum > 0);
            assert!(interrupt_every > 1);
            Self {
                inner,
                maximum,
                interrupt_every,
                calls: 0,
                interruptions: Rc::new(Cell::new(0)),
            }
        }
    }

    impl<R: Read> Read for ChoppyReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            self.calls += 1;
            if self.calls.is_multiple_of(self.interrupt_every) {
                self.interruptions.set(self.interruptions.get() + 1);
                return Err(io::Error::from(ErrorKind::Interrupted));
            }
            let length = buffer.len().min(self.maximum);
            self.inner.read(&mut buffer[..length])
        }
    }

    struct ChoppyWriter<W> {
        inner: W,
        maximum: usize,
        interrupt_every: usize,
        interrupt_after_call: usize,
        calls: usize,
        interruptions: Rc<Cell<usize>>,
    }

    impl<W> ChoppyWriter<W> {
        fn new(inner: W, maximum: usize, interrupt_every: usize) -> Self {
            assert!(maximum > 0);
            assert!(interrupt_every > 1);
            Self {
                inner,
                maximum,
                interrupt_every,
                interrupt_after_call: 0,
                calls: 0,
                interruptions: Rc::new(Cell::new(0)),
            }
        }

        fn delay_interrupts_until(mut self, call: usize) -> Self {
            self.interrupt_after_call = call;
            self
        }

        fn into_inner(self) -> W {
            self.inner
        }
    }

    impl<W: Write> Write for ChoppyWriter<W> {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            self.calls += 1;
            if self.calls > self.interrupt_after_call
                && self.calls.is_multiple_of(self.interrupt_every)
            {
                self.interruptions.set(self.interruptions.get() + 1);
                return Err(io::Error::from(ErrorKind::Interrupted));
            }
            self.inner.write(&buffer[..buffer.len().min(self.maximum)])
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    struct FailAfterReader<R> {
        inner: R,
        remaining: usize,
    }

    impl<R> FailAfterReader<R> {
        fn new(inner: R, remaining: usize) -> Self {
            Self { inner, remaining }
        }
    }

    impl<R: Read> Read for FailAfterReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            if self.remaining == 0 {
                return Err(io::Error::other("injected read failure"));
            }
            let length = buffer.len().min(self.remaining);
            let read = self.inner.read(&mut buffer[..length])?;
            self.remaining -= read;
            Ok(read)
        }
    }

    struct FailAfterWriter {
        bytes: Vec<u8>,
        limit: usize,
    }

    impl FailAfterWriter {
        fn new(limit: usize) -> Self {
            Self {
                bytes: Vec::new(),
                limit,
            }
        }
    }

    impl Write for FailAfterWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            if self.bytes.len() == self.limit {
                return Err(io::Error::other("injected write failure"));
            }
            let length = buffer.len().min(self.limit - self.bytes.len());
            self.bytes.extend_from_slice(&buffer[..length]);
            Ok(length)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
