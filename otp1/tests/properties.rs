use std::io::{self, Cursor, Read, Write};

fn transform(input: &[u8], key: &[u8], length: u64) -> io::Result<Vec<u8>> {
    let mut input = Cursor::new(input);
    let mut key = Cursor::new(key);
    let mut output = Vec::new();
    otp1::xor_stream_exact(&mut input, &mut key, &mut output, length)?;
    Ok(output)
}

fn expected_xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    input
        .iter()
        .zip(key)
        .map(|(&input_byte, &key_byte)| input_byte ^ key_byte)
        .collect()
}

#[derive(Clone)]
struct DeterministicRng(u64);

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        assert_ne!(seed, 0);
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64*: small, deterministic, and sufficient for property inputs.
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let random = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&random[..chunk.len()]);
        }
    }
}

struct ChunkedReader {
    bytes: Vec<u8>,
    position: usize,
    max_chunk: usize,
    calls: usize,
}

impl ChunkedReader {
    fn new(bytes: Vec<u8>, max_chunk: usize) -> Self {
        assert!(max_chunk > 0);
        Self {
            bytes,
            position: 0,
            max_chunk,
            calls: 0,
        }
    }
}

impl Read for ChunkedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        if buffer.is_empty() || self.position == self.bytes.len() {
            return Ok(0);
        }

        let count = buffer
            .len()
            .min(self.max_chunk)
            .min(self.bytes.len() - self.position);
        buffer[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

struct InterruptingReader {
    inner: ChunkedReader,
    interrupt_next: bool,
    interruptions: usize,
}

impl InterruptingReader {
    fn new(bytes: Vec<u8>, max_chunk: usize) -> Self {
        Self {
            inner: ChunkedReader::new(bytes, max_chunk),
            interrupt_next: true,
            interruptions: 0,
        }
    }
}

impl Read for InterruptingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.interrupt_next {
            self.interrupt_next = false;
            self.interruptions += 1;
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "injected read interruption",
            ));
        }
        self.interrupt_next = true;
        self.inner.read(buffer)
    }
}

struct ErrorAfterReader {
    bytes: Vec<u8>,
    position: usize,
    fail_after: usize,
    kind: io::ErrorKind,
}

impl ErrorAfterReader {
    fn new(bytes: Vec<u8>, fail_after: usize, kind: io::ErrorKind) -> Self {
        assert!(fail_after <= bytes.len());
        Self {
            bytes,
            position: 0,
            fail_after,
            kind,
        }
    }
}

impl Read for ErrorAfterReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.fail_after {
            return Err(io::Error::new(self.kind, "injected read failure"));
        }

        let count = buffer
            .len()
            .min(self.fail_after - self.position)
            .min(self.bytes.len() - self.position);
        buffer[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

struct ZeroThenDataReader {
    bytes: Vec<u8>,
    position: usize,
    return_zero_at: usize,
    returned_zero: bool,
}

impl Read for ZeroThenDataReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.returned_zero && self.position >= self.return_zero_at {
            self.returned_zero = true;
            return Ok(0);
        }
        if buffer.is_empty() || self.position == self.bytes.len() {
            return Ok(0);
        }

        let mut count = buffer.len().min(self.bytes.len() - self.position);
        if !self.returned_zero && self.position < self.return_zero_at {
            count = count.min(self.return_zero_at - self.position);
        }
        buffer[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

#[derive(Default)]
struct ChunkedWriter {
    bytes: Vec<u8>,
    max_chunk: usize,
    calls: usize,
}

impl ChunkedWriter {
    fn new(max_chunk: usize) -> Self {
        assert!(max_chunk > 0);
        Self {
            bytes: Vec::new(),
            max_chunk,
            calls: 0,
        }
    }
}

impl Write for ChunkedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        let count = buffer.len().min(self.max_chunk);
        self.bytes.extend_from_slice(&buffer[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct InterruptingWriter {
    inner: ChunkedWriter,
    interrupt_next: bool,
    interruptions: usize,
}

impl InterruptingWriter {
    fn new(max_chunk: usize) -> Self {
        Self {
            inner: ChunkedWriter::new(max_chunk),
            interrupt_next: true,
            interruptions: 0,
        }
    }
}

impl Write for InterruptingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.interrupt_next {
            self.interrupt_next = false;
            self.interruptions += 1;
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "injected write interruption",
            ));
        }
        self.interrupt_next = true;
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct ErrorAfterWriter {
    bytes: Vec<u8>,
    fail_after: usize,
    kind: io::ErrorKind,
}

impl ErrorAfterWriter {
    fn new(fail_after: usize, kind: io::ErrorKind) -> Self {
        Self {
            bytes: Vec::new(),
            fail_after,
            kind,
        }
    }
}

impl Write for ErrorAfterWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.bytes.len() >= self.fail_after {
            return Err(io::Error::new(self.kind, "injected write failure"));
        }
        let count = buffer.len().min(self.fail_after - self.bytes.len());
        self.bytes.extend_from_slice(&buffer[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct ZeroWriter {
    calls: usize,
}

impl Write for ZeroWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        Ok(0)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PanicReader;

impl Read for PanicReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        panic!("zero-length operation unexpectedly read a stream")
    }
}

struct PanicWriter;

impl Write for PanicWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        panic!("zero-length operation unexpectedly wrote a stream")
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const STREAM_CHUNK_LIMIT: usize = 64 * 1024;

fn generated_byte(position: u64, salt: u8) -> u8 {
    let mixed = position.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17)
        ^ u64::from(salt).wrapping_mul(0xa5a5_a5a5_a5a5_a5a5);
    (mixed ^ (mixed >> 23) ^ (mixed >> 41)) as u8
}

struct GeneratedReader {
    length: u64,
    position: u64,
    salt: u8,
    fail_at: Option<(u64, io::ErrorKind)>,
    calls: usize,
    max_requested: usize,
    last_requested: usize,
}

impl GeneratedReader {
    fn new(length: u64, salt: u8) -> Self {
        Self {
            length,
            position: 0,
            salt,
            fail_at: None,
            calls: 0,
            max_requested: 0,
            last_requested: 0,
        }
    }

    fn failing(length: u64, salt: u8, fail_at: u64, kind: io::ErrorKind) -> Self {
        assert!(fail_at < length);
        Self {
            fail_at: Some((fail_at, kind)),
            ..Self::new(length, salt)
        }
    }
}

impl Read for GeneratedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        self.max_requested = self.max_requested.max(buffer.len());
        self.last_requested = buffer.len();
        assert!(
            buffer.len() <= STREAM_CHUNK_LIMIT,
            "xor_stream_exact requested a {}-byte read buffer, exceeding its {}-byte bound",
            buffer.len(),
            STREAM_CHUNK_LIMIT
        );

        if buffer.is_empty() || self.position == self.length {
            return Ok(0);
        }
        if let Some((fail_at, kind)) = self.fail_at
            && self.position >= fail_at
        {
            return Err(io::Error::new(
                kind,
                "injected late generated-reader failure",
            ));
        }

        let remaining = usize::try_from(self.length - self.position).unwrap_or(usize::MAX);
        let mut count = buffer.len().min(remaining);
        if let Some((fail_at, _)) = self.fail_at {
            let before_failure = usize::try_from(fail_at - self.position).unwrap_or(usize::MAX);
            count = count.min(before_failure);
        }

        for (offset, byte) in buffer[..count].iter_mut().enumerate() {
            *byte = generated_byte(self.position + offset as u64, self.salt);
        }
        self.position += count as u64;
        Ok(count)
    }
}

struct VerifyingCountingSink {
    position: u64,
    input_salt: u8,
    key_salt: u8,
    fail_at: Option<(u64, io::ErrorKind)>,
    calls: usize,
    max_requested: usize,
    last_requested: usize,
}

impl VerifyingCountingSink {
    fn new(input_salt: u8, key_salt: u8) -> Self {
        Self {
            position: 0,
            input_salt,
            key_salt,
            fail_at: None,
            calls: 0,
            max_requested: 0,
            last_requested: 0,
        }
    }

    fn failing(input_salt: u8, key_salt: u8, fail_at: u64, kind: io::ErrorKind) -> Self {
        Self {
            fail_at: Some((fail_at, kind)),
            ..Self::new(input_salt, key_salt)
        }
    }
}

impl Write for VerifyingCountingSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        self.max_requested = self.max_requested.max(buffer.len());
        self.last_requested = buffer.len();
        assert!(
            buffer.len() <= STREAM_CHUNK_LIMIT,
            "xor_stream_exact offered a {}-byte write slice, exceeding its {}-byte bound",
            buffer.len(),
            STREAM_CHUNK_LIMIT
        );

        if let Some((fail_at, kind)) = self.fail_at
            && self.position >= fail_at
        {
            return Err(io::Error::new(kind, "injected late counting-sink failure"));
        }

        let mut count = buffer.len();
        if let Some((fail_at, _)) = self.fail_at {
            let before_failure = usize::try_from(fail_at - self.position).unwrap_or(usize::MAX);
            count = count.min(before_failure);
        }

        for (offset, &actual) in buffer[..count].iter().enumerate() {
            let position = self.position + offset as u64;
            let expected =
                generated_byte(position, self.input_salt) ^ generated_byte(position, self.key_salt);
            assert_eq!(
                actual, expected,
                "incorrect streamed output byte at absolute position {position}"
            );
        }
        self.position += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn known_vector() {
    let input = [0x00, 0xff, 0x55, 0xaa, 0x12, 0x80];
    let key = [0x00, 0x0f, 0xaa, 0x55, 0x34, 0xff];
    let expected = [0x00, 0xf0, 0xff, 0xff, 0x26, 0x7f];

    assert_eq!(
        transform(&input, &key, input.len() as u64).unwrap(),
        expected
    );
}

#[test]
fn all_65_536_byte_pairs_are_xored_correctly() {
    let mut input = Vec::with_capacity(256 * 256);
    let mut key = Vec::with_capacity(256 * 256);
    let mut expected = Vec::with_capacity(256 * 256);

    for input_byte in 0_u8..=u8::MAX {
        for key_byte in 0_u8..=u8::MAX {
            input.push(input_byte);
            key.push(key_byte);
            expected.push(input_byte ^ key_byte);
        }
    }

    assert_eq!(
        transform(&input, &key, input.len() as u64).unwrap(),
        expected
    );
}

#[test]
fn empty_streams_produce_empty_output() {
    assert_eq!(transform(&[], &[], 0).unwrap(), Vec::<u8>::new());
}

#[test]
fn zero_length_does_not_access_any_stream() {
    let mut input = PanicReader;
    let mut key = PanicReader;
    let mut output = PanicWriter;

    otp1::xor_stream_exact(&mut input, &mut key, &mut output, 0).unwrap();
}

#[test]
fn output_is_appended_at_the_writer_position() {
    let mut input = Cursor::new([0xaa, 0x55]);
    let mut key = Cursor::new([0x0f, 0xf0]);
    let mut output = vec![0xde, 0xad];

    otp1::xor_stream_exact(&mut input, &mut key, &mut output, 2).unwrap();

    assert_eq!(output, [0xde, 0xad, 0xa5, 0xa5]);
}

#[test]
fn processes_exactly_the_requested_prefix() {
    let input_bytes = [1, 2, 3, 4, 0xee, 0xee];
    let key_bytes = [8, 7, 6, 5, 0xdd, 0xdd, 0xdd];
    let mut input = Cursor::new(input_bytes);
    let mut key = Cursor::new(key_bytes);
    let mut output = Vec::new();

    otp1::xor_stream_exact(&mut input, &mut key, &mut output, 4).unwrap();

    assert_eq!(output, [9, 5, 5, 1]);
    assert_eq!(input.position(), 4, "input was read past requested length");
    assert_eq!(key.position(), 4, "key was read past requested length");
}

#[test]
fn key_may_be_longer_than_input() {
    let input_bytes = [1, 2, 3];
    let key_bytes = [4, 5, 6, 7, 8, 9];
    let mut input = Cursor::new(input_bytes);
    let mut key = Cursor::new(key_bytes);
    let mut output = Vec::new();

    otp1::xor_stream_exact(&mut input, &mut key, &mut output, 3).unwrap();

    assert_eq!(output, [5, 7, 5]);
    assert_eq!(key.position(), 3);
}

#[test]
fn many_lengths_around_common_buffer_boundaries() {
    const LENGTHS: &[usize] = &[
        0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024, 2047,
        2048, 4095, 4096, 4097, 8191, 8192, 8193, 16_383, 16_384, 16_385, 32_767, 32_768, 32_769,
        65_535, 65_536, 65_537,
    ];
    let mut rng = DeterministicRng::new(0x0123_4567_89ab_cdef);

    for &length in LENGTHS {
        let mut input = vec![0; length];
        let mut key = vec![0; length];
        rng.fill(&mut input);
        rng.fill(&mut key);

        let actual = transform(&input, &key, length as u64).unwrap();
        assert_eq!(actual, expected_xor(&input, &key), "length {length}");
    }
}

#[test]
fn deterministic_random_vectors_match_direct_xor() {
    let mut rng = DeterministicRng::new(0xd1b5_4a32_d192_ed03);

    for case in 0..128 {
        let length = (rng.next_u64() % 100_003) as usize;
        let mut input = vec![0; length];
        let mut key = vec![0; length + (rng.next_u64() % 97) as usize];
        rng.fill(&mut input);
        rng.fill(&mut key);

        let actual = transform(&input, &key, length as u64).unwrap();
        assert_eq!(actual, expected_xor(&input, &key[..length]), "case {case}");
    }
}

#[test]
fn applying_the_same_key_twice_restores_the_input() {
    let mut rng = DeterministicRng::new(0x8a5c_17e2_3d49_b60f);

    for case in 0..64 {
        let length = (rng.next_u64() % 131_073) as usize;
        let mut plaintext = vec![0; length];
        let mut key = vec![0; length];
        rng.fill(&mut plaintext);
        rng.fill(&mut key);

        let ciphertext = transform(&plaintext, &key, length as u64).unwrap();
        let recovered = transform(&ciphertext, &key, length as u64).unwrap();
        assert_eq!(recovered, plaintext, "case {case}");
    }
}

#[test]
fn xor_identity_complement_and_self_properties_hold() {
    let mut rng = DeterministicRng::new(0x44c0_ffee_1234_5678);
    let mut input = vec![0; 98_765];
    rng.fill(&mut input);

    assert_eq!(
        transform(&input, &vec![0; input.len()], input.len() as u64).unwrap(),
        input
    );
    assert_eq!(
        transform(&input, &vec![u8::MAX; input.len()], input.len() as u64).unwrap(),
        input.iter().map(|byte| !byte).collect::<Vec<_>>()
    );
    assert_eq!(
        transform(&input, &input, input.len() as u64).unwrap(),
        vec![0; input.len()]
    );
}

#[test]
fn xor_composition_property_holds() {
    let mut rng = DeterministicRng::new(0xa11c_e5ed_f00d_beef);

    for case in 0..32 {
        let length = (rng.next_u64() % 65_539) as usize;
        let mut input = vec![0; length];
        let mut first_key = vec![0; length];
        let mut second_key = vec![0; length];
        rng.fill(&mut input);
        rng.fill(&mut first_key);
        rng.fill(&mut second_key);

        let first = transform(&input, &first_key, length as u64).unwrap();
        let sequential = transform(&first, &second_key, length as u64).unwrap();
        let combined_key = expected_xor(&first_key, &second_key);
        let combined = transform(&input, &combined_key, length as u64).unwrap();
        assert_eq!(sequential, combined, "case {case}");
    }
}

#[test]
fn one_byte_partial_readers_are_supported() {
    let input_bytes: Vec<_> = (0..=u8::MAX).cycle().take(20_001).collect();
    let key_bytes: Vec<_> = (0..=u8::MAX).rev().cycle().take(20_001).collect();
    let expected = expected_xor(&input_bytes, &key_bytes);
    let mut input = ChunkedReader::new(input_bytes, 1);
    let mut key = ChunkedReader::new(key_bytes, 1);
    let mut output = Vec::new();

    otp1::xor_stream_exact(&mut input, &mut key, &mut output, expected.len() as u64).unwrap();

    assert_eq!(output, expected);
    assert!(input.calls >= output.len());
    assert!(key.calls >= output.len());
}

#[test]
fn differently_sized_partial_readers_are_supported() {
    let mut rng = DeterministicRng::new(0x7777_aaaa_5555_cccc);
    let mut input_bytes = vec![0; 70_003];
    let mut key_bytes = vec![0; 70_003];
    rng.fill(&mut input_bytes);
    rng.fill(&mut key_bytes);
    let expected = expected_xor(&input_bytes, &key_bytes);
    let mut input = ChunkedReader::new(input_bytes, 3);
    let mut key = ChunkedReader::new(key_bytes, 11);
    let mut output = Vec::new();

    otp1::xor_stream_exact(&mut input, &mut key, &mut output, expected.len() as u64).unwrap();

    assert_eq!(output, expected);
}

#[test]
fn interrupted_and_partial_readers_are_retried() {
    let input_bytes: Vec<_> = (0..50_007).map(|n| (n * 31) as u8).collect();
    let key_bytes: Vec<_> = (0..50_007).map(|n| (n * 47 + 9) as u8).collect();
    let expected = expected_xor(&input_bytes, &key_bytes);
    let mut input = InterruptingReader::new(input_bytes, 5);
    let mut key = InterruptingReader::new(key_bytes, 7);
    let mut output = Vec::new();

    otp1::xor_stream_exact(&mut input, &mut key, &mut output, expected.len() as u64).unwrap();

    assert_eq!(output, expected);
    assert!(input.interruptions > 1);
    assert!(key.interruptions > 1);
}

#[test]
fn one_byte_partial_writer_is_supported() {
    let input_bytes: Vec<_> = (0..32_009).map(|n| (n * 13) as u8).collect();
    let key_bytes: Vec<_> = (0..32_009).map(|n| (n * 19 + 1) as u8).collect();
    let expected = expected_xor(&input_bytes, &key_bytes);
    let mut input = Cursor::new(input_bytes);
    let mut key = Cursor::new(key_bytes);
    let mut output = ChunkedWriter::new(1);

    otp1::xor_stream_exact(&mut input, &mut key, &mut output, expected.len() as u64).unwrap();

    assert_eq!(output.bytes, expected);
    assert!(output.calls >= output.bytes.len());
}

#[test]
fn interrupted_and_partial_writers_are_retried() {
    let input_bytes: Vec<_> = (0..41_003).map(|n| (n * 7 + 3) as u8).collect();
    let key_bytes: Vec<_> = (0..41_003).map(|n| (n * 23 + 5) as u8).collect();
    let expected = expected_xor(&input_bytes, &key_bytes);
    let mut input = Cursor::new(input_bytes);
    let mut key = Cursor::new(key_bytes);
    let mut output = InterruptingWriter::new(13);

    otp1::xor_stream_exact(&mut input, &mut key, &mut output, expected.len() as u64).unwrap();

    assert_eq!(output.inner.bytes, expected);
    assert!(output.interruptions > 1);
}

#[test]
fn simultaneous_partial_and_interrupted_io_is_supported() {
    let input_bytes: Vec<_> = (0..12_345).map(|n| (n * 29 + 7) as u8).collect();
    let key_bytes: Vec<_> = (0..12_345).map(|n| (n * 43 + 11) as u8).collect();
    let expected = expected_xor(&input_bytes, &key_bytes);
    let mut input = InterruptingReader::new(input_bytes, 2);
    let mut key = InterruptingReader::new(key_bytes, 3);
    let mut output = InterruptingWriter::new(5);

    otp1::xor_stream_exact(&mut input, &mut key, &mut output, expected.len() as u64).unwrap();

    assert_eq!(output.inner.bytes, expected);
    assert!(input.interruptions > 0);
    assert!(key.interruptions > 0);
    assert!(output.interruptions > 0);
}

#[test]
fn premature_input_eof_is_reported() {
    let mut input = Cursor::new([1, 2, 3]);
    let mut key = Cursor::new([4, 5, 6, 7]);
    let mut output = Vec::new();

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, 4).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn premature_key_eof_is_reported() {
    let mut input = Cursor::new([1, 2, 3, 4]);
    let mut key = Cursor::new([5, 6, 7]);
    let mut output = Vec::new();

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, 4).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn immediate_input_eof_is_reported() {
    let mut input = Cursor::new([]);
    let mut key = Cursor::new([1]);
    let mut output = Vec::new();

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, 1).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn immediate_key_eof_is_reported() {
    let mut input = Cursor::new([1]);
    let mut key = Cursor::new([]);
    let mut output = Vec::new();

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, 1).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn a_zero_read_before_requested_length_is_eof() {
    let bytes: Vec<_> = (0..32).collect();
    let mut input = ZeroThenDataReader {
        bytes,
        position: 0,
        return_zero_at: 7,
        returned_zero: false,
    };
    let mut key = Cursor::new(vec![0; 32]);
    let mut output = Vec::new();

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, 32).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn input_read_errors_are_propagated() {
    let mut input = ErrorAfterReader::new(vec![0x11; 100], 17, io::ErrorKind::PermissionDenied);
    let mut key = Cursor::new(vec![0x22; 100]);
    let mut output = Vec::new();

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, 100).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "injected read failure");
}

#[test]
fn key_read_errors_are_propagated() {
    let mut input = Cursor::new(vec![0x11; 100]);
    let mut key = ErrorAfterReader::new(vec![0x22; 100], 19, io::ErrorKind::InvalidData);
    let mut output = Vec::new();

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, 100).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "injected read failure");
}

#[test]
fn writer_errors_are_propagated_without_corrupting_the_prefix() {
    let input_bytes: Vec<_> = (0..100).map(|n| (n * 3) as u8).collect();
    let key_bytes: Vec<_> = (0..100).map(|n| (n * 5 + 1) as u8).collect();
    let expected = expected_xor(&input_bytes, &key_bytes);
    let mut input = Cursor::new(input_bytes);
    let mut key = Cursor::new(key_bytes);
    let mut output = ErrorAfterWriter::new(23, io::ErrorKind::StorageFull);

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, expected.len() as u64)
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    assert_eq!(error.to_string(), "injected write failure");
    assert_eq!(output.bytes, expected[..23]);
}

#[test]
fn a_zero_length_write_is_reported_as_write_zero() {
    let mut input = Cursor::new([1, 2, 3]);
    let mut key = Cursor::new([4, 5, 6]);
    let mut output = ZeroWriter::default();

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, 3).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert_eq!(output.calls, 1);
}

#[test]
fn virtual_stream_uses_bounded_chunks_and_exact_counts_without_storing_output() {
    const LENGTH: u64 = 32 * STREAM_CHUNK_LIMIT as u64 + 137;
    const EXPECTED_CALLS: usize = 33;
    const INPUT_SALT: u8 = 0x3d;
    const KEY_SALT: u8 = 0xc7;

    let mut input = GeneratedReader::new(LENGTH, INPUT_SALT);
    let mut key = GeneratedReader::new(LENGTH, KEY_SALT);
    let mut output = VerifyingCountingSink::new(INPUT_SALT, KEY_SALT);

    otp1::xor_stream_exact(&mut input, &mut key, &mut output, LENGTH).unwrap();

    assert_eq!(input.position, LENGTH);
    assert_eq!(key.position, LENGTH);
    assert_eq!(output.position, LENGTH);
    assert_eq!(input.calls, EXPECTED_CALLS);
    assert_eq!(key.calls, EXPECTED_CALLS);
    assert_eq!(output.calls, EXPECTED_CALLS);
    assert_eq!(input.max_requested, STREAM_CHUNK_LIMIT);
    assert_eq!(key.max_requested, STREAM_CHUNK_LIMIT);
    assert_eq!(output.max_requested, STREAM_CHUNK_LIMIT);
    assert_eq!(input.last_requested, 137);
    assert_eq!(key.last_requested, 137);
    assert_eq!(output.last_requested, 137);
}

#[test]
fn late_input_error_after_three_chunks_preserves_exact_completed_output_count() {
    const CHUNK: u64 = STREAM_CHUNK_LIMIT as u64;
    const LENGTH: u64 = 8 * CHUNK + 19;
    const FAIL_AT: u64 = 3 * CHUNK + 257;
    const COMPLETED_OUTPUT: u64 = 3 * CHUNK;
    const INPUT_SALT: u8 = 0x51;
    const KEY_SALT: u8 = 0xae;

    let mut input =
        GeneratedReader::failing(LENGTH, INPUT_SALT, FAIL_AT, io::ErrorKind::PermissionDenied);
    let mut key = GeneratedReader::new(LENGTH, KEY_SALT);
    let mut output = VerifyingCountingSink::new(INPUT_SALT, KEY_SALT);

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, LENGTH).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "injected late generated-reader failure");
    assert_eq!(input.position, FAIL_AT);
    assert_eq!(key.position, COMPLETED_OUTPUT);
    assert_eq!(output.position, COMPLETED_OUTPUT);
    assert_eq!(input.calls, 5);
    assert_eq!(key.calls, 3);
    assert_eq!(output.calls, 3);
    assert_eq!(input.max_requested, STREAM_CHUNK_LIMIT);
    assert_eq!(key.max_requested, STREAM_CHUNK_LIMIT);
    assert_eq!(output.max_requested, STREAM_CHUNK_LIMIT);
}

#[test]
fn late_key_error_after_three_chunks_preserves_exact_completed_output_count() {
    const CHUNK: u64 = STREAM_CHUNK_LIMIT as u64;
    const LENGTH: u64 = 8 * CHUNK + 29;
    const FAIL_AT: u64 = 3 * CHUNK + 257;
    const COMPLETED_OUTPUT: u64 = 3 * CHUNK;
    const INPUT_SALT: u8 = 0x92;
    const KEY_SALT: u8 = 0x2b;

    let mut input = GeneratedReader::new(LENGTH, INPUT_SALT);
    let mut key = GeneratedReader::failing(LENGTH, KEY_SALT, FAIL_AT, io::ErrorKind::InvalidData);
    let mut output = VerifyingCountingSink::new(INPUT_SALT, KEY_SALT);

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, LENGTH).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "injected late generated-reader failure");
    assert_eq!(input.position, 4 * CHUNK);
    assert_eq!(key.position, FAIL_AT);
    assert_eq!(output.position, COMPLETED_OUTPUT);
    assert_eq!(input.calls, 4);
    assert_eq!(key.calls, 5);
    assert_eq!(output.calls, 3);
    assert_eq!(input.max_requested, STREAM_CHUNK_LIMIT);
    assert_eq!(key.max_requested, STREAM_CHUNK_LIMIT);
    assert_eq!(output.max_requested, STREAM_CHUNK_LIMIT);
}

#[test]
fn late_write_error_reports_exact_verified_prefix_without_buffering_output() {
    const CHUNK: u64 = STREAM_CHUNK_LIMIT as u64;
    const LENGTH: u64 = 8 * CHUNK + 31;
    const FAIL_AT: u64 = 3 * CHUNK + 257;
    const INPUT_SALT: u8 = 0x6e;
    const KEY_SALT: u8 = 0xd4;

    let mut input = GeneratedReader::new(LENGTH, INPUT_SALT);
    let mut key = GeneratedReader::new(LENGTH, KEY_SALT);
    let mut output =
        VerifyingCountingSink::failing(INPUT_SALT, KEY_SALT, FAIL_AT, io::ErrorKind::StorageFull);

    let error = otp1::xor_stream_exact(&mut input, &mut key, &mut output, LENGTH).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    assert_eq!(error.to_string(), "injected late counting-sink failure");
    assert_eq!(input.position, 4 * CHUNK);
    assert_eq!(key.position, 4 * CHUNK);
    assert_eq!(output.position, FAIL_AT);
    assert_eq!(input.calls, 4);
    assert_eq!(key.calls, 4);
    assert_eq!(output.calls, 5);
    assert_eq!(input.max_requested, STREAM_CHUNK_LIMIT);
    assert_eq!(key.max_requested, STREAM_CHUNK_LIMIT);
    assert_eq!(output.max_requested, STREAM_CHUNK_LIMIT);
    assert_eq!(output.last_requested, STREAM_CHUNK_LIMIT - 257);
}
