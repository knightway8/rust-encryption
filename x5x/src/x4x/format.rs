use crate::x4x::Error;

pub(crate) const HEADER_LEN: usize = 64;
pub(crate) const FRAME_HEADER_LEN: usize = 8;
pub(crate) const TAG_LEN: usize = 16;

const MAGIC: &[u8; 8] = b"X4XCRYPT";
const VERSION: u8 = 1;
const CIPHER_XCHACHA20_POLY1305: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const FINAL_FRAME: u8 = 1;

pub(crate) const MIN_MEMORY_KIB: u32 = 8 * 1024;
pub(crate) const MAX_MEMORY_KIB: u32 = 512 * 1024;
pub(crate) const MIN_ITERATIONS: u32 = 1;
pub(crate) const MAX_ITERATIONS: u32 = 10;
pub(crate) const MIN_PARALLELISM: u32 = 1;
pub(crate) const MAX_PARALLELISM: u32 = 16;
pub(crate) const MIN_CHUNK_SIZE: u32 = 4 * 1024;
pub(crate) const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EncryptionOptions {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub chunk_size: u32,
}

impl Default for EncryptionOptions {
    fn default() -> Self {
        // RFC 9106's memory-constrained recommendation: Argon2id with 64 MiB
        // and three passes. One lane avoids surprising thread oversubscription.
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
            chunk_size: 1024 * 1024,
        }
    }
}

impl EncryptionOptions {
    pub(crate) fn validate(self) -> Result<(), Error> {
        bounded(
            self.memory_kib,
            MIN_MEMORY_KIB,
            MAX_MEMORY_KIB,
            "Argon2 memory cost is outside supported bounds",
        )?;
        bounded(
            self.iterations,
            MIN_ITERATIONS,
            MAX_ITERATIONS,
            "Argon2 iteration count is outside supported bounds",
        )?;
        bounded(
            self.parallelism,
            MIN_PARALLELISM,
            MAX_PARALLELISM,
            "Argon2 parallelism is outside supported bounds",
        )?;
        bounded(
            self.chunk_size,
            MIN_CHUNK_SIZE,
            MAX_CHUNK_SIZE,
            "chunk size is outside supported bounds",
        )?;

        // Argon2 requires at least 8 blocks per lane. The absolute minimum
        // above is stronger, but this keeps the relationship explicit.
        if self.memory_kib < self.parallelism.saturating_mul(8) {
            return Err(Error::UnsafeParameters(
                "Argon2 memory is too small for its parallelism",
            ));
        }
        Ok(())
    }
}

fn bounded(value: u32, min: u32, max: u32, message: &'static str) -> Result<(), Error> {
    if !(min..=max).contains(&value) {
        return Err(Error::UnsafeParameters(message));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct Header {
    raw: [u8; HEADER_LEN],
    pub options: EncryptionOptions,
    pub salt: [u8; 16],
    pub nonce_prefix: [u8; 16],
}

impl Header {
    pub(crate) fn new(
        options: EncryptionOptions,
        salt: [u8; 16],
        nonce_prefix: [u8; 16],
    ) -> Result<Self, Error> {
        options.validate()?;
        let mut raw = [0_u8; HEADER_LEN];
        raw[0..8].copy_from_slice(MAGIC);
        raw[8] = VERSION;
        raw[9] = CIPHER_XCHACHA20_POLY1305;
        raw[10] = KDF_ARGON2ID;
        raw[11] = 0;
        raw[12..16].copy_from_slice(&options.memory_kib.to_be_bytes());
        raw[16..20].copy_from_slice(&options.iterations.to_be_bytes());
        raw[20..24].copy_from_slice(&options.parallelism.to_be_bytes());
        raw[24..28].copy_from_slice(&options.chunk_size.to_be_bytes());
        raw[28..44].copy_from_slice(&salt);
        raw[44..60].copy_from_slice(&nonce_prefix);
        // bytes 60..64 are reserved and must remain zero.
        Ok(Self {
            raw,
            options,
            salt,
            nonce_prefix,
        })
    }

    pub(crate) fn parse(raw: [u8; HEADER_LEN]) -> Result<Self, Error> {
        if &raw[0..8] != MAGIC {
            return Err(Error::InvalidFormat("bad magic"));
        }
        if raw[8] != VERSION {
            return Err(Error::UnsupportedVersion(raw[8]));
        }
        if raw[9] != CIPHER_XCHACHA20_POLY1305 {
            return Err(Error::InvalidFormat("unsupported cipher identifier"));
        }
        if raw[10] != KDF_ARGON2ID {
            return Err(Error::InvalidFormat("unsupported KDF identifier"));
        }
        if raw[11] != 0 {
            return Err(Error::InvalidFormat("unsupported header flags"));
        }
        if raw[60..64] != [0; 4] {
            return Err(Error::InvalidFormat("non-zero reserved header bytes"));
        }

        let options = EncryptionOptions {
            memory_kib: read_u32(&raw, 12),
            iterations: read_u32(&raw, 16),
            parallelism: read_u32(&raw, 20),
            chunk_size: read_u32(&raw, 24),
        };
        options.validate()?;

        let mut salt = [0_u8; 16];
        salt.copy_from_slice(&raw[28..44]);
        let mut nonce_prefix = [0_u8; 16];
        nonce_prefix.copy_from_slice(&raw[44..60]);
        Ok(Self {
            raw,
            options,
            salt,
            nonce_prefix,
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8; HEADER_LEN] {
        &self.raw
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameHeader {
    raw: [u8; FRAME_HEADER_LEN],
    pub plaintext_len: u32,
    pub final_frame: bool,
}

impl FrameHeader {
    pub(crate) fn new(plaintext_len: u32, final_frame: bool) -> Self {
        let mut raw = [0_u8; FRAME_HEADER_LEN];
        raw[0..4].copy_from_slice(&plaintext_len.to_be_bytes());
        raw[4] = u8::from(final_frame);
        Self {
            raw,
            plaintext_len,
            final_frame,
        }
    }

    pub(crate) fn parse(raw: [u8; FRAME_HEADER_LEN], chunk_size: u32) -> Result<Self, Error> {
        if raw[4] & !FINAL_FRAME != 0 {
            return Err(Error::InvalidFormat("unsupported frame flags"));
        }
        if raw[5..8] != [0; 3] {
            return Err(Error::InvalidFormat("non-zero reserved frame bytes"));
        }
        let plaintext_len = read_u32(&raw, 0);
        let final_frame = raw[4] & FINAL_FRAME != 0;
        if plaintext_len > chunk_size {
            return Err(Error::InvalidFormat("frame exceeds declared chunk size"));
        }
        if !final_frame && plaintext_len != chunk_size {
            return Err(Error::InvalidFormat("short non-final frame"));
        }
        Ok(Self {
            raw,
            plaintext_len,
            final_frame,
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8; FRAME_HEADER_LEN] {
        &self.raw
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub(crate) fn nonce(prefix: &[u8; 16], frame_index: u64) -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..].copy_from_slice(&frame_index.to_be_bytes());
    nonce
}

pub(crate) fn associated_data(
    header: &Header,
    frame_index: u64,
    frame: &FrameHeader,
) -> [u8; HEADER_LEN + 8 + FRAME_HEADER_LEN] {
    let mut aad = [0_u8; HEADER_LEN + 8 + FRAME_HEADER_LEN];
    aad[..HEADER_LEN].copy_from_slice(header.as_bytes());
    aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&frame_index.to_be_bytes());
    aad[HEADER_LEN + 8..].copy_from_slice(frame.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn options() -> EncryptionOptions {
        EncryptionOptions {
            memory_kib: MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
            chunk_size: MIN_CHUNK_SIZE,
        }
    }

    fn raw_header() -> [u8; HEADER_LEN] {
        *Header::new(options(), [7; 16], [9; 16]).unwrap().as_bytes()
    }

    #[test]
    fn header_round_trip_is_exact() {
        let original = Header::new(options(), [7; 16], [9; 16]).unwrap();
        let parsed = Header::parse(*original.as_bytes()).unwrap();
        assert_eq!(parsed.options, options());
        assert_eq!(parsed.salt, [7; 16]);
        assert_eq!(parsed.nonce_prefix, [9; 16]);
        assert_eq!(parsed.as_bytes(), original.as_bytes());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut raw = raw_header();
        raw[0] ^= 1;
        assert!(matches!(Header::parse(raw), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn distinguishes_future_version() {
        let mut raw = raw_header();
        raw[8] = 2;
        assert!(matches!(
            Header::parse(raw),
            Err(Error::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_unknown_cipher() {
        let mut raw = raw_header();
        raw[9] = 99;
        assert!(matches!(Header::parse(raw), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn rejects_unknown_kdf() {
        let mut raw = raw_header();
        raw[10] = 99;
        assert!(matches!(Header::parse(raw), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn rejects_header_flags_and_reserved_bytes() {
        for offset in [11, 60, 61, 62, 63] {
            let mut raw = raw_header();
            raw[offset] = 1;
            assert!(matches!(Header::parse(raw), Err(Error::InvalidFormat(_))));
        }
    }

    #[test]
    fn rejects_kdf_and_chunk_values_outside_every_bound() {
        for (offset, value) in [
            (12, MIN_MEMORY_KIB - 1),
            (12, MAX_MEMORY_KIB + 1),
            (16, MIN_ITERATIONS - 1),
            (16, MAX_ITERATIONS + 1),
            (20, MIN_PARALLELISM - 1),
            (20, MAX_PARALLELISM + 1),
            (24, MIN_CHUNK_SIZE - 1),
            (24, MAX_CHUNK_SIZE + 1),
        ] {
            let mut raw = raw_header();
            raw[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            assert!(matches!(
                Header::parse(raw),
                Err(Error::UnsafeParameters(_))
            ));
        }
    }

    #[test]
    fn frame_round_trip() {
        for (len, final_frame) in [(MIN_CHUNK_SIZE, false), (0, true), (17, true)] {
            let frame = FrameHeader::new(len, final_frame);
            assert_eq!(
                FrameHeader::parse(*frame.as_bytes(), MIN_CHUNK_SIZE).unwrap(),
                frame
            );
        }
    }

    #[test]
    fn rejects_oversized_frame() {
        let frame = FrameHeader::new(MIN_CHUNK_SIZE + 1, true);
        assert!(matches!(
            FrameHeader::parse(*frame.as_bytes(), MIN_CHUNK_SIZE),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn rejects_short_non_final_frame() {
        let frame = FrameHeader::new(MIN_CHUNK_SIZE - 1, false);
        assert!(matches!(
            FrameHeader::parse(*frame.as_bytes(), MIN_CHUNK_SIZE),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn rejects_frame_flags_and_reserved_bytes() {
        for offset in [4, 5, 6, 7] {
            let mut raw = *FrameHeader::new(0, true).as_bytes();
            raw[offset] |= if offset == 4 { 2 } else { 1 };
            assert!(matches!(
                FrameHeader::parse(raw, MIN_CHUNK_SIZE),
                Err(Error::InvalidFormat(_))
            ));
        }
    }

    #[test]
    fn nonces_change_with_frame_index() {
        let prefix = [42; 16];
        let first = nonce(&prefix, 0);
        let second = nonce(&prefix, 1);
        assert_ne!(first, second);
        assert_eq!(&first[..16], &prefix);
        assert_eq!(&second[16..], &1_u64.to_be_bytes());
    }

    #[test]
    fn associated_data_binds_index_and_final_marker() {
        let header = Header::new(options(), [1; 16], [2; 16]).unwrap();
        let regular = FrameHeader::new(MIN_CHUNK_SIZE, false);
        let final_frame = FrameHeader::new(MIN_CHUNK_SIZE, true);
        assert_ne!(
            associated_data(&header, 0, &regular),
            associated_data(&header, 1, &regular)
        );
        assert_ne!(
            associated_data(&header, 0, &regular),
            associated_data(&header, 0, &final_frame)
        );
    }

    #[test]
    fn exact_parameter_bounds_are_accepted() {
        for bounded_options in [
            EncryptionOptions {
                memory_kib: MIN_MEMORY_KIB,
                iterations: MIN_ITERATIONS,
                parallelism: MIN_PARALLELISM,
                chunk_size: MIN_CHUNK_SIZE,
            },
            EncryptionOptions {
                memory_kib: MAX_MEMORY_KIB,
                iterations: MAX_ITERATIONS,
                parallelism: MAX_PARALLELISM,
                chunk_size: MAX_CHUNK_SIZE,
            },
        ] {
            let header = Header::new(bounded_options, [0; 16], [255; 16]).unwrap();
            assert_eq!(
                Header::parse(*header.as_bytes()).unwrap().options,
                bounded_options
            );
        }
    }

    #[test]
    fn header_encoding_uses_documented_offsets_and_big_endian_values() {
        let custom = EncryptionOptions {
            memory_kib: 0x0000_2000,
            iterations: 0x0000_0002,
            parallelism: 0x0000_0003,
            chunk_size: 0x0000_4000,
        };
        let raw = *Header::new(custom, [0x5a; 16], [0xa5; 16])
            .unwrap()
            .as_bytes();
        assert_eq!(&raw[..8], b"X4XCRYPT");
        assert_eq!(&raw[12..16], &custom.memory_kib.to_be_bytes());
        assert_eq!(&raw[16..20], &custom.iterations.to_be_bytes());
        assert_eq!(&raw[20..24], &custom.parallelism.to_be_bytes());
        assert_eq!(&raw[24..28], &custom.chunk_size.to_be_bytes());
        assert_eq!(&raw[28..44], &[0x5a; 16]);
        assert_eq!(&raw[44..60], &[0xa5; 16]);
    }

    #[test]
    fn frame_encoding_is_canonical() {
        assert_eq!(
            FrameHeader::new(0x0102_0304, true).as_bytes(),
            &[1, 2, 3, 4, 1, 0, 0, 0]
        );
        assert_eq!(
            FrameHeader::new(MIN_CHUNK_SIZE, false).as_bytes()[4..],
            [0, 0, 0, 0]
        );
    }

    #[test]
    fn maximum_frame_counter_has_a_distinct_nonce() {
        let prefix = [11; 16];
        assert_eq!(&nonce(&prefix, u64::MAX)[16..], &u64::MAX.to_be_bytes());
        assert_ne!(nonce(&prefix, u64::MAX), nonce(&prefix, u64::MAX - 1));
    }

    #[test]
    fn associated_data_binds_every_header_field() {
        let frame = FrameHeader::new(0, true);
        let base = Header::new(options(), [1; 16], [2; 16]).unwrap();
        let changed_salt = Header::new(options(), [3; 16], [2; 16]).unwrap();
        let changed_nonce = Header::new(options(), [1; 16], [4; 16]).unwrap();
        assert_ne!(
            associated_data(&base, 0, &frame),
            associated_data(&changed_salt, 0, &frame)
        );
        assert_ne!(
            associated_data(&base, 0, &frame),
            associated_data(&changed_nonce, 0, &frame)
        );
    }

    #[test]
    fn production_defaults_are_locked_to_the_documented_values() {
        assert_eq!(
            EncryptionOptions::default(),
            EncryptionOptions {
                memory_kib: 64 * 1024,
                iterations: 3,
                parallelism: 1,
                chunk_size: 1024 * 1024,
            }
        );
    }

    #[test]
    fn every_unsupported_frame_flag_combination_is_rejected() {
        for flags in 2_u8..=u8::MAX {
            let mut raw = *FrameHeader::new(0, true).as_bytes();
            raw[4] = flags;
            assert!(matches!(
                FrameHeader::parse(raw, MIN_CHUNK_SIZE),
                Err(Error::InvalidFormat("unsupported frame flags"))
            ));
        }
    }

    #[test]
    fn any_nonzero_frame_reserved_byte_is_rejected() {
        for offset in 5..8 {
            for value in [1, 0x80, 0xff] {
                let mut raw = *FrameHeader::new(0, true).as_bytes();
                raw[offset] = value;
                assert!(matches!(
                    FrameHeader::parse(raw, MIN_CHUNK_SIZE),
                    Err(Error::InvalidFormat("non-zero reserved frame bytes"))
                ));
            }
        }
    }

    #[test]
    fn representative_final_frame_lengths_are_all_valid() {
        for length in [0, 1, MIN_CHUNK_SIZE / 2, MIN_CHUNK_SIZE - 1, MIN_CHUNK_SIZE] {
            let frame = FrameHeader::new(length, true);
            assert_eq!(
                FrameHeader::parse(*frame.as_bytes(), MIN_CHUNK_SIZE).unwrap(),
                frame
            );
        }
    }

    #[test]
    fn every_representative_short_nonfinal_length_is_rejected() {
        for length in [0, 1, MIN_CHUNK_SIZE / 2, MIN_CHUNK_SIZE - 1] {
            let frame = FrameHeader::new(length, false);
            assert!(matches!(
                FrameHeader::parse(*frame.as_bytes(), MIN_CHUNK_SIZE),
                Err(Error::InvalidFormat("short non-final frame"))
            ));
        }
    }

    #[test]
    fn nonce_layout_is_exact_for_representative_counters() {
        let prefix = [0x33; 16];
        for counter in [0, 1, 255, 256, u64::from(u32::MAX), u64::MAX] {
            let generated = nonce(&prefix, counter);
            assert_eq!(&generated[..16], &prefix);
            assert_eq!(&generated[16..], &counter.to_be_bytes());
        }
    }

    #[test]
    fn associated_data_layout_is_exact() {
        let header = Header::new(options(), [0x11; 16], [0x22; 16]).unwrap();
        let frame = FrameHeader::new(17, true);
        let index = 0x0102_0304_0506_0708;
        let aad = associated_data(&header, index, &frame);
        assert_eq!(&aad[..HEADER_LEN], header.as_bytes());
        assert_eq!(&aad[HEADER_LEN..HEADER_LEN + 8], &index.to_be_bytes());
        assert_eq!(&aad[HEADER_LEN + 8..], frame.as_bytes());
    }

    #[test]
    fn all_supported_header_fields_survive_serialization() {
        let parameter_sets = [
            EncryptionOptions::default(),
            options(),
            EncryptionOptions {
                memory_kib: 128 * 1024,
                iterations: 7,
                parallelism: 4,
                chunk_size: 2 * 1024 * 1024,
            },
        ];
        for (index, parameters) in parameter_sets.into_iter().enumerate() {
            let index = u8::try_from(index).expect("parameter-set index fits in u8");
            let salt = [index; 16];
            let nonce_prefix = [255 - index; 16];
            let parsed = Header::parse(
                *Header::new(parameters, salt, nonce_prefix)
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
            assert_eq!(parsed.options, parameters);
            assert_eq!(parsed.salt, salt);
            assert_eq!(parsed.nonce_prefix, nonce_prefix);
        }
    }

    #[test]
    fn first_ten_thousand_frame_nonces_are_unique() {
        let prefix = [0x7c; 16];
        let nonces: BTreeSet<_> = (0..10_000).map(|index| nonce(&prefix, index)).collect();
        assert_eq!(nonces.len(), 10_000);
    }

    #[test]
    fn first_ten_thousand_associated_data_values_are_unique() {
        let header = Header::new(options(), [1; 16], [2; 16]).unwrap();
        let frame = FrameHeader::new(MIN_CHUNK_SIZE, false);
        let values: BTreeSet<_> = (0..10_000)
            .map(|index| associated_data(&header, index, &frame))
            .collect();
        assert_eq!(values.len(), 10_000);
    }

    #[test]
    fn frame_parser_matches_its_invariants_for_many_generated_inputs() {
        let mut state = 0x1234_5678_u32;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let length = state % (MIN_CHUNK_SIZE * 2);
            let flags = u8::try_from((state >> 16) & 0xff).expect("masked flags fit in u8");
            let mut raw = [0_u8; FRAME_HEADER_LEN];
            raw[..4].copy_from_slice(&length.to_be_bytes());
            raw[4] = flags;
            let expected_valid =
                flags <= 1 && length <= MIN_CHUNK_SIZE && (flags == 1 || length == MIN_CHUNK_SIZE);
            assert_eq!(
                FrameHeader::parse(raw, MIN_CHUNK_SIZE).is_ok(),
                expected_valid,
                "length={length}, flags={flags}"
            );
        }
    }

    #[test]
    fn each_parameter_validator_accepts_only_its_closed_interval() {
        let base = options();
        for value in [
            0,
            MIN_MEMORY_KIB - 1,
            MIN_MEMORY_KIB,
            MAX_MEMORY_KIB,
            MAX_MEMORY_KIB + 1,
            u32::MAX,
        ] {
            assert_eq!(
                EncryptionOptions {
                    memory_kib: value,
                    ..base
                }
                .validate()
                .is_ok(),
                (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&value)
            );
        }
        for value in [
            0,
            MIN_ITERATIONS,
            MAX_ITERATIONS,
            MAX_ITERATIONS + 1,
            u32::MAX,
        ] {
            assert_eq!(
                EncryptionOptions {
                    iterations: value,
                    ..base
                }
                .validate()
                .is_ok(),
                (MIN_ITERATIONS..=MAX_ITERATIONS).contains(&value)
            );
        }
        for value in [
            0,
            MIN_PARALLELISM,
            MAX_PARALLELISM,
            MAX_PARALLELISM + 1,
            u32::MAX,
        ] {
            assert_eq!(
                EncryptionOptions {
                    parallelism: value,
                    ..base
                }
                .validate()
                .is_ok(),
                (MIN_PARALLELISM..=MAX_PARALLELISM).contains(&value)
            );
        }
        for value in [
            0,
            MIN_CHUNK_SIZE - 1,
            MIN_CHUNK_SIZE,
            MAX_CHUNK_SIZE,
            MAX_CHUNK_SIZE + 1,
            u32::MAX,
        ] {
            assert_eq!(
                EncryptionOptions {
                    chunk_size: value,
                    ..base
                }
                .validate()
                .is_ok(),
                (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&value)
            );
        }
    }
}
