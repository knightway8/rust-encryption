use crate::error::{FileCryptError, Result};

pub const HEADER_SIZE: usize = 96;
pub const RECORD_HEADER_SIZE: usize = 16;
pub const FOOTER_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const CHUNK_SIZE: usize = 1024 * 1024;
const CHUNK_SIZE_FIELD: u32 = 1024 * 1024;
pub const MAX_DATA_RECORDS: u64 = 0x7fff_ffff;
pub const MAX_PLAINTEXT_SIZE: u64 = MAX_DATA_RECORDS * CHUNK_SIZE as u64;

const MAGIC: &[u8; 8] = b"FCRYPT01";
const VERSION: u16 = 1;
const FOOTER_MAGIC: &[u8; 8] = b"FCRYPTEN";

pub const RECORD_DATA: u8 = 1;
pub const RECORD_END: u8 = 2;

/// Supported authenticated-encryption suites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// AES-256-GCM-SIV (RFC 8452).
    Aes256GcmSiv = 1,
    /// XChaCha20-Poly1305.
    XChaCha20Poly1305 = 2,
}

impl Algorithm {
    /// Parse the numeric CLI selector requested by the application interface.
    #[must_use]
    pub fn from_selector(value: &std::ffi::OsStr) -> Option<Self> {
        if value == "1" {
            Some(Self::Aes256GcmSiv)
        } else if value == "2" {
            Some(Self::XChaCha20Poly1305)
        } else {
            None
        }
    }

    /// Human-readable algorithm name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "AES-256-GCM-SIV",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        }
    }

    pub(crate) const fn kdf_info(self) -> &'static [u8] {
        match self {
            Self::Aes256GcmSiv => b"filecrypt/v1/aes-256-gcm-siv/stream-le31/key",
            Self::XChaCha20Poly1305 => b"filecrypt/v1/xchacha20-poly1305/stream-le31/key",
        }
    }

    pub(crate) const fn stream_nonce_size(self) -> usize {
        match self {
            Self::Aes256GcmSiv => 8,
            Self::XChaCha20Poly1305 => 20,
        }
    }
}

impl TryFrom<u8> for Algorithm {
    type Error = FileCryptError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Aes256GcmSiv),
            2 => Ok(Self::XChaCha20Poly1305),
            _ => Err(FileCryptError::InvalidFormat("unsupported algorithm")),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Header {
    pub(crate) raw: [u8; HEADER_SIZE],
    pub(crate) algorithm: Algorithm,
    pub(crate) plaintext_len: u64,
    pub(crate) salt: [u8; 32],
    pub(crate) stream_nonce: [u8; 20],
}

impl Header {
    pub(crate) fn new(
        algorithm: Algorithm,
        plaintext_len: u64,
        salt: [u8; 32],
        mut stream_nonce: [u8; 20],
    ) -> Self {
        // Keep the constructor and parser symmetric: the unused portion of an
        // AES nonce field is reserved, even if an internal caller supplies a
        // fully populated 20-byte array.
        if algorithm == Algorithm::Aes256GcmSiv {
            stream_nonce[algorithm.stream_nonce_size()..].fill(0);
        }

        let mut raw = [0_u8; HEADER_SIZE];
        raw[0..8].copy_from_slice(MAGIC);
        raw[8..10].copy_from_slice(&VERSION.to_le_bytes());
        raw[10] = algorithm as u8;
        raw[11] = 0;
        raw[12..16].copy_from_slice(&CHUNK_SIZE_FIELD.to_le_bytes());
        raw[16..24].copy_from_slice(&plaintext_len.to_le_bytes());
        raw[24..56].copy_from_slice(&salt);
        raw[56..76].copy_from_slice(&stream_nonce);
        // 76..96 is reserved and already zero.

        Self {
            raw,
            algorithm,
            plaintext_len,
            salt,
            stream_nonce,
        }
    }

    pub(crate) fn parse(raw: [u8; HEADER_SIZE]) -> Result<Self> {
        if &raw[0..8] != MAGIC {
            return Err(FileCryptError::InvalidFormat("bad magic"));
        }

        let version = u16::from_le_bytes([raw[8], raw[9]]);
        if version != VERSION {
            return Err(FileCryptError::InvalidFormat("unsupported version"));
        }

        let algorithm = Algorithm::try_from(raw[10])?;
        if raw[11] != 0 || raw[76..96].iter().any(|byte| *byte != 0) {
            return Err(FileCryptError::InvalidFormat(
                "nonzero reserved header field",
            ));
        }

        let chunk_size = u32::from_le_bytes(
            raw[12..16]
                .try_into()
                .map_err(|_| FileCryptError::InvalidFormat("malformed chunk-size field"))?,
        );
        if chunk_size as usize != CHUNK_SIZE {
            return Err(FileCryptError::InvalidFormat("unsupported chunk size"));
        }

        let plaintext_len = u64::from_le_bytes(
            raw[16..24]
                .try_into()
                .map_err(|_| FileCryptError::InvalidFormat("malformed plaintext-length field"))?,
        );
        if plaintext_len > MAX_PLAINTEXT_SIZE {
            return Err(FileCryptError::InvalidFormat(
                "declared plaintext is too large",
            ));
        }

        let mut salt = [0_u8; 32];
        salt.copy_from_slice(&raw[24..56]);
        let mut stream_nonce = [0_u8; 20];
        stream_nonce.copy_from_slice(&raw[56..76]);

        if algorithm == Algorithm::Aes256GcmSiv
            && stream_nonce[algorithm.stream_nonce_size()..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(FileCryptError::InvalidFormat("nonzero AES nonce padding"));
        }

        Ok(Self {
            raw,
            algorithm,
            plaintext_len,
            salt,
            stream_nonce,
        })
    }

    pub(crate) fn data_record_count(&self) -> u64 {
        self.plaintext_len.div_ceil(CHUNK_SIZE as u64)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RecordHeader {
    pub(crate) raw: [u8; RECORD_HEADER_SIZE],
    pub(crate) record_type: u8,
    pub(crate) ciphertext_len: u32,
    pub(crate) sequence: u64,
}

impl RecordHeader {
    pub(crate) fn new(record_type: u8, ciphertext_len: u32, sequence: u64) -> Self {
        let mut raw = [0_u8; RECORD_HEADER_SIZE];
        raw[0] = record_type;
        raw[1] = 0;
        raw[2..4].copy_from_slice(&0_u16.to_le_bytes());
        raw[4..8].copy_from_slice(&ciphertext_len.to_le_bytes());
        raw[8..16].copy_from_slice(&sequence.to_le_bytes());
        Self {
            raw,
            record_type,
            ciphertext_len,
            sequence,
        }
    }

    pub(crate) fn parse(raw: [u8; RECORD_HEADER_SIZE]) -> Result<Self> {
        if raw[1] != 0 || raw[2] != 0 || raw[3] != 0 {
            return Err(FileCryptError::AuthenticationFailed);
        }
        let ciphertext_len = u32::from_le_bytes(
            raw[4..8]
                .try_into()
                .map_err(|_| FileCryptError::AuthenticationFailed)?,
        );
        let sequence = u64::from_le_bytes(
            raw[8..16]
                .try_into()
                .map_err(|_| FileCryptError::AuthenticationFailed)?,
        );
        Ok(Self {
            raw,
            record_type: raw[0],
            ciphertext_len,
            sequence,
        })
    }
}

pub(crate) fn make_aad(
    header: &[u8; HEADER_SIZE],
    record: &[u8; RECORD_HEADER_SIZE],
) -> [u8; HEADER_SIZE + RECORD_HEADER_SIZE] {
    let mut aad = [0_u8; HEADER_SIZE + RECORD_HEADER_SIZE];
    aad[..HEADER_SIZE].copy_from_slice(header);
    aad[HEADER_SIZE..].copy_from_slice(record);
    aad
}

pub(crate) fn make_footer(chunk_count: u64, plaintext_len: u64) -> [u8; FOOTER_SIZE] {
    let mut footer = [0_u8; FOOTER_SIZE];
    footer[0..8].copy_from_slice(FOOTER_MAGIC);
    footer[8..16].copy_from_slice(&chunk_count.to_le_bytes());
    footer[16..24].copy_from_slice(&plaintext_len.to_le_bytes());
    footer
}

pub(crate) fn verify_footer(footer: &[u8], expected_chunks: u64, expected_len: u64) -> Result<()> {
    if footer.len() != FOOTER_SIZE || &footer[0..8] != FOOTER_MAGIC {
        return Err(FileCryptError::AuthenticationFailed);
    }
    let chunks = u64::from_le_bytes(
        footer[8..16]
            .try_into()
            .map_err(|_| FileCryptError::AuthenticationFailed)?,
    );
    let plaintext_len = u64::from_le_bytes(
        footer[16..24]
            .try_into()
            .map_err(|_| FileCryptError::AuthenticationFailed)?,
    );
    if chunks != expected_chunks || plaintext_len != expected_len {
        return Err(FileCryptError::AuthenticationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    const SALT: [u8; 32] = [0xa5; 32];

    fn nonce() -> [u8; 20] {
        std::array::from_fn(|index| u8::try_from(index).unwrap_or_default())
    }

    fn valid_raw(algorithm: Algorithm) -> [u8; HEADER_SIZE] {
        Header::new(algorithm, CHUNK_SIZE as u64 + 7, SALT, nonce()).raw
    }

    #[test]
    fn selectors_are_exact_and_algorithm_metadata_is_stable() {
        assert_eq!(
            Algorithm::from_selector(OsStr::new("1")),
            Some(Algorithm::Aes256GcmSiv)
        );
        assert_eq!(
            Algorithm::from_selector(OsStr::new("2")),
            Some(Algorithm::XChaCha20Poly1305)
        );
        for invalid in ["", "0", "01", "3", " 1", "1 ", "aes", "AES"] {
            assert_eq!(Algorithm::from_selector(OsStr::new(invalid)), None);
        }

        assert_eq!(Algorithm::Aes256GcmSiv as u8, 1);
        assert_eq!(Algorithm::XChaCha20Poly1305 as u8, 2);
        assert_eq!(Algorithm::Aes256GcmSiv.name(), "AES-256-GCM-SIV");
        assert_eq!(Algorithm::XChaCha20Poly1305.name(), "XChaCha20-Poly1305");
        assert_eq!(Algorithm::Aes256GcmSiv.stream_nonce_size(), 8);
        assert_eq!(Algorithm::XChaCha20Poly1305.stream_nonce_size(), 20);
        assert_ne!(
            Algorithm::Aes256GcmSiv.kdf_info(),
            Algorithm::XChaCha20Poly1305.kdf_info()
        );
    }

    #[cfg(unix)]
    #[test]
    fn selector_rejects_non_utf8_os_strings() {
        use std::os::unix::ffi::OsStrExt;

        assert_eq!(Algorithm::from_selector(OsStr::from_bytes(&[0xff])), None);
    }

    #[test]
    fn numeric_algorithm_parser_accepts_only_defined_values() {
        assert_eq!(Algorithm::try_from(1).ok(), Some(Algorithm::Aes256GcmSiv));
        assert_eq!(
            Algorithm::try_from(2).ok(),
            Some(Algorithm::XChaCha20Poly1305)
        );
        for invalid in [0, 3, 127, 255] {
            assert!(matches!(
                Algorithm::try_from(invalid),
                Err(FileCryptError::InvalidFormat("unsupported algorithm"))
            ));
        }
    }

    #[test]
    fn header_constructor_encodes_every_field_at_its_specified_offset() {
        let header = Header::new(
            Algorithm::XChaCha20Poly1305,
            0x0102_0304_0506_0708,
            SALT,
            nonce(),
        );

        assert_eq!(&header.raw[0..8], MAGIC);
        assert_eq!(&header.raw[8..10], &VERSION.to_le_bytes());
        assert_eq!(header.raw[10], 2);
        assert_eq!(header.raw[11], 0);
        assert_eq!(&header.raw[12..16], &CHUNK_SIZE_FIELD.to_le_bytes());
        assert_eq!(
            &header.raw[16..24],
            &0x0102_0304_0506_0708_u64.to_le_bytes()
        );
        assert_eq!(&header.raw[24..56], &SALT);
        assert_eq!(&header.raw[56..76], &nonce());
        assert_eq!(&header.raw[76..96], &[0; 20]);
    }

    #[test]
    fn aes_constructor_canonicalizes_unused_nonce_padding() {
        let header = Header::new(Algorithm::Aes256GcmSiv, 0, SALT, [0xff; 20]);

        assert_eq!(&header.stream_nonce[..8], &[0xff; 8]);
        assert_eq!(&header.stream_nonce[8..], &[0; 12]);
        assert_eq!(&header.raw[56..64], &[0xff; 8]);
        assert_eq!(&header.raw[64..76], &[0; 12]);
        assert!(Header::parse(header.raw).is_ok());
    }

    #[test]
    fn canonical_headers_round_trip_at_length_boundaries() {
        let lengths = [
            0,
            1,
            CHUNK_SIZE as u64 - 1,
            CHUNK_SIZE as u64,
            CHUNK_SIZE as u64 + 1,
            MAX_PLAINTEXT_SIZE - 1,
            MAX_PLAINTEXT_SIZE,
        ];

        for algorithm in [Algorithm::Aes256GcmSiv, Algorithm::XChaCha20Poly1305] {
            for plaintext_len in lengths {
                let expected = Header::new(algorithm, plaintext_len, SALT, nonce());
                let parsed = Header::parse(expected.raw);
                assert!(parsed.is_ok(), "failed to parse length {plaintext_len}");
                let parsed = parsed.unwrap_or_else(|_| unreachable!());
                assert_eq!(parsed.raw, expected.raw);
                assert_eq!(parsed.algorithm, algorithm);
                assert_eq!(parsed.plaintext_len, plaintext_len);
                assert_eq!(parsed.salt, SALT);
                assert_eq!(parsed.stream_nonce, expected.stream_nonce);
            }
        }
    }

    #[test]
    fn data_record_counts_are_exact_at_every_boundary() {
        let cases = [
            (0, 0),
            (1, 1),
            (CHUNK_SIZE as u64 - 1, 1),
            (CHUNK_SIZE as u64, 1),
            (CHUNK_SIZE as u64 + 1, 2),
            (2 * CHUNK_SIZE as u64, 2),
            (MAX_PLAINTEXT_SIZE - CHUNK_SIZE as u64, MAX_DATA_RECORDS - 1),
            (MAX_PLAINTEXT_SIZE - 1, MAX_DATA_RECORDS),
            (MAX_PLAINTEXT_SIZE, MAX_DATA_RECORDS),
        ];

        for (plaintext_len, expected_count) in cases {
            let header = Header::new(Algorithm::XChaCha20Poly1305, plaintext_len, SALT, nonce());
            assert_eq!(header.data_record_count(), expected_count);
        }
    }

    #[test]
    fn header_parser_rejects_every_magic_byte_mutation() {
        for offset in 0..MAGIC.len() {
            let mut raw = valid_raw(Algorithm::XChaCha20Poly1305);
            raw[offset] ^= 0xff;
            assert!(matches!(
                Header::parse(raw),
                Err(FileCryptError::InvalidFormat("bad magic"))
            ));
        }
    }

    #[test]
    fn header_parser_rejects_unknown_versions_algorithms_and_flags() {
        for version in [0_u16, 2, u16::MAX] {
            let mut raw = valid_raw(Algorithm::XChaCha20Poly1305);
            raw[8..10].copy_from_slice(&version.to_le_bytes());
            assert!(matches!(
                Header::parse(raw),
                Err(FileCryptError::InvalidFormat("unsupported version"))
            ));
        }

        for algorithm in [0_u8, 3, 255] {
            let mut raw = valid_raw(Algorithm::XChaCha20Poly1305);
            raw[10] = algorithm;
            assert!(matches!(
                Header::parse(raw),
                Err(FileCryptError::InvalidFormat("unsupported algorithm"))
            ));
        }

        let mut raw = valid_raw(Algorithm::XChaCha20Poly1305);
        raw[11] = 1;
        assert!(matches!(
            Header::parse(raw),
            Err(FileCryptError::InvalidFormat(
                "nonzero reserved header field"
            ))
        ));
    }

    #[test]
    fn header_parser_rejects_each_nonzero_reserved_byte() {
        for offset in 76..HEADER_SIZE {
            let mut raw = valid_raw(Algorithm::XChaCha20Poly1305);
            raw[offset] = 1;
            assert!(matches!(
                Header::parse(raw),
                Err(FileCryptError::InvalidFormat(
                    "nonzero reserved header field"
                ))
            ));
        }
    }

    #[test]
    fn header_parser_requires_the_canonical_chunk_size() {
        for chunk_size in [0, 1, CHUNK_SIZE_FIELD - 1, CHUNK_SIZE_FIELD + 1, u32::MAX] {
            let mut raw = valid_raw(Algorithm::XChaCha20Poly1305);
            raw[12..16].copy_from_slice(&chunk_size.to_le_bytes());
            assert!(matches!(
                Header::parse(raw),
                Err(FileCryptError::InvalidFormat("unsupported chunk size"))
            ));
        }
    }

    #[test]
    fn header_parser_enforces_plaintext_limit() {
        for plaintext_len in [MAX_PLAINTEXT_SIZE + 1, u64::MAX] {
            let mut raw = valid_raw(Algorithm::XChaCha20Poly1305);
            raw[16..24].copy_from_slice(&plaintext_len.to_le_bytes());
            assert!(matches!(
                Header::parse(raw),
                Err(FileCryptError::InvalidFormat(
                    "declared plaintext is too large"
                ))
            ));
        }
    }

    #[test]
    fn header_parser_rejects_each_aes_nonce_padding_byte() {
        for offset in 64..76 {
            let mut raw = valid_raw(Algorithm::Aes256GcmSiv);
            raw[offset] = 1;
            assert!(matches!(
                Header::parse(raw),
                Err(FileCryptError::InvalidFormat("nonzero AES nonce padding"))
            ));
        }
    }

    #[test]
    fn xchacha_header_uses_all_twenty_nonce_bytes() {
        let raw = valid_raw(Algorithm::XChaCha20Poly1305);
        let parsed = Header::parse(raw);
        assert!(parsed.is_ok());
        assert_eq!(
            parsed.unwrap_or_else(|_| unreachable!()).stream_nonce,
            nonce()
        );
    }

    #[test]
    fn record_header_layout_round_trips_extreme_fields() {
        for (record_type, ciphertext_len, sequence) in [
            (RECORD_DATA, 0, 0),
            (RECORD_DATA, u32::MAX, u64::MAX),
            (RECORD_END, 40, MAX_DATA_RECORDS),
        ] {
            let expected = RecordHeader::new(record_type, ciphertext_len, sequence);
            assert_eq!(expected.raw[0], record_type);
            assert_eq!(&expected.raw[1..4], &[0; 3]);
            assert_eq!(&expected.raw[4..8], &ciphertext_len.to_le_bytes());
            assert_eq!(&expected.raw[8..16], &sequence.to_le_bytes());

            let parsed = RecordHeader::parse(expected.raw);
            assert!(parsed.is_ok());
            let parsed = parsed.unwrap_or_else(|_| unreachable!());
            assert_eq!(parsed.raw, expected.raw);
            assert_eq!(parsed.record_type, record_type);
            assert_eq!(parsed.ciphertext_len, ciphertext_len);
            assert_eq!(parsed.sequence, sequence);
        }
    }

    #[test]
    fn record_header_parser_rejects_each_reserved_byte() {
        for offset in 1..4 {
            let mut raw = RecordHeader::new(RECORD_DATA, 16, 0).raw;
            raw[offset] = 1;
            assert!(matches!(
                RecordHeader::parse(raw),
                Err(FileCryptError::AuthenticationFailed)
            ));
        }
    }

    #[test]
    fn aad_is_the_exact_header_record_concatenation() {
        let header = valid_raw(Algorithm::XChaCha20Poly1305);
        let record = RecordHeader::new(RECORD_DATA, 123, 456).raw;
        let aad = make_aad(&header, &record);

        assert_eq!(aad.len(), HEADER_SIZE + RECORD_HEADER_SIZE);
        assert_eq!(&aad[..HEADER_SIZE], &header);
        assert_eq!(&aad[HEADER_SIZE..], &record);

        let mut changed_record = record;
        changed_record[8] ^= 1;
        assert_ne!(aad, make_aad(&header, &changed_record));
    }

    #[test]
    fn footer_layout_and_verification_are_exact() {
        let footer = make_footer(0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
        assert_eq!(&footer[0..8], FOOTER_MAGIC);
        assert_eq!(&footer[8..16], &0x0102_0304_0506_0708_u64.to_le_bytes());
        assert_eq!(&footer[16..24], &0x1112_1314_1516_1718_u64.to_le_bytes());
        assert!(verify_footer(&footer, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718).is_ok());
    }

    #[test]
    fn footer_verifier_rejects_noncanonical_lengths_and_values() {
        let footer = make_footer(7, 11);
        for length in [0, 1, FOOTER_SIZE - 1, FOOTER_SIZE + 1, FOOTER_SIZE * 2] {
            let mut bytes = vec![0_u8; length];
            let copied = length.min(FOOTER_SIZE);
            bytes[..copied].copy_from_slice(&footer[..copied]);
            assert!(matches!(
                verify_footer(&bytes, 7, 11),
                Err(FileCryptError::AuthenticationFailed)
            ));
        }

        for offset in 0..FOOTER_MAGIC.len() {
            let mut changed = footer;
            changed[offset] ^= 1;
            assert!(matches!(
                verify_footer(&changed, 7, 11),
                Err(FileCryptError::AuthenticationFailed)
            ));
        }
        assert!(matches!(
            verify_footer(&footer, 8, 11),
            Err(FileCryptError::AuthenticationFailed)
        ));
        assert!(matches!(
            verify_footer(&footer, 7, 12),
            Err(FileCryptError::AuthenticationFailed)
        ));
    }
}
