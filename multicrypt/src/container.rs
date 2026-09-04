use crate::{Algorithm, Error};

pub const MAGIC: [u8; 8] = *b"MCRYPTF\0";
pub const VERSION_MAJOR: u8 = 1;
pub const VERSION_MINOR: u8 = 0;
pub const BASE_HEADER_LEN: usize = 88;
pub const SALT_LEN: usize = 32;
pub const KEY_ID_LEN: usize = 16;

#[derive(Debug)]
pub(crate) struct ParsedContainer<'a> {
    pub algorithm: Algorithm,
    pub header: &'a [u8],
    pub key_id: &'a [u8; KEY_ID_LEN],
    pub salt: &'a [u8; SALT_LEN],
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub tag: &'a [u8],
}

pub(crate) fn build_header(
    algorithm: Algorithm,
    plaintext_len: usize,
    key_id: &[u8; KEY_ID_LEN],
    salt: &[u8; SALT_LEN],
    nonce: &[u8],
) -> Result<Vec<u8>, Error> {
    if nonce.len() != algorithm.nonce_len() {
        return Err(Error::Crypto("internal nonce length mismatch"));
    }

    let header_len = BASE_HEADER_LEN
        .checked_add(nonce.len())
        .ok_or(Error::InputTooLarge)?;
    let header_len_u16 = u16::try_from(header_len).map_err(|_| Error::InputTooLarge)?;
    let nonce_len_u16 = u16::try_from(nonce.len()).map_err(|_| Error::InputTooLarge)?;
    let tag_len_u16 = u16::try_from(algorithm.tag_len()).map_err(|_| Error::InputTooLarge)?;
    let data_len_u64 = u64::try_from(plaintext_len).map_err(|_| Error::InputTooLarge)?;

    let mut header = Vec::new();
    header
        .try_reserve_exact(header_len)
        .map_err(|_| Error::OutOfMemory)?;
    header.extend_from_slice(&MAGIC);
    header.push(VERSION_MAJOR);
    header.push(VERSION_MINOR);
    header.extend_from_slice(&algorithm.id().to_be_bytes());
    header.extend_from_slice(&0_u16.to_be_bytes());
    header.extend_from_slice(&header_len_u16.to_be_bytes());
    header.extend_from_slice(&nonce_len_u16.to_be_bytes());
    header.extend_from_slice(&tag_len_u16.to_be_bytes());
    header.extend_from_slice(&0_u32.to_be_bytes());
    header.extend_from_slice(&data_len_u64.to_be_bytes());
    header.extend_from_slice(&data_len_u64.to_be_bytes());
    header.extend_from_slice(key_id);
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);

    debug_assert_eq!(header.len(), header_len);
    Ok(header)
}

pub(crate) fn parse<'a>(
    input: &'a [u8],
    requested: Algorithm,
) -> Result<ParsedContainer<'a>, Error> {
    if input.len() < BASE_HEADER_LEN {
        return Err(Error::InvalidContainer("truncated header"));
    }
    if input[..MAGIC.len()] != MAGIC {
        return Err(Error::InvalidContainer("bad magic"));
    }
    if input[8] != VERSION_MAJOR || input[9] != VERSION_MINOR {
        return Err(Error::InvalidContainer("unsupported format version"));
    }

    let suite_id = read_u16(input, 10);
    let algorithm =
        Algorithm::from_id(suite_id).ok_or(Error::InvalidContainer("unknown suite identifier"))?;
    if algorithm != requested {
        return Err(Error::AlgorithmMismatch {
            requested,
            actual: algorithm,
        });
    }

    if read_u16(input, 12) != 0 {
        return Err(Error::InvalidContainer("unsupported flags"));
    }
    let header_len = usize::from(read_u16(input, 14));
    let nonce_len = usize::from(read_u16(input, 16));
    let tag_len = usize::from(read_u16(input, 18));
    if read_u32(input, 20) != 0 {
        return Err(Error::InvalidContainer("reserved field is not zero"));
    }
    if nonce_len != algorithm.nonce_len() {
        return Err(Error::InvalidContainer("unexpected nonce length"));
    }
    if tag_len != algorithm.tag_len() {
        return Err(Error::InvalidContainer(
            "unexpected authentication tag length",
        ));
    }
    let expected_header_len = BASE_HEADER_LEN
        .checked_add(nonce_len)
        .ok_or(Error::InvalidContainer("header length overflow"))?;
    if header_len != expected_header_len {
        return Err(Error::InvalidContainer("inconsistent header length"));
    }
    if header_len > input.len() {
        return Err(Error::InvalidContainer("truncated variable header"));
    }

    let plaintext_len = usize::try_from(read_u64(input, 24)).map_err(|_| Error::InputTooLarge)?;
    let ciphertext_len = usize::try_from(read_u64(input, 32)).map_err(|_| Error::InputTooLarge)?;
    if plaintext_len != ciphertext_len {
        return Err(Error::InvalidContainer(
            "plaintext and ciphertext lengths differ",
        ));
    }

    let expected_len = header_len
        .checked_add(ciphertext_len)
        .and_then(|length| length.checked_add(tag_len))
        .ok_or(Error::InvalidContainer("container length overflow"))?;
    if expected_len != input.len() {
        return Err(if expected_len > input.len() {
            Error::InvalidContainer("truncated ciphertext or tag")
        } else {
            Error::InvalidContainer("trailing data")
        });
    }

    let key_id = input[40..56]
        .try_into()
        .map_err(|_| Error::InvalidContainer("truncated key identifier"))?;
    let salt = input[56..88]
        .try_into()
        .map_err(|_| Error::InvalidContainer("truncated salt"))?;
    let nonce = &input[BASE_HEADER_LEN..header_len];
    let ciphertext_end = header_len + ciphertext_len;

    Ok(ParsedContainer {
        algorithm,
        header: &input[..header_len],
        key_id,
        salt,
        nonce,
        ciphertext: &input[header_len..ciphertext_end],
        tag: &input[ciphertext_end..],
    })
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(algorithm: Algorithm, data_len: usize) -> Vec<u8> {
        let nonce = vec![0x33; algorithm.nonce_len()];
        let header = build_header(
            algorithm,
            data_len,
            &[0x11; KEY_ID_LEN],
            &[0x22; SALT_LEN],
            &nonce,
        )
        .unwrap();
        let mut result = header;
        result.extend(std::iter::repeat_n(0x44, data_len));
        result.extend(std::iter::repeat_n(0x55, algorithm.tag_len()));
        result
    }

    #[test]
    fn every_algorithm_header_round_trips() {
        for algorithm in Algorithm::ALL {
            for data_len in [0, 1, 15, 16, 17, 127, 128, 129, 4096] {
                let bytes = fixture(algorithm, data_len);
                let parsed = parse(&bytes, algorithm).unwrap();
                assert_eq!(parsed.algorithm, algorithm);
                assert_eq!(parsed.key_id, &[0x11; KEY_ID_LEN]);
                assert_eq!(parsed.salt, &[0x22; SALT_LEN]);
                assert_eq!(parsed.nonce, vec![0x33; algorithm.nonce_len()]);
                assert_eq!(parsed.ciphertext, vec![0x44; data_len]);
                assert_eq!(parsed.tag, vec![0x55; algorithm.tag_len()]);
            }
        }
    }

    #[test]
    fn parser_rejects_every_truncation_and_trailing_data() {
        for algorithm in Algorithm::ALL {
            let bytes = fixture(algorithm, 33);
            for end in 0..bytes.len() {
                assert!(parse(&bytes[..end], algorithm).is_err(), "end={end}");
            }

            let mut with_trailing = bytes;
            with_trailing.push(0);
            assert!(matches!(
                parse(&with_trailing, algorithm),
                Err(Error::InvalidContainer("trailing data"))
            ));
        }
    }

    #[test]
    fn parser_rejects_wrong_algorithm() {
        let bytes = fixture(Algorithm::Aes256GcmSiv, 1);
        assert!(matches!(
            parse(&bytes, Algorithm::Aegis256),
            Err(Error::AlgorithmMismatch { .. })
        ));
    }

    #[test]
    fn parser_rejects_malformed_fixed_fields() {
        let original = fixture(Algorithm::Aes256GcmSiv, 4);
        for (offset, value) in [
            (0, original[0] ^ 1),
            (8, 2),
            (9, 1),
            (10, original[10] ^ 1),
            (11, 0),
            (12, 1),
            (14, original[14] ^ 1),
            (16, original[16] ^ 1),
            (18, original[18] ^ 1),
            (20, 1),
            (31, 5),
            (39, 5),
        ] {
            let mut changed = original.clone();
            changed[offset] = value;
            assert!(
                parse(&changed, Algorithm::Aes256GcmSiv).is_err(),
                "offset={offset}"
            );
        }
    }

    #[test]
    fn parser_never_panics_on_short_arbitrary_inputs() {
        for length in 0..BASE_HEADER_LEN {
            let bytes: Vec<u8> = (0..length)
                .map(|index| (index as u8).wrapping_mul(37))
                .collect();
            assert!(parse(&bytes, Algorithm::Aes256GcmSiv).is_err());
        }
    }
}
