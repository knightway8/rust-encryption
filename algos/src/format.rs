use crate::{Error, Result, Suite};

pub(crate) const MAGIC: [u8; 8] = *b"ALGOENC1";
pub(crate) const VERSION: u16 = 1;
pub(crate) const HEADER_LEN: usize = 80;
const HEADER_LEN_U16: u16 = 80;
pub(crate) const RECORD_HEADER_LEN: usize = 16;
pub(crate) const CHUNK_SIZE: u32 = 64 * 1024;
pub(crate) const KDF_ARGON2ID: u8 = 1;
pub(crate) const ARGON_MEMORY_KIB: u32 = 64 * 1024;
pub(crate) const ARGON_TIME_COST: u32 = 3;
pub(crate) const ARGON_LANES: u16 = 1;
pub(crate) const FINAL_FLAG: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Header {
    pub suite: Suite,
    pub plaintext_len: u64,
    pub salt: [u8; 16],
    pub nonce_seed: [u8; 24],
}

impl Header {
    pub fn new(suite: Suite, plaintext_len: u64, salt: [u8; 16], nonce_seed: [u8; 24]) -> Self {
        Self {
            suite,
            plaintext_len,
            salt,
            nonce_seed,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[0..8].copy_from_slice(&MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&HEADER_LEN_U16.to_le_bytes());
        bytes[12..14].copy_from_slice(&self.suite.id().to_le_bytes());
        bytes[14] = KDF_ARGON2ID;
        bytes[15] = 0;
        bytes[16..20].copy_from_slice(&ARGON_MEMORY_KIB.to_le_bytes());
        bytes[20..24].copy_from_slice(&ARGON_TIME_COST.to_le_bytes());
        bytes[24..26].copy_from_slice(&ARGON_LANES.to_le_bytes());
        bytes[26..28].copy_from_slice(&0_u16.to_le_bytes());
        bytes[28..32].copy_from_slice(&CHUNK_SIZE.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.plaintext_len.to_le_bytes());
        bytes[40..56].copy_from_slice(&self.salt);
        bytes[56..80].copy_from_slice(&self.nonce_seed);
        bytes
    }

    pub fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self> {
        if bytes[0..8] != MAGIC
            || read_u16(bytes, 8) != VERSION
            || usize::from(read_u16(bytes, 10)) != HEADER_LEN
            || bytes[14] != KDF_ARGON2ID
            || bytes[15] != 0
            || read_u32(bytes, 16) != ARGON_MEMORY_KIB
            || read_u32(bytes, 20) != ARGON_TIME_COST
            || read_u16(bytes, 24) != ARGON_LANES
            || read_u16(bytes, 26) != 0
            || read_u32(bytes, 28) != CHUNK_SIZE
        {
            return Err(Error::InvalidFormat);
        }

        let suite = Suite::from_id(read_u16(bytes, 12)).ok_or(Error::InvalidFormat)?;
        let mut salt = [0_u8; 16];
        salt.copy_from_slice(&bytes[40..56]);
        let mut nonce_seed = [0_u8; 24];
        nonce_seed.copy_from_slice(&bytes[56..80]);

        Ok(Self {
            suite,
            plaintext_len: read_u64(bytes, 32),
            salt,
            nonce_seed,
        })
    }

    pub fn data_record_count(&self) -> u64 {
        self.plaintext_len.div_ceil(u64::from(CHUNK_SIZE))
    }

    pub fn expected_encrypted_len(&self) -> Result<u64> {
        let record_count = self
            .data_record_count()
            .checked_add(1)
            .ok_or(Error::FileTooLarge)?;
        let overhead = u64::try_from(RECORD_HEADER_LEN + self.suite.tag_len())
            .map_err(|_| Error::FileTooLarge)?;
        u64::try_from(HEADER_LEN)
            .map_err(|_| Error::FileTooLarge)?
            .checked_add(self.plaintext_len)
            .and_then(|value| value.checked_add(record_count.checked_mul(overhead)?))
            .ok_or(Error::FileTooLarge)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecordHeader {
    pub index: u64,
    pub plaintext_len: u32,
    pub flags: u8,
}

impl RecordHeader {
    pub fn data(index: u64, plaintext_len: u32) -> Self {
        Self {
            index,
            plaintext_len,
            flags: 0,
        }
    }

    pub fn final_record(index: u64) -> Self {
        Self {
            index,
            plaintext_len: 0,
            flags: FINAL_FLAG,
        }
    }

    pub fn encode(self) -> [u8; RECORD_HEADER_LEN] {
        let mut bytes = [0_u8; RECORD_HEADER_LEN];
        bytes[0..8].copy_from_slice(&self.index.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.plaintext_len.to_le_bytes());
        bytes[12] = self.flags;
        bytes
    }

    pub fn decode(bytes: &[u8; RECORD_HEADER_LEN]) -> Result<Self> {
        if bytes[13..16] != [0_u8; 3] || (bytes[12] != 0 && bytes[12] != FINAL_FLAG) {
            return Err(Error::InvalidFormat);
        }
        Ok(Self {
            index: read_u64(bytes, 0),
            plaintext_len: read_u32(bytes, 8),
            flags: bytes[12],
        })
    }

    pub fn is_final(self) -> bool {
        self.flags == FINAL_FLAG
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip_and_exact_size() {
        let header = Header::new(Suite::Aes256Gcm, 123_456, [7; 16], [9; 24]);
        let encoded = header.encode();
        assert_eq!(encoded.len(), 80);
        assert_eq!(Header::decode(&encoded).unwrap(), header);
    }

    #[test]
    fn every_interpretation_field_is_canonical() {
        let original = Header::new(Suite::Aes128Gcm, 0, [1; 16], [2; 24]).encode();
        for offset in [0, 8, 10, 12, 14, 15, 16, 20, 24, 26, 28] {
            let mut changed = original;
            changed[offset] ^= 0x80;
            assert!(Header::decode(&changed).is_err(), "offset {offset}");
        }
    }

    #[test]
    fn expected_length_is_checked() {
        let header = Header::new(Suite::Aes128Gcm, u64::MAX, [0; 16], [0; 24]);
        assert!(matches!(
            header.expected_encrypted_len(),
            Err(Error::FileTooLarge)
        ));
    }

    #[test]
    fn final_record_is_canonical() {
        let final_record = RecordHeader::final_record(42);
        assert_eq!(
            RecordHeader::decode(&final_record.encode()).unwrap(),
            final_record
        );
        let mut bad = final_record.encode();
        bad[15] = 1;
        assert!(RecordHeader::decode(&bad).is_err());
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(256))]

        #[test]
        fn arbitrary_headers_and_records_never_panic(
            header_bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), HEADER_LEN),
            record_bytes in proptest::array::uniform16(proptest::prelude::any::<u8>()),
        ) {
            let header_bytes: [u8; HEADER_LEN] = header_bytes.try_into().unwrap();
            if let Ok(header) = Header::decode(&header_bytes) {
                let _ = header.expected_encrypted_len();
            }
            let _ = RecordHeader::decode(&record_bytes);
        }
    }
}
