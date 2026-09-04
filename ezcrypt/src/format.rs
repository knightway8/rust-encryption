use crate::error::FormatError;

pub(crate) const MAGIC: [u8; 8] = *b"EZCRYPT\0";
pub(crate) const VERSION: u16 = 1;
pub(crate) const HEADER_LEN: usize = 80;
pub(crate) const HEADER_TAG_LEN: u64 = 16;
pub(crate) const TAG_LEN: u64 = 16;
pub(crate) const FINAL_TAG_LEN: u64 = 16;
pub(crate) const CHUNK_SIZE: u32 = 1024 * 1024;
pub(crate) const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;
pub(crate) const DEFAULT_TIME_COST: u32 = 3;
pub(crate) const DEFAULT_LANES: u32 = 1;
pub(crate) const MIN_MEMORY_KIB: u32 = 8 * 1024;
// Unauthenticated v1 headers are validated before their header tag can be checked.
// Cap accepted costs at the production tuple so a forged tiny file cannot amplify
// work beyond one legitimate password attempt.
pub(crate) const MAX_MEMORY_KIB: u32 = DEFAULT_MEMORY_KIB;
pub(crate) const MAX_TIME_COST: u32 = DEFAULT_TIME_COST;
pub(crate) const MAX_LANES: u32 = DEFAULT_LANES;
pub(crate) const MAX_FILE_LEN: u64 = i64::MAX as u64;

const OFF_VERSION: usize = 8;
const OFF_HEADER_LEN: usize = 10;
const OFF_FLAGS: usize = 12;
const OFF_CHUNK_SIZE: usize = 16;
const OFF_PLAINTEXT_LEN: usize = 20;
const OFF_MEMORY: usize = 28;
const OFF_TIME: usize = 32;
const OFF_LANES: usize = 36;
const OFF_SALT: usize = 40;
const OFF_NONCE: usize = 56;
const OFF_RESERVED: usize = 72;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KdfParams {
    pub(crate) memory_kib: u32,
    pub(crate) time_cost: u32,
    pub(crate) lanes: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: DEFAULT_MEMORY_KIB,
            time_cost: DEFAULT_TIME_COST,
            lanes: DEFAULT_LANES,
        }
    }
}

impl KdfParams {
    pub(crate) fn validate(self) -> Result<(), FormatError> {
        let minimum_for_lanes = self
            .lanes
            .checked_mul(8)
            .ok_or(FormatError::InvalidKdfParameters)?;
        if self.memory_kib < MIN_MEMORY_KIB
            || self.memory_kib > MAX_MEMORY_KIB
            || self.memory_kib < minimum_for_lanes
            || self.time_cost == 0
            || self.time_cost > MAX_TIME_COST
            || self.lanes == 0
            || self.lanes > MAX_LANES
        {
            return Err(FormatError::InvalidKdfParameters);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Header {
    pub(crate) plaintext_len: u64,
    pub(crate) kdf: KdfParams,
    pub(crate) salt: [u8; 16],
    pub(crate) nonce_prefix: [u8; 16],
}

impl Header {
    pub(crate) fn new(
        plaintext_len: u64,
        kdf: KdfParams,
        salt: [u8; 16],
        nonce_prefix: [u8; 16],
    ) -> Result<Self, FormatError> {
        let header = Self {
            plaintext_len,
            kdf,
            salt,
            nonce_prefix,
        };
        header.validate()?;
        Ok(header)
    }

    pub(crate) fn validate(&self) -> Result<(), FormatError> {
        self.kdf.validate()?;
        if self.salt.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidSalt);
        }
        if self.nonce_prefix.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidNonce);
        }
        self.encoded_len()?;
        Ok(())
    }

    pub(crate) fn encode(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[OFF_VERSION..OFF_HEADER_LEN].copy_from_slice(&VERSION.to_le_bytes());
        bytes[OFF_HEADER_LEN..OFF_FLAGS].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        bytes[OFF_FLAGS..OFF_CHUNK_SIZE].copy_from_slice(&0u32.to_le_bytes());
        bytes[OFF_CHUNK_SIZE..OFF_PLAINTEXT_LEN].copy_from_slice(&CHUNK_SIZE.to_le_bytes());
        bytes[OFF_PLAINTEXT_LEN..OFF_MEMORY].copy_from_slice(&self.plaintext_len.to_le_bytes());
        bytes[OFF_MEMORY..OFF_TIME].copy_from_slice(&self.kdf.memory_kib.to_le_bytes());
        bytes[OFF_TIME..OFF_LANES].copy_from_slice(&self.kdf.time_cost.to_le_bytes());
        bytes[OFF_LANES..OFF_SALT].copy_from_slice(&self.kdf.lanes.to_le_bytes());
        bytes[OFF_SALT..OFF_NONCE].copy_from_slice(&self.salt);
        bytes[OFF_NONCE..OFF_RESERVED].copy_from_slice(&self.nonce_prefix);
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() != HEADER_LEN {
            return Err(FormatError::TruncatedHeader);
        }
        if bytes[..8] != MAGIC {
            return Err(FormatError::BadMagic);
        }
        if read_u16(bytes, OFF_VERSION) != VERSION {
            return Err(FormatError::UnsupportedVersion);
        }
        if read_u16(bytes, OFF_HEADER_LEN) as usize != HEADER_LEN {
            return Err(FormatError::BadHeaderLength);
        }
        if read_u32(bytes, OFF_FLAGS) != 0 {
            return Err(FormatError::UnsupportedFlags);
        }
        if read_u32(bytes, OFF_CHUNK_SIZE) != CHUNK_SIZE {
            return Err(FormatError::InvalidChunkSize);
        }
        if bytes[OFF_RESERVED..].iter().any(|byte| *byte != 0) {
            return Err(FormatError::ReservedBytes);
        }

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[OFF_SALT..OFF_NONCE]);
        let mut nonce_prefix = [0u8; 16];
        nonce_prefix.copy_from_slice(&bytes[OFF_NONCE..OFF_RESERVED]);
        Self::new(
            read_u64(bytes, OFF_PLAINTEXT_LEN),
            KdfParams {
                memory_kib: read_u32(bytes, OFF_MEMORY),
                time_cost: read_u32(bytes, OFF_TIME),
                lanes: read_u32(bytes, OFF_LANES),
            },
            salt,
            nonce_prefix,
        )
    }

    pub(crate) fn chunk_count(&self) -> Result<u64, FormatError> {
        if self.plaintext_len == 0 {
            return Ok(0);
        }
        let chunk = u64::from(CHUNK_SIZE);
        let chunks = self.plaintext_len / chunk + u64::from(self.plaintext_len % chunk != 0);
        if chunks == u64::MAX {
            return Err(FormatError::SizeOverflow);
        }
        Ok(chunks)
    }

    pub(crate) fn chunk_plaintext_len(&self, index: u64) -> Result<usize, FormatError> {
        let chunks = self.chunk_count()?;
        if index >= chunks {
            return Err(FormatError::SizeOverflow);
        }
        let offset = index
            .checked_mul(u64::from(CHUNK_SIZE))
            .ok_or(FormatError::SizeOverflow)?;
        let remaining = self
            .plaintext_len
            .checked_sub(offset)
            .ok_or(FormatError::SizeOverflow)?;
        Ok(remaining.min(u64::from(CHUNK_SIZE)) as usize)
    }

    pub(crate) fn encoded_len(&self) -> Result<u64, FormatError> {
        if self.plaintext_len > MAX_FILE_LEN {
            return Err(FormatError::SizeOverflow);
        }
        let chunks = self.chunk_count()?;
        let tag_bytes = chunks
            .checked_mul(TAG_LEN)
            .ok_or(FormatError::SizeOverflow)?;
        let total = (HEADER_LEN as u64)
            .checked_add(HEADER_TAG_LEN)
            .and_then(|value| value.checked_add(self.plaintext_len))
            .and_then(|value| value.checked_add(tag_bytes))
            .and_then(|value| value.checked_add(FINAL_TAG_LEN))
            .ok_or(FormatError::SizeOverflow)?;
        if total > MAX_FILE_LEN {
            return Err(FormatError::SizeOverflow);
        }
        Ok(total)
    }

    pub(crate) fn nonce(&self, counter: u64) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&self.nonce_prefix);
        nonce[16..].copy_from_slice(&counter.to_le_bytes());
        nonce
    }
}

pub(crate) fn header_aad(header: &[u8; HEADER_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(14 + HEADER_LEN);
    aad.extend_from_slice(b"EZCRYPT-HDR-V1");
    aad.extend_from_slice(header);
    aad
}

pub(crate) fn chunk_aad(header: &[u8; HEADER_LEN], index: u64, plaintext_len: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(15 + HEADER_LEN + 8 + 4);
    aad.extend_from_slice(b"EZCRYPT-DATA-V1");
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&(plaintext_len as u32).to_le_bytes());
    aad
}

pub(crate) fn final_aad(header: &[u8; HEADER_LEN], chunks: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(14 + HEADER_LEN + 8);
    aad.extend_from_slice(b"EZCRYPT-END-V1");
    aad.extend_from_slice(header);
    aad.extend_from_slice(&chunks.to_le_bytes());
    aad
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("fixed field"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed field"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed field"))
}
