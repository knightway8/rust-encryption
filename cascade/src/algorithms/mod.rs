//! Small, separate adapters for each cryptographic suite.

use zeroize::Zeroizing;

use crate::error::AppError;

pub(crate) mod aes;
pub(crate) mod serpent;
pub(crate) mod threefish;
pub(crate) mod xchacha;

pub(crate) const SALT_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    Aes256GcmSiv = 1,
    XChaCha20Poly1305 = 2,
    Serpent256 = 3,
    Threefish1024 = 4,
}

impl Algorithm {
    pub fn from_selector(selector: &str) -> Option<Self> {
        match selector {
            "A" => Some(Self::Aes256GcmSiv),
            "X" => Some(Self::XChaCha20Poly1305),
            "S" => Some(Self::Serpent256),
            "T" => Some(Self::Threefish1024),
            _ => None,
        }
    }

    pub(crate) fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Self::Aes256GcmSiv),
            2 => Some(Self::XChaCha20Poly1305),
            3 => Some(Self::Serpent256),
            4 => Some(Self::Threefish1024),
            _ => None,
        }
    }

    pub const fn id(self) -> u8 {
        self as u8
    }

    pub const fn suite_id(self) -> u8 {
        match self {
            Self::Aes256GcmSiv => 0x11,
            Self::XChaCha20Poly1305 => 0x12,
            Self::Serpent256 => 0x21,
            Self::Threefish1024 => 0x22,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "AES-256-GCM-SIV",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Self::Serpent256 => "Serpent-256",
            Self::Threefish1024 => "Threefish-1024",
        }
    }

    pub const fn key_filename(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "aes.key",
            Self::XChaCha20Poly1305 => "cha.key",
            Self::Serpent256 => "ser.key",
            Self::Threefish1024 => "thr.key",
        }
    }

    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv | Self::XChaCha20Poly1305 | Self::Serpent256 => 32,
            Self::Threefish1024 => 128,
        }
    }

    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv => aes::NONCE_LEN,
            Self::XChaCha20Poly1305 => xchacha::NONCE_LEN,
            Self::Serpent256 => serpent::IV_LEN,
            Self::Threefish1024 => threefish::IV_LEN,
        }
    }

    pub const fn tag_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv => aes::TAG_LEN,
            Self::XChaCha20Poly1305 => xchacha::TAG_LEN,
            Self::Serpent256 | Self::Threefish1024 => 64,
        }
    }

    pub(crate) fn expected_ciphertext_len(self, plaintext_len: usize) -> Option<usize> {
        match self {
            Self::Aes256GcmSiv | Self::XChaCha20Poly1305 => Some(plaintext_len),
            Self::Serpent256 => padded_len(plaintext_len, serpent::BLOCK_LEN),
            Self::Threefish1024 => padded_len(plaintext_len, threefish::BLOCK_LEN),
        }
    }

    pub(crate) fn seal(
        self,
        master_key: &[u8],
        salt: &[u8; SALT_LEN],
        nonce: &[u8],
        header: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), AppError> {
        match self {
            Self::Aes256GcmSiv => aes::seal(master_key, salt, nonce, header, plaintext),
            Self::XChaCha20Poly1305 => xchacha::seal(master_key, salt, nonce, header, plaintext),
            Self::Serpent256 => serpent::seal(master_key, salt, nonce, header, plaintext),
            Self::Threefish1024 => threefish::seal(master_key, salt, nonce, header, plaintext),
        }
    }

    pub(crate) fn open(
        self,
        master_key: &[u8],
        salt: &[u8; SALT_LEN],
        nonce: &[u8],
        header: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AppError> {
        match self {
            Self::Aes256GcmSiv => aes::open(master_key, salt, nonce, header, ciphertext, tag),
            Self::XChaCha20Poly1305 => {
                xchacha::open(master_key, salt, nonce, header, ciphertext, tag)
            }
            Self::Serpent256 => serpent::open(master_key, salt, nonce, header, ciphertext, tag),
            Self::Threefish1024 => {
                threefish::open(master_key, salt, nonce, header, ciphertext, tag)
            }
        }
    }
}

fn padded_len(plaintext_len: usize, block_len: usize) -> Option<usize> {
    plaintext_len
        .checked_div(block_len)?
        .checked_add(1)?
        .checked_mul(block_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_are_strict_and_uppercase() {
        assert_eq!(Algorithm::from_selector("A"), Some(Algorithm::Aes256GcmSiv));
        assert_eq!(Algorithm::from_selector("S"), Some(Algorithm::Serpent256));
        assert_eq!(
            Algorithm::from_selector("X"),
            Some(Algorithm::XChaCha20Poly1305)
        );
        assert_eq!(
            Algorithm::from_selector("T"),
            Some(Algorithm::Threefish1024)
        );
        for invalid in ["a", "s", "x", "t", "AES", "", "Ａ"] {
            assert_eq!(Algorithm::from_selector(invalid), None);
        }
    }

    #[test]
    fn padded_lengths_are_checked() {
        assert_eq!(padded_len(0, 16), Some(16));
        assert_eq!(padded_len(15, 16), Some(16));
        assert_eq!(padded_len(16, 16), Some(32));
        assert_eq!(padded_len(usize::MAX, 16), None);
    }
}
