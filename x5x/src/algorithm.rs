use anyhow::{Result, bail};
use std::fmt;

/// Encryption algorithms supported by the standalone cipher binaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    Aes256GcmSiv = 1,
    XChaCha20Poly1305 = 2,
    Serpent256 = 3,
    Threefish1024 = 4,
    AsconAead128 = 5,
    Rabbit = 6,
    Aegis256 = 7,
    Aegis128L = 8,
}

impl Algorithm {
    pub(crate) const fn id(self) -> u8 {
        self as u8
    }

    pub(crate) fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::Aes256GcmSiv),
            2 => Ok(Self::XChaCha20Poly1305),
            3 => Ok(Self::Serpent256),
            4 => Ok(Self::Threefish1024),
            5 => Ok(Self::AsconAead128),
            6 => Ok(Self::Rabbit),
            7 => Ok(Self::Aegis256),
            8 => Ok(Self::Aegis128L),
            _ => bail!("unknown algorithm identifier {id}"),
        }
    }

    /// Fixed key filename expected in the working directory.
    #[must_use]
    pub const fn key_filename(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "aes.key",
            Self::XChaCha20Poly1305 => "cha.key",
            Self::Serpent256 => "ser.key",
            Self::Threefish1024 => "thf.key",
            Self::AsconAead128 => "asc.key",
            Self::Rabbit => "rab.key",
            Self::Aegis256 => "aegis256.key",
            Self::Aegis128L => "aegis128l.key",
        }
    }

    /// Exact raw key length accepted by the algorithm.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv | Self::XChaCha20Poly1305 | Self::Serpent256 | Self::Aegis256 => 32,
            Self::Threefish1024 => 128,
            Self::AsconAead128 | Self::Rabbit | Self::Aegis128L => 16,
        }
    }

    pub(crate) const fn is_aead(self) -> bool {
        matches!(
            self,
            Self::Aes256GcmSiv
                | Self::XChaCha20Poly1305
                | Self::AsconAead128
                | Self::Aegis256
                | Self::Aegis128L
        )
    }

    pub(crate) const fn tag_len(self) -> usize {
        if self.is_aead() { 16 } else { 64 }
    }

    pub(crate) const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv => 12,
            Self::XChaCha20Poly1305 => 24,
            Self::AsconAead128 | Self::Aegis128L => 16,
            Self::Aegis256 | Self::Serpent256 | Self::Threefish1024 | Self::Rabbit => 32,
        }
    }

    /// Command name of the standalone binary for this algorithm.
    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "aes",
            Self::XChaCha20Poly1305 => "cha",
            Self::Serpent256 => "ser",
            Self::Threefish1024 => "thf",
            Self::AsconAead128 => "asc",
            Self::Rabbit => "rabbit",
            Self::Aegis256 => "aegis256",
            Self::Aegis128L => "aegis128l",
        }
    }

    /// Command name of the standalone password-based binary for this algorithm.
    #[must_use]
    pub const fn password_command(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "aesp",
            Self::XChaCha20Poly1305 => "chap",
            Self::Serpent256 => "serp",
            Self::Threefish1024 => "thfp",
            Self::AsconAead128 => "ascp",
            Self::Rabbit => "rabbitp",
            Self::Aegis256 => "aegis256p",
            Self::Aegis128L => "aegis128lp",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Aes256GcmSiv => "AES-256-GCM-SIV",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Self::Serpent256 => "Serpent-256-CTR + HMAC-SHA-512",
            Self::Threefish1024 => "Threefish-1024-CTR + HMAC-SHA-512",
            Self::AsconAead128 => "Ascon-AEAD128",
            Self::Rabbit => "Rabbit + HMAC-SHA-512",
            Self::Aegis256 => "AEGIS-256",
            Self::Aegis128L => "AEGIS-128L",
        };
        f.write_str(name)
    }
}

/// Operation selected by the required uppercase command argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

impl Mode {
    /// Parse the mandatory uppercase operation.
    ///
    /// # Errors
    /// Returns an error unless value is exactly E or D.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "E" => Ok(Self::Encrypt),
            "D" => Ok(Self::Decrypt),
            _ => bail!("operation must be exactly E or D (uppercase)"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const ALGORITHMS: [Algorithm; 8] = [
        Algorithm::Aes256GcmSiv,
        Algorithm::XChaCha20Poly1305,
        Algorithm::Serpent256,
        Algorithm::Threefish1024,
        Algorithm::AsconAead128,
        Algorithm::Rabbit,
        Algorithm::Aegis256,
        Algorithm::Aegis128L,
    ];

    #[test]
    fn identifiers_round_trip_and_reject_unknown_values() {
        for (expected_id, algorithm) in (1_u8..=8).zip(ALGORITHMS) {
            assert_eq!(algorithm.id(), expected_id);
            assert_eq!(Algorithm::from_id(expected_id).unwrap(), algorithm);
        }
        for unknown in [0, 9, u8::MAX] {
            assert!(Algorithm::from_id(unknown).is_err());
        }
    }

    #[test]
    fn every_app_name_and_key_filename_is_unique() {
        let mut commands = HashSet::new();
        let mut password_commands = HashSet::new();
        let mut key_filenames = HashSet::new();
        for algorithm in ALGORITHMS {
            assert!(commands.insert(algorithm.command()));
            assert!(password_commands.insert(algorithm.password_command()));
            assert!(key_filenames.insert(algorithm.key_filename()));
            assert!(matches!(algorithm.key_len(), 16 | 32 | 128));
            assert!(matches!(algorithm.tag_len(), 16 | 64));
            assert!(algorithm.nonce_len() >= 12);
        }
    }

    #[test]
    fn modes_accept_only_the_documented_uppercase_operations() {
        assert_eq!(Mode::parse("E").unwrap(), Mode::Encrypt);
        assert_eq!(Mode::parse("D").unwrap(), Mode::Decrypt);
        for invalid in ["", "e", "d", "ED", "encrypt", "DECRYPT"] {
            assert!(Mode::parse(invalid).is_err());
        }
    }
}
