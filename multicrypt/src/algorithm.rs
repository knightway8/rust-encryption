use std::fmt;
use std::str::FromStr;

use crate::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum Algorithm {
    Aes256GcmSiv = 1,
    Serpent256CtrHmacSha512 = 2,
    Threefish1024CtrHmacSha512 = 3,
    AsconAead128 = 4,
    RabbitHmacSha512 = 5,
    Aegis256 = 6,
    Aegis128L = 7,
}

impl Algorithm {
    pub const ALL: [Self; 7] = [
        Self::Aes256GcmSiv,
        Self::Serpent256CtrHmacSha512,
        Self::Threefish1024CtrHmacSha512,
        Self::AsconAead128,
        Self::RabbitHmacSha512,
        Self::Aegis256,
        Self::Aegis128L,
    ];

    pub const fn id(self) -> u16 {
        self as u16
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "AES-256-GCM-SIV",
            Self::Serpent256CtrHmacSha512 => "SERPENT-256-CTR-HMAC-SHA-512",
            Self::Threefish1024CtrHmacSha512 => "THREEFISH-1024-CTR-HMAC-SHA-512",
            Self::AsconAead128 => "ASCON-AEAD128",
            Self::RabbitHmacSha512 => "RABBIT-HMAC-SHA-512",
            Self::Aegis256 => "AEGIS-256",
            Self::Aegis128L => "AEGIS-128L",
        }
    }

    pub const fn key_filename(self) -> &'static str {
        match self {
            Self::Aes256GcmSiv => "aes-256-gcm-siv.mckey",
            Self::Serpent256CtrHmacSha512 => "serpent-256-ctr-hmac-sha512.mckey",
            Self::Threefish1024CtrHmacSha512 => "threefish-1024-ctr-hmac-sha512.mckey",
            Self::AsconAead128 => "ascon-aead128.mckey",
            Self::RabbitHmacSha512 => "rabbit-hmac-sha512.mckey",
            Self::Aegis256 => "aegis-256.mckey",
            Self::Aegis128L => "aegis-128l.mckey",
        }
    }

    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv => 12,
            Self::Serpent256CtrHmacSha512 => 16,
            Self::Threefish1024CtrHmacSha512 => 128,
            Self::AsconAead128 => 16,
            Self::RabbitHmacSha512 => 8,
            Self::Aegis256 => 32,
            Self::Aegis128L => 16,
        }
    }

    pub const fn tag_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv | Self::AsconAead128 => 16,
            Self::Serpent256CtrHmacSha512
            | Self::Threefish1024CtrHmacSha512
            | Self::RabbitHmacSha512 => 64,
            Self::Aegis256 | Self::Aegis128L => 32,
        }
    }

    pub const fn encryption_key_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv | Self::Serpent256CtrHmacSha512 | Self::Aegis256 => 32,
            Self::Threefish1024CtrHmacSha512 => 128,
            Self::AsconAead128 | Self::RabbitHmacSha512 | Self::Aegis128L => 16,
        }
    }

    pub const fn mac_key_len(self) -> usize {
        match self {
            Self::Serpent256CtrHmacSha512
            | Self::Threefish1024CtrHmacSha512
            | Self::RabbitHmacSha512 => 64,
            _ => 0,
        }
    }

    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            1 => Some(Self::Aes256GcmSiv),
            2 => Some(Self::Serpent256CtrHmacSha512),
            3 => Some(Self::Threefish1024CtrHmacSha512),
            4 => Some(Self::AsconAead128),
            5 => Some(Self::RabbitHmacSha512),
            6 => Some(Self::Aegis256),
            7 => Some(Self::Aegis128L),
            _ => None,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.to_ascii_uppercase();
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.name() == normalized)
            .ok_or_else(|| Error::UnknownAlgorithm(value.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_and_are_unique() {
        for algorithm in Algorithm::ALL {
            assert_eq!(Algorithm::from_id(algorithm.id()), Some(algorithm));
        }
        assert_eq!(Algorithm::from_id(0), None);
        assert_eq!(Algorithm::from_id(u16::MAX), None);
    }

    #[test]
    fn parser_is_case_insensitive_but_not_fuzzy() {
        assert_eq!(
            "aes-256-gcm-siv".parse::<Algorithm>().unwrap(),
            Algorithm::Aes256GcmSiv
        );
        assert!("AES256GCM-SIV".parse::<Algorithm>().is_err());
        assert!(" AES-256-GCM-SIV".parse::<Algorithm>().is_err());
    }

    #[test]
    fn suite_parameters_are_sane() {
        for algorithm in Algorithm::ALL {
            assert!(algorithm.nonce_len() >= 8);
            assert!(algorithm.tag_len() >= 16);
            assert!(algorithm.encryption_key_len() >= 16);
            assert!(algorithm.key_filename().ends_with(".mckey"));
        }
    }
}
