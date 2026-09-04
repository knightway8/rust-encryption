/// A stable on-disk identifier for one complete cipher suite.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum Suite {
    Aes128Gcm = 1,
    Aes256Gcm,
    Aes128GcmSiv,
    Aes256GcmSiv,
    Aes128CmacSiv,
    Aes256CmacSiv,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    Aes128CtrHmac,
    Aes192CtrHmac,
    Aes256CtrHmac,
    Camellia128CtrHmac,
    Camellia192CtrHmac,
    Camellia256CtrHmac,
    Aria128CtrHmac,
    Aria192CtrHmac,
    Aria256CtrHmac,
    Twofish128CtrHmac,
    Twofish192CtrHmac,
    Twofish256CtrHmac,
    Serpent128CtrHmac,
    Serpent192CtrHmac,
    Serpent256CtrHmac,
    Sm4CtrHmac,
    KuznyechikCtrHmac,
    Cast6CtrHmac,
    BeltCtrHmac,
    Salsa20Hmac,
    XSalsa20Hmac,
    Hc256Hmac,
}

pub const ALL_SUITES: [Suite; 30] = [
    Suite::Aes128Gcm,
    Suite::Aes256Gcm,
    Suite::Aes128GcmSiv,
    Suite::Aes256GcmSiv,
    Suite::Aes128CmacSiv,
    Suite::Aes256CmacSiv,
    Suite::ChaCha20Poly1305,
    Suite::XChaCha20Poly1305,
    Suite::Aes128CtrHmac,
    Suite::Aes192CtrHmac,
    Suite::Aes256CtrHmac,
    Suite::Camellia128CtrHmac,
    Suite::Camellia192CtrHmac,
    Suite::Camellia256CtrHmac,
    Suite::Aria128CtrHmac,
    Suite::Aria192CtrHmac,
    Suite::Aria256CtrHmac,
    Suite::Twofish128CtrHmac,
    Suite::Twofish192CtrHmac,
    Suite::Twofish256CtrHmac,
    Suite::Serpent128CtrHmac,
    Suite::Serpent192CtrHmac,
    Suite::Serpent256CtrHmac,
    Suite::Sm4CtrHmac,
    Suite::KuznyechikCtrHmac,
    Suite::Cast6CtrHmac,
    Suite::BeltCtrHmac,
    Suite::Salsa20Hmac,
    Suite::XSalsa20Hmac,
    Suite::Hc256Hmac,
];

const NAMES: [&str; 30] = [
    "AES-128-GCM",
    "AES-256-GCM",
    "AES-128-GCM-SIV",
    "AES-256-GCM-SIV",
    "AES-128-CMAC-SIV",
    "AES-256-CMAC-SIV",
    "ChaCha20-Poly1305",
    "XChaCha20-Poly1305",
    "AES-128-CTR + HMAC-SHA256",
    "AES-192-CTR + HMAC-SHA256",
    "AES-256-CTR + HMAC-SHA256",
    "Camellia-128-CTR + HMAC-SHA256",
    "Camellia-192-CTR + HMAC-SHA256",
    "Camellia-256-CTR + HMAC-SHA256",
    "ARIA-128-CTR + HMAC-SHA256",
    "ARIA-192-CTR + HMAC-SHA256",
    "ARIA-256-CTR + HMAC-SHA256",
    "Twofish-128-CTR + HMAC-SHA256",
    "Twofish-192-CTR + HMAC-SHA256",
    "Twofish-256-CTR + HMAC-SHA256",
    "Serpent-128-CTR + HMAC-SHA256",
    "Serpent-192-CTR + HMAC-SHA256",
    "Serpent-256-CTR + HMAC-SHA256",
    "SM4-CTR + HMAC-SHA256",
    "Kuznyechik-CTR + HMAC-SHA256",
    "CAST6-256-CTR + HMAC-SHA256",
    "BelT-CTR + HMAC-SHA256",
    "Salsa20 + HMAC-SHA256",
    "XSalsa20 + HMAC-SHA256",
    "HC-256 + HMAC-SHA256",
];

const BINARIES: [&str; 30] = [
    "aes128-gcm-file",
    "aes256-gcm-file",
    "aes128-gcm-siv-file",
    "aes256-gcm-siv-file",
    "aes128-cmac-siv-file",
    "aes256-cmac-siv-file",
    "chacha20-poly1305-file",
    "xchacha20-poly1305-file",
    "aes128-ctr-hmac-file",
    "aes192-ctr-hmac-file",
    "aes256-ctr-hmac-file",
    "camellia128-ctr-hmac-file",
    "camellia192-ctr-hmac-file",
    "camellia256-ctr-hmac-file",
    "aria128-ctr-hmac-file",
    "aria192-ctr-hmac-file",
    "aria256-ctr-hmac-file",
    "twofish128-ctr-hmac-file",
    "twofish192-ctr-hmac-file",
    "twofish256-ctr-hmac-file",
    "serpent128-ctr-hmac-file",
    "serpent192-ctr-hmac-file",
    "serpent256-ctr-hmac-file",
    "sm4-ctr-hmac-file",
    "kuznyechik-ctr-hmac-file",
    "cast6-ctr-hmac-file",
    "belt-ctr-hmac-file",
    "salsa20-hmac-file",
    "xsalsa20-hmac-file",
    "hc256-hmac-file",
];

impl Suite {
    #[must_use]
    pub const fn id(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_id(id: u16) -> Option<Self> {
        if id == 0 || id > 30 {
            None
        } else {
            Some(ALL_SUITES[(id - 1) as usize])
        }
    }

    #[must_use]
    pub const fn is_native_aead(self) -> bool {
        self.id() <= 8
    }

    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm
            | Self::Aes128GcmSiv
            | Self::Aes128CtrHmac
            | Self::Camellia128CtrHmac
            | Self::Aria128CtrHmac
            | Self::Twofish128CtrHmac
            | Self::Serpent128CtrHmac
            | Self::Sm4CtrHmac => 16,
            Self::Aes192CtrHmac
            | Self::Camellia192CtrHmac
            | Self::Aria192CtrHmac
            | Self::Twofish192CtrHmac
            | Self::Serpent192CtrHmac => 24,
            Self::Aes256CmacSiv => 64,
            _ => 32,
        }
    }

    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes128Gcm
            | Self::Aes256Gcm
            | Self::Aes128GcmSiv
            | Self::Aes256GcmSiv
            | Self::ChaCha20Poly1305 => 12,
            Self::XChaCha20Poly1305 | Self::XSalsa20Hmac => 24,
            Self::Salsa20Hmac => 8,
            Self::Hc256Hmac => 32,
            _ => 16,
        }
    }

    #[must_use]
    pub const fn tag_len(self) -> usize {
        if self.is_native_aead() { 16 } else { 32 }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        NAMES[(self.id() - 1) as usize]
    }

    #[must_use]
    pub const fn binary_name(self) -> &'static str {
        BINARIES[(self.id() - 1) as usize]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn registry_has_exactly_thirty_unique_canonical_entries() {
        assert_eq!(ALL_SUITES.len(), 30);
        let ids: HashSet<_> = ALL_SUITES.iter().map(|suite| suite.id()).collect();
        let names: HashSet<_> = ALL_SUITES.iter().map(|suite| suite.name()).collect();
        let binaries: HashSet<_> = ALL_SUITES.iter().map(|suite| suite.binary_name()).collect();
        assert_eq!(ids.len(), 30);
        assert_eq!(names.len(), 30);
        assert_eq!(binaries.len(), 30);

        for (offset, suite) in ALL_SUITES.iter().copied().enumerate() {
            let expected_id = u16::try_from(offset + 1).unwrap();
            assert_eq!(suite.id(), expected_id);
            assert_eq!(Suite::from_id(expected_id), Some(suite));
            assert!((16..=64).contains(&suite.key_len()));
            assert!(matches!(suite.nonce_len(), 8 | 12 | 16 | 24 | 32));
            assert!(matches!(suite.tag_len(), 16 | 32));
        }
        assert_eq!(Suite::from_id(0), None);
        assert_eq!(Suite::from_id(31), None);
    }

    #[test]
    fn manifest_declares_every_registry_binary_once() {
        let manifest = include_str!("../Cargo.toml");
        assert_eq!(manifest.matches("[[bin]]").count(), 30);
        for binary in BINARIES {
            let declarations = manifest
                .lines()
                .filter_map(|line| line.trim().strip_prefix("name = "))
                .filter(|name| name.trim_matches('"') == binary)
                .count();
            assert_eq!(declarations, 1, "{binary}");
        }
    }
}
