use crate::Algorithm;
use anyhow::{Result, anyhow, bail};
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

pub(super) const KDF_ID_ARGON2ID: u8 = 1;
const ROOT_KEY_LEN: usize = 64;
const MAX_MEMORY_KIB: u32 = 512 * 1024;
const MAX_ITERATIONS: u16 = 4;
const MAX_LANES: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PasswordKdf {
    pub(super) memory_kib: u32,
    pub(super) iterations: u16,
    pub(super) lanes: u8,
}

impl PasswordKdf {
    pub(super) const PRODUCTION: Self = Self {
        memory_kib: MAX_MEMORY_KIB,
        iterations: MAX_ITERATIONS,
        lanes: MAX_LANES,
    };

    pub(super) fn from_header(memory_kib: u32, iterations: u16, lanes: u8) -> Result<Self> {
        let parameters = Self {
            memory_kib,
            iterations,
            lanes,
        };
        parameters.validate()?;
        Ok(parameters)
    }

    fn validate(self) -> Result<()> {
        #[cfg(not(test))]
        const MIN_MEMORY_KIB: u32 = 64 * 1024;
        #[cfg(test)]
        const MIN_MEMORY_KIB: u32 = 8;

        #[cfg(not(test))]
        const MIN_ITERATIONS: u16 = 3;
        #[cfg(test)]
        const MIN_ITERATIONS: u16 = 1;

        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib) {
            bail!(
                "password KDF memory cost must be from {MIN_MEMORY_KIB} through {MAX_MEMORY_KIB} KiB"
            );
        }
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations) {
            bail!(
                "password KDF iteration count must be from {MIN_ITERATIONS} through {MAX_ITERATIONS}"
            );
        }
        if !(1..=MAX_LANES).contains(&self.lanes) {
            bail!("password KDF lane count must be from 1 through {MAX_LANES}");
        }
        if self.memory_kib < u32::from(self.lanes) * 8 {
            bail!("password KDF memory cost is too small for its lane count");
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) const fn testing() -> Self {
        Self {
            memory_kib: 32,
            iterations: 1,
            lanes: 1,
        }
    }
}

pub(super) fn derive_key(
    password: &[u8],
    salt: &[u8; 32],
    algorithm: Algorithm,
    parameters: PasswordKdf,
) -> Result<Zeroizing<Vec<u8>>> {
    if password.is_empty() {
        bail!("password must not be empty");
    }
    parameters.validate()?;

    let argon_parameters = Params::new(
        parameters.memory_kib,
        u32::from(parameters.iterations),
        u32::from(parameters.lanes),
        Some(ROOT_KEY_LEN),
    )
    .map_err(|error| anyhow!("invalid Argon2id parameters: {error}"))?;
    let argon2 = Argon2::new(ArgonAlgorithm::Argon2id, Version::V0x13, argon_parameters);
    let mut root_key = Zeroizing::new([0_u8; ROOT_KEY_LEN]);
    argon2
        .hash_password_into(password, salt, &mut *root_key)
        .map_err(|error| anyhow!("Argon2id key derivation failed: {error}"))?;

    let hkdf = Hkdf::<Sha512>::new(Some(salt), &*root_key);
    let mut information = *b"x3x/v2/password/algorithm-key/\0";
    *information.last_mut().expect("label is not empty") = algorithm.id();
    let mut key = Zeroizing::new(vec![0_u8; algorithm.key_len()]);
    hkdf.expand(&information, &mut key)
        .map_err(|_| anyhow!("password key expansion failed"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_salt_and_algorithm_separated() {
        let first = derive_key(
            b"long test password",
            &[1_u8; 32],
            Algorithm::Aes256GcmSiv,
            PasswordKdf::testing(),
        )
        .unwrap();
        let other_salt = derive_key(
            b"long test password",
            &[2_u8; 32],
            Algorithm::Aes256GcmSiv,
            PasswordKdf::testing(),
        )
        .unwrap();
        let other_algorithm = derive_key(
            b"long test password",
            &[1_u8; 32],
            Algorithm::XChaCha20Poly1305,
            PasswordKdf::testing(),
        )
        .unwrap();

        assert_ne!(&*first, &*other_salt);
        assert_ne!(&*first, &*other_algorithm);
    }

    #[test]
    fn production_parameters_are_deliberately_expensive() {
        assert_eq!(PasswordKdf::PRODUCTION.memory_kib, 512 * 1024);
        assert_eq!(PasswordKdf::PRODUCTION.iterations, 4);
        assert_eq!(PasswordKdf::PRODUCTION.lanes, 4);
    }

    #[test]
    fn header_parameters_cannot_exceed_the_production_budget() {
        assert!(
            PasswordKdf::from_header(
                MAX_MEMORY_KIB + 1,
                PasswordKdf::PRODUCTION.iterations,
                PasswordKdf::PRODUCTION.lanes,
            )
            .is_err()
        );
        assert!(
            PasswordKdf::from_header(
                PasswordKdf::PRODUCTION.memory_kib,
                MAX_ITERATIONS + 1,
                PasswordKdf::PRODUCTION.lanes,
            )
            .is_err()
        );
        assert!(
            PasswordKdf::from_header(
                PasswordKdf::PRODUCTION.memory_kib,
                PasswordKdf::PRODUCTION.iterations,
                MAX_LANES + 1,
            )
            .is_err()
        );
    }

    #[test]
    fn empty_password_is_rejected() {
        assert!(
            derive_key(
                b"",
                &[1_u8; 32],
                Algorithm::Aes256GcmSiv,
                PasswordKdf::testing(),
            )
            .is_err()
        );
    }
}
