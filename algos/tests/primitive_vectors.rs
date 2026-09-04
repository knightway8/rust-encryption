//! Independent known-answer tests for every primitive used by the 30 suites.
//!
//! These tests deliberately exercise the crates directly, rather than calling
//! the container implementation. That keeps the expected bytes independent of
//! our format/key-schedule code and makes this file a useful audit boundary.
//!
//! Every frozen output below comes from a named external specification or
//! upstream conformance corpus. Metamorphic checks (fragmented I/O, inverse
//! operations, and authentication failure) are marked as such and do not claim
//! to be independent known-answer vectors.

use aead::{Aead, Payload};
use cipher::{
    Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit, KeyIvInit, StreamCipher,
    array::Array,
    consts::{U10, U16},
};
use hex_literal::hex;

fn assert_block_vector<C>(key: &[u8], plaintext: [u8; 16], ciphertext: [u8; 16])
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt + KeyInit,
{
    let cipher = C::new_from_slice(key).expect("published vector has a valid key length");
    let mut block = Block::<C>::from(plaintext);

    cipher.encrypt_block(&mut block);
    assert_eq!(&block[..], &ciphertext);

    cipher.decrypt_block(&mut block);
    assert_eq!(&block[..], &plaintext);
}

fn assert_stream_vector<C>(key: &[u8], iv: &[u8], plaintext: &[u8], ciphertext: &[u8])
where
    C: KeyIvInit + StreamCipher,
{
    assert_eq!(plaintext.len(), ciphertext.len());

    let mut one_shot = plaintext.to_vec();
    C::new_from_slices(key, iv)
        .expect("published vector has valid key/IV lengths")
        .apply_keystream(&mut one_shot);
    assert_eq!(one_shot, ciphertext);

    // Metamorphic buffering check: chunk boundaries must not reset or skip the
    // stream position. The pattern crosses word and block boundaries.
    let mut fragmented = plaintext.to_vec();
    let mut cipher = C::new_from_slices(key, iv).unwrap();
    let widths = [1usize, 2, 7, 16, 3, 31, 5, 64];
    let mut offset = 0;
    let mut width_index = 0;
    while offset < fragmented.len() {
        let end = (offset + widths[width_index % widths.len()]).min(fragmented.len());
        cipher.apply_keystream(&mut fragmented[offset..end]);
        offset = end;
        width_index += 1;
    }
    assert_eq!(fragmented, ciphertext);

    let mut decrypted = ciphertext.to_vec();
    C::new_from_slices(key, iv)
        .unwrap()
        .apply_keystream(&mut decrypted);
    assert_eq!(decrypted, plaintext);
}

macro_rules! assert_aead_vector {
    ($cipher:ty, $key:expr, $nonce:expr, $aad:expr, $plaintext:expr, $combined:expr) => {{
        let key = Array($key);
        let nonce = Array($nonce);
        let aad: &[u8] = ($aad).as_ref();
        let plaintext: &[u8] = ($plaintext).as_ref();
        let expected: &[u8] = ($combined).as_ref();
        let cipher = <$cipher>::new(&key);

        let encrypted = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .unwrap();
        assert_eq!(encrypted, expected);

        let decrypted = cipher
            .decrypt(&nonce, Payload { msg: expected, aad })
            .unwrap();
        assert_eq!(decrypted, plaintext);

        // Metamorphic authentication checks. Every ciphertext/tag byte, the
        // associated data, and the nonce must be covered by verification.
        for index in 0..expected.len() {
            let mut damaged = expected.to_vec();
            damaged[index] ^= 1;
            assert!(
                cipher
                    .decrypt(&nonce, Payload { msg: &damaged, aad })
                    .is_err(),
                "tampering byte {index} was accepted"
            );
        }

        let mut wrong_aad = aad.to_vec();
        if wrong_aad.is_empty() {
            wrong_aad.push(1);
        } else {
            wrong_aad[0] ^= 1;
        }
        assert!(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: expected,
                        aad: &wrong_aad,
                    },
                )
                .is_err()
        );

        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 1;
        assert!(
            cipher
                .decrypt(&wrong_nonce, Payload { msg: expected, aad })
                .is_err()
        );
    }};
}

// FIPS 197, Appendix C:
// https://csrc.nist.gov/pubs/fips/197/final
#[test]
fn aes_fips_197_all_key_sizes() {
    let plaintext = hex!("00112233445566778899aabbccddeeff");
    assert_block_vector::<aes::Aes128>(
        &hex!("000102030405060708090a0b0c0d0e0f"),
        plaintext,
        hex!("69c4e0d86a7b0430d8cdb78070b4c55a"),
    );
    assert_block_vector::<aes::Aes192>(
        &hex!("000102030405060708090a0b0c0d0e0f1011121314151617"),
        plaintext,
        hex!("dda97ca4864cdfe06eaf70a0ec0d7191"),
    );
    assert_block_vector::<aes::Aes256>(
        &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        plaintext,
        hex!("8ea2b7ca516745bfeafc49904b496089"),
    );
}

// NIST CAVP ECB known-answer vectors (all-zero key and plaintext).
#[test]
fn aes_cavp_zero_vectors_all_key_sizes() {
    let plaintext = [0u8; 16];
    assert_block_vector::<aes::Aes128>(
        &[0u8; 16],
        plaintext,
        hex!("66e94bd4ef8a2c3b884cfa59ca342b2e"),
    );
    assert_block_vector::<aes::Aes192>(
        &[0u8; 24],
        plaintext,
        hex!("aae06992acbf52a3e8f4a96ec9300bd7"),
    );
    assert_block_vector::<aes::Aes256>(
        &[0u8; 32],
        plaintext,
        hex!("dc95c078a2408989ad48a21492842087"),
    );
}

// NIST SP 800-38A, Appendix F.5 (CTR-AES128/192/256.Encrypt):
// https://csrc.nist.gov/pubs/sp/800/38/a/final
#[test]
fn aes_ctr_nist_sp800_38a_all_key_sizes() {
    let counter = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plaintext = hex!(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    );

    assert_stream_vector::<ctr::Ctr128BE<aes::Aes128>>(
        &hex!("2b7e151628aed2a6abf7158809cf4f3c"),
        &counter,
        &plaintext,
        &hex!(
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee"
        ),
    );
    assert_stream_vector::<ctr::Ctr128BE<aes::Aes192>>(
        &hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
        &counter,
        &plaintext,
        &hex!(
            "1abc932417521ca24f2b0459fe7e6e0b"
            "090339ec0aa6faefd5ccc2c6f4ce8e94"
            "1e36b26bd1ebc670d1bd1d665620abf7"
            "4f78a7f6d29809585a97daec58c6b050"
        ),
    );
    assert_stream_vector::<ctr::Ctr128BE<aes::Aes256>>(
        &hex!(
            "603deb1015ca71be2b73aef0857d7781"
            "1f352c073b6108d72d9810a30914dff4"
        ),
        &counter,
        &plaintext,
        &hex!(
            "601ec313775789a5b7a7f504bbf3d228"
            "f443e3ca4d62b59aca84e990cacaf5c5"
            "2b0930daa23de94ce87017ba2d84988d"
            "dfc9c58db67aada613c2dd08457941a6"
        ),
    );
}

// RFC 3713, Section 4. Test Vectors:
// https://www.rfc-editor.org/rfc/rfc3713.html#section-4
#[test]
fn camellia_rfc3713_all_key_sizes() {
    let plaintext = hex!("0123456789abcdeffedcba9876543210");
    assert_block_vector::<camellia::Camellia128>(
        &hex!("0123456789abcdeffedcba9876543210"),
        plaintext,
        hex!("67673138549669730857065648eabe43"),
    );
    assert_block_vector::<camellia::Camellia192>(
        &hex!("0123456789abcdeffedcba98765432100011223344556677"),
        plaintext,
        hex!("b4993401b3e996f84ee5cee7d79b09b9"),
    );
    assert_block_vector::<camellia::Camellia256>(
        &hex!(
            "0123456789abcdeffedcba9876543210"
            "00112233445566778899aabbccddeeff"
        ),
        plaintext,
        hex!("9acc237dff16d76c20ef7c919e3a7509"),
    );
}

// NESSIE Camellia Set 1, vectors 0..2. These are copied from the
// `camellia` crate's upstream NESSIE fixture, not generated by this project.
// Archive/source: https://www.cosic.esat.kuleuven.be/nessie/testvectors/
#[test]
fn camellia_nessie_single_bit_keys() {
    let plaintext = [0u8; 16];
    let keys = [0x80u8, 0x40, 0x20];
    let ct128 = [
        hex!("6c227f749319a3aa7da235a9bba05a2c"),
        hex!("f04d51e45e70fb6dee0d16a204fbba16"),
        hex!("ed44242e619f8c32eaa2d3641da47ea4"),
    ];
    let ct192 = [
        hex!("1b6220d365c2176c1d41a5826520fca1"),
        hex!("0f6daeea95cfc8925f23afa932df489b"),
        hex!("7330199225ad384f8dd39582d61389bb"),
    ];
    let ct256 = [
        hex!("2136fabda091dfb5171b94b8efbb5d08"),
        hex!("6ebc4f33b3eada5dbf25130f3d02cd34"),
        hex!("3a7bcdc53a1f02ef20c79cfce107d38b"),
    ];

    for index in 0..keys.len() {
        let mut key128 = [0u8; 16];
        key128[0] = keys[index];
        assert_block_vector::<camellia::Camellia128>(&key128, plaintext, ct128[index]);

        let mut key192 = [0u8; 24];
        key192[0] = keys[index];
        assert_block_vector::<camellia::Camellia192>(&key192, plaintext, ct192[index]);

        let mut key256 = [0u8; 32];
        key256[0] = keys[index];
        assert_block_vector::<camellia::Camellia256>(&key256, plaintext, ct256[index]);
    }
}

// RFC 5794, Appendices A.1, A.2, and A.3:
// https://www.rfc-editor.org/rfc/rfc5794.html#appendix-A
#[test]
fn aria_rfc5794_all_key_sizes() {
    let plaintext = hex!("00112233445566778899aabbccddeeff");
    assert_block_vector::<aria::Aria128>(
        &hex!("000102030405060708090a0b0c0d0e0f"),
        plaintext,
        hex!("d718fbd6ab644c739da95f3be6451778"),
    );
    assert_block_vector::<aria::Aria192>(
        &hex!("000102030405060708090a0b0c0d0e0f1011121314151617"),
        plaintext,
        hex!("26449c1805dbe7aa25a468ce263a9e79"),
    );
    assert_block_vector::<aria::Aria256>(
        &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        plaintext,
        hex!("f92bd7c79fb72e2f2b8f80c1972d24fc"),
    );
}

fn assert_twofish_sequence<const KEY_LEN: usize>(checkpoints: &[(usize, [u8; 16])]) {
    let mut key = [0u8; KEY_LEN];
    let mut plaintext = [0u8; 16];

    for iteration in 1..50 {
        let cipher = twofish::Twofish::new_from_slice(&key).unwrap();
        let mut block = Block::<twofish::Twofish>::from(plaintext);
        cipher.encrypt_block(&mut block);
        let mut ciphertext = [0u8; 16];
        ciphertext.copy_from_slice(&block);

        if let Some((_, expected)) = checkpoints.iter().find(|(at, _)| *at == iteration) {
            assert_eq!(&ciphertext, expected, "Twofish iteration {iteration}");
        }

        cipher.decrypt_block(&mut block);
        assert_eq!(&block[..], &plaintext);

        let (left, right) = key.split_at_mut(16);
        right.copy_from_slice(&left[..KEY_LEN - 16]);
        left.copy_from_slice(&plaintext);
        plaintext = ciphertext;
    }
}

// Twofish submission `ecb_ival.txt`, also printed in the Twofish paper,
// Appendix B.2, "Full Encryptions":
// https://www.schneier.com/wp-content/uploads/2016/02/paper-twofish-paper.pdf
#[test]
fn twofish_submission_sequences_all_key_sizes() {
    assert_twofish_sequence::<16>(&[
        (1, hex!("9f589f5cf6122c32b6bfec2f2ae8c35a")),
        (2, hex!("d491db16e7b1c39e86cb086b789f5419")),
        (3, hex!("019f9809de1711858faac3a3ba20fbc3")),
        (4, hex!("6363977de839486297e661c6c9d668eb")),
        (5, hex!("816d5bd0fae35342bf2a7412c246f752")),
        (48, hex!("6b459286f3ffd28d49f15b1581b08e42")),
    ]);
    assert_twofish_sequence::<24>(&[
        (1, hex!("efa71f788965bd4453f860178fc19101")),
        (2, hex!("88b2b2706b105e36b446bb6d731a1e88")),
        (3, hex!("39da69d6ba4997d585b6dc073ca341b2")),
        (4, hex!("182b02d81497ea45f9daacdc29193a65")),
        (5, hex!("7aff7a70ca2ff28ac31dd8ae5daaab63")),
        (48, hex!("f0ab73301125fa21ef70be5385fb76b6")),
    ]);
    assert_twofish_sequence::<32>(&[
        (1, hex!("57ff739d4dc92c1bd7fc01700cc8216f")),
        (2, hex!("d43bb7556ea32e46f2a282b7d45b4e0d")),
        (3, hex!("90afe91bb288544f2c32dc239b2635e6")),
        (4, hex!("6cb4561c40bf0a9705931cb6d408e7fa")),
        (5, hex!("3059d6d61753b958d92f4781c8640e58")),
        (48, hex!("431058f4dbc7f734da4f02f04cc4f459")),
    ]);
}

// NESSIE Serpent Set 1, vectors 0..2. The exact byte-oriented vectors are
// archived in the `serpent` crate and originate here:
// https://www.cs.technion.ac.il/~biham/Reports/Serpent/
#[test]
fn serpent_nessie_all_key_sizes() {
    let plaintext = [0u8; 16];
    let key_heads = [0x80u8, 0x40, 0x20];
    let ct128 = [
        hex!("264e5481eff42a4606abda06c0bfda3d"),
        hex!("4a231b3bc727993407ac6ec8350e8524"),
        hex!("e03269f9e9fd853c7d8156df14b98d56"),
    ];
    let ct192 = [
        hex!("9e274ead9b737bb21efcfca548602689"),
        hex!("92fc8e510399e46a041bf365e7b3ae82"),
        hex!("5e0da386c46ad493dea203fdc6f57d70"),
    ];
    let ct256 = [
        hex!("a223aa1288463c0e2be38ebd825616c0"),
        hex!("eae1d405570174df7df2f9966d509159"),
        hex!("65f37684471e921dc8a30f45b43c4499"),
    ];

    for index in 0..key_heads.len() {
        let mut key128 = [0u8; 16];
        key128[0] = key_heads[index];
        assert_block_vector::<serpent::Serpent>(&key128, plaintext, ct128[index]);

        let mut key192 = [0u8; 24];
        key192[0] = key_heads[index];
        assert_block_vector::<serpent::Serpent>(&key192, plaintext, ct192[index]);

        let mut key256 = [0u8; 32];
        key256[0] = key_heads[index];
        assert_block_vector::<serpent::Serpent>(&key256, plaintext, ct256[index]);
    }
}

// GM/T 0002-2012, Example 1 (also reproduced by the IETF SM4 drafts).
#[test]
fn sm4_gmt_0002_example_one() {
    let key_and_plaintext = hex!("0123456789abcdeffedcba9876543210");
    assert_block_vector::<sm4::Sm4>(
        &key_and_plaintext,
        key_and_plaintext,
        hex!("681edf34d206965e86b3e94f536e4246"),
    );
}

// GM/T 0002-2012, Example 2: one million repeated encryptions.
#[test]
fn sm4_gmt_0002_million_iteration_vector() {
    let key = hex!("0123456789abcdeffedcba9876543210");
    let cipher = sm4::Sm4::new(&key.into());
    let mut block = Block::<sm4::Sm4>::from(key);
    for _ in 0..1_000_000 {
        cipher.encrypt_block(&mut block);
    }
    assert_eq!(&block[..], &hex!("595298c7c6fd271f0402f804c33d3f66"));
    for _ in 0..1_000_000 {
        cipher.decrypt_block(&mut block);
    }
    assert_eq!(&block[..], &key);
}

// GOST R 34.12-2015 / RFC 7801, Section 5.4:
// https://www.rfc-editor.org/rfc/rfc7801.html#section-5.4
#[test]
fn kuznyechik_rfc7801() {
    assert_block_vector::<kuznyechik::Kuznyechik>(
        &hex!(
            "8899aabbccddeeff0011223344556677"
            "fedcba98765432100123456789abcdef"
        ),
        hex!("1122334455667700ffeeddccbbaa9988"),
        hex!("7f679d90bebc24305a468d42b9d4edcd"),
    );
}

// RFC 2612, Appendix A. Although suite 26 deliberately fixes a 256-bit key,
// checking every standardized CAST-256 key size gives broader schedule coverage.
// https://www.rfc-editor.org/rfc/rfc2612.html#appendix-A
#[test]
fn cast6_rfc2612_all_published_key_sizes() {
    let plaintext = [0u8; 16];
    assert_block_vector::<cast6::Cast6>(
        &hex!("2342bb9efa38542c0af75647f29f615d"),
        plaintext,
        hex!("c842a08972b43d20836c91d1b7530f6b"),
    );
    assert_block_vector::<cast6::Cast6>(
        &hex!("2342bb9efa38542cbed0ac83940ac298bac77a7717942863"),
        plaintext,
        hex!("1b386c0210dcadcbdd0e41aa08a7a7e8"),
    );
    assert_block_vector::<cast6::Cast6>(
        &hex!("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604"),
        plaintext,
        hex!("4f6a2038286897b9c9870136553317fa"),
    );
}

// STB 34.101.31-2020, Tables A.15 and A.16:
// https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
#[test]
fn belt_ctr_standard_tables_a15_a16() {
    assert_stream_vector::<belt_ctr::BeltCtr>(
        &hex!(
            "e9dee72c8f0c0fa62ddb49f46f739647"
            "06075316ed247a3739cba38303a98bf6"
        ),
        &hex!("be32971343fc9a48a02a885f194b09a1"),
        &hex!(
            "b194bac80a08f53b366d008e584a5de4"
            "8504fa9d1bb6c7ac252e72c202fdce0d"
            "5be3d61217b96181fe6786ad716b890b"
        ),
        &hex!(
            "52c9af96ff50f64435fc43def56bd797"
            "d5b5b1ff79fb41257ab9cdf6e63e81f8"
            "f00341473eae409833622de05213773a"
        ),
    );
    assert_stream_vector::<belt_ctr::BeltCtr>(
        &hex!(
            "92bd9b1ce5d141015445fbc95e4d0ef2"
            "682080aa227d642f2687f93490405511"
        ),
        &hex!("7ecda4d01544af8ca58450bf66d2e88a"),
        &hex!(
            "df181ed008a20f43dcbbb93650dad34b"
            "389cdee5826d40e2d4bd80f49a93f5d2"
            "12f6333166456f169043cc5f"
        ),
        &hex!(
            "e12bdc1ae28257ec703fccf095ee8df1"
            "c1ab76389fe678caf7c6f860d5bb9c4f"
            "f33c657b637c306add4ea779"
        ),
    );
}

// Salsa20/20 verified eSTREAM/ECRYPT vectors, Set 1. These exact cases are
// mirrored by RustCrypto's upstream `salsa20` conformance tests.
#[test]
fn salsa20_ecrypt_verified_vectors() {
    assert_stream_vector::<salsa20::Salsa20>(
        &hex!(
            "80000000000000000000000000000000"
            "00000000000000000000000000000000"
        ),
        &[0u8; 8],
        &[0u8; 64],
        &hex!(
            "e3be8fdd8beca2e3ea8ef9475b29a6e7"
            "003951e1097a5c38d23b7a5fad9f6844"
            "b22c97559e2723c7cbbd3fe4fc8d9a07"
            "44652a83e72a9c461876af4d7ef1a117"
        ),
    );
    assert_stream_vector::<salsa20::Salsa20>(
        &[0u8; 32],
        &hex!("8000000000000000"),
        &[0u8; 64],
        &hex!(
            "2aba3dc45b4947007b14c851cd694456"
            "b303ad59a465662803006705673d6c3e"
            "29f1d3510dfc0405463c03414e0e07e3"
            "59f1f1816c68b2434a19d3eee0464873"
        ),
    );
    assert_stream_vector::<salsa20::Salsa20>(
        &[0u8; 32],
        &hex!("0000000000000001"),
        &[0u8; 64],
        &hex!(
            "b47f96aa96786135297a3c4ec56a613d"
            "0b80095324ff43239d684c57ffe42e1c"
            "44f3cc011613db6cdc880999a1e65aed"
            "1287fcb11c839c37120765afa73e5075"
        ),
    );
}

// XSalsa20 vectors copied from the historical Go x/crypto Salsa20 tests;
// the second source case is also carried by libsodium-compatible suites.
// The derivation itself is specified by Bernstein's "Extending the Salsa20
// nonce" paper: https://cr.yp.to/snuffle/xsalsa-20110204.pdf
#[test]
fn xsalsa20_published_vectors_and_hsalsa_relationship() {
    let key = *b"this is 32-byte key for xsalsa20";
    let nonce = *b"24-byte nonce for xsalsa";
    let expected = hex!(
        "4848297feb1fb52fb66d81609bd547fa"
        "bcbe7026edc8b5e5e449d088bfa69c08"
        "8f5d8da1d791267c2c195a7f8cae9c4b"
        "4050d08ce6d3a151ec265f3a58e47648"
    );
    assert_stream_vector::<salsa20::XSalsa20>(&key, &nonce, &[0u8; 64], &expected);
    assert_stream_vector::<salsa20::XSalsa20>(
        &key,
        &nonce,
        b"Hello world!",
        &hex!("002d4513843fc240c401e541"),
    );

    // Metamorphic specification check: XSalsa20(K, N[0..24]) is Salsa20
    // under HSalsa20(K, N[0..16]) with N[16..24] as its ordinary nonce.
    let key_array = salsa20::Key::from(key);
    let hsalsa_input = Array::<u8, U16>::try_from(&nonce[..16]).unwrap();
    let subkey = salsa20::hsalsa::<U10>(&key_array, &hsalsa_input);
    let tail = salsa20::Nonce::try_from(&nonce[16..]).unwrap();
    let mut direct = [0u8; 257];
    salsa20::XSalsa20::new(&key_array, &nonce.into()).apply_keystream(&mut direct);
    let mut decomposed = [0u8; 257];
    salsa20::Salsa20::new(&subkey, &tail).apply_keystream(&mut decomposed);
    assert_eq!(direct, decomposed);
}

// HC-256 eSTREAM verified test vectors (Set 2), as published with the HC-256
// reference paper and mirrored by RustCrypto and Bouncy Castle.
#[test]
fn hc256_estream_verified_vectors() {
    assert_stream_vector::<hc_256::Hc256>(
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 64],
        &hex!(
            "5b078985d8f6f30d42c5c02fa6b67951"
            "53f06534801f89f24e74248b720b4818"
            "cd9227ecebcf4dbf8dbf6977e4ae14fa"
            "e8504c7bc8a9f3ea6c0106f5327e6981"
        ),
    );
    assert_stream_vector::<hc_256::Hc256>(
        &[0u8; 32],
        &hex!(
            "01000000000000000000000000000000"
            "00000000000000000000000000000000"
        ),
        &[0u8; 64],
        &hex!(
            "afe2a2bf4f17cee9fec2058bd1b18bb1"
            "5fc042ee712b3101dd501fc60b082a50"
            "06c7feed41923d6348c4daa6ff6185af"
            "5a13045e34c44894f3e9e72ddf0b5237"
        ),
    );
    assert_stream_vector::<hc_256::Hc256>(
        &hex!(
            "55000000000000000000000000000000"
            "00000000000000000000000000000000"
        ),
        &[0u8; 32],
        &[0u8; 64],
        &hex!(
            "1c404afe4fe25fed958f9ad1ae36c06f"
            "88a65a3cc0abe223aeb3902f420ed3a8"
            "6c3af05944eb396efb79758f5e7a1370"
            "d8b7106dcdf7d0adda233472e6dd75f5"
        ),
    );
}

fn assert_hmac_sha256(key: &[u8], message: &[u8], expected: [u8; 32]) {
    use hmac::{KeyInit, Mac};

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).unwrap();
    mac.update(message);
    assert_eq!(&mac.finalize().into_bytes()[..], &expected);

    let mut fragmented = <HmacSha256 as KeyInit>::new_from_slice(key).unwrap();
    for chunk in message.chunks(7) {
        fragmented.update(chunk);
    }
    fragmented.verify_slice(&expected).unwrap();

    let mut wrong = expected;
    wrong[0] ^= 1;
    let mut verifier = <HmacSha256 as KeyInit>::new_from_slice(key).unwrap();
    verifier.update(message);
    assert!(verifier.verify_slice(&wrong).is_err());
}

// RFC 4231, test cases 1, 2, 3, 4, 6, and 7. HMAC-SHA-256 is the
// authentication primitive shared by all 22 encrypt-then-MAC suites.
// https://www.rfc-editor.org/rfc/rfc4231.html
#[test]
fn hmac_sha256_rfc4231() {
    assert_hmac_sha256(
        &[0x0b; 20],
        b"Hi There",
        hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    );
    assert_hmac_sha256(
        b"Jefe",
        b"what do ya want for nothing?",
        hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    );
    assert_hmac_sha256(
        &[0xaa; 20],
        &[0xdd; 50],
        hex!("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    );
    let key_case_4: Vec<u8> = (1..=25).collect();
    assert_hmac_sha256(
        &key_case_4,
        &[0xcd; 50],
        hex!("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    );
    assert_hmac_sha256(
        &[0xaa; 131],
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    );
    assert_hmac_sha256(
        &[0xaa; 131],
        b"This is a test using a larger than block-size key and a larger than block-size data. \
          The key needs to be hashed before being used by the HMAC algorithm.",
        hex!("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
    );
}

// NIST GCM examples/CAVP values for a zero key, 96-bit nonce, and one zero
// plaintext block. Combined output is ciphertext || tag.
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/
// cavp-testing-block-cipher-modes
#[test]
fn aes_gcm_nist_vectors_and_authentication() {
    assert_aead_vector!(
        aes_gcm::Aes128Gcm,
        [0u8; 16],
        [0u8; 12],
        hex!(""),
        [0u8; 16],
        hex!(
            "0388dace60b6a392f328c2b971b2fe78"
            "ab6e47d42cec13bdf53a67b21257bddf"
        )
    );
    assert_aead_vector!(
        aes_gcm::Aes256Gcm,
        [0u8; 32],
        [0u8; 12],
        hex!(""),
        [0u8; 16],
        hex!(
            "cea7403d4d606b6e074ec5d3baf39d18"
            "d0d1c8a799996bf0265b98b5d48ab919"
        )
    );
}

// RFC 8452, Appendices C.1 and C.2. Combined output is ciphertext || tag.
// https://www.rfc-editor.org/rfc/rfc8452.html#appendix-C
#[test]
fn aes_gcm_siv_rfc8452_both_key_sizes() {
    assert_aead_vector!(
        aes_gcm_siv::Aes128GcmSiv,
        hex!("01000000000000000000000000000000"),
        hex!("030000000000000000000000"),
        hex!(""),
        hex!("0100000000000000"),
        hex!("b5d839330ac7b786578782fff6013b815b287c22493a364c")
    );
    assert_aead_vector!(
        aes_gcm_siv::Aes256GcmSiv,
        hex!(
            "01000000000000000000000000000000"
            "00000000000000000000000000000000"
        ),
        hex!("030000000000000000000000"),
        hex!(""),
        hex!("0100000000000000"),
        hex!("c2ef328e5c71c83b843122130f7364b761e0b97427e3df28")
    );
}

// RFC 8439, Section 2.8.2. Combined output is ciphertext || tag.
// https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2
#[test]
fn chacha20_poly1305_rfc8439() {
    assert_aead_vector!(
        chacha20poly1305::ChaCha20Poly1305,
        hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        hex!("070000004041424344454647"),
        hex!("50515253c0c1c2c3c4c5c6c7"),
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
        hex!(
            "d31a8d34648e60db7b86afbc53ef7ec2"
            "a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b"
            "1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58"
            "fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b"
            "61161ae10b594f09e26a7e902ecbd0600691"
        )
    );
}

// draft-irtf-cfrg-xchacha, Appendix A.1. Combined output is ciphertext || tag.
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.1
#[test]
fn xchacha20_poly1305_draft_vector() {
    assert_aead_vector!(
        chacha20poly1305::XChaCha20Poly1305,
        hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        hex!("404142434445464748494a4b4c4d4e4f5051525354555657"),
        hex!("50515253c0c1c2c3c4c5c6c7"),
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
        hex!(
            "bd6d179d3e83d43b9576579493c0e939"
            "572a1700252bfaccbed2902c21396cbb"
            "731c7f1b0b4aa6440bf3a82f4eda7e39"
            "ae64c6708c54c216cb96b72e1213b452"
            "2f8c9ba40db5d945b11b69b982c1bb9e"
            "3f3fac2bc369488f76b2383565d3fff9"
            "21f9664c97637da9768812f615c68b13"
            "b52ec0875924c1c7987947deafd8780acf49"
        )
    );
}

// RFC 5297, Appendix A.1 (deterministic authenticated-encryption example).
// AES-SIV prepends its synthetic-IV/tag to the ciphertext.
// https://www.rfc-editor.org/rfc/rfc5297.html#appendix-A.1
#[test]
fn aes128_cmac_siv_rfc5297() {
    use aes_siv::siv::Aes128Siv;

    let key = hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let aad = hex!("101112131415161718191a1b1c1d1e1f2021222324252627");
    let plaintext = hex!("112233445566778899aabbccddee");
    let expected = hex!("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");

    let headers = [&aad[..]];
    let mut cipher = Aes128Siv::new(&key.into());
    assert_eq!(cipher.encrypt(headers, &plaintext).unwrap(), expected);
    assert_eq!(cipher.decrypt(headers, &expected).unwrap(), plaintext);

    for index in 0..expected.len() {
        let mut damaged = expected;
        damaged[index] ^= 1;
        assert!(cipher.decrypt(headers, &damaged).is_err());
    }
    let wrong_aad = hex!("111112131415161718191a1b1c1d1e1f2021222324252627");
    assert!(cipher.decrypt([&wrong_aad[..]], &expected).is_err());
}

// Google Wycheproof AES-SIV, valid 512-bit-key case. This is copied from the
// upstream `aes-siv` crate's `wycheproof-512_pass` corpus. Unlike a locally
// frozen round trip, Wycheproof is an independent conformance oracle.
// https://github.com/C2SP/wycheproof/tree/master/testvectors_v1
#[test]
fn aes256_cmac_siv_wycheproof() {
    use aes_siv::siv::Aes256Siv;

    let key = hex!(
        "aff6388fdd2908e0c3b610e3dcd410c8"
        "146a268d6befd5c45ffdd23508b5b311"
        "cc3a9d8f838f456436b289018682151d"
        "d57d8d65d1a823c06eca8ab8ee01da01"
    );
    let aad = hex!("d0bb2949a411e22d32964526");
    let plaintext = hex!("");
    let expected = hex!("e288d802a0e56ed7544a2e5775459389");

    let headers = [&aad[..]];
    let mut cipher = Aes256Siv::new(&key.into());
    assert_eq!(cipher.encrypt(headers, &plaintext).unwrap(), expected);
    assert_eq!(cipher.decrypt(headers, &expected).unwrap(), plaintext);

    for index in 0..expected.len() {
        let mut damaged = expected;
        damaged[index] ^= 1;
        assert!(cipher.decrypt(headers, &damaged).is_err());
    }
    assert!(cipher.decrypt([&[][..]], &expected).is_err());
}
