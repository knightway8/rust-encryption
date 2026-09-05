#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Public CCTV test identity, never a real user's private key.
    let identity = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0"
        .parse::<age::x25519::Identity>().unwrap();
    let op = best::Operation { max_bytes: Some(1024 * 1024), ..Default::default() };
    let result = best::decrypt_stream(data, std::io::sink(), best::Decryption::Identities(vec![identity]), &op);
    if let Err(error) = result { let _ = error.to_string(); }
});
