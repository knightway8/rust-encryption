#[path = "common/deep_cli.rs"]
mod deep_cli;

macro_rules! define_deep_app {
    ($module:ident, $binary:expr, $kind:expr) => {
        mod $module {
            crate::deep_cli::define_deep_cli_tests!(
                crate::deep_cli::run_case,
                crate::deep_cli::DeepCliApp {
                    binary: $binary,
                    kind: $kind,
                }
            );
        }
    };
}

define_deep_app!(
    aes,
    env!("CARGO_BIN_EXE_aes"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: Some("aes.key"),
        key_len: 32,
    }
);
define_deep_app!(
    aesp,
    env!("CARGO_BIN_EXE_aesp"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: None,
        key_len: 0,
    }
);
define_deep_app!(
    cha,
    env!("CARGO_BIN_EXE_cha"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: Some("cha.key"),
        key_len: 32,
    }
);
define_deep_app!(
    chap,
    env!("CARGO_BIN_EXE_chap"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: None,
        key_len: 0,
    }
);
define_deep_app!(
    ser,
    env!("CARGO_BIN_EXE_ser"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: Some("ser.key"),
        key_len: 32,
    }
);
define_deep_app!(
    serp,
    env!("CARGO_BIN_EXE_serp"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: None,
        key_len: 0,
    }
);
define_deep_app!(
    thf,
    env!("CARGO_BIN_EXE_thf"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: Some("thf.key"),
        key_len: 128,
    }
);
define_deep_app!(
    thfp,
    env!("CARGO_BIN_EXE_thfp"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: None,
        key_len: 0,
    }
);
define_deep_app!(
    asc,
    env!("CARGO_BIN_EXE_asc"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: Some("asc.key"),
        key_len: 16,
    }
);
define_deep_app!(
    ascp,
    env!("CARGO_BIN_EXE_ascp"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: None,
        key_len: 0,
    }
);
define_deep_app!(
    rabbit,
    env!("CARGO_BIN_EXE_rabbit"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: Some("rab.key"),
        key_len: 16,
    }
);
define_deep_app!(
    rabbitp,
    env!("CARGO_BIN_EXE_rabbitp"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: None,
        key_len: 0,
    }
);
define_deep_app!(
    aegis256,
    env!("CARGO_BIN_EXE_aegis256"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: Some("aegis256.key"),
        key_len: 32,
    }
);
define_deep_app!(
    aegis256p,
    env!("CARGO_BIN_EXE_aegis256p"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: None,
        key_len: 0,
    }
);
define_deep_app!(
    aegis128l,
    env!("CARGO_BIN_EXE_aegis128l"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: Some("aegis128l.key"),
        key_len: 16,
    }
);
define_deep_app!(
    aegis128lp,
    env!("CARGO_BIN_EXE_aegis128lp"),
    crate::deep_cli::DeepCliKind::Cipher {
        key_filename: None,
        key_len: 0,
    }
);
define_deep_app!(
    keygen,
    env!("CARGO_BIN_EXE_keygen"),
    crate::deep_cli::DeepCliKind::Size
);
define_deep_app!(
    keymake,
    env!("CARGO_BIN_EXE_keymake"),
    crate::deep_cli::DeepCliKind::Size
);
define_deep_app!(
    key2txt,
    env!("CARGO_BIN_EXE_key2txt"),
    crate::deep_cli::DeepCliKind::SingleInput
);
define_deep_app!(
    txt2key,
    env!("CARGO_BIN_EXE_txt2key"),
    crate::deep_cli::DeepCliKind::SingleInput
);
define_deep_app!(
    otp,
    env!("CARGO_BIN_EXE_otp"),
    crate::deep_cli::DeepCliKind::Otp
);
