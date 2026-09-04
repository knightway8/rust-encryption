@echo off
setlocal
pushd "%~dp0"

for %%S in (
    bin_aes
    bin_aesp
    bin_cha
    bin_chap
    bin_ser
    bin_serp
    bin_thf
    bin_thfp
    bin_asc
    bin_ascp
    bin_rabbit
    bin_rabbitp
    bin_aegis256
    bin_aegis256p
    bin_aegis128l
    bin_aegis128lp
    bin_keygen
    bin_keymake
    bin_key2txt
    bin_txt2key
    bin_otp
    bin_x4x
) do (
    echo.
    echo ===== Testing %%S =====
    cargo test --locked --test %%S -- --test-threads=1
    if errorlevel 1 (
        echo.
        echo FAILED: %%S
        popd
        exit /b 1
    )
)

echo.
echo All 22 binary test suites passed with 21 CLI tests each.
popd
exit /b 0
