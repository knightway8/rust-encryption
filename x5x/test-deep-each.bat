@echo off
setlocal
pushd "%~dp0"

for %%S in (
    aes
    aesp
    cha
    chap
    ser
    serp
    thf
    thfp
    asc
    ascp
    rabbit
    rabbitp
    aegis256
    aegis256p
    aegis128l
    aegis128lp
    keygen
    keymake
    key2txt
    txt2key
    otp
) do (
    echo.
    echo ===== Deep testing %%S =====
    cargo test --locked --test deep_apps -- "%%S::" --test-threads=1
    if errorlevel 1 (
        echo.
        echo FAILED: %%S deep corpus
        popd
        exit /b 1
    )
)

echo.
echo All 21 non-x4x applications passed 126 deep CLI cases each.
popd
exit /b 0
