@echo off
setlocal
cd /d "%~dp0"
:menu
echo.
echo BEST file encryption - developer menu
echo 1. Build release executable
echo 2. Run all checks and tests
echo 3. Show application help
echo 4. Check dependencies with cargo audit
echo 0. Exit
choice /c 12340 /n /m "Choose: "
if errorlevel 5 exit /b 0
if errorlevel 4 goto audit
if errorlevel 3 goto help
if errorlevel 2 goto tests
if errorlevel 1 goto build
goto menu
:build
call build.bat
goto menu
:tests
call test.bat
goto menu
:help
call best.bat --help
goto menu
:audit
cargo audit
if errorlevel 1 echo If cargo-audit is missing, install it with: cargo install cargo-audit --locked
goto menu
