@echo off
setlocal
cd /d "%~dp0"
cargo fmt --all --check
if errorlevel 1 exit /b %errorlevel%
cargo clippy --all-targets --locked -- -D warnings
if errorlevel 1 exit /b %errorlevel%
cargo test --all-targets --locked -- --test-threads=4
if errorlevel 1 exit /b %errorlevel%
cargo test --doc --locked
if errorlevel 1 exit /b %errorlevel%
echo All checks passed.
exit /b 0
