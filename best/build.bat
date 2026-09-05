@echo off
setlocal
cd /d "%~dp0"
cargo build --release --locked
if errorlevel 1 exit /b %errorlevel%
if not exist "dist" mkdir "dist"
copy /y "target\release\best.exe" "dist\best.exe" >nul
if errorlevel 1 exit /b %errorlevel%
echo Built dist\best.exe
exit /b 0
