@echo off
setlocal
if not exist "%~dp0dist\best.exe" (
    echo Run build.bat first to build the release executable.
    exit /b 1
)
if "%~1"=="" (
    "%~dp0dist\best.exe" --help
) else (
    "%~dp0dist\best.exe" %*
)
exit /b %errorlevel%
