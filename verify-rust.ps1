[CmdletBinding()]
param(
    [string[]]$Projects = @('algos','be','best','cascade','e-tools','ezcrypt','filecrypt','multicrypt','otp','otp1','tf1024','threefish1024','versakey','x2','x5x'),
    [switch]$BuildRelease,
    [switch]$SkipSlow
)

$ErrorActionPreference = 'Stop'
$failed = @()
$previousRustdocFlags = $env:RUSTDOCFLAGS
try {
    foreach ($project in $Projects) {
        $projectPath = Join-Path $PSScriptRoot $project
        Push-Location -LiteralPath $projectPath
        try {
            Write-Host "Verifying $project with Rust 1.98.1"
            cargo +1.98.1 fmt --all -- --check
            if ($LASTEXITCODE -ne 0) { throw 'Formatting failed' }
            cargo +1.98.1 clippy --locked --workspace --all-targets --all-features -- -D warnings
            if ($LASTEXITCODE -ne 0) { throw 'Clippy failed' }
            $testArguments = @('+1.98.1','test','--locked','--workspace','--all-targets','--all-features','--no-fail-fast','--','--test-threads=2')
            if (-not $SkipSlow) { $testArguments += '--include-ignored' }
            & cargo @testArguments
            if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
            $env:RUSTDOCFLAGS = '-D warnings'
            cargo +1.98.1 doc --locked --workspace --no-deps
            if ($LASTEXITCODE -ne 0) { throw 'Documentation failed' }
            if ($BuildRelease) {
                cargo +1.98.1 build --locked --workspace --release --bins
                if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }
            }
        } catch {
            $failed += $project
            Write-Warning "$project`: $_"
        } finally {
            Pop-Location
        }
    }
} finally {
    $env:RUSTDOCFLAGS = $previousRustdocFlags
}
Write-Host 'Linux runtime tests require Linux: secure, OTP2/otp2, OTP2/otp2-auth, OTP2/versakey.'
Write-Host 'cascade file operations are Unix-only; Windows tests verify their explicit rejection.'
if ($failed.Count -gt 0) { throw "Verification failed: $($failed -join ', ')" }
Write-Host 'All selected projects passed.'
