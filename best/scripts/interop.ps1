param(
    [Parameter(Mandatory = $true)][string]$AgeExe,
    [string]$BestExe = (Join-Path $PSScriptRoot '..\target\release\best.exe')
)
$ErrorActionPreference = 'Stop'
$AgeExe = (Resolve-Path -LiteralPath $AgeExe).Path
$BestExe = (Resolve-Path -LiteralPath $BestExe).Path
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$runDir = Join-Path $tempRoot ('best-interop-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runDir | Out-Null
$checks = 0
try {
    $key = Join-Path $runDir 'test.identity'
    $public = & $BestExe --quiet keygen -o $key
    if ($LASTEXITCODE -ne 0) { throw 'best key generation failed' }
    foreach ($size in @(0, 1, 15, 16, 17, 65535, 65536, 65537, 131072, 1048576, 67108864)) {
        $caseDir = Join-Path $runDir ([string]$size)
        New-Item -ItemType Directory -Path $caseDir | Out-Null
        $inputPath = Join-Path $caseDir 'sample binary input.bin'
        $stream = [IO.File]::Open($inputPath, [IO.FileMode]::CreateNew)
        try {
            $buffer = New-Object byte[] 65536
            $random = New-Object Random 12345
            $remaining = $size
            while ($remaining -gt 0) {
                $random.NextBytes($buffer)
                $count = [Math]::Min($remaining, $buffer.Length)
                $stream.Write($buffer, 0, $count)
                $remaining -= $count
            }
        } finally { $stream.Dispose() }
        $expected = (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash
        $bestCipher = Join-Path $caseDir 'best.age'
        $ageCipher = Join-Path $caseDir 'reference.age'
        $bestPlain = Join-Path $caseDir 'best-restored.bin'
        $agePlain = Join-Path $caseDir 'reference-restored.bin'
        & $BestExe --quiet encrypt $inputPath -r $public -o $bestCipher
        if ($LASTEXITCODE -ne 0) { throw "best encryption failed: $size" }
        & $AgeExe -d -i $key -o $agePlain $bestCipher
        if ($LASTEXITCODE -ne 0) { throw "reference decryption failed: $size" }
        & $AgeExe -r $public -o $ageCipher $inputPath
        if ($LASTEXITCODE -ne 0) { throw "reference encryption failed: $size" }
        & $BestExe --quiet decrypt $ageCipher -i $key -o $bestPlain
        if ($LASTEXITCODE -ne 0) { throw "best decryption failed: $size" }
        & $BestExe --quiet verify $ageCipher -i $key
        if ($LASTEXITCODE -ne 0) { throw "best verification failed: $size" }
        foreach ($plain in @($bestPlain, $agePlain)) {
            if ((Get-FileHash -LiteralPath $plain -Algorithm SHA256).Hash -ne $expected) { throw "plaintext mismatch: $size" }
            $checks++
        }
    }
    $secondKey = Join-Path $runDir 'second.identity'
    $secondPublic = & $BestExe --quiet keygen -o $secondKey
    if ($LASTEXITCODE -ne 0) { throw 'second key generation failed' }
    $multi = Join-Path $runDir 'multi.age'
    & $BestExe --quiet encrypt $inputPath -r $public -r $secondPublic -o $multi
    if ($LASTEXITCODE -ne 0) { throw 'multi-recipient encryption failed' }
    foreach ($identity in @($key, $secondKey)) {
        $restored = Join-Path $runDir ([Guid]::NewGuid().ToString('N') + '.bin')
        & $AgeExe -d -i $identity -o $restored $multi
        if ($LASTEXITCODE -ne 0) { throw 'reference multi-recipient decryption failed' }
        if ((Get-FileHash -LiteralPath $restored -Algorithm SHA256).Hash -ne $expected) { throw 'multi-recipient mismatch' }
        $checks++
    }
    Write-Output "PASS: $checks independent plaintext hash comparisons; 11 sizes through 64 MiB, both encryption directions, verification and multiple recipients."
    & $AgeExe --version
    & $BestExe --version
} finally {
    $resolvedRun = [IO.Path]::GetFullPath($runDir)
    $prefix = $tempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedRun.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFileName($resolvedRun)).StartsWith('best-interop-')) {
        throw 'Refusing cleanup outside the verified test directory'
    }
    if (Test-Path -LiteralPath $resolvedRun) { Remove-Item -LiteralPath $resolvedRun -Recurse -Force }
}
