$ErrorActionPreference = 'Stop'

$expected = @(
    'AES-256-GCM', 'ChaCha20-Poly1305', 'Ascon-AEAD128', 'AEGIS-256',
    'XSalsa20-Poly1305', 'Deoxys-II-256', 'ISAP-Keccak-128A', 'MORUS-1280-128',
    'Gimli-AEAD', 'Xoodyak', 'Forro14-Poly1305', 'KCipher-2', 'SNOW-V-GCM',
    'Strumok', 'Enocoro-128v2', 'HC-128', 'Turing', 'NORX64-4-1',
    'Grain-128AEADv2', 'Romulus-M', 'Saturnin-CTR-Cascade', 'MKV128-256-GCM',
    'BLAKE3-AEAD', 'Kalyna-256/256-GCM', 'ZUC-128', 'SIMON128-256', 'SPECK128-256',
    'CAST6-256', 'RC6-256', 'IDEA-128', 'SEED-128', 'PRESENT-128', 'Magma',
    'Trivium', 'ARIA-256', 'Camellia-256', 'Serpent-256', 'Twofish-256',
    'Kuznyechik', 'SM4', 'Blowfish', 'BELT-DWP', 'GIFT-128', 'Threefish-256',
    'LEA-256', 'Spritz', 'Rabbit', 'TEA-32', 'Skipjack', 'RC4-drop3072'
)

# Labels alone are insufficient: require the concrete backend symbol too.
$implementationEvidence = @(
    'aes_gcm::Aes256Gcm', 'chacha20poly1305::ChaCha20Poly1305',
    'ascon_aead::AsconAead128', 'Aegis256', 'crypto_secretbox::seal',
    'deoxys::DeoxysII256', 'isap_aead::IsapKeccak128A', 'morus::Morus',
    'gimli_aead::GimliAead', 'XoodyakKeyed::new', 'forro::Forro14Poly1305',
    'kcipher2::KCipher2', 'snowv_gcm::SnowVGcm', 'dstu8845::Dstu8845_256',
    'enocoro128v2::Enocoro128', 'hc128::HC128', 'turing_cipher::Turing',
    'norx::Norx', 'Grain128', 'lib_q_romulus::RomulusM',
    'lib_q_saturnin::SaturninAead', 'Mkv128256Gcm', 'blake3_aead::encrypt',
    'Kalyna256_256Gcm', 'Zuc128Ct', 'Simon128_256', 'Speck128_256',
    'cast6::Cast6', 'rc6::RC6', 'idea::Idea', 'SeedCt', 'Present128Ct',
    'MagmaCt', 'trivium::Trivium', 'aria::Aria256', 'camellia::Camellia256',
    'serpent::Serpent', 'twofish::Twofish', 'kuznyechik::Kuznyechik',
    'sm4::Sm4', 'blowfish::Blowfish', 'belt_dwp::Dwp', 'gift_cipher::Gift128',
    'threefish::Threefish256', 'lea::Lea256', 'spritz_cipher::SpritzCipherContext',
    'rabbit::Rabbit', 'tea_soft::Tea32', 'skipjack::skipjack::encrypt_block',
    'rc4::Rc4'
)

if ($expected.Count -ne 50 -or ($expected | Sort-Object -Unique).Count -ne 50) {
    throw 'The expected primitive map itself is not 50 entries and globally unique.'
}
if ($implementationEvidence.Count -ne 50) {
    throw 'The implementation-evidence map must contain exactly 50 entries.'
}

$seen = [System.Collections.Generic.List[string]]::new()
$hashes = [System.Collections.Generic.List[string]]::new()
for ($id = 1; $id -le 50; $id++) {
    $directory = Join-Path $PSScriptRoot "x$id"
    $readmePath = Join-Path $directory 'README.md'
    $sourcePath = Join-Path $directory 'src/main.rs'
    $manifestPath = Join-Path $directory 'Cargo.toml'
    foreach ($path in @($readmePath, $sourcePath, $manifestPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "x$id is missing $path"
        }
    }

    $manifest = (Get-Content -LiteralPath $manifestPath -Raw) -replace [char]13, ''
    if ($manifest -notmatch "(?m)^name = `"x$id`"$") {
        throw "x$id has the wrong Cargo package name"
    }

    $readme = Get-Content -LiteralPath $readmePath -Raw
    $matches = [regex]::Matches($readme, '(?m)^- Payload algorithm: (.+)$')
    if ($matches.Count -ne 1) {
        throw "x$id must have exactly one '- Payload algorithm:' README line"
    }
    $algorithm = $matches[0].Groups[1].Value.Trim()
    if ($algorithm -ne $expected[$id - 1]) {
        throw "x$id says '$algorithm'; expected '$($expected[$id - 1])'"
    }

    $source = (Get-Content -LiteralPath $sourcePath -Raw) -replace [char]13, ''
    if (-not $source.Contains($algorithm)) {
        throw "x$id source does not name its assigned primitive '$algorithm'"
    }
    if ($source -notmatch "(?m)^const APP_ID: u8 = $id;$") {
        throw "x$id source has the wrong APP_ID"
    }
    $backend = $implementationEvidence[$id - 1]
    if ($source -notmatch [regex]::Escape($backend)) {
        throw ('x{0} is missing backend evidence: {1}' -f $id, $backend)
    }
    $seen.Add($algorithm)
    $hashes.Add((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash)
}

if (($seen | Sort-Object -Unique).Count -ne 50) {
    throw 'Two or more apps declare the same payload algorithm.'
}
if (($hashes | Sort-Object -Unique).Count -ne 50) {
    throw 'Two or more apps still have byte-identical src/main.rs implementations.'
}

Write-Output 'Verified: 50 packages, 50 named payload algorithms, 50 distinct implementations.'
