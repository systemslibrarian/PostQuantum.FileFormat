<#
.SYNOPSIS
    End-to-end roundtrip smoke test for the in-tree pqf CLI (Windows).

.DESCRIPTION
    PowerShell parallel to scripts/smoke.sh. Generates two keypairs,
    encrypts a sample plaintext, inspects the container, decrypts in
    Authenticated Mode, verifies byte-identity, and exercises a refusal
    path (truncated container must be rejected).

.NOTES
    Exit codes:
      0  success
      1  unexpected failure
#>

$ErrorActionPreference = 'Stop'

$RepoRoot   = Resolve-Path (Join-Path $PSScriptRoot "..")
$CliProject = Join-Path $RepoRoot "cli/PostQuantum.FileFormat.Cli/PostQuantum.FileFormat.Cli.csproj"
$Config     = if ($env:PQF_SMOKE_CONFIG) { $env:PQF_SMOKE_CONFIG } else { "Release" }
$WorkDir    = Join-Path ([System.IO.Path]::GetTempPath()) ("pqf-smoke-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))

New-Item -ItemType Directory -Path $WorkDir | Out-Null

try {
    function Invoke-Pqf {
        param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $Args)
        & dotnet run --project $CliProject -c $Config --no-restore --no-build -- @Args
        if ($LASTEXITCODE -ne 0) { throw "pqf exited with $LASTEXITCODE" }
    }

    Write-Host "==> Smoke test working directory: $WorkDir"
    Write-Host "==> Building CLI in $Config configuration"
    & dotnet build $CliProject -c $Config --nologo -v minimal
    if ($LASTEXITCODE -ne 0) { throw "build failed" }

    Push-Location $WorkDir
    # PowerShell's Push-Location does not update .NET's Environment.CurrentDirectory,
    # so [System.IO.File]::* APIs below would otherwise write to the wrong directory.
    [System.Environment]::CurrentDirectory = (Get-Location).Path

    Write-Host "==> 1/7 Generate encryption keypair"
    Invoke-Pqf keygen --type encrypt --public-out alice.pub.pem --private-out alice.key.json

    Write-Host "==> 2/7 Generate signing keypair"
    Invoke-Pqf keygen --type sign    --public-out signer.pub.pem --private-out signer.key.json

    Write-Host "==> 3/7 Create sample plaintext"
    $bytes = New-Object byte[] 200000
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [System.IO.File]::WriteAllBytes("sample.bin", $bytes)
    $shaIn = (Get-FileHash sample.bin -Algorithm SHA256).Hash
    Write-Host "    sample.bin sha256=$shaIn"

    Write-Host "==> 4/7 Encrypt and sign"
    Invoke-Pqf encrypt --in sample.bin --out sample.pqf --recipient alice.pub.pem --signing-key signer.key.json

    Write-Host "==> 5/7 Inspect container (no plaintext released)"
    Invoke-Pqf inspect --in sample.pqf | Tee-Object -FilePath inspect.txt | Select-Object -First 20

    Write-Host "==> 6/7 Decrypt in Authenticated Mode"
    Invoke-Pqf decrypt --in sample.pqf --out sample.out.bin --identity alice.key.json --mode authenticated
    $shaOut = (Get-FileHash sample.out.bin -Algorithm SHA256).Hash
    Write-Host "    sample.out.bin sha256=$shaOut"
    if ($shaIn -ne $shaOut) { throw "roundtrip hash mismatch ($shaIn != $shaOut)" }
    Write-Host "    OK: roundtrip hash matches"

    Write-Host "==> 7/7 Refusal path: truncated container must be rejected"
    $full     = [System.IO.File]::ReadAllBytes("sample.pqf")
    $truncLen = $full.Length - 32
    [System.IO.File]::WriteAllBytes("sample.truncated.pqf", $full[0..($truncLen - 1)])

    $rc = 0
    try {
        & dotnet run --project $CliProject -c $Config --no-restore --no-build -- `
            decrypt --in sample.truncated.pqf --out should-not-exist.bin `
            --identity alice.key.json --mode authenticated `
            *> truncated.log
        $rc = $LASTEXITCODE
    } catch {
        $rc = if ($LASTEXITCODE -ne 0) { $LASTEXITCODE } else { 1 }
    }

    if ($rc -eq 0) {
        Get-Content truncated.log -ErrorAction SilentlyContinue
        throw "truncated container was accepted (exit code 0)"
    }
    if ((Test-Path should-not-exist.bin) -and (Get-Item should-not-exist.bin).Length -gt 0) {
        throw "truncated container produced non-empty plaintext output"
    }
    Write-Host "    OK: truncated container refused with exit code $rc"

    Write-Host ""
    Write-Host "PQF smoke test PASSED."
    exit 0
}
finally {
    Pop-Location -ErrorAction SilentlyContinue
    [System.Environment]::CurrentDirectory = (Get-Location).Path
    Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
}
