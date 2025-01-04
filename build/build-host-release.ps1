#!pwsh
<#
    OpenSSL is already installed on windows-latest virtual environment.
    If you need OpenSSL, consider install it by:

    choco install openssl
#>
param(
    [Parameter(HelpMessage = "extra features")]
    [Alias('f')]
    [string]$Features
)

$ErrorActionPreference = "Stop"

$TargetTriple = (rustc -Vv | Select-String -Pattern "host: (.*)" | ForEach-Object { $_.Matches.Value }).split()[-1]

Write-Host "Started building release for ${TargetTriple} ..."

if ([string]::IsNullOrEmpty($Features)) {
    cargo build --release
}
else {
    cargo build --release --features "${Features}"
}

if (!$?) {
    exit $LASTEXITCODE
}

$Version = (Select-String -Pattern '^version *= *"([^"]*)"$' -Path "${PSScriptRoot}\..\Cargo.toml" | ForEach-Object { $_.Matches.Value }).split()[-1]
$Version = $Version -replace '"'

$PackageReleasePath = "${PSScriptRoot}\release"
$PackageName = "shadowsocks-v${Version}.${TargetTriple}.zip"
$PackagePath = "${PackageReleasePath}\${PackageName}"
$ReleaseBuildPath = "${PSScriptRoot}\..\target\release"

Write-Host $Version
Write-Host $PackageReleasePath
Write-Host $PackageName
Write-Host $PackagePath
Write-Host $ReleaseBuildPath

Push-Location $ReleaseBuildPath

$ProgressPreference = "SilentlyContinue"
New-Item "${PackageReleasePath}" -ItemType Directory -ErrorAction SilentlyContinue
$CompressParam = @{
    LiteralPath     = "sslocal.exe", "ssserver.exe", "ssurl.exe", "ssmanager.exe", "ssservice.exe"
    DestinationPath = "${PackagePath}"
}
if ([System.IO.File]::Exists("$ReleaseBuildPath\sswinservice.exe")) {
    $CompressParam.LiteralPath += "sswinservice.exe"
}
Compress-Archive @CompressParam

Write-Host "Created release packet ${PackagePath}"

$PackageChecksumPath = "${PackagePath}.sha256"
$PackageHash = (Get-FileHash -Path "${PackagePath}" -Algorithm SHA256).Hash
"${PackageHash}  ${PackageName}" | Out-File -FilePath "${PackageChecksumPath}"

Write-Host "Created release packet checksum ${PackageChecksumPath}"

Pop-Location
