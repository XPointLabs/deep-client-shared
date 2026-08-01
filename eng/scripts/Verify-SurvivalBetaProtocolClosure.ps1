[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$vendor = Join-Path $root "vendor\survival-beta-e570512"
$manifestPath = Join-Path $vendor "package-provenance.json"
$expectedVersion = "0.4.0-survival.e570512"
$expectedCommit = "e5705123836b32060ec4392e813d5b8c44635e2e"
$expectedIds = @(
    "Deep.Protocol",
    "Deep.Protocol.Abstractions",
    "Deep.Protocol.MembershipRoutes",
    "Deep.Protocol.ProfileCarrier",
    "Deep.Protocol.Protobuf"
)

function Assert-Equal([string]$Expected, [string]$Actual, [string]$Label) {
    if ($Expected -cne $Actual) { throw "Survival Beta protocol closure: $Label differs." }
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
Assert-Equal "deep-survival-beta-protocol-closure.v1" ([string]$manifest.schema) "manifest schema"
Assert-Equal $expectedVersion ([string]$manifest.version) "closure version"
Assert-Equal $expectedCommit ([string]$manifest.protocolSourceCommit) "protocol source commit"
Assert-Equal $expectedCommit ([string]$manifest.profileCarrierSourceCommit) "ProfileCarrier source commit"
if ($manifest.networkSourcesAllowedForDeepProtocol -ne $false) {
    throw "Survival Beta protocol closure: network protocol source must be disabled."
}
if ($manifest.packages.Count -ne $expectedIds.Count) {
    throw "Survival Beta protocol closure: package count differs."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
foreach ($id in $expectedIds) {
    $items = @($manifest.packages | Where-Object { $_.id -ceq $id })
    if ($items.Count -ne 1) { throw "Survival Beta protocol closure: package identity set differs." }
    $item = $items[0]
    Assert-Equal $expectedVersion ([string]$item.version) "$id manifest version"
    $path = Join-Path $vendor ([string]$item.file)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Survival Beta protocol closure: $id package is missing."
    }
    Assert-Equal ([string]$item.bytes) ([string](Get-Item -LiteralPath $path).Length) "$id byte length"
    Assert-Equal ([string]$item.sha256) ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()) "$id SHA-256"
    Assert-Equal ([string]$item.sha512) ((Get-FileHash -LiteralPath $path -Algorithm SHA512).Hash.ToLowerInvariant()) "$id SHA-512"

    $archive = [IO.Compression.ZipFile]::OpenRead($path)
    try {
        $entries = @($archive.Entries | Where-Object { $_.FullName -ceq "$id.nuspec" })
        if ($entries.Count -ne 1) { throw "Survival Beta protocol closure: $id nuspec identity differs." }
        $reader = [IO.StreamReader]::new($entries[0].Open())
        try { [xml]$nuspec = $reader.ReadToEnd() } finally { $reader.Dispose() }
        Assert-Equal $id ([string]$nuspec.package.metadata.id) "$id nuspec id"
        Assert-Equal $expectedVersion ([string]$nuspec.package.metadata.version) "$id nuspec version"
        Assert-Equal $expectedCommit ([string]$nuspec.package.metadata.repository.commit) "$id repository commit"
        if ($id -ceq "Deep.Protocol.ProfileCarrier") {
            $dependency = @($nuspec.package.metadata.dependencies.group.dependency |
                Where-Object { $_.id -ceq "Deep.Protocol" })
            if ($dependency.Count -ne 1) { throw "Survival Beta protocol closure: ProfileCarrier dependency differs." }
            Assert-Equal "[$expectedVersion]" ([string]$dependency[0].version) "ProfileCarrier core dependency"
        }
    }
    finally { $archive.Dispose() }
}

$activeFiles = @(
    Get-ChildItem -LiteralPath (Join-Path $root "src") -Recurse -File |
        Where-Object { $_.Name -like '*.csproj' -or $_.Name -ceq 'packages.lock.json' }
    Get-ChildItem -LiteralPath (Join-Path $root "tests") -Recurse -File |
        Where-Object { $_.Name -like '*.csproj' -or $_.Name -ceq 'packages.lock.json' }
    Get-Item -LiteralPath (Join-Path $root "NuGet.Config")
)
foreach ($file in $activeFiles) {
    if ($file.FullName -match '[\\/](bin|obj)[\\/]') { continue }
    $text = Get-Content -LiteralPath $file.FullName -Raw
    if ($text -match '0\.[23]\.0-p10[ij]|p10j-protocol-local-pinned') {
        throw "Survival Beta protocol closure: stale active protocol pin in $($file.FullName)."
    }
}
$config = Get-Content -LiteralPath (Join-Path $root "NuGet.Config") -Raw
if ($config -notmatch 'vendor\\survival-beta-e570512\\packages' -or
    $config -notmatch '<package pattern="Deep\.Protocol\*"') {
    throw "Survival Beta protocol closure: active NuGet source mapping differs."
}

Write-Output "Survival Beta protocol closure gate PASS"
