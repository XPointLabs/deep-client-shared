[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$vendorRoot = Join-Path $repositoryRoot "vendor\p10i"
$manifestPath = Join-Path $vendorRoot "package-provenance.json"
$protocolVersion = "0.3.0-p10i.a9b7a10"
$carrierVersion = "0.2.0-p10i.a9b7a10"
$expectedPackages = @{
    "Deep.Protocol" = @{
        Version = $protocolVersion
        Bytes = 153855
        Sha256 = "925106e6098fe03a9fc247c5be519a13783318bb349b3b8f3cebaa299b8d0a78"
        Source = "a9b7a10a555758d4b2e30707a70d271f010b6c30"
    }
    "Deep.Protocol.Abstractions" = @{
        Version = $protocolVersion
        Bytes = 25666
        Sha256 = "0daa36393ff1e048186ae90883d7e5aaef18bab345e7c1219fa770a1e17776a6"
        Source = "a9b7a10a555758d4b2e30707a70d271f010b6c30"
    }
    "Deep.Protocol.MembershipRoutes" = @{
        Version = $protocolVersion
        Bytes = 13280
        Sha256 = "cb7cf4b4319349fb8eea81ea700b411f6b3d81ba580aef6a44c4dd141f6dee7e"
        Source = "a9b7a10a555758d4b2e30707a70d271f010b6c30"
    }
    "Deep.Protocol.ProfileCarrier" = @{
        Version = $carrierVersion
        Bytes = 28904
        Sha256 = "ccae562846602d99115e2de75ddf5b9e3290d17461a8eaa6a9ac0860b231da31"
        Source = "a9b7a10a555758d4b2e30707a70d271f010b6c30"
    }
    "Deep.Protocol.Protobuf" = @{
        Version = $protocolVersion
        Bytes = 51186
        Sha256 = "5583ede034a85cf514840c8db325a4cffb7cdb0ab840af8c6df7d34fb0c1bade"
        Source = "a9b7a10a555758d4b2e30707a70d271f010b6c30"
    }
}

function Assert-Equal {
    param([string]$Expected, [string]$Actual, [string]$Label)
    if ($Expected -ne $Actual) {
        throw "P10I dependency gate: $Label differs."
    }
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
Assert-Equal "deep-client-p10i-offline-package-set.v1" `
    ([string]$manifest.schema) "manifest schema"
Assert-Equal "a9b7a10a555758d4b2e30707a70d271f010b6c30" `
    ([string]$manifest.protocolSourceCommit) "protocol source"
Assert-Equal "a9b7a10a555758d4b2e30707a70d271f010b6c30" `
    ([string]$manifest.profileCarrierSourceCommit) "carrier source"
if ($manifest.packages.Count -ne 5) {
    throw "P10I dependency gate: the exact package count differs."
}
foreach ($package in $manifest.packages) {
    if (-not $expectedPackages.ContainsKey([string]$package.id)) {
        throw "P10I dependency gate: an unexpected package id is present."
    }
    $expected = $expectedPackages[[string]$package.id]
    $path = Join-Path $vendorRoot $package.file
    Assert-Equal ([string]$expected.Version) `
        ([string]$package.version) `
        "$($package.id) manifest version"
    Assert-Equal ([string]$expected.Bytes) `
        ([string]$package.bytes) `
        "$($package.id) manifest byte length"
    Assert-Equal ([string]$expected.Sha256) `
        ([string]$package.sha256) `
        "$($package.id) manifest SHA-256"
    Assert-Equal ([string]$expected.Bytes) `
        ([string](Get-Item -LiteralPath $path).Length) `
        "$($package.id) byte length"
    Assert-Equal ([string]$expected.Sha256) `
        (Get-Sha256 $path) `
        "$($package.id) SHA-256"

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($path)
    try {
        $nuspec = @($archive.Entries | Where-Object {
            $_.FullName -eq "$($package.id).nuspec"
        })
        if ($nuspec.Count -ne 1) {
            throw "P10I dependency gate: $($package.id) nuspec identity differs."
        }
        $reader = [IO.StreamReader]::new($nuspec[0].Open())
        try {
            [xml]$xml = $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
        $metadata = $xml.package.metadata
        Assert-Equal ([string]$package.id) ([string]$metadata.id) `
            "$($package.id) nuspec id"
        Assert-Equal ([string]$expected.Version) ([string]$metadata.version) `
            "$($package.id) nuspec version"
        Assert-Equal ([string]$expected.Source) `
            ([string]$metadata.repository.commit) `
            "$($package.id) nuspec repository commit"
    }
    finally {
        $archive.Dispose()
    }
}
if ($expectedPackages.Count -ne $manifest.packages.Count) {
    throw "P10I dependency gate: package identity set differs."
}

$project = Get-Content -LiteralPath (Join-Path $repositoryRoot `
    "src\Deep.Client.Shared\Deep.Client.Shared.csproj") -Raw
foreach ($expected in @(
    "Deep.Protocol`" Version=`"[$protocolVersion]",
    "Deep.Protocol.MembershipRoutes`" Version=`"[$protocolVersion]",
    "Deep.Protocol.ProfileCarrier`" Version=`"[$carrierVersion]"
)) {
    if ($project.IndexOf($expected, [StringComparison]::Ordinal) -lt 0) {
        throw "P10I dependency gate: an exact project package pin is missing."
    }
}
if ($project.IndexOf("ProjectReference", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "P10I dependency gate: project-reference substitution is forbidden."
}

foreach ($relative in @(
    "src\Deep.Client.Shared\packages.lock.json",
    "tests\Deep.Client.Shared.Tests\packages.lock.json"
)) {
    $lock = Get-Content -LiteralPath (Join-Path $repositoryRoot $relative) -Raw |
        ConvertFrom-Json
    $target = $lock.dependencies.'net10.0'
    Assert-Equal $protocolVersion ([string]$target.'Deep.Protocol'.resolved) `
        "$relative Deep.Protocol"
    Assert-Equal $protocolVersion `
        ([string]$target.'Deep.Protocol.MembershipRoutes'.resolved) `
        "$relative MembershipRoutes"
    Assert-Equal $carrierVersion `
        ([string]$target.'Deep.Protocol.ProfileCarrier'.resolved) `
        "$relative ProfileCarrier"
}

$config = Get-Content -LiteralPath (Join-Path $repositoryRoot "NuGet.Config") -Raw
if ($config.IndexOf("<clear", [StringComparison]::Ordinal) -lt 0 -or
    $config.IndexOf("vendor\p10i\packages", [StringComparison]::Ordinal) -lt 0 -or
    $config.IndexOf("http://", [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
    $config.IndexOf("https://", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "P10I dependency gate: NuGet sources are not exact and local-only."
}

Write-Output "P10I dependency gate PASS"
