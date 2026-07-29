[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$vendorRoot = Join-Path $repositoryRoot "vendor\p10b3"
$manifestPath = Join-Path $vendorRoot "package-provenance.json"
$protocolVersion = "0.3.0-p10b3.60ce2e3"
$carrierVersion = "0.2.0-p10b3.60ce2e3"
$expectedPackages = @{
    "Deep.Protocol" = @{
        Version = $protocolVersion
        Bytes = 149753
        Sha256 = "588a889f362a618bd06b8277fd4afc8b6c64ec37797f4cdf291af1865f0fd779"
        Source = "60ce2e3a5140f245d6bcfecf60fa456c26ffe730"
    }
    "Deep.Protocol.Abstractions" = @{
        Version = $protocolVersion
        Bytes = 24952
        Sha256 = "af23f03aade18ee726d5a6345e2a613c91fbea0bf62d3d0431dd629062e603bd"
        Source = "60ce2e3a5140f245d6bcfecf60fa456c26ffe730"
    }
    "Deep.Protocol.MembershipRoutes" = @{
        Version = $protocolVersion
        Bytes = 12871
        Sha256 = "16f4a0dd0c33461d85ed15bf69268e4b78b70617c059aa60d3b662d922155b96"
        Source = "60ce2e3a5140f245d6bcfecf60fa456c26ffe730"
    }
    "Deep.Protocol.ProfileCarrier" = @{
        Version = $carrierVersion
        Bytes = 28902
        Sha256 = "e2d03040daaf7c7fe29952db3cfbc3227fb9f0da42740b5f57f65a02ae8118a2"
        Source = "dfb182d65d3e8d3ee44a2246ae94c68159bc692d"
    }
    "Deep.Protocol.Protobuf" = @{
        Version = $protocolVersion
        Bytes = 50213
        Sha256 = "ec5478d4ebc03fba3a97a4e0675b0fbdac4bd43c4503ed39033e1b6e469f1250"
        Source = "60ce2e3a5140f245d6bcfecf60fa456c26ffe730"
    }
}

function Assert-Equal {
    param([string]$Expected, [string]$Actual, [string]$Label)
    if ($Expected -ne $Actual) {
        throw "P10B3 dependency gate: $Label differs."
    }
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
Assert-Equal "deep-client-p10b3-offline-package-set.v1" `
    ([string]$manifest.schema) "manifest schema"
Assert-Equal "60ce2e3a5140f245d6bcfecf60fa456c26ffe730" `
    ([string]$manifest.protocolSourceCommit) "protocol source"
Assert-Equal "dfb182d65d3e8d3ee44a2246ae94c68159bc692d" `
    ([string]$manifest.profileCarrierSourceCommit) "carrier source"
if ($manifest.packages.Count -ne 5) {
    throw "P10B3 dependency gate: the exact package count differs."
}
foreach ($package in $manifest.packages) {
    if (-not $expectedPackages.ContainsKey([string]$package.id)) {
        throw "P10B3 dependency gate: an unexpected package id is present."
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
            throw "P10B3 dependency gate: $($package.id) nuspec identity differs."
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
    throw "P10B3 dependency gate: package identity set differs."
}

$project = Get-Content -LiteralPath (Join-Path $repositoryRoot `
    "src\Deep.Client.Shared\Deep.Client.Shared.csproj") -Raw
foreach ($expected in @(
    "Deep.Protocol`" Version=`"[$protocolVersion]",
    "Deep.Protocol.MembershipRoutes`" Version=`"[$protocolVersion]",
    "Deep.Protocol.ProfileCarrier`" Version=`"[$carrierVersion]"
)) {
    if ($project.IndexOf($expected, [StringComparison]::Ordinal) -lt 0) {
        throw "P10B3 dependency gate: an exact project package pin is missing."
    }
}
if ($project.IndexOf("ProjectReference", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "P10B3 dependency gate: project-reference substitution is forbidden."
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
    $config.IndexOf("vendor\p10b3\packages", [StringComparison]::Ordinal) -lt 0 -or
    $config.IndexOf("http://", [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
    $config.IndexOf("https://", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "P10B3 dependency gate: NuGet sources are not exact and local-only."
}

Write-Output "P10B3 dependency gate PASS"
