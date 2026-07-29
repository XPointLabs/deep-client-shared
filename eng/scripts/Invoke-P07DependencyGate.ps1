[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$vendorRoot = Join-Path $repositoryRoot "vendor\p10b3"
$manifestPath = Join-Path $vendorRoot "package-provenance.json"
$protocolVersion = "0.3.0-p10b3.60ce2e3"
$carrierVersion = "0.2.0-p10b3.60ce2e3"

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
    $path = Join-Path $vendorRoot $package.file
    Assert-Equal ([string]$package.bytes) `
        ([string](Get-Item -LiteralPath $path).Length) `
        "$($package.id) byte length"
    Assert-Equal ([string]$package.sha256) `
        (Get-Sha256 $path) `
        "$($package.id) SHA-256"
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
