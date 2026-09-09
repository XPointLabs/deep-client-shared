[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = Split-Path -Parent $repositoryRoot
$mauiRoot = Join-Path $workspaceRoot 'deep-client-maui'
$mauiProject = Join-Path $mauiRoot 'src\Deep.Client.Maui\Deep.Client.Maui.csproj'
$obsoleteFriendTarget = Join-Path $mauiRoot 'eng\DeepClientMaui.SharedFriend.targets'
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("deep-msg01-friend-" + [Guid]::NewGuid().ToString('N'))
$temporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
$systemTemporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())

if (-not $temporaryRoot.StartsWith($systemTemporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The hostile friend probe did not resolve beneath the system temporary directory.'
}

New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
try {
    if (-not (Test-Path -LiteralPath $mauiProject)) {
        throw 'The actual Deep.Client.Maui dependency graph is unavailable.'
    }
    if (Test-Path -LiteralPath $obsoleteFriendTarget) {
        throw 'The obsolete MAUI-to-Shared friend injection target still exists.'
    }
    $mauiProjectText = [IO.File]::ReadAllText($mauiProject)
    if ($mauiProjectText.Contains('CustomAfterMicrosoftCommonTargets') -or
        $mauiProjectText.Contains('DeepClientMaui.SharedFriend.targets')) {
        throw 'The MAUI ProjectReference still injects a friend-enabled Shared build.'
    }

    Push-Location $mauiRoot
    try {
        & dotnet msbuild $mauiProject `
            '-t:ResolveProjectReferences' `
            '-p:Configuration=Release' `
            '-p:TargetFramework=net10.0-windows10.0.19041.0' `
            '-p:BuildProjectReferences=true' `
            '-p:EnableDeepTestInternals=false' `
            '-p:UseSharedCompilation=false' `
            '-p:Restore=false' `
            '-v:minimal'
    }
    finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0) {
        throw 'The actual Release MAUI dependency graph failed before the hostile friend probe.'
    }

    $sharedAssemblyPath = Join-Path $repositoryRoot `
        'src\Deep.Client.Shared\bin\Release\net10.0\Deep.Client.Shared.dll'
    if (-not (Test-Path -LiteralPath $sharedAssemblyPath)) {
        throw 'The Shared assembly produced by the actual MAUI graph was not found.'
    }
    $sharedAssembly = Get-Item -LiteralPath $sharedAssemblyPath

    $probeProject = Join-Path $temporaryRoot 'FriendProbe.csproj'
    $probeSource = Join-Path $temporaryRoot 'FriendProbe.cs'
    @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <AssemblyName>Deep.Client.Maui</AssemblyName>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="Deep.Client.Shared" HintPath="$($sharedAssembly.FullName)" />
  </ItemGroup>
</Project>
"@ | Set-Content -LiteralPath $probeProject -Encoding utf8
    @'
using Deep.Client.Shared.Persistence.MessagingV1;

namespace HostileFriendProbe;

internal static class Forge
{
    internal static object InterfaceType() => typeof(IMsg01AuthenticatedEvidenceSource);
    internal static object AuthorityType() => typeof(Msg01VerifiedSessionAuthority);
}
'@ | Set-Content -LiteralPath $probeSource -Encoding utf8

    $probeOutput = (& dotnet build $probeProject -c Release '-p:UseSharedCompilation=false' 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0) {
        throw 'A release assembly named Deep.Client.Maui compiled direct access to the MSG-01 trust root.'
    }
    if ($probeOutput -notmatch 'CS0122' -or
        $probeOutput -notmatch 'IMsg01AuthenticatedEvidenceSource' -or
        $probeOutput -notmatch 'Msg01VerifiedSessionAuthority') {
        throw "The hostile friend probe failed for an unexpected reason.`n$probeOutput"
    }

    Write-Host 'MSG-01 release friend boundary: PASS (actual MAUI graph rejects direct authority/source access with CS0122).'
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
