[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$protocolRoot = (Resolve-Path (Join-Path $repoRoot '..\..\wave01b\deep-protocol')).Path
$packageRoot = Join-Path $protocolRoot 'artifacts\survival\P04'
$expectedVersion = '0.3.0-p04.b887fa0'
$expectedSourceCommit = 'b887fa088f486390be182cac4cbcb59b60ce8931'

$pins = @(
    @{
        Path = Join-Path $packageRoot 'package-manifest.json'
        Bytes = 868
        Sha256 = 'fd3ef27bf0b9272570d6c6e680a3c99e581f6220799d13ee3afbd86ea0e99298'
    },
    @{
        Path = Join-Path $packageRoot "packages\Deep.Protocol.$expectedVersion.nupkg"
        Bytes = 91148
        Sha256 = '8ef4e70ad0b6c1cc0087f25c0313d6ab6a5387d16246679e4c10a3c00898a442'
    },
    @{
        Path = Join-Path $packageRoot "packages\Deep.Protocol.Abstractions.$expectedVersion.nupkg"
        Bytes = 25670
        Sha256 = 'fc1212a6765f5778188fcb3866ef923023c2253c3ead299a542271f4cc4f844f'
    },
    @{
        Path = Join-Path $packageRoot "packages\Deep.Protocol.Protobuf.$expectedVersion.nupkg"
        Bytes = 51180
        Sha256 = '755a027c58be670151456cc0bca4764731f7c493932d9eedd00c02e704baf818'
    },
    @{
        Path = Join-Path $protocolRoot 'tests\Deep.Protocol.GoldenVectors\Vectors\membership-contract-v1.json'
        Bytes = 8830
        Sha256 = '758707e4705c0499f546ce1e1e5201df253ef70822225c5fd3086c43d8d9bf45'
    }
)

function Assert-ExactFile {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][long] $Bytes,
        [Parameter(Mandatory)][string] $Sha256
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "P07 dependency gate: a pinned local artifact is missing."
    }

    $item = Get-Item -LiteralPath $Path
    $actualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($item.Length -ne $Bytes -or $actualHash -ne $Sha256) {
        throw "P07 dependency gate: pinned local artifact identity mismatch."
    }
}

function Assert-ConsumerText {
    param([Parameter(Mandatory)][string] $Text)

    if ($Text -notmatch '<PackageReference\s+Include="Deep\.Protocol"\s+Version="\[0\.3\.0-p04\.b887fa0\]"\s*/>') {
        throw 'P07 dependency gate: exact Deep.Protocol PackageReference is required.'
    }
    if ($Text -match 'ProjectReference[^>]+deep-protocol') {
        throw 'P07 dependency gate: deep-protocol ProjectReference substitution is forbidden.'
    }
}

function Assert-LockText {
    param([Parameter(Mandatory)][string] $Text)

    $lock = $Text | ConvertFrom-Json
    $matched = $false
    foreach ($target in $lock.dependencies.PSObject.Properties) {
        $property = $target.Value.PSObject.Properties['Deep.Protocol']
        $dependency = if ($null -eq $property) { $null } else { $property.Value }
        if ($null -ne $dependency -and
            $dependency.resolved -eq $expectedVersion -and
            ($dependency.type -ne 'Direct' -or
             $dependency.requested -eq "[$expectedVersion, $expectedVersion]")) {
            $matched = $true
        }
    }
    if (-not $matched) {
        throw 'P07 dependency gate: lock file does not pin the exact Deep.Protocol version.'
    }
}

foreach ($pin in $pins) {
    Assert-ExactFile @pin
}

$manifest = Get-Content -Raw -Encoding UTF8 (Join-Path $packageRoot 'package-manifest.json') | ConvertFrom-Json
if ($manifest.packageVersion -ne $expectedVersion -or
    $manifest.sourceCommit -ne $expectedSourceCommit -or
    $manifest.publication -ne 'local-only-not-published') {
    throw 'P07 dependency gate: package manifest metadata mismatch.'
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$protocolNupkg = Join-Path $packageRoot "packages\Deep.Protocol.$expectedVersion.nupkg"
$archive = [IO.Compression.ZipFile]::OpenRead($protocolNupkg)
try {
    $entry = $archive.Entries | Where-Object FullName -eq 'Deep.Protocol.nuspec'
    if ($null -eq $entry) {
        throw 'P07 dependency gate: package nuspec is missing.'
    }
    $reader = [IO.StreamReader]::new($entry.Open(), [Text.Encoding]::UTF8, $true)
    try {
        [xml]$nuspec = $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }
    $repository = $nuspec.package.metadata.repository
    if ($repository.type -ne 'git' -or $repository.commit -ne $expectedSourceCommit) {
        throw 'P07 dependency gate: nupkg repository source commit mismatch.'
    }
}
finally {
    $archive.Dispose()
}

function Get-GitBlobBytes {
    param(
        [Parameter(Mandatory)][string] $Repository,
        [Parameter(Mandatory)][string] $Object
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'git'
    $start.Arguments = "-C `"$Repository`" show `"$Object`""
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $memory = [IO.MemoryStream]::new()
    $process.StandardOutput.BaseStream.CopyTo($memory)
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw 'P07 dependency gate: pinned Git artifact is unavailable.'
    }
    return $memory.ToArray()
}

function Assert-BytesHash {
    param([byte[]] $Bytes, [string] $Expected)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $actual = -join ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $sha.Dispose()
    }
    if ($actual -ne $Expected) {
        throw 'P07 dependency gate: pinned Git artifact hash mismatch.'
    }
}

$devops = (Resolve-Path (Join-Path $repoRoot '..\..\wave01b\deep-devops-w1w2-manifest')).Path
$accepted = '1c01e24e24647a46b4f37622f3934dc2cc1284ef'
$corrective = '1fc3fcd376f9ffc9d4bca68f0143bf12b761e7dc'
$carrier = '524c5796aa868fa3d057fbf7eaa13cfea2e0d19c'
if ((git -C $devops rev-parse HEAD).Trim() -ne $accepted -or
    -not [string]::IsNullOrWhiteSpace((git -C $devops status --porcelain))) {
    throw 'P07 dependency gate: accepted DevOps prerequisite must be clean at its exact commit.'
}
git -C $devops merge-base --is-ancestor $corrective $accepted
if ($LASTEXITCODE -ne 0) {
    throw 'P07 dependency gate: accepted prerequisite ancestry mismatch.'
}
$manifestBytes = Get-GitBlobBytes $devops "$accepted`:release/manifests/survival-v2.1.0-w1w2-gate.detached.local.json"
$contractBytes = Get-GitBlobBytes $devops "$carrier`:release/contracts/survival-compatibility-v2.1.0-w1w2-gate.json"
$closureBytes = Get-GitBlobBytes $devops "$accepted`:release/evidence/w1w2-dependency-closure.json"
Assert-BytesHash $manifestBytes '920b24bb5bcfcc8b4f91aef56ed210127246ec9fd2d49178ed9856c8555d0b93'
Assert-BytesHash $contractBytes 'c45f66f7a688cbd70b7ca57a777851962ce2ab59eb37a3304d9b4bf7e4c55719'
Assert-BytesHash $closureBytes 'b2f813061e7986d1e383c2df5b5ce345367c4cca06a03cf8122221c5cfa5c51b'
$closure = [Text.Encoding]::UTF8.GetString($closureBytes) | ConvertFrom-Json
if ($closure.status -ne 'W1-CONTRACT-CLOSED-W2-BLOCKED' -or
    $closure.contract.carrierCommit -ne $carrier -or
    $closure.contract.runtimeBaseCommit -ne '1eb9a2a40ce01ce0f8c924e9dafaf3752b197d31' -or
    $closure.P04.sourceCommit -ne $expectedSourceCommit -or
    $closure.P04.runtimeAuthorized -ne $false) {
    throw 'P07 dependency gate: accepted closure semantics mismatch.'
}

$nugetConfig = Get-Content -Raw -Encoding UTF8 (Join-Path $repoRoot 'NuGet.Config')
if ($nugetConfig -notmatch '<clear\s*/>' -or
    $nugetConfig -notmatch 'p04-local-pinned' -or
    $nugetConfig -match 'nuget\.org|https?://') {
    throw 'P07 dependency gate: NuGet sources must be local-only and cleared.'
}

$projectPath = Join-Path $repoRoot 'src\Deep.Client.Shared\Deep.Client.Shared.csproj'
$projectText = Get-Content -Raw -Encoding UTF8 $projectPath
Assert-ConsumerText $projectText

$lockPaths = @(
    (Join-Path $repoRoot 'src\Deep.Client.Shared\packages.lock.json'),
    (Join-Path $repoRoot 'tests\Deep.Client.Shared.Tests\packages.lock.json')
)
foreach ($lockPath in $lockPaths) {
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'P07 dependency gate: a required package lock file is missing.'
    }
    Assert-LockText (Get-Content -Raw -Encoding UTF8 $lockPath)
}

$assetsPath = Join-Path $repoRoot 'src\Deep.Client.Shared\obj\project.assets.json'
if (Test-Path -LiteralPath $assetsPath -PathType Leaf) {
    $assets = Get-Content -Raw -Encoding UTF8 $assetsPath | ConvertFrom-Json
    if (-not $assets.libraries.PSObject.Properties["Deep.Protocol/$expectedVersion"]) {
        throw 'P07 dependency gate: resolved assets do not contain the exact Deep.Protocol version.'
    }

    $globalPackages = if ([string]::IsNullOrWhiteSpace($env:NUGET_PACKAGES)) {
        Join-Path ([Environment]::GetFolderPath('UserProfile')) '.nuget\packages'
    }
    else {
        $env:NUGET_PACKAGES
    }
    $packageFolder = Join-Path $globalPackages "deep.protocol\$expectedVersion"
    $cachedNupkg = Join-Path $packageFolder "deep.protocol.$expectedVersion.nupkg"
    Assert-ExactFile $cachedNupkg 91148 '8ef4e70ad0b6c1cc0087f25c0313d6ab6a5387d16246679e4c10a3c00898a442'
}

# In-memory negative controls prove the gate rejects the required substitution classes.
$negativeControls = @(
    { Assert-ConsumerText ($projectText -replace [regex]::Escape($expectedVersion), '0.3.0-p04.stale') },
    { Assert-ConsumerText ($projectText -replace [regex]::Escape("[$expectedVersion]"), $expectedVersion) },
    { Assert-ConsumerText ($projectText -replace '<PackageReference Include="Deep.Protocol"[^>]+/>', '<ProjectReference Include="..\..\deep-protocol\src\Deep.Protocol.csproj" />') },
    { Assert-LockText '{"version":1,"dependencies":{"net10.0":{"Deep.Protocol":{"type":"Direct","requested":"[0.3.0-p04.stale, )","resolved":"0.3.0-p04.stale"}}}}' }
)
foreach ($negativeControl in $negativeControls) {
    $rejected = $false
    try {
        & $negativeControl
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw 'P07 dependency gate: a synthetic negative control was not rejected.'
    }
}

Write-Output 'P07 dependency gate PASS'
