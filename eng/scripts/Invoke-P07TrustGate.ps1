[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$sourceRoot = Join-Path $repoRoot 'src\Deep.Client.Shared'
$runtime = Get-Content -Raw -Encoding UTF8 (Join-Path $sourceRoot 'State\ClientRuntime.cs')
$flags = Get-Content -Raw -Encoding UTF8 (Join-Path $sourceRoot 'Features\ClientFeatureFlags.cs')
$production = Get-ChildItem -LiteralPath $sourceRoot -Recurse -Filter '*.cs' |
    ForEach-Object { Get-Content -Raw -Encoding UTF8 $_.FullName } |
    Out-String
$p07Production = @(
    (Join-Path $sourceRoot 'Domain\MembershipTrust.cs'),
    (Join-Path $sourceRoot 'Persistence\MembershipTrustRepository.cs'),
    (Join-Path $sourceRoot 'Services\MembershipTrustService.cs')
) | ForEach-Object { Get-Content -Raw -Encoding UTF8 $_ } | Out-String

if ($runtime -match 'MembershipTrust|IMembershipSignatureVerifier') {
    throw 'P07 trust gate: runtime registration is forbidden.'
}
if ($production -match 'FixtureMembershipVerifier|DeterministicMembershipVerifier|MembershipSigningDomains\.Frame') {
    throw 'P07 trust gate: production fixture verifier or signing helper detected.'
}
if ($flags -notmatch 'MembershipTrustEnabled = false' -or
    $flags -notmatch 'LegacyEmbeddedBootstrapRollbackAllowed = false') {
    throw 'P07 trust gate: dormant flags must remain false.'
}
if ($p07Production -match 'https?://|(?:\d{1,3}\.){3}\d{1,3}') {
    throw 'P07 trust gate: endpoint material is forbidden in P07 production source.'
}

$testProject = Join-Path $repoRoot 'tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj'
dotnet test $testProject --configuration Release --no-restore `
    --filter 'FullyQualifiedName~MembershipTrustPrivacyTests' --verbosity minimal
if ($LASTEXITCODE -ne 0) {
    throw 'P07 trust gate: privacy/source scan tests failed.'
}

Write-Output 'P07 trust gate PASS'
