[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$sharedProject = Join-Path $repositoryRoot 'src\Deep.Client.Shared\Deep.Client.Shared.csproj'
$testProject = Join-Path $repositoryRoot 'tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj'
$filter = @(
    'FullyQualifiedName~ContactResolverTrustedVerifierSurfaceTests'
    'FullyQualifiedName~PermanentContactResolverCapabilitySourceTests'
    'FullyQualifiedName~ProductionContactResolvePathAuthoritySourceTests'
    'FullyQualifiedName~HttpContactResolveDirectoryCodecTests'
    'FullyQualifiedName~HttpContactResolveDirectoryArtifactSourceTests'
    'FullyQualifiedName~ContactResolveOperationCoordinatorTests'
    'FullyQualifiedName~ContactRelationshipStateMachineTests'
) -join '|'

$productionSource = Get-Content -Raw (Join-Path $repositoryRoot `
    'src\Deep.Client.Shared\Services\ContactV1\ContactResolverVerification.cs')
if ($productionSource.IndexOf(
        'CONTACT01_PERMANENT_IDENTITY_PRODUCER_UNAVAILABLE',
        [StringComparison]::Ordinal) -ge 0) {
    throw 'The removed permanent DID1 producer-unavailable branch is still present.'
}

& dotnet build $sharedProject `
    --configuration Release `
    --no-restore `
    '-p:BuildProjectReferences=false' `
    '-p:EnableDeepTestInternals=true' `
    '-warnaserror'
if ($LASTEXITCODE -ne 0) {
    throw 'The Release Shared assembly failed to build for the focused ContactResolver gate.'
}

& dotnet test $testProject `
    --configuration Release `
    --no-restore `
    '-p:BuildProjectReferences=false' `
    --filter $filter
if ($LASTEXITCODE -ne 0) {
    throw 'The focused ContactResolver production capability gate failed.'
}

Write-Host 'ContactResolver production capability gate: PASS.'
