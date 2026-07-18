[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments)]
    [Alias('Filter', 'TestFilter', 'FullyQualifiedName')]
    [object[]] $CallerArguments = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$harnessExit = 2
$runDirectory = $null
$previousGateValue = [Environment]::GetEnvironmentVariable('DEEP_SURVIVAL_METADATA_GATE', 'Process')

try {
    if ($CallerArguments.Count -ne 0 -or $MyInvocation.UnboundArguments.Count -ne 0) {
        throw 'metadata-gate-does-not-accept-caller-arguments'
    }

    $repositoryRoot = [IO.Path]::GetFullPath(
        (Join-Path (Join-Path $PSScriptRoot '..') '..'))
    $solutionPath = Join-Path $repositoryRoot 'Deep.Client.Shared.slnx'
    $expectationsPath = [IO.Path]::Combine(
        $repositoryRoot,
        'tests',
        'Deep.Client.Shared.Tests',
        'Fixtures',
        'metadata-expectations.v1.json')
    $modulePath = Join-Path $PSScriptRoot 'MetadataPrivacyGateHarness.psm1'
    Import-Module -Name $modulePath -Force -ErrorAction Stop
    $contract = Get-MetadataPrivacyGateContract

    $tempRoot = [IO.Path]::GetFullPath(
        (Join-Path ([IO.Path]::GetTempPath()) 'deep-metadata-privacy-gate'))
    $runDirectory = [IO.Path]::GetFullPath(
        (Join-Path $tempRoot ([Guid]::NewGuid().ToString('N'))))
    if (-not $runDirectory.StartsWith(
        $tempRoot + [IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'metadata-gate-temp-path-escaped-root'
    }

    New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
    $trxPath = Join-Path $runDirectory 'metadata-privacy-gate.trx'
    [Environment]::SetEnvironmentVariable($contract.EnvironmentVariable, '1', 'Process')

    & dotnet test $solutionPath `
        --no-restore `
        --filter $contract.Filter `
        --logger 'trx;LogFileName=metadata-privacy-gate.trx' `
        --results-directory $runDirectory
    $dotnetExitCode = $LASTEXITCODE

    Write-Output "metadata-gate-trx=$trxPath"
    $validation = Test-MetadataPrivacyGateResult `
        -TrxPath $trxPath `
        -ExpectationsPath $expectationsPath `
        -DotnetExitCode $dotnetExitCode `
        -StrictGateValue ([Environment]::GetEnvironmentVariable($contract.EnvironmentVariable, 'Process')) `
        -ExecutedFilter $contract.Filter

    Write-Output "metadata-gate-total=$($validation.ExpectedCount)"
    Write-Output "metadata-gate-unresolved=$($validation.UnresolvedCount)"
    if ($validation.Problems.Count -gt 0) {
        [Console]::Error.WriteLine(
            "metadata-gate-harness-mismatch: " + ($validation.Problems -join ','))
    }

    $harnessExit = $validation.ExitCode
}
catch {
    [Console]::Error.WriteLine("metadata-gate-harness-failed: $($_.Exception.Message)")
    $harnessExit = 2
}
finally {
    try {
        [Environment]::SetEnvironmentVariable(
            'DEEP_SURVIVAL_METADATA_GATE',
            $previousGateValue,
            'Process')
    }
    catch {
        [Console]::Error.WriteLine('metadata-gate-env-restore-failed')
        $harnessExit = 2
    }

    try {
        if ($null -ne $runDirectory -and (Test-Path -LiteralPath $runDirectory -PathType Container)) {
            $resolvedRunDirectory = [IO.Path]::GetFullPath(
                (Resolve-Path -LiteralPath $runDirectory -ErrorAction Stop).Path)
            $expectedTempRoot = [IO.Path]::GetFullPath(
                (Join-Path ([IO.Path]::GetTempPath()) 'deep-metadata-privacy-gate'))
            if ($resolvedRunDirectory.StartsWith(
                $expectedTempRoot + [IO.Path]::DirectorySeparatorChar,
                [System.StringComparison]::OrdinalIgnoreCase) -and
                [IO.Path]::GetFileName($resolvedRunDirectory) -match '^[0-9a-f]{32}$') {
                Remove-Item -LiteralPath $resolvedRunDirectory -Recurse -Force
            }
            else {
                [Console]::Error.WriteLine('metadata-gate-refused-unsafe-temp-cleanup')
                $harnessExit = 2
            }
        }
    }
    catch {
        [Console]::Error.WriteLine('metadata-gate-temp-cleanup-failed')
        $harnessExit = 2
    }
}

exit $harnessExit
