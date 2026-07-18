[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$exitCode = 2
$testDirectory = $null

function Write-SyntheticTrx {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $ResultFindingIds,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [hashtable] $Outcomes
    )

    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Indent = $true
    $settings.Encoding = [Text.UTF8Encoding]::new($false)
    $writer = [System.Xml.XmlWriter]::Create($Path, $settings)
    try {
        $writer.WriteStartDocument()
        $writer.WriteStartElement('TestRun')
        $writer.WriteStartElement('ResultSummary')
        $writer.WriteAttributeString('outcome', 'Completed')
        $writer.WriteStartElement('Counters')
        $writer.WriteAttributeString('total', [string] $ResultFindingIds.Count)
        $writer.WriteAttributeString('executed', [string] $ResultFindingIds.Count)
        $passed = @($ResultFindingIds | Where-Object { $Outcomes[$_] -ceq 'Passed' }).Count
        $failed = $ResultFindingIds.Count - $passed
        $writer.WriteAttributeString('passed', [string] $passed)
        $writer.WriteAttributeString('failed', [string] $failed)
        foreach ($attribute in @(
            'error',
            'timeout',
            'aborted',
            'inconclusive',
            'passedButRunAborted',
            'notRunnable',
            'notExecuted',
            'disconnected',
            'warning'
        )) {
            $writer.WriteAttributeString($attribute, '0')
        }
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteStartElement('Results')
        foreach ($findingId in $ResultFindingIds) {
            $outcome = [string] $Outcomes[$findingId]
            $writer.WriteStartElement('UnitTestResult')
            $writer.WriteAttributeString(
                'testName',
                "$($script:TestContract.Test)(findingId: `"$findingId`")")
            $writer.WriteAttributeString('outcome', $outcome)
            if ($outcome -ceq 'Failed') {
                $writer.WriteStartElement('Output')
                $writer.WriteStartElement('ErrorInfo')
                $writer.WriteElementString(
                    'Message',
                    "$findingId`: strict metadata gate requires resolved evidence.")
                $writer.WriteEndElement()
                $writer.WriteEndElement()
            }
            $writer.WriteEndElement()
        }
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteEndDocument()
    }
    finally {
        $writer.Dispose()
    }
}

function Invoke-SyntheticValidation {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $ExpectationsPath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $ResultFindingIds,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [hashtable] $Outcomes,

        [Parameter(Mandatory)]
        [int] $DotnetExitCode,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $StrictGateValue,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $ExecutedFilter,

        [Parameter(Mandatory)]
        [int] $ExpectedHarnessExit
    )

    $trxPath = Join-Path $script:TestDirectory "$Name.trx"
    Write-SyntheticTrx `
        -Path $trxPath `
        -ResultFindingIds $ResultFindingIds `
        -Outcomes $Outcomes
    $result = Test-MetadataPrivacyGateResult `
        -TrxPath $trxPath `
        -ExpectationsPath $ExpectationsPath `
        -DotnetExitCode $DotnetExitCode `
        -StrictGateValue $StrictGateValue `
        -ExecutedFilter $ExecutedFilter
    if ($result.ExitCode -ne $ExpectedHarnessExit) {
        throw "$Name expected harness exit $ExpectedHarnessExit but received $($result.ExitCode)"
    }
}

try {
    if ($MyInvocation.UnboundArguments.Count -ne 0) {
        throw 'metadata-gate-self-test-does-not-accept-caller-arguments'
    }

    $repositoryRoot = [IO.Path]::GetFullPath(
        (Join-Path (Join-Path $PSScriptRoot '..') '..'))
    Import-Module (Join-Path $PSScriptRoot 'MetadataPrivacyGateHarness.psm1') -Force
    $script:TestContract = Get-MetadataPrivacyGateContract
    $expectationsPath = [IO.Path]::Combine(
        $repositoryRoot,
        'tests',
        'Deep.Client.Shared.Tests',
        'Fixtures',
        'metadata-expectations.v1.json')
    $expectations = Get-Content -LiteralPath $expectationsPath -Raw | ConvertFrom-Json
    $script:Findings = @($expectations.findings | Where-Object { $_.beta_blocking -eq $true })
    $findingIds = @($script:Findings | ForEach-Object { [string] $_.id })
    $unresolvedOutcomes = @{}
    foreach ($findingId in $findingIds) {
        $unresolvedOutcomes[$findingId] = 'Failed'
    }

    $tempRoot = [IO.Path]::GetFullPath(
        (Join-Path ([IO.Path]::GetTempPath()) 'deep-metadata-privacy-gate-self-test'))
    $script:TestDirectory = [IO.Path]::GetFullPath(
        (Join-Path $tempRoot ([Guid]::NewGuid().ToString('N'))))
    $testDirectory = $script:TestDirectory
    if (-not $testDirectory.StartsWith(
        $tempRoot + [IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'metadata-gate-self-test-temp-path-escaped-root'
    }
    New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null

    Invoke-SyntheticValidation `
        -Name 'baseline-unresolved' `
        -ExpectationsPath $expectationsPath `
        -ResultFindingIds $findingIds `
        -Outcomes $unresolvedOutcomes `
        -DotnetExitCode 1 `
        -StrictGateValue '1' `
        -ExecutedFilter $script:TestContract.Filter `
        -ExpectedHarnessExit 1

    Invoke-SyntheticValidation `
        -Name 'omitted-strict-env' `
        -ExpectationsPath $expectationsPath `
        -ResultFindingIds $findingIds `
        -Outcomes $unresolvedOutcomes `
        -DotnetExitCode 1 `
        -StrictGateValue '' `
        -ExecutedFilter $script:TestContract.Filter `
        -ExpectedHarnessExit 2

    Invoke-SyntheticValidation `
        -Name 'typo-filter' `
        -ExpectationsPath $expectationsPath `
        -ResultFindingIds $findingIds `
        -Outcomes $unresolvedOutcomes `
        -DotnetExitCode 1 `
        -StrictGateValue '1' `
        -ExecutedFilter ($script:TestContract.Filter + '.Typo') `
        -ExpectedHarnessExit 2

    Invoke-SyntheticValidation `
        -Name 'zero-match' `
        -ExpectationsPath $expectationsPath `
        -ResultFindingIds @() `
        -Outcomes @{} `
        -DotnetExitCode 0 `
        -StrictGateValue '1' `
        -ExecutedFilter $script:TestContract.Filter `
        -ExpectedHarnessExit 2

    Invoke-SyntheticValidation `
        -Name 'missing-test' `
        -ExpectationsPath $expectationsPath `
        -ResultFindingIds @($findingIds | Select-Object -Skip 1) `
        -Outcomes $unresolvedOutcomes `
        -DotnetExitCode 1 `
        -StrictGateValue '1' `
        -ExecutedFilter $script:TestContract.Filter `
        -ExpectedHarnessExit 2

    $duplicateIds = @($findingIds)
    $duplicateIds[-1] = $duplicateIds[0]
    Invoke-SyntheticValidation `
        -Name 'duplicate-result-finding' `
        -ExpectationsPath $expectationsPath `
        -ResultFindingIds $duplicateIds `
        -Outcomes $unresolvedOutcomes `
        -DotnetExitCode 1 `
        -StrictGateValue '1' `
        -ExecutedFilter $script:TestContract.Filter `
        -ExpectedHarnessExit 2

    $duplicateExpectations = $expectations | ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $duplicateExpectations.findings[-1].id = $duplicateExpectations.findings[0].id
    $duplicateExpectationsPath = Join-Path $testDirectory 'duplicate-expectations.json'
    $duplicateExpectations |
        ConvertTo-Json -Depth 16 |
        Set-Content -LiteralPath $duplicateExpectationsPath -Encoding utf8
    Invoke-SyntheticValidation `
        -Name 'duplicate-expectation-finding' `
        -ExpectationsPath $duplicateExpectationsPath `
        -ResultFindingIds $findingIds `
        -Outcomes $unresolvedOutcomes `
        -DotnetExitCode 1 `
        -StrictGateValue '1' `
        -ExecutedFilter $script:TestContract.Filter `
        -ExpectedHarnessExit 2

    $mutatedExpectations = $expectations | ConvertTo-Json -Depth 16
    $mutatedExpectationsPath = Join-Path $testDirectory 'mismatched-expectations.json'
    $mutated = $mutatedExpectations | ConvertFrom-Json
    $mutated.findings += [pscustomobject]@{
        id = 'META-SYNTHETIC-MISMATCH'
        observer = 'synthetic'
        domain = 'harness'
        beta_blocking = $true
        status = 'unresolved'
        evidence = 'synthetic'
        required_producer_contract = 'synthetic'
    }
    $mutated | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $mutatedExpectationsPath -Encoding utf8
    Invoke-SyntheticValidation `
        -Name 'mismatched-finding-count' `
        -ExpectationsPath $mutatedExpectationsPath `
        -ResultFindingIds $findingIds `
        -Outcomes $unresolvedOutcomes `
        -DotnetExitCode 1 `
        -StrictGateValue '1' `
        -ExecutedFilter $script:TestContract.Filter `
        -ExpectedHarnessExit 2

    $resolved = $expectations | ConvertTo-Json -Depth 16 | ConvertFrom-Json
    foreach ($finding in $resolved.findings) {
        if ($finding.beta_blocking -eq $true) {
            $finding.status = 'resolved'
        }
    }
    $resolvedPath = Join-Path $testDirectory 'resolved-expectations.json'
    $resolved | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $resolvedPath -Encoding utf8
    $resolvedOutcomes = @{}
    foreach ($findingId in $findingIds) {
        $resolvedOutcomes[$findingId] = 'Passed'
    }
    Invoke-SyntheticValidation `
        -Name 'all-resolved' `
        -ExpectationsPath $resolvedPath `
        -ResultFindingIds $findingIds `
        -Outcomes $resolvedOutcomes `
        -DotnetExitCode 0 `
        -StrictGateValue '1' `
        -ExecutedFilter $script:TestContract.Filter `
        -ExpectedHarnessExit 0

    Invoke-SyntheticValidation `
        -Name 'false-green-unresolved' `
        -ExpectationsPath $expectationsPath `
        -ResultFindingIds $findingIds `
        -Outcomes $resolvedOutcomes `
        -DotnetExitCode 0 `
        -StrictGateValue '1' `
        -ExecutedFilter $script:TestContract.Filter `
        -ExpectedHarnessExit 2

    Write-Output 'metadata-gate-harness-self-tests=10'
    Write-Output 'metadata-gate-harness-mutations-rejected=8'
    $exitCode = 0
}
catch {
    [Console]::Error.WriteLine(
        "metadata-gate-harness-self-test-failed: $($_.Exception.Message)")
    $exitCode = 2
}
finally {
    try {
        if ($null -ne $testDirectory -and (Test-Path -LiteralPath $testDirectory -PathType Container)) {
            $resolvedTestDirectory = [IO.Path]::GetFullPath(
                (Resolve-Path -LiteralPath $testDirectory -ErrorAction Stop).Path)
            $expectedTempRoot = [IO.Path]::GetFullPath(
                (Join-Path ([IO.Path]::GetTempPath()) 'deep-metadata-privacy-gate-self-test'))
            if ($resolvedTestDirectory.StartsWith(
                $expectedTempRoot + [IO.Path]::DirectorySeparatorChar,
                [System.StringComparison]::OrdinalIgnoreCase) -and
                [IO.Path]::GetFileName($resolvedTestDirectory) -match '^[0-9a-f]{32}$') {
                Remove-Item -LiteralPath $resolvedTestDirectory -Recurse -Force
            }
            else {
                [Console]::Error.WriteLine('metadata-gate-self-test-refused-unsafe-temp-cleanup')
                $exitCode = 2
            }
        }
    }
    catch {
        [Console]::Error.WriteLine('metadata-gate-self-test-temp-cleanup-failed')
        $exitCode = 2
    }
}

exit $exitCode
