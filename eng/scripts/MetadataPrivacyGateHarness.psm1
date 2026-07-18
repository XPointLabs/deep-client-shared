Set-StrictMode -Version Latest

$script:MetadataGateEnvironmentVariable = 'DEEP_SURVIVAL_METADATA_GATE'
$script:ExpectedMetadataGateFilter =
    'FullyQualifiedName=Deep.Client.Shared.Tests.Services.MetadataPrivacyCharacterizationTests.BetaMetadataGate_FailsForEachUnresolvedFinding'
$script:ExpectedMetadataGateTest =
    'Deep.Client.Shared.Tests.Services.MetadataPrivacyCharacterizationTests.BetaMetadataGate_FailsForEachUnresolvedFinding'

function Get-MetadataPrivacyGateContract {
    [CmdletBinding()]
    param()

    [pscustomobject]@{
        EnvironmentVariable = $script:MetadataGateEnvironmentVariable
        Filter = $script:ExpectedMetadataGateFilter
        Test = $script:ExpectedMetadataGateTest
    }
}

function Test-MetadataPrivacyGateResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $TrxPath,

        [Parameter(Mandatory)]
        [string] $ExpectationsPath,

        [Parameter(Mandatory)]
        [int] $DotnetExitCode,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $StrictGateValue,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $ExecutedFilter
    )

    $problems = [System.Collections.Generic.List[string]]::new()

    if ($StrictGateValue -cne '1') {
        $problems.Add('strict-env-not-one')
    }

    if ($ExecutedFilter -cne $script:ExpectedMetadataGateFilter) {
        $problems.Add('unexpected-test-filter')
    }

    if (-not (Test-Path -LiteralPath $ExpectationsPath -PathType Leaf)) {
        $problems.Add('expectations-file-missing')
    }

    if (-not (Test-Path -LiteralPath $TrxPath -PathType Leaf)) {
        $problems.Add('trx-file-missing')
    }

    if ($problems.Count -gt 0) {
        return New-MetadataGateResult -ExitCode 2 -Problems $problems
    }

    try {
        $expectations = Get-Content -LiteralPath $ExpectationsPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $problems.Add('expectations-parse-failed')
        return New-MetadataGateResult -ExitCode 2 -Problems $problems
    }

    if ($expectations.schema -cne 'deep-metadata-expectations.v1') {
        $problems.Add('expectations-schema-mismatch')
    }

    $findings = @($expectations.findings | Where-Object { $_.beta_blocking -eq $true })
    if ($findings.Count -eq 0) {
        $problems.Add('no-beta-blocking-findings')
    }

    $findingIds = @($findings | ForEach-Object { [string] $_.id })
    if (@($findingIds | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
        $problems.Add('blank-finding-id')
    }

    $uniqueFindingIds = @($findingIds | Sort-Object -Unique)
    if ($uniqueFindingIds.Count -ne $findingIds.Count) {
        $problems.Add('duplicate-finding-id')
    }

    $allowedStatuses = @('unresolved', 'mitigated', 'resolved')
    if (@($findings | Where-Object { $allowedStatuses -cnotcontains ([string] $_.status) }).Count -gt 0) {
        $problems.Add('invalid-finding-status')
    }

    try {
        [xml] $trx = Get-Content -LiteralPath $TrxPath -Raw -ErrorAction Stop
    }
    catch {
        $problems.Add('trx-parse-failed')
        return New-MetadataGateResult -ExitCode 2 -Problems $problems
    }

    $counters = @($trx.SelectNodes("//*[local-name()='Counters']"))
    $results = @($trx.SelectNodes("//*[local-name()='UnitTestResult']"))
    if ($counters.Count -ne 1) {
        $problems.Add('trx-counter-count-mismatch')
    }

    if ($counters.Count -eq 1) {
        $counter = $counters[0]
        $expectedCount = $findings.Count
        if ([int] $counter.total -ne $expectedCount -or
            [int] $counter.executed -ne $expectedCount -or
            $results.Count -ne $expectedCount) {
            $problems.Add('trx-test-count-mismatch')
        }

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
            if ($counter.HasAttribute($attribute) -and [int] $counter.GetAttribute($attribute) -ne 0) {
                $problems.Add("trx-nonzero-$attribute")
            }
        }
    }

    $seenFindingIds = [System.Collections.Generic.List[string]]::new()
    foreach ($result in $results) {
        $testName = [string] $result.testName
        if (-not $testName.StartsWith(
            "$($script:ExpectedMetadataGateTest)(",
            [System.StringComparison]::Ordinal)) {
            $problems.Add('unexpected-test-id')
        }

        $matchingIds = @($findingIds | Where-Object {
            $testName.IndexOf($_, [System.StringComparison]::Ordinal) -ge 0
        })
        if ($matchingIds.Count -ne 1) {
            $problems.Add('result-finding-cardinality-mismatch')
            continue
        }

        $findingId = $matchingIds[0]
        $seenFindingIds.Add($findingId)
        $finding = $findings | Where-Object { $_.id -ceq $findingId } | Select-Object -First 1
        $expectedOutcome = if ($finding.status -ceq 'resolved') { 'Passed' } else { 'Failed' }
        if ([string] $result.outcome -cne $expectedOutcome) {
            $problems.Add("unexpected-outcome-$findingId")
        }

        if ($expectedOutcome -ceq 'Failed') {
            $messageNodes = @($result.SelectNodes(".//*[local-name()='Message']"))
            $message = ($messageNodes | ForEach-Object { $_.InnerText }) -join "`n"
            if ($message.IndexOf(
                "$findingId`: strict metadata gate requires resolved evidence.",
                [System.StringComparison]::Ordinal) -lt 0) {
                $problems.Add("missing-failure-evidence-$findingId")
            }
        }
    }

    if (@($seenFindingIds | Sort-Object).Count -ne @($findingIds | Sort-Object).Count -or
        (Compare-Object -ReferenceObject @($findingIds | Sort-Object) -DifferenceObject @($seenFindingIds | Sort-Object))) {
        $problems.Add('finding-set-mismatch')
    }

    $unresolvedCount = @($findings | Where-Object { $_.status -cne 'resolved' }).Count
    $expectedDotnetExit = if ($unresolvedCount -eq 0) { 0 } else { 1 }
    if ($DotnetExitCode -ne $expectedDotnetExit) {
        $problems.Add('dotnet-exit-mismatch')
    }

    if ($problems.Count -gt 0) {
        return New-MetadataGateResult `
            -ExitCode 2 `
            -Problems $problems `
            -ExpectedCount $findings.Count `
            -UnresolvedCount $unresolvedCount
    }

    New-MetadataGateResult `
        -ExitCode $expectedDotnetExit `
        -Problems $problems `
        -ExpectedCount $findings.Count `
        -UnresolvedCount $unresolvedCount
}

function New-MetadataGateResult {
    param(
        [Parameter(Mandatory)]
        [int] $ExitCode,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]] $Problems,

        [int] $ExpectedCount = 0,

        [int] $UnresolvedCount = 0
    )

    [pscustomobject]@{
        ExitCode = $ExitCode
        ExpectedCount = $ExpectedCount
        UnresolvedCount = $UnresolvedCount
        Problems = @($Problems | Sort-Object -Unique)
    }
}

Export-ModuleMember -Function Get-MetadataPrivacyGateContract, Test-MetadataPrivacyGateResult
