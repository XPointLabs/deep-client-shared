param(
    [Parameter(Mandatory = $true)][string] $InputPath,
    [Parameter(Mandatory = $true)][string] $OutputPath,
    [Parameter(Mandatory = $true)][string] $Command,
    [Parameter(Mandatory = $true)][string] $SourceCommit
)

$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $InputPath).Path
[xml] $document = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8
$ns = [System.Xml.XmlNamespaceManager]::new($document.NameTable)
$ns.AddNamespace('t', 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010')
$counters = $document.SelectSingleNode('//t:ResultSummary/t:Counters', $ns)
if ($null -eq $counters) { throw 'TRX counters are missing.' }

$sortedTests = @(
    $document.SelectNodes('//t:UnitTestResult', $ns) |
        ForEach-Object {
            [ordered]@{ testName = [string] $_.testName; outcome = [string] $_.outcome }
        } |
        Sort-Object -Property @{ Expression = { $_.testName } }, @{ Expression = { $_.outcome } }
)
$occurrences = @{}
$tests = @(
    foreach ($test in $sortedTests) {
        $key = $test.testName + [char] 0x1f + $test.outcome
        $previous = if ($occurrences.ContainsKey($key)) {
            [int] $occurrences[$key]
        } else {
            0
        }
        $occurrence = 1 + $previous
        $occurrences[$key] = $occurrence
        [ordered]@{
            testName = $test.testName
            outcome = $test.outcome
            occurrence = $occurrence
        }
    }
)

$evidence = [ordered]@{
    schema = 'deep.sanitized-test-evidence.v1'
    sourceCommit = $SourceCommit
    command = $Command
    originalLocalTrxSha256 =
        (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    privacy = [ordered]@{
        userHostPathsTimesAndExecutionIdsRemoved = $true
    }
    counters = [ordered]@{
        total = [int] $counters.total
        executed = [int] $counters.executed
        passed = [int] $counters.passed
        failed = [int] $counters.failed
        skipped = [int] $counters.notExecuted
    }
    tests = $tests
}

$json = $evidence | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText(
    $OutputPath,
    $json + "`n",
    [System.Text.UTF8Encoding]::new($false))
