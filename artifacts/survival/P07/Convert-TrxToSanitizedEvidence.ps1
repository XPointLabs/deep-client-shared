param(
    [Parameter(Mandatory = $true)]
    [string] $InputPath,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [Parameter(Mandatory = $true)]
    [string] $Command,

    [Parameter(Mandatory = $true)]
    [string] $SourceCommit
)

$ErrorActionPreference = 'Stop'
$resolvedInput = (Resolve-Path -LiteralPath $InputPath).Path
[xml] $document = Get-Content -LiteralPath $resolvedInput -Raw
$manager = [System.Xml.XmlNamespaceManager]::new($document.NameTable)
$manager.AddNamespace('t', 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010')

$counters = $document.SelectSingleNode('//t:ResultSummary/t:Counters', $manager)
if ($null -eq $counters) {
    throw "TRX result counters are missing."
}

$tests = @(
    $document.SelectNodes('//t:UnitTestResult', $manager) |
        ForEach-Object {
            [ordered]@{
                testName = [string] $_.testName
                outcome = [string] $_.outcome
            }
        } |
        Sort-Object -Property @{ Expression = { $_.testName } }, @{ Expression = { $_.outcome } }
)

$originalHash = (Get-FileHash -LiteralPath $resolvedInput -Algorithm SHA256).Hash.ToLowerInvariant()
$evidence = [ordered]@{
    schema = 'deep.p07.sanitized-test-evidence.v1'
    sourceCommit = $SourceCommit
    command = $Command
    originalLocalTrxSha256 = $originalHash
    privacy = [ordered]@{
        machineNamesRemoved = $true
        userNamesRemoved = $true
        absolutePathsRemoved = $true
        timestampsRemoved = $true
        executionIdsRemoved = $true
    }
    counters = [ordered]@{
        total = [int] $counters.total
        executed = [int] $counters.executed
        passed = [int] $counters.passed
        failed = [int] $counters.failed
        error = [int] $counters.error
        timeout = [int] $counters.timeout
        aborted = [int] $counters.aborted
        inconclusive = [int] $counters.inconclusive
        passedButRunAborted = [int] $counters.passedButRunAborted
        notRunnable = [int] $counters.notRunnable
        notExecuted = [int] $counters.notExecuted
        disconnected = [int] $counters.disconnected
        warning = [int] $counters.warning
        completed = [int] $counters.completed
        inProgress = [int] $counters.inProgress
        pending = [int] $counters.pending
    }
    tests = $tests
}

$json = $evidence | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText(
    $OutputPath,
    $json + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false))
