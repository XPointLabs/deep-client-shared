$ErrorActionPreference = 'Stop'
$verifier = Join-Path $PSScriptRoot 'Test-ProductionTestResults.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ('deep-shared-trx-contracts-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$currentPath = Join-Path $root 'current.trx'
$referencePath = Join-Path $root 'reference.trx'
$secondPath = Join-Path $root 'second.trx'
$checks = 0

function Receipt([string]$Name = 'Example.Case', [string]$Outcome = 'Passed',
    [int]$Executed = 1, [int]$Passed = 1, [int]$Failed = 0,
    [string]$DefinedName = $Name, [string]$EntryId = 'e1') {
    $methodName = ($DefinedName -split '\(', 2)[0]
    $methodName = $methodName.Substring($methodName.LastIndexOf('.') + 1)
    @"
<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Results><UnitTestResult testName="$Name" testId="t1" executionId="e1" outcome="$Outcome" /></Results>
  <TestDefinitions><UnitTest id="t1" name="$DefinedName"><Execution id="e1" /><TestMethod className="Example" name="$methodName" /></UnitTest></TestDefinitions>
  <TestEntries><TestEntry testId="t1" executionId="$EntryId" /></TestEntries>
  <ResultSummary><Counters total="1" executed="$Executed" passed="$Passed" failed="$Failed" notExecuted="0" /></ResultSummary>
</TestRun>
"@
}

function Require-Rejection([scriptblock]$Action, [string]$ExpectedMessage) {
    $rejected = $false
    try { & $Action | Out-Null }
    catch {
        if ($ExpectedMessage -and !$_.Exception.Message.Contains($ExpectedMessage)) { throw }
        $rejected = $true
    }
    if (!$rejected) { throw 'A hostile result fixture was accepted.' }
    $script:checks++
}

try {
    Receipt | Set-Content -LiteralPath $currentPath -Encoding UTF8
    Receipt | Set-Content -LiteralPath $referencePath -Encoding UTF8
    $result = & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode 0
    if ($result.Passed -ne 1 -or !$result.ExactCaseMapping) { throw 'Valid receipt rejected.' }
    $checks++

    Receipt -Name 'Example.Case(value: 2)' -DefinedName 'Example.Case' |
        Set-Content -LiteralPath $currentPath -Encoding UTF8
    Copy-Item -LiteralPath $currentPath -Destination $referencePath
    $result = & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode 0
    if ($result.Passed -ne 1) { throw 'Canonical theory mapping rejected.' }
    $checks++

    Receipt | Set-Content -LiteralPath $currentPath -Encoding UTF8
    Receipt | Set-Content -LiteralPath $referencePath -Encoding UTF8
    Require-Rejection { & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode 1 } 'actual native test exit'
    Require-Rejection { & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode $null }
    Receipt -EntryId 'wrong' | Set-Content -LiteralPath $currentPath -Encoding UTF8
    Require-Rejection { & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode 0 } 'lost its definition or execution entry'
    Receipt -DefinedName 'Another.Case' | Set-Content -LiteralPath $currentPath -Encoding UTF8
    Require-Rejection { & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode 0 } 'mapping disagree'
    Receipt -Executed 0 | Set-Content -LiteralPath $currentPath -Encoding UTF8
    Require-Rejection { & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode 0 } 'counters disagree'
    Receipt -Outcome Failed -Passed 0 -Failed 1 | Set-Content -LiteralPath $currentPath -Encoding UTF8
    Require-Rejection { & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode 0 } 'every execution to pass'
    Receipt -Outcome NotExecuted -Executed 0 -Passed 0 | Set-Content -LiteralPath $currentPath -Encoding UTF8
    Require-Rejection { & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode 0 } 'every execution to pass'
    Receipt -Name 'Example.NewCase' | Set-Content -LiteralPath $currentPath -Encoding UTF8
    Require-Rejection { & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode 0 } 'predeclared full/focused case union'
    '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010" />' |
        Set-Content -LiteralPath $currentPath -Encoding UTF8
    Require-Rejection { & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode 0 } 'Empty or incomplete'

    Receipt | Set-Content -LiteralPath $currentPath -Encoding UTF8
    Receipt | Set-Content -LiteralPath $referencePath -Encoding UTF8
    Copy-Item -LiteralPath $currentPath -Destination $secondPath
    Require-Rejection { & $verifier -ReceiptPaths @($currentPath, $secondPath) -ReferencePaths $referencePath -NativeExitCode 0 } 'more than once'

    Receipt -Name 'Example.Other' | Set-Content -LiteralPath $secondPath -Encoding UTF8
    Require-Rejection { & $verifier -ReceiptPaths @($currentPath, $secondPath) -ReferencePaths @($referencePath, $secondPath) -NativeExitCode 0 } 'test identity is duplicated'
    (Receipt -Name 'Example.Other').Replace('testId="t1"', 'testId="t2"').Replace('id="t1"', 'id="t2"') |
        Set-Content -LiteralPath $secondPath -Encoding UTF8
    Require-Rejection { & $verifier -ReceiptPaths @($currentPath, $secondPath) -ReferencePaths @($referencePath, $secondPath) -NativeExitCode 0 } 'execution identity is duplicated'
    (Get-Content -LiteralPath $secondPath -Raw).Replace('executionId="e1"', 'executionId="e2"').Replace('id="e1"', 'id="e2"') |
        Set-Content -LiteralPath $secondPath -Encoding UTF8
    $result = & $verifier -ReceiptPaths @($currentPath, $secondPath) -ReferencePaths @($referencePath, $secondPath) -NativeExitCode 0
    if ($result.Passed -ne 2) { throw 'Distinct merged executions rejected.' }
    $checks++

    Receipt -Outcome NotExecuted -Executed 0 -Passed 0 |
        Set-Content -LiteralPath $referencePath -Encoding UTF8
    $result = & $verifier -ReceiptPaths $currentPath -ReferencePaths $referencePath -NativeExitCode 0
    if ($result.Passed -ne 1) { throw 'Preserved historical skipped-row convention rejected.' }
    $checks++
    Write-Output "Production TRX contracts passed: $checks"
} finally {
    foreach ($path in @($currentPath, $referencePath, $secondPath)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
    }
    [IO.Directory]::Delete($root, $false)
}
