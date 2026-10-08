param(
    [Parameter(Mandatory = $true)][string[]]$ReceiptPaths,
    [Parameter(Mandatory = $true)][string[]]$ReferencePaths,
    [Parameter(Mandatory = $true)][ValidateNotNull()][Nullable[int]]$NativeExitCode
)
$ErrorActionPreference = 'Stop'
if ($NativeExitCode -ne 0) { throw 'The actual native test exit is not zero.' }
if ($ReceiptPaths.Count -eq 0 -or $ReferencePaths.Count -eq 0) {
    throw 'Current receipts and a predeclared reference matrix are required.'
}

function Read-Executions([string]$Path) {
    [xml]$document = Get-Content -LiteralPath $Path -Raw
    $manager = New-Object System.Xml.XmlNamespaceManager($document.NameTable)
    $manager.AddNamespace('t', 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010')
    $rows = @($document.SelectNodes('/t:TestRun/t:Results/t:UnitTestResult', $manager))
    $definitions = @($document.SelectNodes('/t:TestRun/t:TestDefinitions/t:UnitTest', $manager))
    $entries = @($document.SelectNodes('/t:TestRun/t:TestEntries/t:TestEntry', $manager))
    if ($rows.Count -eq 0 -or $rows.Count -ne $definitions.Count -or
        $rows.Count -ne $entries.Count) { throw 'Empty or incomplete TRX execution mappings.' }

    $definitionMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $entryMap = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($definition in $definitions) {
        $definitionMap.Add($definition.GetAttribute('id'), $definition)
    }
    foreach ($entry in $entries) {
        $entryMap.Add($entry.GetAttribute('executionId'), $entry.GetAttribute('testId'))
    }
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $executions = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $passed = 0; $failed = 0; $skipped = 0
    foreach ($row in $rows) {
        $name = $row.GetAttribute('testName')
        $id = $row.GetAttribute('testId')
        $execution = $row.GetAttribute('executionId')
        if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($id) -or
            [string]::IsNullOrWhiteSpace($execution) -or !$names.Add($name) -or
            !$ids.Add($id) -or !$executions.Add($execution)) {
            throw 'Empty or duplicate test identity.'
        }
        if (!$definitionMap.ContainsKey($id) -or !$entryMap.ContainsKey($execution)) {
            throw 'A result lost its definition or execution entry.'
        }
        $definition = $definitionMap[$id]
        $definedName = $definition.GetAttribute('name')
        $definedExecution = $definition.SelectSingleNode('t:Execution', $manager)
        $method = $definition.SelectSingleNode('t:TestMethod', $manager)
        if ($null -eq $definedExecution -or $null -eq $method -or
            [string]::IsNullOrWhiteSpace($definedName) -or
            [string]::IsNullOrWhiteSpace($method.GetAttribute('className')) -or
            [string]::IsNullOrWhiteSpace($method.GetAttribute('name')) -or
            $definedExecution.GetAttribute('id') -cne $execution -or
            $entryMap[$execution] -cne $id -or
            !($name -ceq $definedName -or
                $name.StartsWith($definedName + '(', [StringComparison]::Ordinal))) {
            throw 'Result, method, definition and execution mapping disagree.'
        }
        $methodName = $method.GetAttribute('className') + '.' + $method.GetAttribute('name')
        if (!($name -ceq $methodName -or
            $name.StartsWith($methodName + '(', [StringComparison]::Ordinal))) {
            throw 'The result does not identify its declared method.'
        }
        switch -CaseSensitive ($row.GetAttribute('outcome')) {
            'Passed' { $passed++ }
            'Failed' { $failed++ }
            'NotExecuted' { $skipped++ }
            default { throw 'Unsupported or incomplete execution outcome.' }
        }
    }
    $counters = $document.SelectSingleNode('/t:TestRun/t:ResultSummary/t:Counters', $manager)
    foreach ($required in @('total', 'executed', 'passed', 'failed', 'notExecuted')) {
        if ($null -eq $counters -or !$counters.HasAttribute($required)) {
            throw 'TRX counters are absent.'
        }
    }
    if ([int]$counters.GetAttribute('total') -ne $rows.Count -or
        [int]$counters.GetAttribute('executed') -ne ($passed + $failed) -or
        [int]$counters.GetAttribute('passed') -ne $passed -or
        [int]$counters.GetAttribute('failed') -ne $failed -or
        [int]$counters.GetAttribute('notExecuted') -notin @(0, $skipped)) {
        throw 'TRX counters disagree with the actual result rows.'
    }
    foreach ($terminalError in @('error', 'timeout', 'aborted', 'inconclusive', 'disconnected', 'inProgress', 'pending')) {
        if ($counters.HasAttribute($terminalError) -and
            [int]$counters.GetAttribute($terminalError) -ne 0) {
            throw 'TRX contains an incomplete or erroneous terminal.'
        }
    }
    [pscustomobject]@{
        Names = $names; Ids = $ids; Executions = $executions
        Passed = $passed; Failed = $failed; Skipped = $skipped
        Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    }
}

$requiredNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($path in $ReferencePaths) {
    $reference = Read-Executions $path
    foreach ($name in $reference.Names) { $null = $requiredNames.Add($name) }
}
$actualNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$actualIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$actualExecutions = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$hashes = @()
foreach ($path in $ReceiptPaths) {
    $current = Read-Executions $path
    if ($current.Failed -ne 0 -or $current.Skipped -ne 0) {
        throw 'Current production qualification requires every execution to pass.'
    }
    foreach ($name in $current.Names) {
        if (!$actualNames.Add($name)) { throw 'A case was executed more than once across receipts.' }
    }
    foreach ($id in $current.Ids) {
        if (!$actualIds.Add($id)) { throw 'A test identity is duplicated across receipts.' }
    }
    foreach ($execution in $current.Executions) {
        if (!$actualExecutions.Add($execution)) { throw 'An execution identity is duplicated across receipts.' }
    }
    $hashes += $current.Sha256
}
if (!$requiredNames.SetEquals($actualNames)) {
    throw 'The predeclared full/focused case union differs from actual executions.'
}
[pscustomobject]@{
    NativeExitCode = $NativeExitCode
    Passed = $actualNames.Count
    Required = $requiredNames.Count
    ExactCaseMapping = $true
    ReceiptSha256 = $hashes
}
