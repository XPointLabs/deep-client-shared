#Requires -Version 5.1
param(
    [Parameter(Mandatory = $true)][string[]]$ReceiptPaths,
    [Parameter(Mandatory = $true)][string[]]$ReferencePaths,
    [Parameter(Mandatory = $true)][ValidateNotNull()][Nullable[int]]$NativeExitCode
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\scripts\TestGate.psm1') -Force
Test-TestGateResults -ReceiptPaths $ReceiptPaths -ReferencePaths $ReferencePaths -NativeExitCode $NativeExitCode
