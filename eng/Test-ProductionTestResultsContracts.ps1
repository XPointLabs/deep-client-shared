#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot '..\..\scripts\Test-RepositoryTestGateContracts.ps1')
