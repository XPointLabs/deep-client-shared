# Test results

Date: 2026-07-18

## Default full suite

```powershell
dotnet test Deep.Client.Shared.slnx --no-restore --logger "console;verbosity=minimal"
```

Result: exit `0`; 309 passed, 0 failed, 0 skipped.

## Focused characterization

```powershell
dotnet test Deep.Client.Shared.slnx --no-restore --filter "FullyQualifiedName~MetadataPrivacyCharacterizationTests|FullyQualifiedName~RoutedSessionStorageMessageTransport_SendAndReceive_UsesRouterRpcAndTracksRoute" --logger "console;verbosity=minimal"
```

Result: exit `0`; 14 passed, 0 failed, 0 skipped. This includes five characterization/fixture tests, eight default-mode blocker cases and the routed final-storage-layer characterization.

## Explicit strict expected-red lane

```powershell
& ./eng/scripts/Invoke-MetadataPrivacyGate.ps1
```

Result: expected wrapper exit `1`; exact TRX total `8`, unresolved `8`, 0 passed, 8 failed,
0 skipped. Every unresolved Beta finding failed as an independent theory case:

- `META-DPE1-CLEAR-SENDER`
- `META-DPE1-CLEAR-RECIPIENT`
- `META-STORAGE-RAW-TARGET`
- `META-STORAGE-STABLE-IDEMPOTENCY`
- `META-OPAQUE-DEPOSIT-CAPABILITY`
- `META-OPAQUE-RETRIEVE-CAPABILITY`
- `META-PUSH-RAW-ACCOUNT`
- `META-PUSH-ROTATING-HANDLE`

The wrapper distinguishes this required privacy-red signal from harness/infrastructure failure,
which returns exit `2`.

## Harness mutation tests

```powershell
& ./eng/scripts/Test-MetadataPrivacyGateHarness.ps1
```

Result: exit `0`; 17 self-test scenarios passed. Fifteen mutation classes returned harness exit `2`:
omitted strict environment, typo filter, zero-match, missing test, duplicate finding result,
duplicate expectation finding, mismatched expectations count and false-green unresolved outcomes.
Additional mutations cover inconsistent passed/failed/skipped counters, mismatched
`ResultSummary.outcome`, nonzero infrastructure counters, unresolved process exit `2` and resolved
process exit `1`. Positive controls prove current unresolved exit `1` and exact all-resolved exit `0`.

## Evidence paths

- `tests/Deep.Client.Shared.Tests/Services/MetadataPrivacyCharacterizationTests.cs`
- `tests/Deep.Client.Shared.Tests/Fixtures/metadata-expectations.v1.json`
- `tests/Deep.Client.Shared.Tests/Fixtures/metadata-synthetic-fixtures.v1.json`
- `eng/scripts/Invoke-MetadataPrivacyGate.ps1`
- `eng/scripts/MetadataPrivacyGateHarness.psm1`
- `eng/scripts/Test-MetadataPrivacyGateHarness.ps1`
- `artifacts/survival/P01/observer-collusion-matrix.md`
