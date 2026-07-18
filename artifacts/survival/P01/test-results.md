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
$env:DEEP_SURVIVAL_METADATA_GATE='1'
dotnet test Deep.Client.Shared.slnx --no-restore --filter FullyQualifiedName~BetaMetadataGate --logger "console;verbosity=minimal"
```

Result: expected exit `1`; 0 passed, 8 failed, 0 skipped. Every unresolved Beta finding failed as an independent theory case:

- `META-DPE1-CLEAR-SENDER`
- `META-DPE1-CLEAR-RECIPIENT`
- `META-STORAGE-RAW-TARGET`
- `META-STORAGE-STABLE-IDEMPOTENCY`
- `META-OPAQUE-DEPOSIT-CAPABILITY`
- `META-OPAQUE-RETRIEVE-CAPABILITY`
- `META-PUSH-RAW-ACCOUNT`
- `META-PUSH-ROTATING-HANDLE`

The nonzero strict result is the required release signal, not a test infrastructure failure.

## Evidence paths

- `tests/Deep.Client.Shared.Tests/Services/MetadataPrivacyCharacterizationTests.cs`
- `tests/Deep.Client.Shared.Tests/Fixtures/metadata-expectations.v1.json`
- `tests/Deep.Client.Shared.Tests/Fixtures/metadata-synthetic-fixtures.v1.json`
- `artifacts/survival/P01/observer-collusion-matrix.md`
