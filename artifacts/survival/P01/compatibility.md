# Compatibility

- Base commit: `2e55f78c68699520e49ec0c8d5ddebd4b9817584`.
- Production source files changed: none.
- DPE1 bytes, storage RPC, routed transport and push DTO semantics: unchanged.
- Existing fixture `push-signature-v2.golden.json`: unchanged.
- New files are test fixtures, characterization tests and evidence only.
- The default test lane remains green.
- The strict lane is intentionally red while any `beta_blocking` finding is not `resolved`.

Strict lane:

```powershell
$env:DEEP_SURVIVAL_METADATA_GATE='1'
dotnet test Deep.Client.Shared.slnx --no-restore --filter FullyQualifiedName~BetaMetadataGate
```

This lane has one xUnit theory case per blocker and uses no skipped tests.
