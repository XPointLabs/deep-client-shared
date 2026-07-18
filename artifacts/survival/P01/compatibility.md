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
& ./eng/scripts/Invoke-MetadataPrivacyGate.ps1
```

The wrapper does not accept a caller-supplied filter. It internally sets
`DEEP_SURVIVAL_METADATA_GATE=1`, uses the exact fully-qualified gate test, writes an isolated TRX,
and verifies the TRX finding set and counters against `metadata-expectations.v1.json`.

- Exit `0`: the exact suite ran and every blocker is resolved.
- Exit `1`: the exact suite ran and every current unresolved blocker failed as intended.
- Exit `2`: environment, filter, no-test, count, finding-set, TRX parse or infrastructure mismatch.

Harness mutation tests:

```powershell
& ./eng/scripts/Test-MetadataPrivacyGateHarness.ps1
```
