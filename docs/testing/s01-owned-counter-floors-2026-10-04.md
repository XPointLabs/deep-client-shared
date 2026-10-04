# S01 account-owned Store counter floors — 2026-10-04

Local source integration under
[DR-0092](../../../docs/survival-program/decisions/DR-0092-did2-owned-mailbox-counter-floors.md),
not shipping activation, compaction or physical E2E. Input Protocol
`6afceb2fc457b2df9ea207f542204de945cbb746`, Shared
`13c9b3da35bb94c8690b15d7c320c21885960da3`, Node
`5d4c5d545b62ed0c98e99ddaf9b09dcd405b7d4f`; final source pins belong to the
root RC commit. No deployment, device reset, secret, native asset, wire or crypto
domain changes. The sole local format mapping is
[Shared architecture](../ARCHITECTURE.md#owned-store-counter-floor-format).

## Actual owner and limits

The existing account lease and protected Store root now retain the Protocol replay
namespace, exact grant digest and independent highest reserved counter. New pending
custody enrolls the verified grant before SQL/signing; prepared request and higher
floor are adopted in the same CAS/read-back. A reader cannot reconstruct a missing
floor from remaining work. Full floors reject a new scope before acquisition;
the normal signature/currentness checks still run for a retained winner. Existing
exact unknown work resumes at full capacity. Version3 replaces the previous
reader, including empty roots; isolated old QA accounts require explicit reset,
not migration or automatic repair.

Protocol computes the same namespace as an actual verified issuer/holder-signed
claim. That helper performs structural validation only: it mints no claim,
reserves no replay, and verifies neither signatures nor current authority.

The native owner tests use real DID2/session crypto and SQLCipher with in-process
grant/receipt fixtures, not deployed Registry/node or platform secure storage.
They cover before/after prepared-root interruptions, exact SQL adoption, lost
response/cold reopen, capacity before callbacks and rollback. A corruption fixture
removes a working commitment while retaining its floor, then rolls encrypted SQL
back. The reopened actual signer rejects the reused counter before signing or a
second transport call. Synthetic filler roots prove structural capacity only,
not issuance of512 real grants or sustained compaction.

## Commands and terminal evidence

```powershell
# Protocol repository
dotnet build Deep.Protocol.slnx -c Release --no-restore -warnaserror
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj -c Release --no-build --no-restore --filter FullyQualifiedName~AuthenticatedMailboxCapabilityContractTests --logger trx --results-directory artifacts/s01-owned-counter-floors/final-signed-namespace
dotnet test Deep.Protocol.slnx -c Release --no-build --no-restore --logger trx --results-directory artifacts/s01-owned-counter-floors/full-final
./eng/Test-DeepProtocolRegistry.ps1
./eng/Repin-DeepProtocolRegistrySources.ps1
./eng/Repin-DeepProtocolRegistryAnchors.ps1
./eng/Test-Dnp1EvidenceOwnership.ps1
./eng/Test-ProductionProtocolGraph.ps1 -Configuration Release
# Shared repository
dotnet build Deep.Client.Shared.Production.slnx -c Release -m:1 --no-restore -warnaserror
dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1 --no-build --no-restore --logger trx --results-directory artifacts/s01-owned-counter-floors/full-final
```

Final Protocol/Shared builds finish exit0 with zero warnings/errors. Final signed
namespace selection22/22 finishes exit0, no skips. Full Protocol finishes exit1:
**2087 passed /1 failed /12 skipped**. The unchanged actual package witness rejects
retired MCG2 assembly bytes; source graph still rejects MAU2 in the retired PMA1
consumer. Neither gate is removed or weakened. The twelve separate-evidence
skips remain unqualified as recorded in the
[preceding checkpoint](s00-one-time-custody-2026-10-04.md).

Shared owner/format selection **32/32**, exit0, no skips,12m54s:25 structural
cases and7 actual account-owner cases. This uses the final floor implementation
before the metadata-only registry repin. Final full Shared is running on rebuilt
dependencies; previous552 is not its result.

Strict registry passes44 artifacts/244 magics/10 suites/5 carriers/4 profiles/
11 retired aliases. Earlier drift came from the already accepted DR91 root docs:
reviewed generator repins change only3 normalized source hashes and172 anchor
line positions, plus derived digest files, not wire allocations or quote hashes.
Final dry repins report0 changed sources/0 anchors needing updates.
Evidence ownership classifies314/package219/final95, mapped0/packageMissing219;
this is integrity/classification, not package-complete or release evidence.
Unchanged XNode host builds against the new Protocol source with exit0 and zero
warnings/errors; this is downstream compilation, not a new Node full run.
Root public documentation gate passes174 checks. The precommit scoped secret
scan passes23 selected source/docs/TRX files, including Node reproduction receipts;
it does not yet include a final full Shared receipt.

| Sanitized local receipt | SHA-256 |
| --- | --- |
| Shared `artifacts/s01-owned-counter-floors/focused/nikit_SURFACE-LT_2026-10-04_17_28_42_net10.0.trx` | `7f047eb983ff2186fcab7a0b764d51c00d4bfcfdeea891239816f69178987516` |
| Protocol `artifacts/s01-owned-counter-floors/final-signed-namespace/nikit_SURFACE-LT_2026-10-04_17_57_27_net10.0.trx` | `d4ec9ee8b39ccc9a030d81945d9ce47950b12cd89941d56870d7909cd5d7505c` |
| Protocol core1851/1/12 `artifacts/s01-owned-counter-floors/full-final/nikit_SURFACE-LT_2026-10-04_17_57_47_net10.0.trx` | `b7d0fe5ddc88396d727c549315017f61f5502abf4d1e79ae871f5b02067c1d51` |
| Protocol routes131 `artifacts/s01-owned-counter-floors/full-final/nikit_SURFACE-LT_2026-10-04_17_57_48_net10.0.trx` | `893de7b5b4ba7564b245fc07a86cf83e3a0bb1c15b79f5e39bac162c9c37474f` |
| Protocol carrier105 `artifacts/s01-owned-counter-floors/full-final/nikit_SURFACE-LT_2026-10-04_17_57_48_net10.0[1].trx` | `ac6ae2cb4bcd4388a68ee1b9c7888b915a870ab5f4eb3cfad89e3e5e91a89e6a` |

## Remaining integration fence

No working entry or namespace is retired by this implementation. Protected
compaction plans, terminal evidence, authored sequences, grant renewal,
Retrieve/ACK lifecycle and the unified object/retained-route horizon remain open.
Actual Program/DI and MAUI Release composition must be closed before physical
contact/text; this checkpoint does not replace the auditor's integration-first
DAG. The older Node1205 reproduction uses its preceding dependency binaries,
not this floor matrix, and leaves the original setup PartialFailure unclassified.
