# S01 authored counter floors — 2026-10-06

Status: accepted bounded source slice; cleanup inactive, whole S01 open.

Root input `d3abc9405a07061f0e580970af49d0797fd2a32d`; Shared input
`f4982e38c0848161f4b289218c62fb050e7bec5d` plus the exact patch below.
Protocol source `4fa9f95989db38d1012bd65c0dd73326824b8b91`, unchanged.
Semantic owner: [§8.4.3](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#843-compaction-and-boundedness).
Decision/API: [DR-0098](../../../docs/survival-program/decisions/DR-0098-owned-authored-counter-floors.md),
[private layout](../architecture/owned-authored-counter-custody.md).

## Scope and remaining work

One current private ordinary journal reader, independent conversation/device
counter floors and transition revision, actual owner reservation/CAS/read-back,
SQL floor checks and catalog-backed pending projection. Text/offer share the
original counter; old local text roots reject. No wire/crypto/public Protocol API,
SQL schema, application registration or operator identity/key changes.

Isolated cleanup fixtures test counter survival, not authorization to delete.
The new native fixture uses actual accounts, retained consent, SQLCipher and
native ratchet with independently signed proofs and newly opened account/source
instances for pending/SQL/stable faults. It does not send its queued texts over
sockets or claim physical device/production delivery. No compactor, floor
retirement, accepted-object migration or receipt scheduler is activated.
Protected plan/dependency closure and messaging journal checkpoints remain S01;
whole S01, physical E2E and release are unaccepted.

## Frozen current full-gate inputs

Captured after final focused compilation and before the required full gate.
DLL paths below are the actual test-host copies, not inferred producer outputs.
Actual non-test Production build passed terminal0, zero warnings/errors, 3.89s;
its separate assembly/dependency hashes are included without equating it to the
test-internals build. No rebuild/source edit is permitted during this gate.

| File (Shared-relative) | SHA-256 |
| --- | --- |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDid2DirectTextJournal.cs` | `D049C9B430A69517A3B281CEDA8A42FACF69B8CD115BAC1FE129F7E2387F9C60` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDeepIdV2AccountOwner.TextOutbox.cs` | `4652319266C67523DF526FEF7838C82E38C50AB2F93197AE8BB70B05CEF65AF8` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDeepIdV2AccountOwner.ContactApplication.cs` | `381AE875A4DCAAAE6E934E9122C4E3B615D811446FE23F375AF992DD7EBC963B` |
| `src/Deep.Client.Shared/Persistence/SqliteDeepMailboxStore.OwnedTextOutbox.cs` | `78B49A6CBA2FEC7D284A4B04FDA749F409FAEF863764F91A26BA6B57C3260E71` |
| `tests/Deep.Client.Shared.Production.Tests/Did2OwnedTextOutboxTests.cs` | `2E92FCD4164E6D466787B2BC0C6568598D05ED53AE964928771F27001D7129B7` |
| `tests/Deep.Client.Shared.Production.Tests/DeepIdV2ContactPathAuthoritySourceTests.AuthoredFloors.cs` | `9AB12BDD24906FAAA2407683D6325AD1E0A4210C4E197245844122BF9E473056` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Client.Shared.Production.Tests.dll` | `21AC87857E9273E4B888AE0C2339FEB52F4DD73D62E1E9810DAC470AD9C2EAB8` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Client.Shared.dll` | `0669496199CC54F1A8BA1FFE9624D3B7D364CE8DD6B4419E57A1A5050E60CD27` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Protocol.dll` | `BE194EAE29AECFB680E1E3859269F575AEA8CAF6573C3234CD2EBAE242986F34` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Protocol.MembershipRoutes.dll` | `502BA42B6B88374E8D7C5A7200E8D24F5CD0EBC0F1DB92185EF6243DC6500BA7` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Protocol.ProfileCarrier.dll` | `FA6CC24AA173707D715134AA88F5087F3DAF39F7CC5D95D2F37C87157E4344F8` |
| `src/Deep.Client.Shared/bin-production/Release/net10.0/Deep.Client.Shared.dll` | `5BC331F5AB96099158EF33B455DFA76629FB0E4BAC044FA23C168C0D4EF521E8` |
| `src/Deep.Client.Shared/bin-production/Release/net10.0/Deep.Protocol.dll` | `BE194EAE29AECFB680E1E3859269F575AEA8CAF6573C3234CD2EBAE242986F34` |
| `../deep-protocol/registry/deep-protocol-v1.registry.json` | `22E94830946E05C025F1CF3E44F587293679CA37E845CC79D9156541DDDE00A6` |

## Terminal focused receipts

Candidate connected command:

```powershell
dotnet test tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj -c Release -m:1 --filter 'FullyQualifiedName~Did2OwnedTextOutboxTests|FullyQualifiedName~Did2AuthoredFloor|FullyQualifiedName~Did2ContactOwner_ExplicitAcceptanceExactRetryPeerReceiveAndReply|FullyQualifiedName~Did2OwnedMailboxSend_CommittedTextFaultsExactReopenLostReplyAndDurableReceipt' --logger 'trx;LogFileName=s01-authored-floor-connected.trx' --results-directory artifacts/s01-authored-floor-connected
```

28/0/0 terminal0. TRX SHA256
`010D9488215C25384AA2556E84C7BC8E484B96C75905E7040561544931279DE5`;
start08:45:37.8653579+05, finish08:51:51.8958139+05. After this build, the final
source added refusal of a noninitial floorless root and extended two existing
negative tests; it is not the frozen final full-gate compilation. Do not use
this candidate receipt as a substitute for the current required gate.

Final current focused command:

```powershell
dotnet test tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj -c Release -m:1 --no-restore --filter FullyQualifiedName~Did2OwnedTextOutboxTests --logger 'trx;LogFileName=s01-authored-floor-final.trx' --results-directory artifacts/s01-authored-floor-final
```

25/0/0 terminal0. TRX SHA256
`00195FCF41FF0DCA1700AFC5FAD5B4EB9F10DE1C7B6D35397A26C4100D200CB6`;
start08:52:32.2654202+05, finish08:52:34.0134185+05. Includes seven new unit
cases: initiator/responder empty-working-set cold reopen, three counter-loss/
rollback/advance faults, canonical/missing/foreign/exhausted floors, bounded
floor population without working rows. Native fault case requires the full
gate's current compiled receipt below before source acceptance.

## Required full gate — accepted

```powershell
dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1 --no-build --no-restore --logger 'trx;LogFileName=s01-authored-floor-full.trx' --logger 'console;verbosity=normal' --results-directory artifacts/s01-authored-floor-full
```

The exact final test project and its production project dependencies were built
by the final focused command. Full solution runs those same frozen binaries;
`--no-build` prevents accidental input replacement. Require terminal0, all final
25 unit cases + native authored-floor fault case + actual contact/send/receive
cases independently mapped to Passed, then every frozen hash rechecked before
commit/push. Terminal0: **591/0/0**, all 591 results independently read as
Passed, no skips. Start `2026-10-06T08:53:36.9150606+05:00`, finish
`2026-10-06T09:46:17.8384985+05:00`; duration52.6817 minutes. TRX SHA256
`A1E48C17E8B3EAFC42615BCAC31E8B11B6AABB54125BF41E90A054C4A3E26D00`.

All 25 exact test names from the final focused TRX mapped uniquely to Passed
in this full TRX. Eleven connected results also mapped to Passed:

| Current source scenario | Results |
| --- | --- |
| `Did2AuthoredFloor_ActualOwnerPendingSqlStableFaultsColdResumeWithoutSequenceReuse` | 1/1 Passed |
| `Did2ContactOwner_ExplicitAcceptanceExactRetryPeerReceiveAndReply` | 1/1 Passed |
| `Did2OwnedMailboxSend_RejectsUnavailableOrChangedCustodyBeforeGrantAcquisition`, faults0–3 | 4/4 Passed |
| `Did2OwnedMailboxSend_FullWorkingJournalStillReconcilesExactUnknownAttempt` | 1/1 Passed |
| `Did2OwnedMailboxSend_CommittedTextFaultsExactReopenLostReplyAndDurableReceipt` | 1/1 Passed |
| `Did2OwnedMailboxSend_RemovedWorkingCommitmentCannotSignRolledBackCounter` | 1/1 Passed |
| `Did2OwnedMailboxReceive_ActualPublicationRetainedPageSemanticFaultLostAckAndNextEmptyPoll`, selectedSuccessor false/true | 2/2 Passed |

All14 frozen input hashes matched after terminal completion. This qualifies
the current authored-floor source and connected regression cases, not runtime
cleanup, socket/device delivery, whole S01 or shipping artifacts.

Unchanged shipping blockers remain in NEXT-SPRINT, including actual Protocol
package/source MAU2 closure. Root documentation174 checks pass. This receipt is
local source evidence only, not permission to deploy/reset/publish/merge main.

## Outbox replay prerequisite — focused only

Shared input `a120ebf92dee84fda2fdf77a78fd9858b7316960` plus this patch;
Protocol source `90dbe5135c43be7977389ee148f5c92e0fee94f4`, unchanged.
The same-scope actual owner rejects an existing native committed operation when
its ordinary working entry is absent, before a new pending reservation or SQL
materialization. No wire, schema, format generation or cleanup activation changes.

The extended native authored-floor fixture sends one actual owned text, then
constructs a fixture-only disposition shape by removing both its ordinary entry
and its application SQL outbox row. It keeps independent application history,
native committed custody and both authored counters. Repeated old operation
must fail without reaching any write handover; protected root, complete ordered
outbox/counter/inbox cell digest and native floor remain exact. Separate new work
uses sequence6 and advances the protected next counter to7 exactly once.
The fixture manipulation is not a production selector or remote Store proof.

Receipts (Shared-relative, all terminal and retained):

| Receipt | Result | SHA-256 |
| --- | --- | --- |
| `artifacts/s01-outbox-replay-red/s01-outbox-replay-red.trx` | 0/1/0, terminal1: fixture used insert-only WriteBatch on existing slot; setup corrected to exact CAS | `1E18EF9128938F0E88D4841112D3BDF84C3FAA41059B2E71295B0C645C7F26CE` |
| `artifacts/s01-outbox-replay-red-corrected-fixture/s01-outbox-replay-red-corrected-fixture.trx` | 0/1/0, terminal1: corrected fixture reached new Pending write on original runtime | `5DA730C3F7484D408365660AA1CD4370376CD6E625AD8DB8C5581DA198BAF6DA` |
| `artifacts/s01-outbox-replay-focused/s01-outbox-replay-focused.trx` | 26/0/0, terminal0: actual native case1 and ordinary unit cases25 independently mapped Passed | `F69E5DBF0DCE16B90E94719900F75E1044AF733BED91CF62CFFB4F20623C9596` |

Focused command: production test project, Release, `-m:1 --no-restore`, filter
`FullyQualifiedName~Did2AuthoredFloor_ActualOwnerPendingSqlStableFaultsColdResumeWithoutSequenceReuse|FullyQualifiedName~Did2OwnedTextOutboxTests`.
Green start `2026-10-06T15:20:39.5498911+05:00`, finish
`2026-10-06T15:22:16.5265198+05:00`. Four focused frozen inputs matched after
terminal: owner source `0A7318430879CA3A6CCAE1B6FDE74A030E485EE07E2698EB7BB1C44AB7BC99AE`,
authored-floor fixture `D9E66C9C93215BC26C7F0094BFBC7B637585319AF6C147AC2B53D2531B3B1AEE`,
test-host Shared DLL `8AB634E6D721439C1A30A5A3ACC76592FDA8D4B5A2C62779EDB4B2471A348104`,
test-host test DLL `7426DCBCE1171562C1A2F27D195BD188A78553B39D1AD431E8005DEDA08E74BA`.
Separate non-test Production Release build terminal0, zero warnings/errors.

The required complete coupled gate is deferred until the current outbox-only
disposition/API batch is complete. This focused patch does not inherit prior
full-gate qualification, close S01, authorize native event deletion, preserve
receipt work by assertion, or prove socket/device/shipping delivery. Next remains
the actual bounded selection and dependency/recovery closure, not another stage.
