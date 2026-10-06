# S01 compaction plan envelope/readback model — 2026-10-06

Status: historical frozen model matrix plus subsequent working-source matrices.
Old full outcomes completed but the original command's exit code was not captured;
they do not qualify current source. The narrow actual prefix SQL/adoption/recovery
owner is now implemented and under focused/native qualification below. Whole
S01, sustained lifecycle, shipping and physical E2E remain unaccepted.

Root input `76aa536b2a033c412c556950680843264d6865d0`;
Shared input `0b38a6dc895b38b833377355b9d80f41c8b6604b` plus this exact patch.
Protocol input `90dbe5135c43be7977389ee148f5c92e0fee94f4`, unchanged.
Semantic owner: [§8.4.3](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#843-compaction-and-boundedness).
Private layout/API: [local plan envelope](../architecture/owned-authored-counter-custody.md#local-plan-envelope-and-successor-custody).

## Original model scope / nonclaims (historical)

One private bounded metadata grammar and exact ordered readback model, with
owned exact successor bytes, canonical scope/target/dependency descriptors,
monotonic phase revision and bounded parts. No SQL writer, protected slot
registration, actor-owned deletion capability, checkpoint/history backend,
cleanup, signer, transport callback, account reset or production activation.

The new36 cases are structural metadata/crash-shape tests. They do not create
a real compaction account, commit a SQL cleanup transaction or prove native
exclusion/terminal evidence. Returned observations and phase encoders cannot
authorize SQL/CAS. Existing current reader/schema/floors remain unchanged.
Actual held owner, mandatory registration/staging/read-back, complete SQL effect
verification, checkpoint/history and retained-object obligations remain S01/S04
integration work. Whole S01, physical E2E and release remain unaccepted.

## Frozen full-gate inputs

Captured after final focused compilation and separate actual Production build.
The exact model/test sources and executed binaries below stay frozen during
the full gate; no rebuild replaces them. Later registration/staging work is
edited separately while it runs and is not covered by this receipt. Test-host
copies are the executed dependency inputs; the non-test assembly is separately
identified. This gate cannot qualify the subsequently edited working tree.

| File (Shared-relative) | SHA-256 |
| --- | --- |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2CompactionPlan.cs` | `8646CA6C9DE6B2E4712D75504515D9FD681CC2C8F45318730D6AEAA5A0322EF8` |
| `tests/Deep.Client.Shared.Production.Tests/Did2CompactionPlanTests.cs` | `F9F702696FE62E054F2C478B180A7E144C5FA338A4CE54399E5E77BD8F8A0E3D` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Client.Shared.Production.Tests.dll` | `2EF490E86CD6B3637024C8F5C32A8C67EFF1532C619C3B74E183A663337A1C95` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Client.Shared.dll` | `6FCFBE3B3F63B1CF8D1E9D94DE430E52A717CB420E9339AD293A99C360D3FA06` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Protocol.dll` | `D0CF5A5C3B69591C62335626F702493F1D6F7A37E03B41744E90C92AAF3E2CC8` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Protocol.MembershipRoutes.dll` | `10DFD55EE696700FD8A6B32CB154EA26892FDAF37C5903677DD706ADD1ADB716` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Protocol.ProfileCarrier.dll` | `22A357F6C787DAD3D3811FF8DA9B7A927DD2053659382578951D8BABC6255A47` |
| `src/Deep.Client.Shared/bin-production/Release/net10.0/Deep.Client.Shared.dll` | `2323EE68A92E3A489DD25B840C02597B573E7AC395A6526BCC9DE9FF0C95C6C8` |
| `src/Deep.Client.Shared/bin-production/Release/net10.0/Deep.Protocol.dll` | `D0CF5A5C3B69591C62335626F702493F1D6F7A37E03B41744E90C92AAF3E2CC8` |
| `../deep-protocol/registry/deep-protocol-v1.registry.json` | `A8FF8ABD6D0C857B2A42AF40BB4F1E932BDCB057967B84B6AEDF99AC7B2985AE` |
| `../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md` | `42096B862E1D00E44F85D562ACF76DC97B36772508C7F2201B00C45F637D2D77` |

## Final terminal focused receipt

```powershell
dotnet test tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj -c Release -m:1 --no-restore --filter 'FullyQualifiedName~Did2CompactionPlanTests|FullyQualifiedName~Did2OwnedTextOutboxTests|FullyQualifiedName~Did2MessagingSqlJournalTests' --logger 'trx;LogFileName=s01-compaction-plan-final.trx' --results-directory artifacts/s01-compaction-plan-final
```

73/0/0 terminal0: independently inspected36 plan,25 authored-floor and12 current
SQL results, all Passed. TRX SHA256
`DB4E8725E7194BA185EA2DEEF06F665B225F0778A393EB944A69479FBB54A055`;
start2026-10-06T10:24:26.4636934+05:00,
finish2026-10-06T10:24:28.7821406+05:00.
Separate actual Production Release build terminal0, zero warnings/errors,4.75s.

An earlier72-case candidate had one fixture failure: changing the already-zero
high byte of a u16 row count did not corrupt its input. The negative input now
sets a nonzero high byte/zero low count; its required rejection assertion is
unchanged. That candidate is not final source evidence.

## Earlier frozen full run — completed outcomes, exit code unavailable

```powershell
dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1 --no-build --no-restore --logger 'trx;LogFileName=s01-compaction-plan-full.trx' --logger 'console;verbosity=normal' --results-directory artifacts/s01-compaction-plan-full
```

TRX contains627/0/0 with every result Passed; all84 required names were matched
exactly (73 final focused, native authored-floor fault, actual contact exchange,
seven owned-send and two owned-receive). SHA256
`8045D54656231EC8A742EB71B6AFF0C9CA64BB912E309292D6619674AEE8F91C`;
start2026-10-06T10:29:13.0851663+05:00,
finish2026-10-06T11:39:23.8095406+05:00. All11 inputs were last checked unchanged
after the history build and before this run completed. The observer completed,
but printed no original ExitCode: its own terminal0 is not the original command
receipt. The original process is gone. Do not restart this old run just because
observation was incomplete: require a fresh full gate of the completed current
coupled API change instead. No old-full or whole-S01 acceptance is inferred.
Later peer-bootstrap selection updates the model source after these binaries
finished; this frozen table is historical, not current source/package evidence.

## Registration/staging working source — separate matrix

Edited after the model gate began, without replacing any of its11 inputs.
This is the same S01 integration task, not another accepted release stage.
`SqliteDeepIdV2AccountGeneration.EnsureAsync` now inserts the empty scoped plan
with the account key/instance and other mandatory roots in the existing atomic
batch. It requires that root on reopen and rejects active state before ordinary
receiver reconciliation. No new SQL/application generation, optional marker,
missing-slot initializer, SQL deletion or active-plan recovery is added.

`ProtectedDid2CompactionPlan` stages exact owned successors through the existing
CAS-and-insert under a matching actual borrowed file lease, validates all parts
and plan read-back, and preserves cold exact retry after a lost publication
response. Capacity/protection/conflicts publish neither a half-plan nor partial
parts. It does not authenticate terminal descriptors or authorize native/SQL
mutation; fabricated descriptors are deliberately hostile metadata fixtures.

Build/test output paths were independently queried before dispatch. The test
host is under `artifacts/s01-compaction-owner-build`; source-cutover non-test
output is `src/Deep.Client.Shared/bin-production/release/Deep.Client.Shared.dll`.
Neither replaces the frozen model host or its `Release/net10.0` non-test input.
All11 original frozen inputs were checked unchanged after these builds.

Final focused14/0/0 terminal0; TRX
`artifacts/s01-compaction-owner-final/s01-compaction-owner-final.trx`, SHA256
`9591DEE2A28973D99A600F367DCF50F89B986B22DDBA17325A69D6C63B21F95A`,
start2026-10-06T10:47:08.9182119+05:00,
finish2026-10-06T10:47:09.8715934+05:00.
Includes one genuine DID2-account registration/reopen/reset case plus13 actual
lock/storage staging cases, not genuine compaction selection or SQL cleanup.
The first14-case candidate was13pass/1fail: a cold fixture incorrectly shared
an owned protector, which the second store disposed. Each store now owns its
own protector; authentication assertions remain unchanged. Candidate excluded.

Connected registration/reopen/lease/storage regression37/0/0 terminal0, all
outcomes independently inspected as Passed; TRX
`artifacts/s01-compaction-registration-regression/s01-compaction-registration-regression.trx`,
SHA256 `E83F847D031BB7B07DCDFE2F77AE3E2BFE72CFD616763CF5EC1A1D114676EEDD`,
start2026-10-06T10:48:51.3672014+05:00,
finish2026-10-06T10:48:53.4130254+05:00.
Actual non-test Production build terminal0, zero warnings/errors,11.19s.
Combined current model/staging/authored-floor/SQL matrix87/0/0 terminal0, all
outcomes independently inspected as Passed; TRX
`artifacts/s01-compaction-current-combined/s01-compaction-current-combined.trx`,
SHA256 `A86D5B3C779CF5B2A0436BEBADF019E89AFEF65F1A16066C51379AE3091A18F3`,
start2026-10-06T10:52:35.4367352+05:00,
finish2026-10-06T10:52:36.7919727+05:00.
Connected actual contact/send/receive/native authored-floor checks completed
on that same registration host:11/0/0 terminal0, every outcome independently
inspected as Passed. TRX
`artifacts/s01-compaction-registration-connected/s01-compaction-registration-connected.trx`,
SHA256 `09582E8AD25695219E1BBD6EA4183008A14EF676D9DE3EB6AE4E747EFF43FBC9`;
start2026-10-06T10:53:21.0600021+05:00,
finish2026-10-06T11:28:07.7849598+05:00.
This focused matrix does not substitute for the required full gate of the
completed coupled S01 API/consumer change. Selection, SQL complete-effect
verification/adoption/recovery, checkpoint/history and retained-object closure
remain unfinished; no source or whole-S01 acceptance is claimed here.

| Registration-matrix file (Shared-relative; not the later history host) | SHA-256 |
| --- | --- |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDid2CompactionPlan.cs` | `8D1424BF7B6764FF2A3B9B3B1002B8B80921D307233523F6B8BCD7B5A8CB703A` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/SqliteDeepIdV2AccountGeneration.cs` | `CF43343AEDE65A893DD2577A906D132D11EEEA3116869C5F58389C8C831346A9` |
| `tests/Deep.Client.Shared.Production.Tests/ProtectedDid2CompactionPlanTests.cs` | `1D83C94BD498F98120F14A20ED324B9AEE93CA102B5356633637314891695EA3` |
| `tests/Deep.Client.Shared.Production.Tests/ProtectedDeepIdV2AccountOwnerTests.cs` | `A299D4D692F34FB895C7A95AC5375DF7FFCD6D18F310B000B95504269C7C5F9E` |
| `artifacts/s01-compaction-owner-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Client.Shared.Production.Tests.dll` | `C3B7A3387103D1959553167D8E109F38322A42B8DCC6CAF8639ECBF4E46D5BCC` |
| `artifacts/s01-compaction-owner-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Client.Shared.dll` | `ECB1589C180239C6EE0709A4141774E13EB363191EC080FE8FAD550F635D7097` |
| `artifacts/s01-compaction-owner-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Protocol.dll` | `C98012ADB0E81998B83A46D16D431EAA91B304B3215A57E077624ECD53BBC8A8` |
| `artifacts/s01-compaction-owner-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Protocol.MembershipRoutes.dll` | `4A5A7B6C38B753D848AA07D7E74D749F07265476741FBE05184B87BCEA16F645` |
| `artifacts/s01-compaction-owner-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Protocol.ProfileCarrier.dll` | `B751BAD65B3E182912E31E94321211C2B4A664F7DCDF344FD226A880E531E3D1` |
| `src/Deep.Client.Shared/bin-production/release/Deep.Client.Shared.dll` | `A6DB69487C3C97FAB4F46957D0EE774AE28BF9FE2181DEBD8A662EF1BF20F078` |

## History consumer working source — separate matrix

Same unfinished S01 task. [Consumer mapping](../architecture/owned-authored-counter-custody.md#messaging-history-checkpoint-consumer)
describes the mandatory protected root and schema3-only reader. No production
SQL-prefix deletion, plan selection/adoption/recovery or cleanup owner is
installed. The native fixture explicitly simulates the proposed SQL/root
outcome; its actual DID2 accounts, contact authorization, native crypto,
retirement and SQLCipher qualify retained acceptance/history/exact replay and
the next owned ratchet operation, not deletion authority or physical delivery.

```powershell
dotnet test tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj -c Release -m:1 --no-restore --artifacts-path artifacts/s01-history-checkpoint-build --filter 'FullyQualifiedName~Did2MessagingHistoryCheckpointTests|FullyQualifiedName~Did2MessagingSqlJournalTests|FullyQualifiedName~Did2CompactionPlanTests|FullyQualifiedName~ProtectedDid2CompactionPlanTests|FullyQualifiedName~Did2OwnedTextOutboxTests' --logger 'trx;LogFileName=s01-history-checkpoint-final.trx' --results-directory artifacts/s01-history-checkpoint-final
dotnet test tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj -c Release -m:1 --no-build --no-restore --artifacts-path artifacts/s01-history-checkpoint-build --filter 'FullyQualifiedName~Did2HistoryCheckpoint_ActualOwnedPrefixColdReopenPreservesAcceptanceReplayAndNextRatchet' --logger 'trx;LogFileName=s01-history-checkpoint-native-final.trx' --results-directory artifacts/s01-history-checkpoint-native-final
dotnet build src/Deep.Client.Shared/Deep.Client.Shared.Production.csproj -c Release -m:1 --artifacts-path artifacts/s01-history-checkpoint-production-build
```

Terminal receipts, independently inspected with no non-Passed outcomes:

- Structural/current114/0/0, terminal0; TRX SHA256
  `21A18D2BED09738A326E39D7DD0AF28F87F495CD68C93EB2AC0EEF4D3C140AEE`,
  start2026-10-06T11:31:07.3582342+05:00,
  finish2026-10-06T11:31:08.7131717+05:00.
- Genuine native1/0/0, terminal0; TRX SHA256
  `0ED68E209B4C26BFB5040CC6933F954D70B7BDA04737EE1365220B76552DD9A8`,
  start2026-10-06T11:31:31.9652056+05:00,
  finish2026-10-06T11:33:46.9364055+05:00.
- Actual non-test Production build terminal0, zero warnings/errors,18.57s.

Hostile cases reject scope/version/size/phase/counter/commitment corruption,
initial-evidence substitution, revision overflow, count/ratchet regression,
missing protected state and retired SQL schema2. The genuine case additionally
rejects SQL-prefix removal under the old root, root rollback and same-shape
plaintext substitution; cold exact replay preserves the floor and the next
owned text extends it exactly once. Structural lifetime4098 metadata is not a
genuine4096-message soak or permission to enlarge the working cap.

Excluded candidates: the first structural build missed a test namespace import;
the first114 run had113pass/1 fixture failure because insert-only WriteBatch was
used to replace the deliberately foreign root. The fixture now uses exact CAS;
required rejection/unchanged-state assertions remain. A fresh non-test artifacts
path first lacked restored assets; the final command restored/builds that path.

The history host and non-test build use isolated outputs. All11 original model
inputs were rechecked unchanged after the builds. Neither focused receipt is a
full-gate receipt for the completed coupled S01 API, shipping artifact or device.

| History-matrix input (Shared-relative) | SHA-256 |
| --- | --- |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2MessagingHistoryCheckpoint.cs` | `73F25559B958818955A51000CFB1CA0B56C91CBD5EA47C6458E3FC961C2B733D` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2MessagingSqlJournal.History.cs` | `45B3951DFDAEAD9E757EF9FDF738CB990DC3E0902569A7EA47C59457D96790AB` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2MessagingSqlJournal.cs` | `DC58152E86676F202F400F4D08BE91178F5EAE228CB44FCA398970766ADA471D` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2MessagingDurableCustody.cs` | `D419C00DF2483A4403D61B8119B99A4F2AE1E2899D95656ECBA52037719188EE` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDid2MessagingSessionCatalog.cs` | `8555C7050D46FF8DF6D29343CED1A1B899E2D0957A62276C2EA703D65DEA1438` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/SqliteDeepIdV2AccountGeneration.Messaging.cs` | `2551BCC541620B4CB2C046A7751B5613956C6FBD1526A2FC5B67905F3193FA6B` |
| `tests/Deep.Client.Shared.Production.Tests/Did2MessagingHistoryCheckpointTests.cs` | `7B3EDF411980B84354F2D0354FAA698769D561AA00636E87E45F303BEEB848C1` |
| `tests/Deep.Client.Shared.Production.Tests/Did2MessagingSqlJournalTests.cs` | `002405D86371C1C5E6AA2FD70B53EFC59D284D4622D6A24A91EFDBB8E31A52D7` |
| `tests/Deep.Client.Shared.Production.Tests/DeepIdV2ContactPathAuthoritySourceTests.HistoryCheckpoint.cs` | `7EC642D0B566A96B2807D0015C79B995EDDC23990F20EECFC62A6EE5207F168B` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Client.Shared.Production.Tests.dll` | `CCC4B97656E91CF87D17AC8B690016047CA9169093EF7BE1A9F705112E43CAB6` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Client.Shared.dll` | `06F188B5F79BD37248C845CB32733F375491D337A77BC3618E38E6502F349153` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Protocol.dll` | `B9CC19C9D53E6DB5D9F5E29AE8CFBDF7F61AF8CFE26556A46F26D9489A52C869` |
| `src/Deep.Client.Shared/bin-production/release/Deep.Client.Shared.dll` | `868CFB5173B55CC80A3A35E3176E7C84104AA1EF2D607209630566CD5B46871B` |

## Held prefix selection / complete SQL projection — preceding working matrix

At this preceding source checkpoint, after the old full binaries finished, the private model added guard-only peer
bootstrap kind11; the unknown-kind fixture now rejects12. No wire, magic, suite
or compatibility reader changed. The actual owner derives a metadata preparation
from the verified owned session under the matching lease; it does not stage or
apply that plan. [API/effect boundary](../architecture/owned-authored-counter-custody.md#messaging-history-checkpoint-consumer).

Final command uses the preceding history-build artifacts path and the same five
structural filters plus
`FullyQualifiedName~Did2HistoryCheckpoint_ActualOwnedPrefixColdReopenPreservesAcceptanceReplayAndNextRatchet`;
logger/results are `s01-prefix-selection-current-final.trx` under
`artifacts/s01-prefix-selection-current-final`.121/0/0 terminal0, every result
independently inspected as Passed, including exactly one genuine native case.
TRX SHA256 `CC237622EC07848421AC4AAFF5352484D9F7CF7BFD0C4C1B325056A3B337F5A5`;
start2026-10-06T11:50:42.5527581+05:00,
finish2026-10-06T11:53:04.2537619+05:00.
Actual non-test Production build with the same preceding production-build
artifacts path and `--no-restore`: terminal0, zero warnings/errors,10.62s.

The genuine case checks the actual owner preparation's SQL before/after and
owned exact successor against verified capture. Fixture-only prefix trim gives
the exact complete successor; payload substitution changes its digest. Six
additional cases cover peer guard-only state, hostile type/size and a zero-
ordinal journal row that cannot disappear from the projection. Earlier115 was
a candidate before these checks; a first compilation missed the ApplicationCore
verifier namespace. Neither is this final source receipt.

This preceding host Tests DLL SHA256
`A63AB9AD08EBE81B5411E04FDC244074BFFC1860EE2574002D782CD9C94464F2`;
host Shared `73DC68DA73516C31E3F31D7CC7CF60F634A1B7D1BB44CA4A7F63338591B36F37`;
non-test Shared `CAE57DC647015150A5A94DB4AFCCAEF63CEB744F1AC2436ACAB68980292F64B2`.
Protocol host retains the preceding history-matrix hash. These are isolated
working-source outputs, not a shipping package. Root documentation174 and
scoped sensitive scan20 files/zero findings pass. Apply/adoption/recovery,
cancellation/clear faults and retained-object closure remain unfinished.
No source commit, current full-gate acceptance, cleanup activation, device run
or S01 closure is claimed by this preceding selection matrix. The current
coupled API/recovery matrix follows; historical627 cannot substitute for its
required fresh full gate.

## Actual held prefix SQL/adoption/recovery — current working source

The private owner now selects/stages a bounded actual owned prefix, independently
re-captures complete SQL/row/dependency effects, applies one SQLCipher transaction,
records commit, CAS/adopts/read-backs the exact history successor and disposes
staging before clearing. Startup resumes the same stored plan before ordinary
reconciliation; other opens still require idle custody. No service/UI/scheduler
activates fresh cleanup, other dispositions, floor unenrollment or remote settlement.
See the [actual owner boundary](../architecture/owned-authored-counter-custody.md#messaging-history-checkpoint-consumer).

Durable abort phase3 owns only unchanged complete predecessors/SQL Before.
It allows crash-safe staging disposal; SQL After cannot abort, reselect or
reconstruct deleted rows. Phase3 is private local state, not a wire/version change.
Root/SQL read-back also precedes checkpoint adoption and successor disposal.

First recovery command: the history-build artifacts path, filter
`FullyQualifiedName~Did2CompactionPlanTests|FullyQualifiedName~Did2Compaction_ActualEncryptedOwnerAllHandoversColdResumeAndCancellationPreserveExactEvents`,
logger/results `s01-prefix-recovery-native.trx` under
`artifacts/s01-prefix-recovery-native`.53/0/0 terminal0, all results Passed;
TRX SHA256 `76CBBB2F5E08445C6E8E441A8C89C91306B7E6039DB6644C0988B963AEB8A727`,
start2026-10-06T12:09:22.2558191+05:00,
finish2026-10-06T12:15:29.8212266+05:00. This is a preceding candidate before
the additional hostile checks and pre-mutation dependency rechecks.

The genuine native case uses independently authored accounts/contact/acceptance,
actual owned retirement/ratchet and SQLCipher. Sender protected custody uses a
real encrypted journal file with closed/reopened store and protector handles.
Six injected handovers cover stage, SQL commit, recorded commit, history adoption,
part disposal and idle clear. Each cold startup retains the exact floor and
ContactAccept replay; subsequent text extends the ratchet once. Pre-SQL cancel
and crash during explicit durable abort clear resume unchanged SQL. Post-SQL
cancel rejects abort and finishes the same stored plan without fresh proof.
This is a local owner fixture, not Windows/Android device, network deploy or
sustained512/128 delivery evidence.

Separate preceding structural/current130/0/0 terminal0, all Passed, includes
plan/staging/history/SQL/authored-floor/account-owner classes. Receipt
`artifacts/s01-prefix-recovery-focused/s01-prefix-recovery-focused.trx`, SHA256
`32921F25C3383FC9C4262F8D1A207EEBDE82794C02812622B5A75D3D3567E537`;
start2026-10-06T12:18:15.5728086+05:00,
finish2026-10-06T12:18:17.4942345+05:00. Final source adds dependency read-back
immediately before history CAS and staging disposal, so this prior host is not
the final full-gate input.

The first hostile candidate had0/1/0 terminal1 because its new SQL substitution
assertion expected CryptographicException; the closed readback model actually
returns InvalidDataException for third outcomes. The corrected fixture expects
that exact contract error and still verifies every observed protected slot and
complete SQL digest remain unchanged. Missing parts/peer guard, same-shape SQL
payload substitution and exact SQL rollback after the commit marker remain
mandatory cases. Fixture-only restoration is not a production repair path.

The pre-sanitization focused/native run completed131/0/0 terminal0; every result
was independently inspected as Passed, including the genuine owner fixture.
Receipt `artifacts/s01-prefix-owner-final/s01-prefix-owner-final.trx`, SHA256
`4B64AF5570F3F379632F6F3FE6B6A27DACB239E1B5A0B5A3143CC41578CBD7D3`;
start2026-10-06T12:20:57.9851277+05:00,
finish2026-10-06T12:26:56.4285692+05:00.
The last test-only change compares SHA256 commitments, not raw protected records,
so a failed unchanged-state assertion cannot dump catalog/SQL keys. It preserves
the same rejection and unchanged-state invariants. The current full run must
qualify that exact updated fixture, not inherit this preceding receipt.
Actual non-test Production build after final rechecks passed terminal0,
zero warnings/errors,4.84s. Root documentation174 and sensitive scan23files/0
findings passed. No production deploy/reset, shipping or device claim follows.

## Current coupled full gate — running, not accepted

```powershell
dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1 --no-build --no-restore --artifacts-path artifacts/s01-history-checkpoint-build --logger 'trx;LogFileName=s01-prefix-owner-full.trx' --logger 'console;verbosity=normal' --results-directory artifacts/s01-prefix-owner-full
```

The final host was rebuilt after the test-output sanitization. Its structural
focused command retains the six class filters, logger/results
`s01-prefix-owner-sanitized-focused.trx` under
`artifacts/s01-prefix-owner-sanitized-focused`;130/0/0 terminal0.
All130 results were independently inspected as Passed; TRX SHA256
`F43FD727ED2471F7347484ED6EE3CCEB29ACF0190AE62D67423620B36E5A6BBD`,
start2026-10-06T12:28:12.6721505+05:00,
finish2026-10-06T12:28:14.9365351+05:00.
The full command is running against that same frozen host, with an explicit
terminal exit marker in its shell output. It is not accepted until terminal
exit0, independent complete TRX inspection, required-case mapping and unchanged
input recheck. Do not rebuild/replace this host or edit these compiled inputs
while it runs. Documentation may record progress without changing that matrix.
Required coverage includes all131 preceding focused/native case names plus the
existing genuine authored-floor/contact/owned send/receive regressions. Committing
this checkpoint records implementation and frozen inputs, not full-gate
acceptance or whole S01 closure. Terminal qualification or failures will be
recorded separately; no Release/main/deploy follows from the checkpoint.

| Frozen current input (Shared-relative) | SHA-256 |
| --- | --- |
+| `../deep-protocol/registry/deep-protocol-v1.registry.json` | `A8FF8ABD6D0C857B2A42AF40BB4F1E932BDCB057967B84B6AEDF99AC7B2985AE` |
| `../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md` | `42096B862E1D00E44F85D562ACF76DC97B36772508C7F2201B00C45F637D2D77` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Client.Shared.dll` | `EF08A9BF205F03C0C32B8BF3FBF430005D54F6F3AE6ABE1A1F90A22E4553ADAC` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Client.Shared.Production.Tests.dll` | `1DF3F33EE30127B0F479F528DA7B32A13E52908A4FCB7C0D3CE579F8B7F613CB` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Protocol.dll` | `B9CC19C9D53E6DB5D9F5E29AE8CFBDF7F61AF8CFE26556A46F26D9489A52C869` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Protocol.MembershipRoutes.dll` | `E8ACA7A5DF804C9CC14E0F20B28C64517AB2C52623983AA4755C46B3A9B2AD00` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/Deep.Protocol.ProfileCarrier.dll` | `686A9DF03990CCAD7135B15B8D1F543544A17801650D029B1BB014773300EBC1` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/runtimes/win-x64/native/deep_mldsa.dll` | `EE20D61AA6B0ACBD048FBE9F2554B344657BFE6C412EBB7BE6DD5632EA14E7D5` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/runtimes/win-x64/native/deep_mlkem_braid.dll` | `902C80F52221EE2A4DA340F01ED7F3C40EB6EA51F7D91584031AC5679D829E74` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/runtimes/win-x64/native/deep_mlkem.dll` | `462A80FEDA563B30312E836CAD108923EEED0AA16CE1365DE7A8506D389AF8EB` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/runtimes/win-x64/native/e_sqlcipher.dll` | `895C0F5203352446F159D7780021B69B280DEC6347C434C7A643AD6B7D0D883B` |
| `artifacts/s01-history-checkpoint-build/bin/Deep.Client.Shared.Production.Tests/release/runtimes/win-x64/native/libsodium.dll` | `64A1F143868309069F0A0A3C8141C0853C4F17243DDF734E92B11C5411739771` |
| `Deep.Client.Shared.Production.slnx` | `83BB26F71E9FAFDE18AAE7576BD7413C73851FEB71DD2A043482F8133368E4D8` |
| `src/Deep.Client.Shared/bin-production/release/Deep.Client.Shared.dll` | `42F2285257BADA9716311D84EB3107DE2D328B13C53522CD29298153F353B305` |
| `src/Deep.Client.Shared/Deep.Client.Shared.Production.csproj` | `006495C32393D79A37F3458FBBDC350AE2E1EF74FA7E28634327F22AB3FF105F` |
| `src/Deep.Client.Shared/Directory.Build.props` | `5E464BAF268FF3A6C9E973CD641DE4BCC2C696A186ED0B8D5B7A9D0BA4B8011F` |
| `src/Deep.Client.Shared/packages.lock.json` | `0EADFC746386B0596A1E81E10990799E6555981C031D7948AE036164A1F492ED` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2CompactionPlan.cs` | `DE5B6CD424CC465FA5E47A68669369152718CC45FD561052BC1A2F05EA6294A3` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2CompactionTestHooks.cs` | `D27C0E671D9CA2A4143A33BE21769BD02F4A2EA7C875A06F41DF5C575840E464` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2MessagingDurableCustody.cs` | `D419C00DF2483A4403D61B8119B99A4F2AE1E2899D95656ECBA52037719188EE` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2MessagingHistoryCheckpoint.cs` | `73F25559B958818955A51000CFB1CA0B56C91CBD5EA47C6458E3FC961C2B733D` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2MessagingSqlJournal.Compaction.cs` | `73C19398C4537C819A2588CA7221728B15A79FBBE945F9961A9789C7545F4626` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2MessagingSqlJournal.cs` | `DC58152E86676F202F400F4D08BE91178F5EAE228CB44FCA398970766ADA471D` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2MessagingSqlJournal.History.cs` | `45B3951DFDAEAD9E757EF9FDF738CB990DC3E0902569A7EA47C59457D96790AB` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDeepIdV2AccountOwner.Compaction.cs` | `85B59C5D0DCC9172C49A738211B5E4033208AB39BF9790BE46A11CC2B6845A96` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDeepIdV2AccountOwner.cs` | `B44843C211C1E88744B771004E0E1A2D2D899699FBDEC6DB1D43CF1519B6BD69` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDid2CompactionPlan.cs` | `8D1424BF7B6764FF2A3B9B3B1002B8B80921D307233523F6B8BCD7B5A8CB703A` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDid2MessagingSessionCatalog.cs` | `8555C7050D46FF8DF6D29343CED1A1B899E2D0957A62276C2EA703D65DEA1438` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/SqliteDeepIdV2AccountGeneration.cs` | `A049F6C013353F7B0D2C58A539D3A865B6A95D31650E80C027156E2E4B180483` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/SqliteDeepIdV2AccountGeneration.Messaging.cs` | `48A15877C34B722C7A0A2ABEDF27E21D4EB0945B29145BEFBDC4C2E527A22901` |
| `tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj` | `49351CB93CC6CA6CFDC177CCCB3038D270A7EBFCDAB7025A202A23BFE541E9A2` |
| `tests/Deep.Client.Shared.Production.Tests/DeepIdV2ContactPathAuthoritySourceTests.CompactionRecovery.cs` | `693B662AD21ECD9C0752DB4FC738C0E1A70B2D33E030B4B3E65D5471AD7DE419` |
| `tests/Deep.Client.Shared.Production.Tests/DeepIdV2ContactPathAuthoritySourceTests.cs` | `AA51DE9406B909755FB2B56C67511499B67864F2449B05444D4774A208D43F84` |
| `tests/Deep.Client.Shared.Production.Tests/DeepIdV2ContactPathAuthoritySourceTests.HistoryCheckpoint.cs` | `12144403BC5239D1DF8863C55DA559AD11C293AC2524299DBC60A64BBAACC339` |
| `tests/Deep.Client.Shared.Production.Tests/Did2CompactionPlanTests.cs` | `7FBB19A24F39E7FC2D6E64245861333F620EE6CCA5BFD85C688451AE3740A364` |
| `tests/Deep.Client.Shared.Production.Tests/Did2MessagingHistoryCheckpointTests.cs` | `7B3EDF411980B84354F2D0354FAA698769D561AA00636E87E45F303BEEB848C1` |
| `tests/Deep.Client.Shared.Production.Tests/Did2MessagingSqlJournalTests.cs` | `F713BDBC694CA5F0217EF678091292D6BDCA3F5A6057FC56598B70DB261B5E3C` |
| `tests/Deep.Client.Shared.Production.Tests/ProtectedDeepIdV2AccountOwnerTests.cs` | `A299D4D692F34FB895C7A95AC5375DF7FFCD6D18F310B000B95504269C7C5F9E` |
| `tests/Deep.Client.Shared.Production.Tests/ProtectedDid2CompactionPlanTests.cs` | `1D83C94BD498F98120F14A20ED324B9AEE93CA102B5356633637314891695EA3` |
