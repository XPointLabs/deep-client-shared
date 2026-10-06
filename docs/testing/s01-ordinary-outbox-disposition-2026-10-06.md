# S01 ordinary outbox-only disposition — 2026-10-06

Scope: the internal dependency-closed application-database cleanup described in
[the owned consumer mapping](../architecture/owned-authored-counter-custody.md#owned-ordinary-outbox-only-api).
Sole semantics remain workspace TRANSPORT-NEUTRAL-MESSAGING §8.4.3. No scheduler,
namespace retirement, remote-object cleanup, shipping or physical E2E is activated.

## Working source and acceptance boundary

Owned selection verifies original Store/request/grant/counter custody, actual
signed quorum, native event and independent history before selecting a bounded
settled prefix. One actual account lease selects/stages; one application SQLCipher
transaction independently recaptures and commits complete effects. Recovery
dispatches the exact stored application profile, adopts only the ordinary root,
disposes bounded staging and clears after complete agreement. Cold recovery uses
existing initialized account registration, without fresh network authority or
payload reconstruction. History, native events, transport evidence, counters,
dedup, receipt obligations and asset keys are retained.

The Store completion reader now supports a removed working command through
independent native/history custody and the preserved authored floor. The E2EE
send precondition now uses that same retained-event join, requiring exact bytes
and an existing native send before returning cached ciphertext. Its focused
positive/changed-input/missing-history fixture passes. The coupled full gate below
accepts this bounded outbox-only API and its affected readers/recovery, not the
remaining S01 dispositions/fences or S04 runtime cleanup.

## Current coupled full gate — accepted outbox-only slice

Qualified runtime/test source: Shared
`574d934347fb21f48453def7541a0a7a7a86d06d`. The final isolated host was used
without rebuilding or modifying its inputs during the run:

```powershell
dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1 --no-build --no-restore --artifacts-path artifacts\s01-outbox-owner-final-build --logger 'trx;LogFileName=s01-outbox-owner-final-full.trx' --logger 'console;verbosity=normal' --results-directory artifacts\s01-outbox-owner-final-full
```

Observed shell marker `S01_OUTBOX_OWNER_FINAL_FULL_TERMINAL_EXIT=0` and process
exit0. Receipt: `artifacts/s01-outbox-owner-final-full/s01-outbox-owner-final-full.trx`
(Shared-relative), SHA256
`D3FCF3437971DA0B3B5FE416B3CDBF5C46E20CFA1E428E4CC3BCD5306DF07F2E`.
Start `2026-10-06T16:52:43.0696231+05:00`, finish
`2026-10-06T18:31:44.6302396+05:00`.

All687 cases passed, failed/skipped/other counters0. Independently checked:
687 unique result names/execution IDs,687 unique test IDs and687 actual test
definitions; exact frozen discovery with no missing/extra cases, all161 current
required and all678 prior required cases mapped Passed. Both new native cases
are Passed: encrypted cold recovery/all handovers and exact cached encryption
with independent retained history. The prior required authored-floor, removed-working
commitment, receive/ACK and other required regressions remain in this full run.

Expected catalog/input manifest:
`artifacts/s01-outbox-owner-final-full/expected-qualification.json`, SHA256
`4095F2C250FF4361BA62BD4A2C5C4C17EB347F4680464051E8B4FF85105D5336`.
All55 frozen source, normative and actual host/native inputs rechecked exact
after terminal0. The read-only qualifier also rejected partial focused receipts
and a nonzero process exit; it does not turn those receipts into full evidence.

This accepts local selection/staging, complete application SQL effects/writer,
protected adoption/recovery/abort and affected Store/E2EE readers on this matrix.
Native send/grant/receipt/history/asset custody and floors are retained. No
namespace retirement, receipt scheduler, remote-object deletion, sustained
capacity lifecycle, production deployment, shipping package or physical E2E is
qualified by this receipt. Whole S01 and the release remain open. Earlier failed
receipts below remain failures; they are not overwritten or reclassified.

## Focused observations (not full qualification)

| Local TRX under `artifacts/` | Outcome and scope | SHA-256 |
| --- | --- | --- |
| `s01-outbox-selection-connected-corrected/s01-outbox-selection-connected-corrected.trx` | 33/0/0, terminal0: read-only selection, actual Store/native joins and SQL facts; before writer integration | `E10EE664E91898CFBB59979144ED2FA1C63E6200C5C90756A8998A9B404A07F9` |
| `s01-outbox-owner-connected/s01-outbox-owner-connected.trx` | 32/1/0, terminal1: new encrypted-owner fixture rejected its future receipt against frozen synthetic proof time | `A62CB63E753D811FF5307FC323E4EE7D24C084BA226FAC567A9B94F76D6B6590` |
| `s01-outbox-owner-clock-corrected/s01-outbox-owner-clock-corrected.trx` | 32/1/0, terminal1: reached all six handovers/cold replay checks, then attempted outcome-unknown retry before its lease elapsed; whole case FAILED, not accepted coverage | `E773A58B0A4A9B34CB5D6DCA752A37A7F5BB46FB69F60951F2BABAE0E5C58867` |
| `s01-outbox-owner-lease-corrected/s01-outbox-owner-lease-corrected.trx` | 33/0/0, terminal0: six handovers, cold recovery, exact SQL rollback refusal, missing staging/peer/application registration and altered payload, before/after SQL cancellation, old-operation refusal, next counters/history and cached Store; before E2EE cached-send reader integration | `A24A9973A72A2A6824E925F2C9ABC5989742D528A8FD40C1820FFE03A9B9630D` |
| `s01-outbox-plan-regression/s01-outbox-plan-regression.trx` | 71/0/0, terminal0: plan/staging/catalog structural regressions on that same host | `A5DAB4D5FE2DFBF298D0B0189A9865B00DF1FA1A18C5D1496CE9AD933788A4DA` |
| `s01-outbox-cached-encryption/s01-outbox-cached-encryption.trx` | 104/0/0, terminal0: native exact cached encryption, changed bytes/missing independent history refusals, stable native floor/complete application effects, plus103 structural/local cases | `80AFB348B28CD8C0DDD412E903968FFF30B20AFADC1520ACEE92E20F4B54917C` |
| `s01-outbox-final-structural/s01-outbox-final-structural.trx` | 103/0/0, terminal0: same cases after giving the two truncated SQL corruption variations distinct fixture case IDs | `9050220307EDDFD1AF94991F981DC5EA9DB0C16364DA548868BD34DE4C0CC074` |

First owner run: start16:17:33.6755113+05, finish16:19:37.4054108+05.
Clock-corrected run: start16:23:28.7117334+05, finish16:32:11.6944390+05.
Lease-corrected run: start16:33:08.4314567+05, finish16:41:47.3240662+05.
All19 frozen source/host inputs were rechecked exact after its terminal0.
Structural run: start16:40:33.0864920+05, finish16:40:34.7429276+05.
Cached-encryption run: start16:44:10.6304291+05, finish16:46:51.3796870+05.
Its20 frozen inputs were checked after terminal:19 exact, one controlled delta
in the local unit fixture's display case IDs. All compiled host/runtime inputs
and the actual cached-encryption/native fixture remain exact; this does not
claim an unchanged20/20 source matrix. Final structural run uses the rebuilt
isolated host: start16:48:26.9882384+05, finish16:48:29.5692438+05.
Current discovery has687 distinct names, including both new native cases;
all678 prior accepted discovery names are required again, not waived.
The corrected fixture advances synthetic signed/monotonic time past its actual
signed durable statement and respects the existing unknown retry lease. Runtime
signature, future-time, grant and lease predicates were not weakened. A compile
attempt between these runs used an incorrect fixture codec property and failed;
it produced no test receipt and is not test evidence.

Commands use the production test project, Release, `-m:1 --no-restore`, filter
`FullyQualifiedName~Did2OutboxCompaction_EncryptedColdRecoveryAllHandoversPreservesHistoryCountersAndCachedStore|FullyQualifiedName~Did2OwnedTextOutboxTests`.
Logger/results names match each table row. Failed receipts are retained, not
overwritten by passing names. Each owner result includes32 local unit cases and
one actual native account/ratchet/SQLCipher/disk-custody case. The separate
structural command uses `--no-build --no-restore` and filters the plan, protected
staging and messaging catalog test classes. In-process endpoints
and synthetic signed clocks do not prove socket or device delivery.

Actual final non-test Production and isolated final test-host builds: zero
warnings/errors after all reader integration. Root documentation174 passes. Selected-source scan17
files/0 findings. A first broad scan accidentally included old compiled artifacts
and rejected148 unsupported binary files; the corrected selected-source scan is
not an artifact-upload approval. Source changes after any receipt require their
own validation; none inherits the accepted earlier prefix full678 matrix.
