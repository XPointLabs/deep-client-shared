# S01 known send/read retirement — 2026-10-09

Private source batch implementing
[DR-0105](../../../docs/survival-program/decisions/DR-0105-idle-mailbox-counter-retirement.md).
The exact API/profile belongs to
[counter custody](../architecture/owned-mailbox-counter-retirement.md).

## Current scope

Known idle counters may retire under actual held epoch exclusion while grant,
holder, original route, traversals, other floors and semantic/receipt/asset roots
remain unchanged. Active exact send or captured Retrieve/ACK work pins its floor.
The protected plan owns exact cold recovery/abort and every native/dependency
readback; no SQL row, current authority check or working-set limit is relaxed.

The next coherent source increment couples ordinary working-row compaction with
selected authenticated completed send-entry removal. It preserves all counters,
original SQL requests/quorums/coordinator statements, semantic history and
receipt obligations. Its two-root prefix recovery adopts Ordinary then Send;
cached Store reads exact retained custody without re-enrollment or dispatch.
Missing/changed coordinator statements reject without SQL repair. This increment
adds no wire, generation or runtime scheduler activation. Exact private mapping
belongs to [authored custody](../architecture/owned-authored-counter-custody.md#owned-ordinary-outbox-only-api).

Its existing encrypted handover fixture additionally tests second-root adoption,
non-prefix rejection and actual seven-Store cleanup followed by held exclusion
and used-counter retirement. These new assertions are not yet qualified by the
earlier focused binary or any full matrix.

## Observed runs

- `artifacts/s01-ordinary-send-retirement/focused-01/ordinary-send-retirement-01.trx`:
  actual native0, 2 Passed/0 Failed/0 Skipped,12m39s. This binary passed the
  two-root ordinary compaction and second Send-adoption crash/cold-recovery
  assertions. It predates the read-only coordinator-statement reader, hostile
  ledger/non-prefix checks and used-counter retirement at the end of the
  seven-Store scenario. It is not qualification of those subsequent edits.
- The subsequent build exposed two CS1061 errors/zero warnings because the
  production project's explicit compile inventory omitted the new SQL reader.
  The inventory and generic helper return were corrected. The subsequent actual
  Windows PowerShell5.1 solution build exited0, zero warnings/errors,1m11s.
  `artifacts/s01-ordinary-send-retirement/focused-02/ordinary-send-retirement-02.trx`
  then exited native1:1 Passed/1 Failed/0 Skipped,4m02s. Cached custody and
  all missing/changed ledger negatives passed. The handover scenario failed
  in the new hostile fixture: insert-only `WriteBatchAsync` cannot replace an
  existing protected slot, including its attempted restoration. The fixture now
  uses exact compare-exchange both ways; production storage rules are unchanged.
  Source review additionally coupled cached Store to the existing full `Recheck`
  guard (freshness, exact route package, original ciphertext and send root),
  rather than freshness alone. This later source needs fresh targeted evidence.
  The corrected solution rebuilt with actual native0/zero warnings/errors in24s.
  `artifacts/s01-ordinary-send-retirement/focused-03/ordinary-send-retirement-03.trx`
  completed the same two native cases: actual native0,2 Passed/0 Failed/0 Skipped,
  16m34s. All handovers (including separate Send adoption), hostile non-prefix,
  missing dependencies/changed SQL, exact cached Store, unknown pinning,
  abort/cancel and actual seven-Store counter retirement/cold reopening passed.
  Original history/native floor/application projection remained exact after
  exclusion and counter removal. This is targeted source evidence, not full.
  `artifacts/s01-ordinary-send-retirement/preflight-01/retirement-preflight-01.trx`
  completed all6 current prerequisite cases: native0,6/0/0,22s. The declared
  full matrix uses the prior756 full, idle26 focused, corrected semantic ACK1,
  this current preflight and ordinary2 focused receipts. A fresh canonical gate
  is prepared under `artifacts/test-gate-20261009/shared-retirement-full-01`;
  no full PASS or current S01 acceptance is inferred before its terminal.
  Selected changed-source
  secret-pattern scan checked21 files with zero finding files; this is not a
  scan of device artifacts or release-upload qualification.
- Initial solution build failed with two missing test-file Services imports,
  zero warnings. The imports were fixed; no production compile error was waived.
- `artifacts/s01-idle-floors/focused-01/idle-floor-focused-01.trx`: native test0,
  26 Passed/0 Failed/0 Skipped. This predates the final API rename, the connected
  semantic ACK case and missing-floor assertions, so it is not final qualification.
- `artifacts/s01-idle-floors/connected-02/idle-floor-connected-02.trx`: native
  test1, 52 Passed/1 Failed/0 Skipped. All 26 idle-floor cases and the existing
  coupled checks passed, including the final API rename and missing-floor
  rejection. The new completed semantic ACK case failed because its envelope's
  real dispatch creation time was ahead of the fixture's frozen proof time.
- `artifacts/s01-idle-floors/ack-clock-03/idle-floor-ack-clock-03.trx`: native
  test1, 0 Passed/1 Failed/0 Skipped. Tracking elapsed native dispatch time
  exposed a second fixture prerequisite: the initial signed XNV1 ending at1200
  no longer covered the complete30-second issuance interval. Both FAIL receipts
  remain unchanged; neither is production or full qualification.
- The corrected scenario signs an initial authority through2000, an independent
  directory head through6000 and a real successor through6000, keeping both
  proof time and monotonic sample advancing. A preflight row checks this signed
  profile, overlap and encrypted cold-reopen lease. No runtime lifetime,
  assertion, expiry validation or request budget is relaxed.
- `artifacts/s01-idle-floors/ack-window-04/idle-floor-ack-window-04.trx`:
  4 Passed/1 Failed/0 Skipped. All signed-window preflight rows passed. The
  semantic case completed counter retirement/cold recovery/root comparisons,
  then incorrectly invoked current endpoint validation after the original
  rendezvous expired. The outer PowerShell command accidentally expanded
  `$LASTEXITCODE` before launching the child and returned0 despite the failed
  TRX; an independent native-process observer could not capture its exit.
  This run is unqualified, not a native PASS.
- The final fixture separately checks the real offline `ListConversationsAsync`
  projection, exact original scope and zero proof requests; the expired current
  contact-authority reader must still reject. Retained protected roots remain
  byte-exact checks. Neither expiry nor custody assertions are removed.
  `artifacts/s01-idle-floors/ack-local-05/idle-floor-ack-local-05.trx` repeats
  only this corrected scenario with literal child-shell native exit propagation:
  native0, 1 Passed/0 Failed/0 Skipped,2m23s. Real Store, owned semantic
  receive/signed ACK, exclusion, counter-only retirement, encrypted cold reopen,
  exact custody and offline display passed; expired current authority rejected
  before any further Retrieve/ACK callbacks. This is focused source evidence,
  not full, sustained delivery or device qualification.
- `artifacts/test-gate-20261009/shared-retirement-full-01` completed FAIL:
  build0/zero warnings, preflight6/0/0, full783 Passed/1 Failed/0 Skipped,
  actual test1/qualification1/FullAccepted=false. Full elapsed about94m35s;
  complete runner about96m39s. The failed case was
  `Did2MailboxFloorRetirement_UncommittedExactPlanCanAbandon(deposit: False)`.
  It failed during initial Retrieve setup, before retirement, when the durable
  onion entropy reservation reached `JournaledDeepSecureStorage.ReplaceDurably`:
  native `MoveFileEx` reported ACCESS_DENIED. The original full TRX SHA256 is
  `09BBFC51BA288C810E4868E9C0D9C0AF98CBE34D1F33CB42359F70B741013C4D`.
  An independent post-terminal canonical-module check validated the exact784
  reference union and all1825 captured inputs unchanged. Classification retained
  native1 and FullAccepted=false; the failed original artifacts were not rewritten.
  No original host lock/ACL cause or explanation of the full slowdown is proven.
  The existing Windows replacement retries cover only127ms of scheduled delays;
  native file-sharing, cancellation and permanent-denial regressions are being
  checked before a scoped correction. No entropy fallback or permission bypass.
- Current full qualification remains open until the complete corrected batch,
  using the root canonical runner and prior-full/new-focused reference union.

## Atomic protected-storage replacement correction

The isolated backend/test correction is committed locally as `ab78bb8`, authored
by `zhigubigule` with the approved no-reply email. It is not pushed or qualified
as the whole S01 batch. Remaining retirement/ordinary-compaction changes stay
in the working tree; the targeted receipt below covers that composed worktree,
not a claim that every case belongs to this two-file commit.

The native Windows sharing-conflict regression on the original replacement
implementation failed with actual native1 (one failed case), after a zero-warning
build. Its original receipt is
`artifacts/s01-secure-storage-replace/baseline-01/windows-replace-baseline-01.trx`.
The regression holds a real read/write-shared handle without delete-sharing
for350ms, longer than the former127ms retry delay sum. This demonstrates the
bounded replacement defect; it does not identify the handle/ACL responsible
for the original full failure.

Both secure-storage mutation entries now await the same commit implementation.
Windows retries the same write-through atomic rename for at most2 seconds using
monotonic elapsed time and cancellable asynchronous delays, under both the
instance gate and process lease. Errors outside5/32/33 reject immediately;
persistent denial still rejects. No authoritative-file delete/copy, ACL/attribute
modification, protector or entropy fallback is added. Cancellation before rename
leaves the previous complete aggregate authoritative. Recovery discards pending
data, never promotes it; successful rename remains the commit point, with no
post-rename cancellation pretending the commit did not happen. Unix rename and
directory flush semantics are unchanged.

`artifacts/s01-secure-storage-replace/focused-01/windows-replace-focused-01.trx`
passed20/0/0, actual native0,51s after a zero-warning/error build (33.67s).
The canonical TRX reader verified20 unique cases; SHA256:
`5704B41C7DB667F658D9D3A786B09ECBFF4EA861D95338E8D6E3CE23DA93F280`.
The run includes all secure-storage CAS/registration/inventory tests, four new
native Windows replacement cases, both Deposit/Retrieve abort-retirement rows
and all6 preflight cases. The new cases cover temporary delete-sharing conflict,
cancellation, exhausted persistent conflict and read-only destination, including
whole previous ciphertext preservation, foreign-slot retention, no half-added
floor and cold read-back/disposal of pending state. Windows-only facts explicitly
skip on other operating systems rather than claiming those native semantics.
The corrected batch still needs mandatory unfiltered qualification after the
remaining coherent S01 work. Original full remains failed, not retrospectively
accepted; this targeted result is not platform-device or release evidence.

The read-floor fixtures execute actual account/publication/held request/SQLCipher
poll completion. The unused Store-floor fixture enrolls a zero floor for an actual
signed known winner using the private codec; its synthetic pending commitment is
negative dependency coverage, not a settled real Store or non-delivery proof.
The additional connected case exercises semantic initial receive and signed
two-replica ACK before retiring the counter, retaining the last original route.
Encrypted fixture storage uses its own protector, not OS secure storage.
These are local in-process source tests, not HTTPS/native-node/device E2E.

## Original public Store outcome source — DR-0106

Sole contract: [DR-0106](../../../docs/survival-program/decisions/DR-0106-retained-store-public-evidence.md).
Source implementation is present; qualification and known acquisition deletion
permission remain open. It is not S01 acceptance or runtime cleanup S04.

The actual ordinary Store completion producer inserts immutable original public
policy/view/two selected descriptor records into owned SQLCipher before protected
Stored permits compaction. Selection stays read-only. An interrupted insertion
leaves original working custody; exact retry refuses replacement metadata.
Application schema10 rejects schema9 without migration. Holder secrets and
a duplicated peer-route journal are not introduced.

The outcome reader independently checks current owned account/network/time and
actual protected native lineage under the lease. The original peer route comes
from native Hello/Accept, not fresh route authority. Actual native event/semantic
history, exact SQL MAU3, root-signed original issuer policy, signed original
selected keys, quorum and coordinator ledger are joined twice before return.
No missing rows, grants, keys or transport request are reconstructed. Current
Store admission remains current-only; Stored is not recipient Delivered/Read.

Windows PowerShell5.1 Release production test-project build0, zero warnings/errors
in17.85s. The focused filter selected ordinary compaction, new Store public
evidence, raw-key/schema tests and all FixturePreflight cases. Original terminal:
17 cases,16 Passed/1 Failed/0 Skipped, native1,5m08s, receipt
`artifacts/s01-store-public-evidence/focused-01/store-public-evidence-focused-01.trx`.
The signed pair/ownership/tamper test, cached native/history/public-metadata
negative scenario, all6 preflight and all8 raw-key/schema cases passed.
The all-handover case stopped in Store BeginAttempt before its later assertions:
new dispatch clock preceded prepared NotBefore. Its remaining handovers and
floor/acquisition-independence assertions are not qualified by this receipt.

A deterministic regression delays BeforeSql by2.1s without changing the signed
fixture clock or any guard. Before correction it reproduced the same failure:
1 Failed/native1,2m29s, receipt
`artifacts/s01-store-public-evidence/clock-baseline-01/prepared-clock-baseline-01.trx`.
Correction keeps the actual validated preparation clock as a dispatch predecessor,
with both original/new bounded scopes, leases, expiry and network guards still
enforced. No persisted NotBefore is rewritten and unknown retry leases remain.
The corrected focused-02 completed20 Passed/0 Failed/0 Skipped, native0,
15m40s. The canonical reader independently verified all20 exact case mappings;
receipt `artifacts/s01-store-public-evidence/focused-02/store-public-evidence-focused-02.trx`,
SHA256 `4A81FD4E01FB1DFF3570F7C670BD731CCD1DB443FD14E96BFCF9856D765D2B91`.
It includes all ordinary-compaction handovers, actual used-floor retirement,
test-only acquisition removal with unchanged historical result, slow preparation,
full staged working-set exact unknown reconciliation, original lost-reply/fault
scenario, public-record negatives, raw-key/schema and6 preflight cases. The
original failed receipts are unchanged. It is focused source evidence, not the
mandatory full or physical qualification.

Protocol's bounded record-constructor test project builds with zero warnings
and errors (1m01.66s). Its6 size cases pass, native0,14ms; the canonical reader
maps all6. Receipt `../deep-protocol/artifacts/s01-store-public-evidence/bounds-01/replica-evidence-bounds-01.trx`
(relative to the Shared repository root), SHA256
`E769072B19DCA93F93306A071659C7C721A80342511042203D1500479727791E`.
This does not qualify the Protocol package/API/resource graph.

Follow-up in the same S01 business path: completed working ordinary commands
must not need renewed peer-route/issuer authority merely because compaction has
not run. `ReadRetainedMessagingStoreAsync` now selects protected Stored commands
as well as compacted operations, then verifies the actual original public/native/
semantic/SQL outcome. Pending/authored-only commands still use current dispatch.
The mandatory send registration must exist and remain unchanged; an empty root
after verified retirement is allowed, while missing/corrupt custody is not.
No send entry, floor or holder supplies the historical receipt. Final dispatch
freshness is rechecked after awaited local completion: expired authority rejects
the return, but cannot undo a signed durable Store or recreate the request.
Two new actual-path tests cover cold completed-working read after signed epoch/
original-policy expiry and expired own context at the post-completion handover.
One build name collision was corrected; the final build is zero-warning/error0
in17.98s. Focused-03 completed13 Passed/1 Failed/0 Skipped, native1,
9m15s. Receipt `artifacts/s01-store-public-evidence/focused-03/store-public-evidence-focused-03.trx`,
SHA256 `5378A37B326B852831C535AEE7EBDD7753F87537C6C57D48E326326A20B9D6F0`.
The completed-working expiry case and prior compaction regressions passed. The
new expiry test incorrectly advanced only100 seconds, still within the actual
signed directory-head deadline. It now crosses the maximum cached revocation
TTL and separately tests cancellation after completion; no runtime deadline was
extended and the expired case does not fabricate a renewed signed head.

Focused-04 builds0/zero warnings/errors in15.40s and completed8 Passed/1 Failed/
0 Skipped, native1,5m19s. The canonical reader maps all9 results. Receipt
`artifacts/s01-store-public-evidence/focused-04/store-completion-context-focused-04.trx`,
SHA256 `CF22F9F65E2745F6076C0B68F2887705B41BF1420251FEB5A8C23B9F828AE150`.
Actual expiry rejects the return while retaining offline history; the cancellation
case fails on its subsequent retained-result read at the signed receipt interval
guard. The fixture signs with an advancing dispatch clock but leaves its sampled
authority clock frozen. That case now enables the existing monotonic fixture
clock; this correction is unqualified until the next coherent S01 test batch.
The runtime interval guard and failed receipts remain unchanged. Focused-02
does not cover these later edits. No unfiltered gate is launched per file.

The next coherent batch includes ContactAccept, not another stage: the original
public records are retained before ingress, and a durable candidate reads its
actual original Store without renewing peer/grant authority. Pending public
records do not imply success. The reader also requires the exact protected
explicit winner, native Hello/send and retained semantic acceptance, reads
only the already-initialized application backend, and checks original route
and all participating protected roots again before returning. Added encrypted
cold-rollover cases cover ordinary completion and interruption before ingress,
unchanged protected/native/SQL facts, and the existing public-evidence negatives
on the receiver's actual owned backend.

Focused-05 completed13 Passed/0 Failed/0 Skipped, native0,13m45s, after a
zero-warning/error build0 in1m10.09s. The canonical reader maps all13 cases;
receipt `artifacts/s01-store-public-evidence/focused-05/contact-store-batch-05.trx`,
SHA256 `BC4961250775110F65F86003E2F3FE3863BA1898C0BFBA9F2D501695430687F7`.
It covers the two ContactAccept cold/fault cases, completed-working original
policy/epoch expiry, actual signed pair, cancellation and expiry after local
completion, slow preparation and6 preflight cases. The filter's ordinary
compaction term did not match its two actual test names; this receipt does not
repeat those regressions or qualify the full source matrix.

The producer then gained an exact public/native/semantic/explicit-winner
recheck after ingress, before reporting local completion. A new fault case
deletes public evidence at the actual post-ingress handover and requires
outcome-unknown followed by a read-only rejection, no issuer/transport replay,
and unchanged remaining native/protected/SQL facts. This later guard and case
are not covered by focused-05. The follow-up build0 is zero-warning/error in
57.61s; focused-06 passes1/0/0, native0,4m51s. The canonical reader maps its
one actual execution. Receipt
`artifacts/s01-store-public-evidence/focused-06/contact-store-post-ingress-loss-06.trx`,
SHA256 `DADBBACE8BDE1AC2162EA33F83019DCB55CCA63327617C5E8114B3CE3788973F`.
The lost-evidence case proves the actual first return rejects as outcome-unknown,
the later historical read rejects without repair/issuer/transport replay, and
remaining native/protected/SQL facts stay unchanged. This focused receipt does
not repeat the earlier13 cases or qualify the unfiltered source matrix. All
current cases, including the two actual `Did2OutboxCompaction_` regressions,
must join the coherent S01 qualification, not a new stage or per-file full run.
Initial DPH2's distinct original recipient-route closure is implemented in the
next coherent source batch, not qualified by focused-05/06. Neither the Hello
return route nor this outcome reader grants initial/acquisition deletion.

### Initial Store / public StartContact source batch — qualification pending

The same private SQL evidence row additionally retains exact original DCR,
recipient route and positive peer ADP. These three fields are jointly present
only for initial Store. The source checks the protected draft's original DCR
hash, actual key-retired sender source, authenticated initial events and native
scope plus protected peer DID2. The Protocol entry independently checks original
ADH witness lineage, map/append inclusion, ADC/DAB/PQ/device/delegation/revocation
and recipient-route bindings at authenticated original creation/acceptance
times. Its output is historical parsed facts, never a freshness capability.

Before ingress, original evidence is retained without reporting success. Exact
pending retry preserves the first ADP despite a newly fetched nonce-bound proof;
every other public record must still match the original request. Missing
attempted/durable evidence rejects without reconstruction. After ingress,
missing/changed original source returns outcome-unknown. Initial delivery and
the public StartContact retry both read a completed Store before peer resolve.
The unqualified schema10 source layout now rejects earlier schema10 candidates
as well as schema9; pre-production reset is required, not migration or a new
private journal generation.

The Windows PowerShell5.1 Release production solution build passed with zero
warnings/errors in10.12s. Earlier build failures (four source diagnostics and
two missing test-namespace diagnostics) were corrected, not qualified as PASS.
Focused-07 is running the coherent Store/ordinary-compaction/context/preflight
filter with the actual `Did2OutboxCompaction_` names. New initial cases cover
ordinary completion, pre-ingress interruption, lost reply/exact retry, encrypted
cold epoch rollover, public StartContact without resolver, each changed public
field and post-ingress evidence loss. Native terminal and exact receipt mappings
remain pending.

Focused-07 reached native exit1 in13m14s:16 Passed/4 Failed/0 Skipped/20 total.
The canonical receipt reader validates all20 mappings and SHA256
`49774DF3590D95838032E4473251783387723F41F2160CCB25D9055B2E54A293`
at `artifacts/s01-store-public-evidence/focused-07/initial-store-batch-07.trx`.
All four new initial cases failed before ingress at the same exact endpoint
join. Source inspection proves the error: the protected draft stores DID2's
domain-separated `RecordHash`, not raw SHA256 of its bytes. The check now uses
the codec's actual RecordHash; the assertion/binding was not removed.

The same correction batch makes completed public StartContact discover the
actual initial source before interpreting a missing draft as a new request.
Missing draft/source marker/orphan source family fails without reauthoring or
provisioning. Optional local discovery opens only already registered source;
no source-file creation is a historical recovery action. A missing durable SQL
request during the second read now fails explicitly rather than dereferencing
null. Added regression covers unknown first Store with lost public evidence;
it must fail before resolve, new issuance, ingress or local reconstruction.
The cold positive initial case additionally removes the actual protected draft
under its account lease and checks read-only rejection before restoring the
test-only original root.

Matching Windows PowerShell5.1 Release build0 has zero warnings/errors in33.15s.
Focused-08 reached native exit1 in22m12s:20 Passed/1 Failed/0 Skipped/21 total.
The canonical receipt reader validates all21 mappings and SHA256
`82D1F9F61817BD283728F734F7378D06247EC38ED8AE805F85C12CC67CF123D6`
at `artifacts/s01-store-public-evidence/focused-08/initial-store-batch-08.trx`.
The remaining initial pre-ingress interruption case failed before its fault hook:
the freshly issued grant did not cover the client's full authenticated interval.
Other initial cold/unknown/evidence-loss cases and the selected ordinary,
ContactAccept, clock/context and preflight cases passed on that build; this is
not a qualification of the subsequently changed issuer source.

Inspection found a producer mismatch: grant NotBefore used only the issuer's
network lower bound, while the client correctly checks the wider recipient plus
network interval. Current and retained-read issuers now preserve the original
holder-signed bounded request start, floored at signed role ValidFrom, and
measure the unchanged maximum grant lifetime from that start. Current validity,
all expiry ceilings, signatures and final checks remain enforced. Sole semantics
are in root CONTACT-RESOLVER §3.7/§3.7.3. Added deterministic delayed-issuer rows
for0/1/5 seconds in Shared and Protocol; build/targeted qualification pending.
Neither focused-07 nor focused-08 is retrospectively accepted. Matching
full/connected/package/device remain open.

The lightweight Protocol retained-issuance matrix passed44/0/0/native0 in600ms,
including all three new delayed-issuer rows. Canonical44 mappings and SHA256
`B6F117BB6F4F548018EBD37C9056E12EFF5729C98D5B43AA59B428B521ACB205`
at `deep-protocol/artifacts/s01-store-public-evidence/issuer-request-start-01/issuer-request-start-01.trx`
are independently confirmed. The matching Shared production build passed0/zero
warnings/errors in25.84s. This Protocol matrix does not qualify the current
route issuer, Shared initial retry or the subsequently changed compaction.

### Ordinary working cleanup after original epoch expiry — source pending

The S01 selection path now uses the same independent original Store closure,
not current peer/grant admission. Service and held owner accept current own
authority/time only; native and application databases open existing-only.
Every selected command still joins actual native/semantic history, original
public PMA/view/pair, MAU/quorum/coordinator and the exact protected send fields,
original acquisition and replay floor. No acquisition, holder, counter floor,
read/ACK/traversal, semantic receipt, attachment key or history is deleted.
The two-root application plan and complete SQL/root recovery guards are unchanged.

The existing positive/hostile-evidence/cached-history regression now advances
past original policy expiry into a genuinely signed epoch, cold-reopens before
selection, checks public-evidence negatives on selection and requires exactly
one own proof/no peer re-admission for cleanup. Original failure assertions and
all-handover tests remain. Source compilation passed0/zero warnings/errors in
11.77s before the final selection-test assertions; the final matching production
solution build also passed0/zero warnings/errors in10.50s. Shared
targeted/full acceptance is deferred to the coherent remaining S01 batch, not
claimed from the earlier21 or Protocol44 cases.

Test-only acquisition removal proves reader independence only; it is not runtime
deletion permission. The current operational successor author preserves receipt
identity keys: onion/origin rollover is not receipt-key rollover. Independent
issuer/receipt-key replacement and all package/API/resource gates remain open.
No production deploy, account reset, Release/main merge or push occurred here.

### Current issuer / initial pre-ingress regression — targeted PASS

After the issuer request-start correction and the SQL-guard integration, the
previously failing initial pre-ingress interruption case passed with all six
preflight cases:7/0/0/native0 in5m46s. `--list-tests` independently confirmed the
exact seven-case selection before launch; the canonical module validated all
seven mappings and the required interruptBeforeIngress=True row after terminal.
Receipt: `artifacts/s01-store-public-evidence/initial-pre-ingress-issuer-start-01/initial-pre-ingress-issuer-start-01.trx`.
SHA256: `CB76BF292AD89755107B6A08894503845AC564422876C88F9FBE8C3C78AE8D09`.
No runtime or executable test input changed during that run; no build was
repeated between the preceding clean6.25s build and this `--no-build` test.

The fixture genuinely preserves the exact pre-ingress request, executes one
Store, cold-reopens under a signed successor epoch and reads the original
outcome without reissuing/dispatching. Its missing/changed public-evidence
negatives remain. This verifies that specific former guard failure on current
source, not all other initial variants, independent receipt-key rollover,
physical delivery or whole Shared/S01 acceptance. Original focused08 remains
20 Passed/1 Failed/native1; it is not relabelled by the later PASS.

## Still open

### Completed contact-send working disposition — current source pending

The private owner now selects completed initial/ContactAccept sends through
independently authenticated original Store closure, then joins the exact prepared
entry to original native envelope, MAU fields, acquisition request/result and
retained replay floor. It removes only that entry, increments Send revision and
leaves every counter/grant/route/holder/source/receipt/object/read path intact.
Unknown Store remains pinned; already-retired succeeds only after independent
historical verification. ProtectedOnly Audit is distinct from ReplayScope and
uses the closed nine-root recovery profile with complete mailbox-state guard.
No wire, journal generation, package provider or compatibility reader was added.

Guard readback now includes contact intents, initial-key/preclaim roots and
actual protected device source marker/checkpoint plus complete existing device
SQL. It opens ReadOnly under the held account lease, enforces current schema,
SQLCipher/key scope and rejects missing/foreign/pending custody, without source
reconciliation or initialization. The generic SQL projection is shared, not a
second per-database hash implementation.

The two interim builds failed terminally (first invalid using on plain preclaim
State; next test-only missing fixture accessor/private method visibility).
Both are corrected; final matching production solution build0/zero warnings/
errors in4.52s. New tests cover both contact operations, all five stored-plan
handover boundaries using the same genuine one-time Store, unchanged original
application/native/device SQL and other roots/counters, exact cold recovery,
device-SQL-only tampering then fixture-only exact restoration, idempotence,
hostile public evidence and unknown lost-reply pinning without staging/reissue.
The metadata shape test requires a single Audit Send and complete guards.
Focused01 terminated native0:69 Passed/0 Failed/0 Skipped in10m21s.
The canonical module validated all69 mappings, all four completed-contact-send
cases, the new Audit metadata case, both counter handover0 and SQL fault4
domains, actual completed ACK and all six preflight cases. Receipt:
`artifacts/s01-store-public-evidence/completed-contact-send-01/completed-contact-send-01.trx`.
SHA256: `6325F3B062C340C9B6C926B749B0F9673BF167A193820F871D0BBD88589B05E7`.
Executable inputs were not edited during that run. This targeted PASS does not
prove complete responder custody: source review found that the guard did not
yet include the separate prekey database or responder checkpoint.

The following correction adds a conservative exact encrypted prekey-file guard,
stable responder checkpoint and install/inventory/commit marker readback under
the held lease. It streams fixed-size buffers without source initialization,
SQL opening/repair, signing or authority refresh; selection still independently
verifies the actual original source. A logical SQL rewrite is not treated as
equivalent ciphertext. The cold ContactAccept test now changes actual responder
SQL after staging, checks refusal preserves the alteration/send/plan, restores
only the disposable fixture's exact encrypted file and resumes the same plan.
Both device and responder source digests must remain unchanged after all five
handovers. First correction build passed0/zero warnings/errors in28.49s;
final matching rebuild passed0/zero warnings/errors in4.80s.
Before launch, `--list-tests` confirmed exactly71 cases: the preceding69-case
selection plus both modified ordinary compaction regressions. Focused02 passed
71/0/0/native0 in17m13s; the canonical module validated all71 mappings, all four
contact-send cases, both ordinary regressions and all six preflight cases.
Receipt: `artifacts/s01-store-public-evidence/completed-contact-send-02/completed-contact-send-02.trx`.
SHA256: `04BF75711FA72079BD6EC5DA89A39BE217482B3FCF04DA63C572028418C3EB05`.
Executable/source inputs were not edited during this run. Actual responder SQL
tampering refused recovery without repairing the alteration or changing the
send/plan; exact fixture-file restoration then finished the same cold plan.
Ordinary cleanup selection after original issuer expiry/signed successor and
cached encryption/original Store negatives passed on this source.
This is targeted implementation evidence only. Matching mandatory full,
connected/package/platform and physical qualification remain pending; known
acquisition/traversal retirement and terminal receipt/object closure below
remain unfinished. This batch is a partial S01 implementation checkpoint,
not S01 completion, production activation or a release acceptance.

The paired Protocol checkpoint was rebuilt with zero warnings/errors in1.70s.
Its retained-issuance and public-record bounds matrix passed50/0/0/native0
in608ms. The canonical module validated all50 mappings; receipt:
`../deep-protocol/artifacts/s01-store-public-evidence/checkpoint-01/store-evidence-checkpoint-01.trx`
(relative to this repository root), SHA256:
`167C901D53531A872D693F94E2ADB47AB824E710D9395356686F3C9F27CB5BBB`.
This is not the Protocol full/package/API/resource graph gate. DR-0095's existing
shipping boundary remains open; no frozen target or consumer lock was repinned.

### Complete mailbox SQL guard — source pending

Counter staging/recovery now requires the private owner's ninth unchanged guard:
complete application SQL plus every catalogued native SQL/history/floor/peer.
The producer captures and rechecks actual existing state under the held lease;
recovery opens existing-only and rejects changed SQL before counter adoption or
plan disposal. Old eight-root counter plans reject; the distinct unused closed
Deposit profile remains eight-root. No generation, wire or compatibility reader
was added. Original grant/holder/route and last Retrieve/ACK custody stay intact.

New negatives alter a same-width application credential-epoch value with unchanged
protected roots/DNH2, strip the mandatory guard, and alter actual initial native
SQL after completed receive/ACK. They require refusal without counter/plan
mutation, then restore only the disposable fixture's exact original state and
finish the same cold plan. A metadata case checks unique guard-only shape and
changed readback rejection. The first integration build passed zero warnings/
errors in31.82s before the additional native-SQL regression; final matching build
and focused results are recorded below. Known acquisition deletion is not implemented
or qualified by this guard; source/terminal receipt/object closure remains below.

The matching solution build passed zero warnings/errors in4.68s. Focused guard01
terminated native1:93 Passed/1 Failed/0 Skipped/94 total in5m58s. Canonical module
confirmed all94 mappings and SHA256
`CD00FCF0B8BD83EB14EFF0494133377445C7EB20F2F9E2BC1CBFE5E081C802C3`
for `artifacts/s01-store-public-evidence/mailbox-state-guard-01/mailbox-state-guard-01.trx`.
The sole failure was the new Deposit SQL-only fault fixture reading an absent
replay-counter before any Store (NullReferenceException in the test before its
recovery assertion). Actual native-SQL refusal/restoration/recovery, all stored
handover/abort/cancellation cases, missing-guard rejection, the metadata shape
case, all three delayed current issuer cases and preflight passed on that build.
This original FAIL remains FAIL, not retrospectively converted to PASS.

The fixture now alters the mandatory installed credential epoch's expires_at
value for both domains, checks refusal preserves that alteration plus all roots
and the plan, restores only the disposable fixture's exact original value and
finishes the same plan. No product guard or assertion was weakened. Matching
rebuild passed zero warnings/errors in6.25s. Before running, `--list-tests`
confirmed exactly the two changed fault4 cases plus all six preflight cases;
guard02 then passed8/0/0/native0 in26s. Exact8 mappings and both modified cases
were independently validated with the canonical module; its receipt is
`artifacts/s01-store-public-evidence/mailbox-state-guard-02/mailbox-state-guard-02.trx`.
SHA256: `1416E5B8BB9767F913C60C7D4D185BBEFC83890932CDCD8E6EA39115815578CF`.
These targeted receipts are not a matching mandatory full, connected gate,
shipping/package or physical qualification. No full was launched for this
isolated guard correction, and no push/deployment/Release/main merge occurred.

Non-ordinary known send-work and acquisition/traversal slot retirement, exact terminal
receipt/object dependency closure, sustained capacity/recovery and runtime
renewal/cleanup remain unfinished. Whole S01, physical Windows/Android,
files/groups/calls and shipping qualification are not accepted by this batch.
No production deployment, account reset, Release publication or main merge occurred.

## Used Deposit holder retirement — targeted source checkpoint

The next coherent S01 source packet adds the closed internal used-Deposit
producer, native/public Store completeness joins and oldest-first chain
unlinking. Its single private owner is
[grant custody](../architecture/owned-mailbox-grant-custody.md#used-deposit-holder-retirement--s01-source-candidate).
It changes only Grant. Native/public original Store, live accepted objects,
read paths, semantic/source/history/prekey and receipt work remain independently
verifiable and byte-exact. This is write-holder retirement, not object expiry,
recipient delivery, last Retrieve/ACK removal or S04 activation.

Initial exploratory `used-deposit-01` completed61/1/0/native1 in4m51s. Its first
initial Store exceeded the real30s installation scope after dispatch and
returned outcome-unknown; no deletion was performed. Original SHA256:
`60BF322D80E644BEC01C9D4478C9D82523B7D04C8EDF065A12407D43034219F2`.
That FAIL remains FAIL. Its provisional object-expiry-only selection was
replaced by the actual independent-custody disposition required by §8.4.3;
the old receipt does not qualify the replacement or authenticated object expiry.

Matching rebuild under Windows PowerShell5.1/SDK10.0.301 passed with zero
warnings/errors in30.48s. `--list-tests` declared the final65-case selection:
both new contact paths, both modified late-result/chain graph cases, unused
Deposit abandonment, all six fixture prerequisites and existing plan/staging
metadata cases. `used-deposit-02` ran serially with `xUnit.MaxParallelThreads=1`
and completed65/0/0/native0 in12m59s. Canonical `Read-TestGateReceipt` verified
all65 mappings and the named source cases. Receipt:
`artifacts/s01-used-deposit-retirement/used-deposit-02/used-deposit-02.trx`.
SHA256: `2E9F0B40E0BFC4891E1F36E2186C95BDD8A394527DFD54EC956DAAE3297AEB91`.

Both initial DPH2 and ContactAccept use a genuine owned Store whose original
thirty-day object is still live. Each exercises all five cold handovers, SQL
evidence loss before staging and during stored recovery, exact original public
evidence restoration only in the disposable fixture, unchanged complete
application/source/native/non-grant custody and cached Store after acquisition
removal with no new issuer/ingress. A bounded ordinary exact-retry helper can
retry an outcome-unknown original request with fresh guards and checks unchanged
request bytes; it does not widen any signed/installation window or freeze time.
Chain checks distinguish received-unadopted, adopted-oldest and Retrieve cases;
they prove structural unlinking, not independent used multi-acquisition owner
qualification. No production retention/capacity/assertion was shortened.

Matching mandatory full, independent issuer/receipt-key rollover, sustained
128/512 capacity/recovery, broader ordinary/asset dependency closure, known
Retrieve/traversal/last-path retirement and whole S01 remain open. No full was
launched for this source increment. Physical Windows/Android, shipping/package,
files/groups/calls and release acceptance remain unqualified. No production
deployment, reset, GitHub Release publication or main merge occurred.

## Used Deposit chain — actual owner checkpoint

The next coherent S01 packet exercises the actual held retirement producer on
two adopted acquisitions in one scope, not just the journal graph helper.
Its source contract remains in the
[sole grant owner](../architecture/owned-mailbox-grant-custody.md#used-deposit-holder-retirement--s01-source-candidate).
The controlled setup authors a genuine signed successor and persists the three
selection transitions; this is consumer/retirement evidence, not qualification
of an autonomous renewal producer or scheduler.

Both variants perform a real owned ContactAccept Store followed by an ordinary
text Store with the distinct successor holder. The completed variant uses the
actual ordinary cleanup API, removes both excluded idle floors, rejects
newest-first selection, interrupts the oldest's plan after staging and resumes
through a cold owner. The remaining seed/request/result/policy/route and current
selection are preserved. It then retires the remaining used holder and checks
both original cached Store outcomes, exact original encrypted message replay,
unchanged application/native/source/non-grant custody and both live objects.

The lost-reply variant produces a genuine signed durable response but loses it
before the client can confirm the second Store. That unknown successor send
pins oldest-holder retirement after the signed epoch advance. Original
prepared send, grant chain, application SQL, native floor and idle plan remain
unchanged; no reply is invented, no request is reissued and no key is evicted.

The test helper now routes ordinary cleanup to the actual scope's account for
both directions instead of unconditionally choosing the initiator. Product
code required no correction for the tested chain transition. The final build
under Windows PowerShell5.1/SDK10.0.301 passed zero warnings/errors in5.74s.
`--list-tests` declared exactly nine cases: both chain variants, the actual
cached-encryption/history regression and all six fixture prerequisites.
`used-deposit-chain-01` ran serially and completed9/0/0/native0 in8m38s;
the canonical receipt reader verified every mapping. Receipt:
`artifacts/s01-used-deposit-retirement/used-deposit-chain-01/used-deposit-chain-01.trx`.
SHA256: `D41661F7FCA669D0350785466C353500A22AF56B802B1E81F3A702AB0A3B062A`.
No source or executable input changed while this run was live.

This closes the previously untested two-used-acquisition owner scenario, not
sustained128/512 lifetime, independent issuer/receipt-key rollover, known
Retrieve/traversal/last-path closure, the matching mandatory full, whole S01,
runtime activation, physical Windows/Android or release acceptance. No full,
production deployment, account reset, GitHub Release or main merge occurred.

## Original issuer rotation and actual traversal dependency index

The next S01 packet independently changes both MCG3 issuer public keys in a
genuine root-signed PMA2 successor, rebinds/threshold-signs PMT2 and advances the
real protected network lineage. Initial DPH2 and ContactAccept original Stores
remain independently verifiable after encrypted cold reopen, completed-send/
floor/used-holder retirement and a staged cold handover. Substituting the valid
current PMA2 into original SQL evidence rejects before staging or mutation;
restoring the exact disposable-fixture record permits recovery. History, native
floor, source SQL, retained roots and live objects remain exact. No new issuer
or ingress call is needed for cached original outcomes. This covers these two
issuer-rotation consumers, not independent node receipt-key rotation or renewal.

Inspection also found a real dependency-index defect: traversal lookup used the
grant acquisition scope, whereas actual Retrieve stores a different mailbox
scope. Capture now derives that original installed route/mailbox/epoch scope;
the sole mapping belongs to [counter custody](../architecture/owned-mailbox-counter-retirement.md#held-selection-and-exact-dependencies).
The actual Store/receive/semantic ACK case asserts traversal and read-floor
dependencies before retirement, then preserved traversal/last-path pinning and
no read floor afterwards. Unpolled known/unknown Retrieve cases assert that a
traversal is not invented. This correction does not delete a traversal/path.

All runs used Windows PowerShell5.1, SDK10.0.301 and serial xUnit execution;
declared case lists and canonical receipt mappings agreed. No source/executable
input was edited while a run was live. Receipts under
`artifacts/s01-issuer-rotation/`:

- `issuer-rotation-01/issuer-rotation-01.trx`:9/0/0, native0,6m06s;
  predates the production index correction. SHA256
  `97142EA4290BAE8968550010CDD1E8120E05A95BC267F0C17986796F19ADB4A4`.
- `issuer-traversal-02/issuer-traversal-02.trx`:11/1/0, native1,9m58s.
  Both issuer consumers, unpolled cases and prerequisites passed. Actual ACK
  setup stopped at Store's post-dispatch 30s installation fence before the new
  index assertions. This FAIL remains FAIL. SHA256
  `60DFA7AC838DE2A6704FB86DEA0006B8C7F6B41108F8854FA9712C2C77B6BF03`.
- `traversal-receive-03/traversal-receive-03.trx`:7/0/0, native0,3m31s.
  After one bounded exact-retry handling correction in the ACK fixture, actual
  receive/ACK and all six prerequisites passed. The retry uses the public
  original-operation path with a forbidden resolver, checks unchanged MAU bytes
  and one grant acquisition, and never stretches signed time or reencrypts.
  Production code is unchanged from02. SHA256
  `E67F9EDD4A4922D403860853501FBF34BB0BA197D308B0AE852E2E5026F27E9C`.

Final production solution build: native0, zero warnings/errors,9.97s.
No matching mandatory full was launched: remaining S01 dependency/path closure,
receipt-key rotation, sustained lifecycle and connected/shipping/device gates
are still open. No production deploy/reset, Release publication or main merge.

## Superseded Retrieve holder and retained-path guard checkpoint

The S01 source packet implements the private same-original-path holder transition
in the [sole grant owner](../architecture/owned-mailbox-grant-custody.md#superseded-retrieve-holder-retirement--s01-source-candidate).
No wire, schema/journal generation or runtime renewal was added. A controlled
genuine signed successor is installed through the actual owned client; the issuer
callback is not repeated. Both empty and actual initial Store/receive/semantic
ACK cases complete an original read, exclude the old namespace, retire its idle
floor, then complete an actual replacement read on the original selected path.
Only afterward can the oldest private holder retire.

Both cases reject sole-holder removal, installation without a completed read,
and an actual phase3 replacement read interrupted after SQL page commit. Exact
retry completes that read without another terminal callback. Every protected-plan
handover is injected, disk storage is cold-reopened, and recovery preserves the
entire application SQL, native fence, all non-grant roots and original route.
AfterStage additionally corrupts the actual publication journal: recovery rejects
without changing the staged plan or grant root; restoring only the disposable
fixture bytes permits recovery. The remaining current holder still reads the same
mailbox after recovery. MRSO/MCO1 are checked as SQL commitments, not presented as
independent quorum or Delivered/Read authority.

Readback review also found two missing SQL checks: current scope kind/subject/
issuer-context columns were not compared with the exact selector, and the stored
grant digest was not compared with canonical grant bytes before counter use.
The actual current credential resolver now enforces both. Three negative SQLCipher
cases independently alter digest, replica key or scope context; exact installed
readback rejects without repair or allocation. Existing cold exact-MAU and expiry
boundary cases remain unchanged and pass. The complete MailboxStoreState guard now
also binds decoded publication custody and the bounded protected resolver-capability
digest, as required by the replacement path's cold recovery dependencies.

Final build: Windows PowerShell5.1/SDK10.0.301, native0, zero warnings/errors,6.02s.
Both focused runs used predeclared exact case lists, `--no-build --no-restore` and
serial xUnit execution; source/executable inputs did not change while either was
live. Canonical receipt mappings and counters were verified under
`artifacts/s01-superseded-retrieve/`:

- `retrieve-retirement-01/retrieve-retirement-01.trx`:9/1/0, native1,7.7098min.
  The empty case attempted polling before actual completed publication and failed
  before retirement. Nonempty owner recovery, both Deposit-chain variants and all
  prerequisites passed. This FAIL remains FAIL. SHA256:
  `1545DAD5C29847C5AC2C57702567B577B64E468E873DCC02B3C46A4263020433`.
- `retrieve-retirement-02/retrieve-retirement-02.trx`:16/0/0, native0,9.6506min.
  After correcting publication setup and adding the readback/path-loss checks,
  both new owner variants, both Deposit-chain variants, all six current credential
  cases and all six prerequisites passed. SHA256:
  `31307783383B3F5DBEFDABF48C5A971A4A26D3F4E1DBF6AF179E6B4C7D797A2E`.

This qualifies the tested same-route superseded-holder source transition, not
retirement of a traversal/last path, unused/unknown Retrieve acquisitions, cross-path
migration, independent receipt-key rotation, sustained128/512 cleanup, a matching
mandatory full, S01 acceptance, S02/S04 activation or physical Windows/Android.
The current source requires full qualification after the complete S01 batch.
Production, accounts, Release publication and main were not changed.

## Publication promotion preserves original read custody

Source review of the remaining S01 last-path dependency found that successful
contact renewal removed the predecessor publication, including its private owner
Retrieve capability, while original objects or an interrupted read could remain.
Retrieve/ACK also selected only the newest publication. Promotion now atomically
retains the completed predecessor in the already reserved pending slot and selects
an active read's exact original route. All signed records, private route material
and capability remain byte-exact apart from the local intent prefix. The private
reader independently rederives the archived intent binding and rejects missing or
ambiguous original custody. No journal generation, wire, public selector, legacy
reader, reranking, request remint or capacity increase was introduced.

Predeclared focused matrix: three `Did2OwnedRenewal_` cases and all six
`FixturePreflight=true` cases; serial xUnit, Windows PowerShell5.1/SDK10.0.301.
Final build native0, zero warnings/errors,3.17s. Two earlier compilation attempts
failed only on missing/wrong test-hook imports/names; no tests launched from them.
No source/executable inputs changed while the successful focused run was live.
`artifacts/s01-publication-retention/renewal-retention-01/renewal-retention-01.trx`:
**9/0/0, native0,52.6618s**, canonical receipt mappings/counters verified.
SHA256: `A2AC042BE5852432B7CF5AD1392B7ED15C2F3DF79D202D3E2B2BFCC2576ED0E8`.

The encrypted-storage case captures an actual owned empty Retrieve at phase3,
renews through every protected handover/response-loss case, observes lost promotion
reply and reopens the persisted successor. The original read/grant roots stay exact.
Removing only the predecessor in disposable fixture storage rejects without
issuer/terminal callback or root changes; restoring only that fixture permits the
original captured read to complete, without another Retrieve or issuer call.
The existing renewal and expired-incomplete-proposal regressions also pass.
This is actual Shared/native crypto/SQL source evidence with signed in-process
issuer/terminal results, not physical devices or two remote HTTP stores.

An ACK across publication promotion is not qualified by this empty-page case.
Idle polling of every retained publication, last-path/traversal retirement,
unused/unknown Retrieve closure, sustained128/512, current matching full and S01
acceptance remain open. S02/S04 activation, production, Release/main and physical
Windows/Android were not changed. No complete release percentage is inferred.

## Retained publication polling and original lost ACK

The next coherent S01 source increment adds bounded new-read selection across
actual current and archived permanent publications. It uses the existing
owner-protected traversal poll generation, one least-polled route/page per call;
active work still resumes its exact original route. An arbitrary completed entry
with the permanent configuration but an unbound archived intent rejects before
issuer/terminal callbacks or protected read/grant mutations. No new journal,
format, public selector, remint, deletion permission or capacity increase.

The nonempty regression performs actual initial exchange, explicit acceptance,
native ContactAccept commit and semantic materialization. It loses the ACK reply,
renews the actual publication past original XRA expiry, and resumes the exact old
ACK. This exposed a product defect: reconstructing the native-committed Hello
required its old return publication to pass current admission again. The source
now uses the existing closed DR-0072 historical signature/graph verifier only
inside actual native-committed Hello/Accept handoffs, following DR-0063's dated
clarification. Current endpoint/DCA/XUR/network checks remain; actual native
floor/events are independently reread after verification. Historical facts do
not grant new Store, Retrieve, ACK or dispatch authority.

Windows PowerShell5.1 / SDK10.0.301 builds before focused tests:
idle-poll build18.47s; nonempty regression build4.78s; historical-reader build
23.14s and final-readback build16.95s, all native0/zero warnings/errors. An earlier
historical-reader build failed2 diagnostics on an inaccessible trusted-time API;
no tests ran from it. The subsequently compiled source incorrectly used a
lease-acquiring recheck while already holding the account lease. This was a
product deadlock, not infrastructure contention; it was corrected to the existing
held-lease endpoint-pair recheck, without extending timeouts or weakening checks.
Final functional build32.32s, native0/zero warnings/errors.

Fresh serial focused receipts under `artifacts/s01-publication-retention/`:

- `retained-poll-01/retained-poll-01.trx`:10/0/0/native0,1.2963min;
  four renewal cases plus six prerequisites. SHA256
  `FB68870DFB1781ABC122D815C5F6A67A6616E20DAFE7AD9EA4307C1FD8FDF7C0`.
- `retained-read-ack-01/retained-read-ack-01.trx`:9/1/0/native1,12.5970min;
  new ACK-promotion case failed on XRA expiry; existing cases passed. SHA256
  `399759EA4D5ACFBFE6878EC01BA870F4E14158161718DFE34514C60D2DA4923B`.
- `retained-read-ack-02/retained-read-ack-02.trx`:7/3/0/native1,4.9698min;
  all three receive cases failed on the nested account lease. SHA256
  `38D205D0D974ABFB545E36E3E0AA245021807F0001C9261B1690E9E9D0925EC6`.
- `retained-read-ack-03/retained-read-ack-03.trx`:10/0/0/native0,14.3410min;
  both original receive variants, new lost-ACK/promotion case, retained idle
  polling and all six prerequisites pass. SHA256
  `36D9E980EB4AE1C658C933D6490AC71A8B31E0258997AF7639506B45272BB00B`.

The ten-case matrix was listed before execution. No source/executable/normative
edits were made during any live run. The canonical receipt reader verifies each
mapping/counter; `Test-TestGateResults` confirms03 against the predeclared02
reference with native0, exact10 cases and no skips. These are focused receipts,
not an unfiltered full gate. Original FAILs remain unchanged.

Two protected traversals each advance at least three polls; only two original
issuer acquisitions occur, once per publication. Lost-ACK retry uses identical
MAU bytes, one original Retrieve and one issuer acquisition; native/semantic
contact acceptance remains singular. Real PQ/native/SQLCipher custody is used
with signed in-process issuer/terminal results, not remote two-store HTTP or
physical Windows/Android. Original DCA/XUR expiry and PMT/device/delegation/key
rollover are not comprehensively qualified by this same-projection profile.

After the focused terminal, reviewed normative source/inventory repins regenerate
only Protocol registry metadata; strict registry/176-anchor checks pass. This
also records already accepted DR-0106 and signed-request start changes from the
prior source packet. No frozen allocation, approved Git blob, wire bytes,
signature domain or activation status changes. Final matching build is recorded
below; current matching mandatory full, last-path/traversal retirement,
unused/unknown Retrieve closure, sustained128/512, S01 and shipping/device
acceptance remain open. Final build after mechanical metadata repin: native0,
zero warnings/errors,20.55s. No production deploy/reset, Release or main merge.

## Closed-unused Retrieve and retained courier projection

The next S01 increment implements the private closed-unused Retrieve disposition
in the [grant custody owner](../architecture/owned-mailbox-grant-custody.md#closed-unused-retrieve-retirement--s01-source-candidate).
Actual lost issuer reply remains unknown, not non-issuance or a completed read.
Only after its conservative issuance ceiling and independently protected native
epoch exclusion may the held owner select a sole phase3 acquisition. The exact
permanent publication/private capability, resolver custody, complete application/
native SQL and source/history/fence remain unchanged. No traversal, last path,
known winner, journal generation, public API or wire allocation is removed/added.

The two new encrypted fixtures exercise all five protected handovers and cold
recovery, cancellation and phase1-only abandonment, changed publication pinning,
an uninitialized application rejecting without staging, and subsequent actual
owned Retrieve through the same original path with a new current grant. SQL is
initialized only by the ordinary public client projection before positive
selection, never by creating a test substitute or by recovery repairing custody.
The existing known-holder regression rejects this unused-acquisition profile.

The original-path read exposed a product gap: ContactResolve path construction
required the XMG2's original PMT2 to equal the current PMT2, even for an already
host-verified retained request. The owner now loans the existing Protocol-minted
DR-0100 request/time capability through its private dispatch. Only byte-exact
XMG2 can use it; current service placement and all three routing hops remain
current. The real courier rechecks the live capability before HTTP forwarding
and after authenticated reply. Missing capability and another exact request
reject; Deposit/public unowned paths retain the current projection prerequisite.
This is not historical routing, issuer success, lookup or mutation authority.

Windows PowerShell5.1/SDK10.0.301 builds:70.37s,15.31s,19.26s and final5.06s,
all native0, zero warnings/errors. Fresh focused receipts beneath
`artifacts/s01-unused-retrieve/` retain every failure:

- `closed-retrieve-01/closed-retrieve-01.trx`:9/7 passed/2 failed/0 skipped,
  native1,15.6284s. New fixture attempted opening application SQL before its
  normal first open. SHA256
  `9D9494354F2D08B91C702BF39D37092E16EAE0038B6AE3064B9FA113C36C65EB`.
- `closed-retrieve-02/closed-retrieve-02.trx`:9/7/2/0,native1,1.2310min.
  Recovery passed before subsequent read hit the current-projection product
  gap described above. SHA256
  `9A44A13B0D418FF633355320C6A61AF9E62E2E3FFAB67DEDD8BFDCFE103FE17B`.
- `closed-retrieve-03/closed-retrieve-03.trx`:20/18/2/0,native1,5.5877min.
  Both new reads passed path construction but the fixture issuer selected the
  expired original PMA2 instead of its genuinely signed successor. The host
  correctly rejected it; fixture source selection was corrected without time
  extension, unsigned policy or assertion weakening. SHA256
  `D6729137F588EB29F6305CF214AAB4F1D4CD12AB1A06BE845BE2F9DD6D853E60`.
- `closed-retrieve-04/closed-retrieve-04.trx`:20/20/0/0,native0,8.0869min.
  SHA256 `8718F2897F151AEBB3D05640A93BC736FB290F7D9F710D808041FE0DC60399D6`.

The final twenty-case matrix was listed before03, then repeated unchanged in04:
two new facts, existing closed-Deposit abandonment, both superseded Retrieve
variants, nine retained-read cases and all six prerequisites. Existing bounded
two-method concurrency was used; no source/executable/normative edits during
live builds/tests. Canonical receipt readbacks preserve the failures; exact
`Test-TestGateResults`04 against03 passes with native0 and no skips. The generic
qualifier's FullAccepted field does not turn this filtered run into an unfiltered
repository gate or stage acceptance.

Evidence uses real PQ/native/SQLCipher custody, held-frame construction and signed
in-process issuer/terminal results, not physical devices or two remote HTTP stores.
Remaining acquisition/traversal/last-path dispositions, DCA/XUR/PMT/key rollover,
sustained128/512 and current mandatory full after the complete S01 batch remain
open. S02/S04 activation, production deployment/reset, Release and main unchanged.

## Explicit owned Retrieve renewal — 2026-10-09

The new internal owner transition binds renewal to one original adopted XMG2
selector. It reopens actual phase7 original publication/private custody under
the account lease, signs and persists one pending successor before the courier,
then independently verifies and adopts the current host's result. Ordinary
acquisition continues selecting original current while renewal is pending.
Cold retry resumes the exact pending operation/window/holder or already promoted
immediate successor; a further advanced chain rejects the stale selector.
No old grant/path/read/traversal/native/attachment state is removed. The closed
local API owner is
[owned mailbox custody](../architecture/owned-mailbox-grant-custody.md#explicit-owned-retrieve-successor--s01-source-candidate).
No Protocol public API, wire, magic, generation or128/512 limit changes.

The existing empty/nonempty superseded-holder retirement fixtures now obtain
their actual signed replacement through the account owner and held-frame
courier, not direct fixture writes to the grant journal. The old controlled
current-route consumer fixture remains for its separately labelled fault tests;
its now-unused post-epoch authority switch was removed.

Both Windows PowerShell5.1/Desktop/SDK10.0.301 builds passed with native0 and
zero warnings/errors:46.95s and7.84s. Focused receipts are preserved under
`artifacts/s01-owned-retrieve-renewal/`:

- `owned-renewal-01/owned-renewal-01.trx`:23 total,17 passed,6 failed,0 skipped,
  native1,6m40s. All six new rows reached renewed SQL installation but invoked
  the first-install observer that expected one credential. The owner correctly
  retained old plus new credentials; the single-install helper was not relaxed.
  SHA256 `C3027D34E5361F0B5CB7B72B03BD92B8F5142290866A914E67BBBD96A1DA2A68`.
- `owned-renewal-02/owned-renewal-02.trx`:24/24/0/0,native0,6m58s.
  The renewal-specific independent SQLCipher observer requires exactly two
  scopes/epochs/grants and both exact old/new canonical grants, with no prepared
  dispatch/outbox rows. SHA256
  `1A6773DD2980142DAFDC53DFFA9945056B23D9E7479CC9EE5AB882AE3079554A`.

The first23 cases and second24 cases were listed before their runs. The second
matrix adds only `expired` to the same six renewal handovers, two existing
superseded-holder scenarios, nine retained-read cases and six prerequisites.
Canonical receipt parsing verifies all exact result/definition/execution
mappings; set comparison preserves every original23 identity and adds only that
declared expired row. This is a filtered source matrix, not a full repository gate.
No source/executable/normative edits occurred during either live build/test.

Positive cases cover reply loss, cancellation, before-selection, before/after
SQL, exact cold retry and repeated completion without another issuer call.
The ordinary lane cannot implicitly forward/adopt the pending successor.
Expired unknown renewal is closed via the actual owner and then remains pinned:
no fresh request, rewindowing, successful outcome or deletion is inferred.
Further renewal followed by retry of the earlier selector rejects without
mutation/courier. Missing original selector rejects before the courier.
Real PQ/native/SQLCipher and current signed in-process issuer/held-frame facts
are used; this is not two-remote-store, production or physical device evidence.

S01 remains unaccepted: linked/remaining acquisition, traversal/last-path
dispositions, DCA/XUR/PMT/key rollover, sustained128/512 and the current mandatory
full after the complete source batch are still required. S02/S04 activation,
production, GitHub Release and main were not changed by this packet.
