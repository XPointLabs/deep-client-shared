# Native active state and archived payload — proposal, 2026-10-26

Implementation mapping for accepted design
[DR-0175](../../../docs/survival-program/decisions/DR-0175-active-native-state-and-archive-validation.md).
Source implementation, hostile-state provider proof and connected qualification
remain pending; the decision does not activate the cheaper verifier. Custody remains
in [ACCOUNT-DIRECTORY](../../../docs/architecture/ACCOUNT-DIRECTORY-TRANSPARENCY-V1.md)
and [TRANSPORT-NEUTRAL](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md).
The implemented first P1 slice only batches actual protected inventories:
registration 4→1 loads, prefix recovery 7→1, ordinary recovery 13→1, mailbox
roots 8→1, ordinary selection and fresh callback readback 10→1 each. SQL/native
checks remain intact. Qualification, full P1 and latency acceptance are separate.

## Withdrawn image-reuse argument

Before/after file hash and identity do **not** prove SQLCipher validated that
same image: in-place A→B→A and retained page-cache contents defeat that inference.
No cross-callback image cache or its earlier claimed 4→1 verification savings is
approved. Equal ciphertext also cannot bypass mutable protector/key-ring policy.
Application uses WAL in `SqliteSessionStore.Mailbox.cs`; main-file equality would
be insufficient there independently. No existing cipher policy, file-family or
key check is suppressed. Native `OpenMessagingConnection` uses
`OpenConnectionCore`, which authenticates key/schema but does **not** execute
full `cipher_integrity_check`; native `RequireCipherPolicy` checks pragmas only.
Application's full cipher check does not cover native archived overflow pages.
Therefore preserving raw native page-tamper detection requires an explicit full
native page-integrity check at each boundary formerly reading the whole archive.
Its coverage must be proved on this actual provider with corrupted overflow-page
fixtures before activation. This preserves full-page I/O and permits only CPU/
semantic-decoding savings; full existing application cipher checks stay intact.

## Callback-free consolidation first

Use existing transactions and explicit internal methods, not a new storage API.
[Transition context/state](../../src/Deep.Client.Shared/Persistence/DeviceV2/Did2MessagingSqlJournal.cs)
already performs full verification, operation selection, replay classification
and TRS read in one read transaction. `HistoricalRouteRead` is another existing
closed synchronous snapshot. Two remaining concrete consolidations are feasible:

- `VerifyInitialImport` and `RequireAppendCapacity` verify the tip then reread
  `ReadJournal`. Consume the headers returned by `VerifyTipInTransaction(tx,
  out headers)` inside that same transaction instead.
- `CreateVerifiedBraidTransitionContext` calls `ReadVerifiedBraidControl`, then
  `CreateVerifiedContext`: two full verifications without a callback. Select the
  control and construct context after one verification in the same transaction.
  This saves a real recovery read, not the dominant ordinary text work.

Do not move postcommit disk verification before commit. No transaction or private
ratchet loan crosses storage/time/authority/signer/network/diagnostic callbacks.
These safe consolidations alone do not resolve ordinary history amplification.

## Minimal archive boundary using current components

Keep current native schema and 304-byte protected history checkpoint. Separate
live commitments from immutable historical content within existing records:

| Record | Ordinary transition | Payload access / full audit |
| --- | --- | --- |
| Current TRS, pending/cleanup floor and working journal suffix | Verify all against fresh independent floor; no change | Same |
| Archived operation/direction/ordinal and 672-byte metadata | Authenticate the **complete** compact map, including unrelated entries | Same |
| Archived envelope/plaintext content | Do not decode unrelated content after compact-map proof | Fully verify every selected record against its authenticated metadata |
| Initial Hello/Init/consent, selected route controls, Braid or unknown-obligation evidence | Preserve their existing required reads; they are not automatically inert archives | Same |

The [existing producer and verifier](../../src/Deep.Client.Shared/Persistence/DeviceV2/Did2MessagingSqlJournal.History.cs)
compute `HistoryDigest` using SHA-256 over, in this exact order:
`UTF8("Deep/STORE-V2/messaging-history-prefix") || 0x00 || scope.Hash ||
basis.Exact || initialMetadata || (BE64(ordinal) || metadata)* || BE64(count)`.
Rows are ordered by ordinal, lie at/below the exact protected basis, and the
computed count/digest must equal the independently protected
`HistoryCount`/`HistoryDigest`. The producer currently validates all payloads
before constructing that metadata commitment; keep that producer unchanged.

The 672-byte metadata already binds the following current fields. This table
is an implementation map, not a new wire allocation:

| Offset / bytes | Meaning |
| --- | --- |
| 0 / 8 | `MSP2`, version, kind, direction, successor status |
| 8 / 188 | Exact stable predecessor floor |
| 196 / 8 | Successor ratchet generation |
| 204 / 32; 236 / 32 | Successor state commitment; exact TRS hash |
| 268 / 32 | Operation ID |
| 300 / 32; 332 / 32; 364 / 32 | Event, envelope/replay, exact header commitments |
| 396 / 32; 428 / 32; 460 / 32 | Deletion manifest, message-key deletion evidence, replay evidence |
| 492 / 32; 524 / 32; 556 / 32 | Dedup mutation, PQ fence, terminal-state commitments |
| 588 / 20 | Five exact body lengths |
| 608 / 64 | Closed route-processing outcome/time/commitment metadata |

Add an ordinary verifier that streams actual SQL compact records and recomputes
that **same** protected digest/count without loading archived payload blobs.
Preserve canonical storage types, sizes, ordinal order/uniqueness/bounds,
`row.ordinal == metadata.predecessor.Ordinal + 1`, operation equality at offset268,
kind/direction equality, and `ValidateMetadataTransition`. Cheap payload type/
length checks remain where no full blob read is needed. Initial metadata remains
fully checked. Verify the complete working suffix and current TRS as today.

A SQL negative lookup alone never means fresh. First verify the entire compact
map in the **same** read transaction as selector lookup. Any removed, inserted,
changed, reordered or hidden compact entry changes the protected count/digest or
violates its column bindings. Therefore even unrelated active-map corruption
still rejects, and absence is a complete-map proof rather than a trusted index.
No new tree, schema, library, root format, legacy reader or migration is required.

The transaction alone is not proof against raw file A→B→A. While hashing the
complete map, capture the exact selected operation/ordinal/direction/metadata
tuples that enter the digest. After the digest/count matches the independent
root, validate selected payload using those captured tuples, comparing any
refetched metadata with them. Never verify mapA and then trust metadataB from a
second query merely because both queries use one transaction. Alternatively,
validate selected payload while hashing that same buffered metadata tuple and
withhold all results until the complete root/count succeeds. An absent selector
is established by that complete authenticated scan, not a later SQL absence.
Bound selected tuple ownership to the existing batch limits; route/history
streams must not release authority or effects before complete proof succeeds.

## Required consumer changes before enabling the verifier

`ReadSelectedOrdinaryEvent` currently relies on prior full-history verification;
it must explicitly verify selected envelope/plaintext against the authenticated
metadata using the existing full `VerifyHistoricalEvent` rules. No replay,
materialization, ACK or historical success can be granted from unchecked content.
Audit every selector, not only `ReadVerifiedOperation`:

- Single/batched operation reads; transition exact-replay lookup; receive-for-event
  and initial-event reads; `HistoricalRouteRead.ReadOperation/ReadReceiveForEvent`.
- Incoming/outgoing history enumeration, filtered route-control enumeration and
  local history lists; every expected selected record must be fully verified.
- Native Braid classification/control reads, original Store/request/ciphertext/
  receipt consumers, semantic replay/materialization and tombstone ACK consumers.

The protected complete map remains live indefinitely while any operation retains
replay/ordering meaning. TRS has directional counters and bounded skipped keys,
not a lifetime operation-ID dedup map; dropping old IDs would permit changed
operation reuse or turn corrupted exact retry into fresh authoring.

Authenticate all metadata **before** applying route-control filters. The digest
commits accepted/fault markers; hiding a fault by changing marker/type/direction
cannot yield successful empty history. Then fully verify selected Hello/Accept/
route payloads and preserve consent ordinal, route head/predecessor sequence,
first-receive duplicate handling, fork and retained-fault fences. Do not synthesize
a new cached route permission. `HasVerifiedPeerBraidPurposeProgress` still reads
full authenticated received envelopes for peer epoch progress: no inference from
ordinal/generation or missing rows; a future protected max-epoch reducer needs
its own proof. Braid recovery is excluded from payload-read elimination initially.

Content-class selection has strict limits. Incoming route controls are selected
only by authenticated offset608 processing markers, then their DMC2 kind/payload
is fully checked. Hello/Init occupy fixed `initial_events` and are always fully
read. ContactAccept selection comes from the independently checked application
event hash/protected acceptance winner operation, followed by full native content
verification. There is no general content-kind field in native metadata.
In particular, outbound route controls have no receive-processing marker:
`ReadOwnNativeRouteHeadUnderLeaseAsync` must keep its complete existing outgoing
native/application payload reads. Never infer text/accept/noncontrol solely from
a zero route marker. No new type index is part of this proposal.

Unknown Store outcomes, pending materialization, receipts, attachments and original
retry obligations continue pinning their exact content. An expected archived row
that is missing/corrupt returns failure, never null/fresh/empty success. Local list
queries must establish expected selectors/counts from the authenticated compact
map before returning empty, then verify each selected archived payload. Archive
placement does not imply retirement, noncommit, delivery or deletion permission.

## Callback, crash and threat boundaries

The threat model retains hostile filesystem replacement/in-place mutation,
validly reencrypted SQL semantic substitutions, missing records and independent
root rollback; coordinated rollback of all independent protected anchors remains
outside the existing local boundary. No new watcher/OS immutability assumption.

Use existing closed synchronous SQL snapshots for compact-map and selected
content checks. There is no authority callback between those checks. A selected
record must match independently protected metadata, even under A→B→A; matching
outer file hashes are not the argument. Mutable provider/key/floor/revoke/expiry/
boot checks remain actual fresh checks before effects and after callbacks.

Consumers currently awaiting consent/time/authority during native enumeration
must use explicit captured input → closed SQL snapshot → external verification →
fresh required-record/root readback, as `ReadOriginalPeerStoreRouteAsync` already
demonstrates. No private positive cache or live permission crosses the callback.
An existing SQLite page cache is not an actual-custody check.

There is currently no explicit native cold-audit lifecycle: helper openers serve
both startup and later work. Add one to the existing
`ProtectedDeepIdV2AccountOwner`, which `DeepIdV2AccountService` constructs and owns
once. The first successful current-account read under its actual account lease
must audit the protected catalog and all initialized session archives before
ordinary commands are enabled. Integrate this at the existing
`ReadCurrentUnderLeaseAsync`/`RequireCurrentUnderLeaseAsync` shared current-account
path; do not rely on callers having invoked `GetCurrentAsync` beforehand. The
completed-audit marker is only scheduling state for that owner and exact account
instance, never verification permission: each later helper still reads actual
keys/floors/complete compact map and performs the required physical page check.
Owner recreation/process restart or account-instance change starts unaudited;
partial failure/cancellation never marks completion. Explicit archive audit,
producer/checkpoint admission and recovery that consumes archives remain full
semantic verifiers. `OpenRegisteredMessagingUnderLeaseAsync`,
`OpenOwnedMessagingUnderLeaseAsync` and ordinary reconciliation/selection are hot
helper opens and must not each restart the full semantic lifecycle audit.

Actual CLI lifetime is suitable for this scheduling scope. `CliSession.GetProfile`
uses `profile ??= WindowsProfile.Open(binding)`; that profile constructs one
`DeepIdV2AccountService`/Shared owner. `GetNetworkAsync` passes that same Accounts
instance through `NetworkBootstrap` to `DeepIdV2ClientNetworkSession`, which retains
the reference. Network invalidation/reopening disposes only the network context,
so it must not reset archive-audit scheduling. `CliSession.operations` serializes
frames and idle maintenance; session disposal stops/joins maintenance and then
disposes network/profile/storage. Scheduling belongs to the Shared account owner
attached to this profile lifetime, never the command/network/public-proof scope.
Standalone `Program.RunAsync` without a session opens/disposes a profile per
command and is intentionally cold: it performs the full audit each invocation
and cannot be presented as warm-online performance.

The current Accounts service has no disposal API. Before integrating retained
audit scheduling, provide a minimal explicit runtime-close hook on this existing
owner/service and invoke it from profile disposal after command/maintenance
drain, before storage disposal. It marks the scheduling owner closed and clears
the exact-instance marker; no new private buffer, SQL connection or audit Task
survives a command. A later use still fails on actual disposed provider reads;
an audited flag can never bypass those checks. This is lifecycle wiring on the
existing actor, not a process-wide cache or a new background worker.

Keep full payload audit on that cold owner admission; do not restore a remembered
audit success after process restart. Existing
`Did2CompactionPlan` owns prefix intent, SQL before/after evidence, independent
history-root adoption and staging disposal. Every crash resumes that exact plan;
no new root is minted from incomplete SQL. Preserve original ordinals, ratchet
commitments, protected roots, lost responses and exact unknown requests.

## Explicit behavioral change and measurable limit

**Changed guarantee:** a validly reencrypted, same-shape substitution in an
unselected archived payload, whose unchanged metadata still commits the original
content, need not reject an unrelated ordinary send. It must reject the next
selected content access or full archive audit. Today full semantic prefix replay
rejects it during every ordinary tip check. This timing change requires named
normative acceptance; no claim of equivalent detection timing is made.

This is distinct from ciphertext byte tampering. Current native full semantic
reads also force archive overflow-page authentication. The proposed explicit
full native page check must preserve that physical detection at each former
whole-archive boundary; without it the change would additionally defer raw
unselected overflow-page tamper detection and is **not** approved by this narrow
proposal. Existing full application cipher integrity checks remain unchanged.
Missing/changed active metadata, current TRS, suffix, root, route-fault marker or
selected payload still rejects before effects. DR-0170 is lifecycle precedent,
not blanket permission to retire message replay or route authority.

Removed hot work: fetching/allocating every archived envelope/plaintext, decoding
unrelated DPE2/DMC2 and attachment manifests and rechecking their full payload
commitments on every ordinary `VerifyTip`. Complete map scans, full working-suffix
verification, selected-content verification and complete native page checks
remain. Raw
metadata for 10,000 records is6.72MB plus selectors/SQL overhead: bounded-memory
streaming, still O(N), not history-independent operation cost. Existing prefix
compaction can bound the working suffix via an amortized owner trigger; runtime
currently exposes it but does not automatically invoke native prefix maintenance.
This does not resolve repeated protected aggregate decryptions/application WAL
opens or establish P1/one-second acceptance. True O(logN)/bounded lookup would
need authenticated membership/nonmembership paths or an accepted permanent
retirement frontier; neither exists today.

## Required negative and scaling tests

- Fresh/exact replay, changed local operation, skipped-key receive, rollback/latch,
  original Store recovery and semantic dedup remain identical.
- Delete/change/duplicate/hide any compact entry/column binding/route marker/root:
  even unrelated new send rejects with no mutation or false-empty route history.
- Validly reencrypt unrelated archive content: demonstrate the explicitly changed
  ordinary/access/audit outcomes; selected replay/ACK/Store/materialization rejects
  without remint, ratchet advancement or successful missing-history projection.
- Native overflow-page ciphertext corruption must fail the added full native
  cipher check; existing application cipher checks stay intact. Same-size swaps,
  A→B→A and callback key/provider/floor/revoke/expiry/boot changes do not authorize
  unanchored selected bytes or stale permission.
- Persistent session frames reuse one cold-audit scheduling owner; network
  reconnect does not recreate it. New profile/owner, process restart and exact
  account-instance change perform a new full audit. Failed/cancelled admission
  does not mark complete; disposal prevents reuse. Standalone commands remain
  separately measured cold operations.
- Crash at every existing plan/SQL/root/adoption/disposal boundary, cold audit,
  missing archive, lost response and pending-obligation pins; no silent repair.
- Fixtures100/1,000/10,000 count archive payload reads/decodes, full compact scans,
  native checks, storage loads and CPU separately. Cold/full audit still reads
  the complete archive. No connected latency claim before actual measurement.

## Next source slice map — not yet implemented

### Applicability to retained59: native prefix maintenance is mandatory

The sanitized retained59 receipt contains 163/171/189 native reconciliations and
303/319/355 full native verifies per two-target fanout. It does not report
`HistoryCount`, protected basis ordinal or working-suffix count. Source search
finds `CompactOwnedMessagingPrefixAsync` and
`PrepareOwnedMessagingPrefixCompactionAsync` called only by tests, not Shared
services or CLI commands. The captured scenario has no native-prefix command.
Therefore a nonempty archived prefix is **not established** for retained59;
source evidence indicates ordinary records keep accumulating in the working
suffix unless some earlier separately evidenced maintenance occurred. Do not
attribute those observed verification costs to the archived-prefix projector
without a count measurement. An archive-only rewrite could miss this real path.

The integrated slice MUST wire existing prefix ownership into ordinary sessions:

- Under the existing account lease, before an ordinary send/receive takes its
  live ratchet/SQL loan, obtain a fresh floor/history pair. Their ordinal gap is
  a scheduling hint only; the actual prefix producer authenticates SQL fully.
- Use an amortized soft trigger, initially a 64-row working suffix, with one
  at-most32-row existing `Did2CompactionPlan` batch per session/ordinary operation.
  The normal settled working suffix then stays around32–64 rows. This is
  not a new hard capacity limit and does not evict messages or unknown work.
- Invoke `PreparePrefixUnderLeaseAsync` → existing plan staging →
  `ResumeLocalCompactionUnderLeaseAsync`; do not call a public method that tries
  to reacquire the same account lease. Close maintenance SQL before the ordinary
  opener; reopen with the newly adopted actual history root, never an old
  `Did2MessagingSqlJournal` whose captured history root predates compaction.
- Existing active plans and pending ratchet floors recover exactly first. No
  maintenance is authorized from an unresolved phase or a parsed count alone.
  Keep current hard append/backpressure checks. Large already-retained suffixes
  catch up one bounded batch at a time; no startup unbounded compaction loop.
- Connect the trigger to real `RunMessagingUnderLeaseAsync` send/receive and the
  direct/group authoring capacity path where needed before native capacity is
  consumed, not an unused maintenance API. Store/ACK originals remain exact:
  native prefix compaction only removes journal-prefix rows, not event payloads,
  dedup commitments, unknown requests, floors or receipt obligations.

Focused actual-source evidence must first report archived count/basis and working
suffix size in fixtures, prove the real ordinary trigger runs and remains
bounded, and count per-boundary metadata rows, suffix rows, payload decodes and
cipher scans. Include warm already-compacted and retained-like initially
uncompacted fixtures. Compare trigger/compaction amortization together with the
new verifier; do not claim improvement from an archive path never reached by the
measured workload. No live profile/key read is authorized to fill this evidence
gap; retained59 applicability above is deliberately limited to saved receipts
and the runtime call graph.

| File / caller | Minimum connected change |
| --- | --- |
| `Did2MessagingSqlJournal.History.cs` | Keep `ComputeHistoryProjection` as full producer/audit validation. Add an explicit complete compact-map verifier using the same domain/order/count and captured requested tuples. Do not replace the producer with a cheaper routine. |
| `Did2MessagingSqlJournal.cs` | Keep an explicit full-tip audit path. Add the active-tip/selected-read path, full native page scan and anchored tuple-to-row comparison. Initial/TRS/working suffix retain their checks; selected readback cannot rely on old full-history side effects. |
| `Did2MessagingSqlJournal.ReadBatch.cs`, `.HistoricalRouteRead.cs` | Existing bounded batch/closed read-snapshot consumers capture exact selector tuples while the complete map is hashed; materialize only against those tuples after the independent proof succeeds. Construction binds actual connection, scope, floor/history and SQL transaction; caller supplies no unchecked verification flag or external delegate. |
| `Did2MessagingSqlJournal.IncomingHistory.cs`, `.BraidControl.cs` | Do not silently move live iterators to a weaker verifier. Keep outgoing/Braid full paths. Incoming route selection needs complete-map proof, exact selected set/count and selected payload validation before releasing data. |
| `Did2MessagingDurableCustody.cs` | Stable ordinary reconciliation can use the proved active path. Pending/cleanup recovery and interrupted-compaction owners retain explicit full required payload recovery; never cache returned stable success. |
| `ProtectedDeepIdV2AccountOwner.HistoricalPeerRoutes.cs`, `.PeerRouteHistory.cs`, `.OwnRouteHistory.cs`, and ACK/Store/history callers | Join all selected records to captured tuples. Preserve callback readbacks, fixed Hello/Init, known ContactAccept selector, route-fault semantics and full outbound/Braid exclusions. An unmapped consumer stays on full verification. |
| `ProtectedDeepIdV2AccountOwner.cs` / `DeepIdV2AccountService` lifecycle | One actual runtime-owner audit marker, exact account instance and explicit close, under the existing serial/account lease. Finish exact compaction recovery before cold audit where required; audit must not reject a valid intermediate plan merely because its root adoption has not completed. No audit re-entry through the ordinary opener. |
| Existing compaction/checkpoint producer/recovery files | Keep full producer/readback checks, same root formats and exact stored plans. No migration/reset or recreation from SQL. |

For operations/batches, the closed snapshot captures at most the existing32
selector tuples while streaming all prefix metadata, plus selected working-suffix
tuples proved by its journal/floor. Each tuple includes operation, ordinal,
direction and **exact metadata bytes**. An absence result records that the entire
authenticated map/suffix was covered. Selected payload and refetched columns are
compared with that tuple, not with self-consistent attacker-supplied metadata.
The object is bound to its constructing journal/connection/transaction and is
disposed before any external callback. It mints no current authority itself.
Route/history consumers with more selected data must use a closed full scan or
bounded fully proved batches; do not add a new retained-history hard limit or
release a partial stream as complete absence. Existing full paths remain the
safe fallback until each consumer has that proof.

### Provider overflow-page proof to write before broader implementation

Use a new native-only production test file and the existing
`OpenMessagingConnectionForTests` seam, avoiding expensive account/PQ setup.
This probes the **actual** SQLCipher provider and current native configuration,
not a mocked integrity callback. No shipping verifier is changed for the probe.

1. Create a disposable encrypted DELETE-journal database with a small metadata
   row and a separate synthetic archived BLOB spanning many pages. Verify current
   raw-key/provider policy. Record the exact file length/page size and prove the
   chosen physical target is an overflow page (prefer provider `dbstat` page
   classification when available; an unavailable classification prerequisite is
   a blocked proof, not a skip or an inferred last-page PASS).
2. Record an actually clean `PRAGMA cipher_integrity_check` result and the intact
   synthetic payload hash. Choose a byte within the proved overflow page, beyond
   the visible metadata cell; flip exactly that ciphertext byte through a real
   file handle and flush it. Preserve expected original fixture bytes locally
   only for cleanup; never repair product state.
3. Prove the metadata-only query still succeeds and does not read the selected
   archive BLOB. The actual full cipher pragma must return a corruption report
   or fail with the native corruption exception. Fully selecting the archive
   through a separate fresh comparison connection must independently fail as a
   witness that the corrupted page belongs to that payload. This witness does
   not replace the required scan on the original reused/cached connection.
4. Repeat with a fresh connection, a reused connection that previously ran the
   clean cipher check, and a reused connection whose full archive BLOB was read
   before corruption (all relevant pages can be cached). Also inject the raw
   change from a real callback between clean admission and the next check.
   The next actual cipher scan must reject every case. No new connection or
   cleared SQLite cache may hide the reused-connection requirement.
5. Assert no file mutation/repair by the check and unchanged file length. Add
   independent clean controls. Any provider/caching failure blocks active-path
   implementation/activation; retain full native payload reads and report the
   exact negative instead of weakening the assertion.

Pseudocode only: `CreateEncryptedFixture → ProveOverflowPage → CleanCipherScan →
optional(ReadWholeArchive) → callback(FlipActualOverflowByteAndFlush) →
MetadataReadSucceeds → FullCipherScanRejects → ActualArchiveReadRejects`.
`ActualArchiveReadRejects` is the separate fresh-connection comparison witness;
the reused/cached connection must itself reject through the full cipher scan.
The public/provider documentation is not substitute evidence for those actual
native tests. This test source and implementation are deliberately deferred
until the coherent initial P0/P1 source slice is committed and a test slot granted.
