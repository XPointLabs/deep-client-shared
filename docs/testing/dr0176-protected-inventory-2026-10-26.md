# DR-0176 protected inventory — focused source evidence

The format, changed unused-object validation timing and lifecycle contract belong
to [DR-0176](../../../docs/survival-program/decisions/DR-0176-bounded-protected-storage-inventory.md).
This note records Shared implementation evidence, not a second specification.

`JournaledDeepSecureStorage` now opens an existing manifest. Explicit
`CreateNewAsync` durably creates the empty inventory; `EnrollAggregateAsync`
is the sole DSS1 decoding path and preserves every logical slot at the same
path. Ordinary missing state rejects. `AuditAsync` and the first admission of a
new owner authenticate all referenced objects; later admissions still read and
Unprotect the actual complete manifest and verify each selected object.

The existing gate/process lease and `IDeepSecureStorage` APIs remain. Atomic
mutations stage only changed objects and publish one manifest. Protector
callbacks and sharing retry waits require actual predecessor/guard admission
again. Fresh creation uses no-replace publication and rechecks absence after
its provider callback. Retirement checks the exact empty temporary at every
rename attempt, durably replaces the authorized named object with that
tombstone, then unlinks it. A second guarded metadata commit removes completed
cleanup obligations. Pending state never becomes a recovery root; explicit
enrollment recovery rejects untracked object remnants.

The thirteen-field `DeepSecureStorageWorkSnapshot` is an immutable cumulative
instance snapshot and remains readable after disposal. It counts acknowledged
managed manifest/object read/write bytes, plaintext returned by successful
decryption, crypto calls and tombstones, including audit/enrollment/recovery
and failed work up to acknowledged I/O completion. A failed native write can
transfer bytes its managed API does not report. These counters do not measure
device traffic, disk cache misses, metadata I/O or DPAPI's internal byte work.
No observer is invoked inside the storage operation.

## Focused gate

`artifacts/dr0176-protected-inventory-20261026-01` preserves the literal filter,
Release build/native logs, TRX, before/after manifests and terminal receipt.
The root common TestGate helpers ran under Windows PowerShell 5.1, with serial
xUnit collections and threads, against Shared, Protocol, CLI and root normative
inputs. Build-to-test inputs remained frozen.

- Release build: native **0**, **0 warnings / 0 errors**.
- Focused tests: native **0**, **143 PASS / 0 FAIL / 0 SKIP**.
- All **2,267** captured code/binary/normative inputs unchanged;
  `SourceUnchangedDuringBuild=true`, `FocusedAccepted=true`.
- All gate processes terminated, outer native exit **0**, process lease released.
  `FullAccepted=false`.

The finite union contains 108 secure-storage cases (including 56 new DSS2
cases), 30 native checkpoint cases, four affected account/SQL first-create and
reopen cases, and one genuine encrypted owner compaction/recovery case.
Coverage includes bounded framing, complete membership/absence, selected
hash/context/AEAD failures, cold versus warm audit timing, cross-slot CAS,
mutable protector/source callbacks, original process races/sharing behavior,
creation and mutation cancellation, staged/committed crash cutpoints,
empty/missing retirement targets, exact pending recovery and byte-preserving
enrollment with an unchanged actual SQLCipher file.

This is bounded Windows source qualification. CLI shipping compilation/tests,
matched actual-DPAPI measurements, retained-profile enrollment, broader release
gates and other platform execution remain separate. No retained profile,
publication or connected activation was performed. The unrelated unqualified
contact-threshold candidate remains unchanged and its failure is not waived.
No latency or overall P1 completion claim follows from this receipt.

## Packaged Windows path correction

The first downstream CLI gate, `deep-cli/artifacts/dr0176-cli-20261026-01`,
built successfully with zero warnings/errors but ended **23 PASS / 6 FAIL /
0 SKIP**, native **1**. All 2,127 build-source and 2,285 test inputs were
unchanged. Six actual account/session/storage lifecycle cases rejected the
opened LocalApplicationData lock path before creation/enrollment completed.
That failure is preserved; the original Shared143 receipt did not exercise
this packaged-host path spelling.

Read-only probes of the gate's disposable fixture handles established Windows
packaged LocalApplicationData virtualization. The physical path contained
`Packages` and `LocalCache/Local`; it preserved the exact declared relative
tail, drive and filename. Both independently opened requested parent directory
handles resolved to the actual file's physical parent. No private path or
package identifier was exported. The masked `path-identity-probe.json` and
`path-mapping-probe.json` remain with the failed CLI gate.

The Windows predicate now independently opens the requested parent with
no-follow directory semantics, obtains its canonical handle path, appends only
the exact requested filename, and requires complete equality with the actual
file-handle path. It verifies directory/file type, non-reparse status, file
single-link status and common volume, and checks resolved ancestry. Parent
sharing permits read/write but pins rename/delete during that comparison.
There is no package-prefix whitelist, suffix-only comparison or short-name
heuristic. Unix behavior is unchanged.

`artifacts/dr0176-protected-path-20261026-01` records the narrow correction gate:
Release build native **0**, **0 warnings/errors**; **10 PASS / 0 FAIL / 0 SKIP**,
test native **0**; all **2,267** inputs unchanged and source unchanged during
build. Outer native exit **0**, all gate processes terminal, lease released;
`FocusedAccepted=true`, `FullAccepted=false`.

The two new Windows cases exercise actual disposable LocalApplicationData
creation/enrollment/read/audit/reopen and rejection of an existing wrong
canonical parent with the same filename. Eight existing creation, enrollment,
atomic replacement and retirement negatives complete the finite package.
Reparse/no-follow and link-count guards were preserved in source review;
this package adds no independent symlink/hardlink cases. The original143
receipt remains scoped to its earlier source hashes; it was not rerun on this
change. CLI rerun, matched performance evidence, full qualification and
retained activation remain separate gates.

## Downstream focused and isolated measurements

The CLI correction gate
`deep-cli/artifacts/dr0176-cli-20261026-02/terminal.json` accepted its Release
build with zero warnings/errors and **29 PASS / 0 FAIL / 0 SKIP**, native **0**.
All 2,127 build-source and 2,285 test inputs remained unchanged. This includes
disposable genuine DID2/native SQL state converted through an exact DSS1
fixture, explicit CLI enrollment, byte-preserving logical/native readback and
unchanged address/status. It is not retained-profile conversion.

The matched isolated receipts are
`deep-cli/artifacts/p1-storage-benchmark-20261026-baseline04/baseline04.terminal.json`
and
`deep-cli/artifacts/p1-storage-benchmark-20261026-candidate01/candidate01.terminal.json`.
Each completed **141/141** rows, native **0**, with identical two helper hashes;
35 archived-baseline inputs and 2,159 candidate source/runtime inputs were
unchanged. Earlier helper setup failures remain preserved in the CLI artifacts.

The candidate is **slower for every measured operation at all three capacities**
(16, 256 and 1,024). For capacity1,024, descriptive median wall times in ms are:

| Operation | Aggregate baseline | Manifest candidate |
| --- | ---: | ---: |
| Single selected read | 2.76690 | 9.74470 |
| Two-slot selected read | 3.41645 | 11.01090 |
| Atomic registration and deletion | 58.95895 | 448.72485 |

The single-read acknowledged managed bytes fall from4,196,647 to396,813,
but that is not a measured speed improvement. Registration/deletion performs
43 native Unprotect calls versus2 and reads14,428,111 managed bytes versus
8,393,324. Full scalar results are preserved in the CLI
`comparison-baseline04-candidate01.json`; timings are descriptive isolated
measurements, not connected p95. Source correctness evidence and byte isolation
do not qualify this candidate as a performance fix. Full, retained and overall
latency acceptance remain unestablished; no connected activation is authorized
by these receipts.

## Bounded path-buffer allocation correction

The follow-up changes only `ReadWindowsHandlePath` buffer allocation: initial
capacity512, hard maximum32,768 and at most three native attempts. It grows from
the documented required length, never consumes truncated path bytes, and
rejects zero, over-bound or unstable results. Exact parent/file predicates and
all provider/guard calls remain unchanged; there is no cached path or permission.

`artifacts/dr0176-path-buffer-20261026-01` accepted Release build native **0**,
zero warnings/errors, and **3 PASS / 0 FAIL / 0 SKIP**, test native **0**.
Source during build and all **2,267** captured inputs were unchanged; outer
native exit **0**, processes terminal and lease released. The new actual
Windows handle case independently demonstrates required capacity greater than512,
matches a separate full-capacity native reference and preserves the correct/
wrong-parent result. Existing LocalApplicationData lifecycle and wrong-parent
cases complete this finite gate. `FullAccepted=false`.

The unchanged benchmark helpers then ran
`p1-storage-benchmark-20261026-baseline05/baseline05.terminal.json` and
`p1-storage-benchmark-20261026-candidate02/candidate02.terminal.json` under CLI
artifacts. Each completed **141/141**, native **0**, with identical helper hashes;
35 baseline and 2,159 candidate inputs remained unchanged. The fresh candidate
publish was native **0**, zero warnings/errors, with 2,125 inputs unchanged.
No CLI29 rerun was required for this buffer-only patch.

Allocation decreased, but **all nine latency medians remain slower than the
aggregate baseline**. Atomic registration/deletion still makes43 native
Unprotect calls,109 manifest reads and30 object reads. The scalar comparison
is `comparison-baseline05-candidate02.json` in the candidate directory.
Performance acceptance remains **rejected**. No retained conversion, connected
activation or full qualification is established. A closed operation/admission
redesign is analysis only; it is not part of this correction.

## Cleanup callback review of the buffer correction

Source review after the measurements identified an unclosed named-retirement
boundary. That candidate's `CompleteCleanupAsync` retired the object names before
calling `Protect` for the cleanup-free successor. A mutable protector callback
can restore old ciphertext at a retired name without changing the current
manifest. The metadata-only publication checks no newly referenced objects and
does not recheck those retired paths before clearing their obligations. The
focused receipts above do not prove rejection of that scenario.
The subsequent post-adoption `ReadCurrent` also calls `Unprotect` after cleanup
obligations have been cleared; its callback could restore the name as well.

The proposed closed cleanup segment protects its candidate before retirement,
then freshly admits the actual cleanup-bearing root and retires every authorized
nonactive ID before adoption. Any callback or retry invalidates completion facts
for all IDs, including absent/empty names. This is a reviewed design direction,
not an implemented fix in the buffer correction. Moving `Protect` alone is
insufficient if a later provider callback remains. The final boundary must
either be callback-free after the last retirement or retain durable obligations
through every later callback. That choice needs the separate owner contract and
meaningful restoration/retry regressions before activation.

## Closed operations — 2026-10-28

The resumed implementation follows the accepted
[closed-operation contract](../../../docs/survival-program/decisions/DR-0176-bounded-protected-storage-inventory.md#closed-operation-admissions--2026-10-27).
One private owner now spans the outer public operation under its existing gate
and process lease. A selected read performs one actual manifest Unprotect,
verifies selected objects and any cold audit, and rejoins actual source bytes
and paths before every result, including absence. Failed final fences preserve
the cold-audit obligation. Windows directory handles pin verified logical and
physical ancestry within each closed segment; actual leaf type, single-link,
reparse, handle path, length, hash and EOF checks remain.

Mutation prepares and authenticates protected successor candidates before
retirement, disposing key-bearing inventories before provider edges. Normal
recovery plus mutation retains old cleanup IDs in the primary successor.
An overflow uses a prepared metadata-only cleanup root, ordinary primary root
and final cleanup-free root; every serialized cleanup set stays within1,024 IDs.
Abandoned pending/enrollment descriptors remain until all later provider calls
have finished. Clearing a descriptor or adopting the overflow metadata root
starts a synchronous suffix with no external callback, wait or retry. Genuine
I/O failure still reports incomplete work; no forced recovery-only retry or
false CAS result was added. The existing pending-successor validator is unchanged.

Callbacks and sharing waits discard admission and pinned directories. A cleanup
invalidation repeats durable retirement for the entire authorized set, including
absent/empty names. The operation has one two-second retry budget and a separate
maximum of eight immediate hook invalidations. Budget exhaustion is exactly
`IOException("Protected storage operation retry budget exhausted.")`; previous
per-file native-error assertions were adapted while preserving their unchanged
state/permission and successful-retry checks. Hooks consume explicit one-shot
selections before invoking code; final cleanup supports only fixed crash
injection. Final committed readback invokes no provider or arbitrary hook.

The three literal-filter receipts remain in
`artifacts/dr0176-closed-operations-20261028-{01,02,03}/terminal.json`:

- **01:** build native1, two `xUnit2031` errors in test assertions; tests were
  not launched. Both assertions now use the predicate overload of `Assert.Single`.
- **02:** build native0, tests native1, **203 PASS / 3 FAIL / 0 SKIP**;
  all2,279 inputs unchanged. The failures exposed a test expecting a provider
  callback after primary adoption, a crash selector assuming the first random
  staged ID was already unlinked, and a remaining old `Win32Exception`
  assertion. The replacements verify no provider after root change, select
  the actual staged ID's unlink occurrence, and require the exact shared-budget
  IOException. Their source/state/retirement assertions remain required.
- **03:** build and tests native0, **0 warnings / 0 errors**,
  **206 PASS / 0 FAIL / 0 SKIP**:187 storage/native-owner cases and19 contact
  cases. Windows PowerShell5.1.26100.9711 / SDK10.0.301; all2,279 captured inputs
  unchanged, source unchanged during build, `FocusedAccepted=true`,
  `FullAccepted=false`.

The owner explicitly authorized the contact fixture correction: the dependent
successor is rebound and re-signed to the exact corrupted XRC reference so the
negative case reaches its intended witness-signature rejection. Production
threshold validation and signed windows were not changed; all19 contact cases
pass in03. The earlier failed receipt remains preserved.

The focused package now covers real saved-ciphertext restoration during
candidate callbacks, later-ID callbacks and native sharing waits; whole-set
replay, bounded cleanup overflow, pending-descriptor handoff, one-shot selection,
all read return fences, failed-audit preservation, and batch-size-independent
admissions. This is focused source evidence. Matched timings, full qualification,
retained enrollment and connected execution have no acceptance from this receipt.

## Scoped directory and ownership optimization — 2026-10-28

The isolated diagnostic in `artifacts/dr0176-profile-20261028-01` used copied,
instrumented storage sources and the actual CLI DPAPI adapter on disposable
inventories. Its build and execution exited0 with zero warnings/errors;
all18 rows completed and captured inputs stayed unchanged. `profile.json` and
`summary.json` preserve stage counts and inclusive/exclusive durations. These
are diagnostic timings, not another shipping benchmark or modified helper.
Summaries exclude the first instrumented sample and describe two remaining
samples per operation/capacity; nested inclusive durations must not be summed.

At16 slots, a selected read visited137 ancestor nodes through23 complete
attribute walks, opened25 native handles and resolved39 final paths. Attribute
walks took2.85ms descriptively, versus0.40ms in the actual provider Unprotect,
0.05ms decoding and0.004ms selected-object AEAD. The atomic cycle performed179
native opens,629 final-name queries,726 file-information queries and494 ancestor
node visits. At1,024 slots, preparing four roots also incurred an unnecessary
complete decoded-inventory copy per prepared root. This evidence identified
redundant directory work and ownership copies as correction targets.

The resulting package makes four scoped changes:

- Build complete independently verified/pinned logical and physical ancestor
  chains without walking the complete physical ancestry again for each node.
  Mapped logical/physical directory handles must have the same volume/file ID.
- Inside that unchanged pinned segment, recheck parent ID/type/reparse status
  without repeatedly resolving the parent's final name. Every actual leaf still
  verifies its complete handle path against that pinned physical parent and
  exact requested filename, with regular-file/single-link/byte/EOF checks.
- Let the private operation own the actual process lease and its initial
  directory scope. Failed lease attempts drop the scope before waiting; final
  disposal clears loans and pins before releasing the lease.
- Transfer the authenticated decoded candidate inventory directly to its owned
  caller instead of copying its complete map. Failure still disposes it, and
  callers dispose it before the next external provider edge.

No directory handle or admission survives a provider callback, real hook or
sharing wait. No path/string permission cache, skipped source/guard check,
format change, new crypto or cross-operation reuse was introduced.

`artifacts/dr0176-closed-operations-20261028-04/terminal.json` preserves build
native0, zero warnings/errors, tests native1, **206 PASS / 1 FAIL / 0 SKIP** and
all2,280 inputs unchanged. Only the new ACL fixture failed: its independent
probe did not establish the intended denial. A single child READ_ATTRIBUTES
denial still permitted access through its containing directory's LIST_DIRECTORY
right, as described by [Microsoft's file-attribute access explanation](https://devblogs.microsoft.com/oldnewthing/20150428-00/?p=44994).
The failure was not product permission bypass evidence and was not waived.

The corrected nested, fixture-owned ACL witness denies both paths, independently
observes native access-denied5, then requires the real storage operation to fail
before commit with that native cause. It restores both exact original DACLs in
`finally` and verifies unchanged root, objects and logical values. The existing
path witness now exercises the optimized instance under its actual process
lease, accepting the correct parent and rejecting a real wrong parent with the
same leaf name. Production source stayed unchanged between04 and05.

`artifacts/dr0176-closed-operations-20261028-05/terminal.json` records build and
tests native0, **0 warnings / 0 errors**, **207 PASS / 0 FAIL / 0 SKIP**
(188 storage/native-owner and19 contact), source unchanged during build and
all2,280 inputs unchanged. The interpreter remains Windows PowerShell5.1.26100.9711
with SDK10.0.301; `FocusedAccepted=true`, `FullAccepted=false`. All earlier
restoration, replay, guard, crash, permission and exact-original assertions
remain part of the finite package.

The unchanged shipping helpers subsequently completed141 successful rows for
both archived baseline07 and candidate04. Their exact receipts and scalar tables
remain in the [CLI checkpoint](../../../deep-cli/docs/testing/cli-storage-manifest-adapter.md)
and `deep-cli/artifacts/p1-storage-benchmark-20261028-candidate04/comparison-baseline07-candidate04.json`.
All nine candidate latency medians remain above the aggregate baseline:
the1,024-slot single read is3.585ms versus3.576ms, while the atomic cycle is
158.285ms versus51.393ms. Atomic native Unprotect calls are eight versus the
earlier candidate's43; that reduction and improved candidate timings do not
establish a speed improvement over the aggregate. Full, performance and release
acceptance remain unqualified. Separately authorized SAME3 retained diagnostics
have their own preservation and execution receipts; these disposable source and
benchmark results do not prove delivery or p95.
