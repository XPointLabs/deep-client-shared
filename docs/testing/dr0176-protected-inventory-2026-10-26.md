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
