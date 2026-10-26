# DR-0175 correctness and cost checkpoint — 2026-10-26

The connected candidate has focused correctness evidence, **no performance
acceptance** and no full source qualification. No live delivery run, rollout,
profile reset or push was performed. Normative scope remains
[DR-0175](../../../docs/survival-program/decisions/DR-0175-active-native-state-and-archive-validation.md);
the [implementation map](../architecture/semantic-operation-storage-owner-proposal.md)
records conservative full consumers and callback boundaries.

| Preserved run | Result | Meaning |
| --- | --- | --- |
| [01](../../artifacts/dr0175-active-native-20261026-01/terminal.json) | Build1; tests not launched | One test-only nested-fixture access error; original receipt retained. |
| [02](../../artifacts/dr0175-active-native-20261026-02/terminal.json) | Build0; native1;55PASS/3FAIL/0skip; inputs unchanged | Two hostile-replacement fixtures used immutable insertion instead of CAS. A third expected an exact base exception instead of Protocol's internal subclass. Actual threshold compaction had not yet been exercised past that assertion. |
| [03](../../artifacts/dr0175-active-native-20261026-03/terminal.json) | Build0; native0;8PASS/0FAIL/0skip; inputs unchanged | Exact hostile CAS and restoration actually applied; four callback-root cases reject before release and exact retry emits no new event. Genuine64-row threshold scenario completes its interrupted32-row batch on warm retry, preserves originals/receipt obligations and avoids a second selection. Three moved cost cases pass. |
| [04](../../artifacts/dr0175-active-native-20261026-04/terminal.json) | Build0; native0;2PASS/0FAIL/0skip; inputs unchanged | Warm application-history lookup rejects a validly reencrypted native original despite active-map success. Existing full archive/reopen/acceptance/replay case remains green. |

Accepted runs use Windows PowerShell Desktop5.1.26100.9457, SDK10.0.301,
Release builds with zero warnings/errors and the root TestGate native/input/TRX
implementation. Runs03/04 explicitly disable collection parallelization and set
maximum threads1. Run02 set maximum threads1; TRX intervals show no other-case
overlap for any cost case. All native processes exited. Earlier FAIL receipts
remain FAIL; the affected reruns do not turn run02 into an all-green58-case gate.
The full gate remains unqualified.

The focused matrix includes complete-map mutation/absence checks, captured-tuple
substitution, late actual BLOB/TRS size bounds, history/key/catalog callback
readback, warm owner disposal, real automatic prefix recovery, existing Braid
handover, source/clock/floor, lost ACK and protected checkpoint crash cases.
The separate [overflow proof](dr0175-native-overflow-provider-proof-2026-10-26.md)
remains a bounded provider prerequisite. Unmapped projection/history consumers
explicitly retain FULL native verification; an intact application mirror cannot
stand in for selected native payload custody.

## Matched structural microcost: candidate is slower

Run03 used the same provider, file, synthetic TEST root, selected operation and
existing handle for both algorithms, with three alternating repeats per size.
Setup is outside timing. TEST roots never enter protected custody and cloned
DPE2s establish no AEAD, ratchet progression or business authority. The cost class
is separate, preserving the original contact-test scheduler isolation policy.
Preexisting Docker containers were running after the engine startup barrier;
these are local diagnostic measurements, not delivery p95 or device evidence.

| Archive rows | Full median wall / process CPU ms | Active median wall / process CPU ms |
| ---: | ---: | ---: |
| 100 | 2.72 /0 | 6.92 /0 |
| 1,000 | 18.97 /15.62 | 51.34 /46.88 |
| 10,000 | 1,175.74 /1,109.38 | 1,907.05 /1,843.75 |

Process CPU at the smallest size is below timer granularity; zero is not zero
work. Each sample has0opens because this is an explicitly existing-handle
verification microcost. Both algorithms authenticateN metadata rows; full
performsN instrumented payload verifications, active1 selected verification plus
one complete native cipher scan. Working count is0 and archive countN. These
counters do not count every payload allocation or physical page read.
[Exact samples and summary](../../artifacts/dr0175-active-native-20261026-03/cost-summary.json)
are retained, as are run02's independent slower measurements.

The candidate removes unrelated payload decoding but adds whole-file page
authentication and actual-table metadata scans/sorting. Even one10,000-row
selected read exceeds1s here. Automatic32-row mutation batches do not make
full checkpoint production/audit work bounded. This does not satisfy P1 or the
one-second target. See the [lower-bound analysis](../architecture/native-active-state-lower-bound-2026-10-26.md)
before proposing another runtime change; no cache/pooling shortcut is authorized.
