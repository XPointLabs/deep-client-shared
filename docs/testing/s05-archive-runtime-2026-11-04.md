# Archive runtime development checkpoint — 2026-11-04

This is an isolated WIP checkpoint, not runtime activation or release acceptance.

Current follow-up uses Protocol `25e651053111afa260cc6cd7f025a2617b2905d3`,
whose full source/package gate passed 2640 cases with seven predeclared
platform/operator skips. The later Shared evidence below supersedes the earlier
open focused items, but does not qualify a full Shared or retained CLI run.
The normative owners are
[DR-0177](../../../docs/survival-program/decisions/DR-0177-authenticated-native-archive-index.md)
and its [DR-0178 amendment](../../../docs/survival-program/decisions/DR-0178-paged-route-history-and-current-promotion.md),
with [DR-0179](../../../docs/survival-program/decisions/DR-0179-established-native-session-provenance.md)
owning established-session provenance and source-audit timing.

The implementation now has an explicit maintenance-only enrollment entry,
account-wide ordinary-work fencing, fresh paired application/native segments,
six-root prefix/recovery guards and post-cleanup source readback. It preserves
actual authored payload/counter custody. Ordinary account admission cannot
silently enroll an old or partially indexed catalog. Guarded deletion can delete
its exactly matched guard atomically; absent/stale guards still refuse mutation.

Evidence retained under this repository's ignored artifacts directory:

| Artifact | Result |
| --- | --- |
|`archive-resume-20261104-build08`|Release production/test solution, zero warnings/errors; source inputs unchanged|
|`archive-resume-20261104-core02`|31 PASS, zero failures/skips; source and binary inputs unchanged|
|`archive-resume-20261104-core01`|29 guarded-deletion cases PASS; two enrollment cases failed on a missing SQL transaction, then corrected in core02|
|`archive-resume-20261104-smoke01`|3 PASS/14 FAIL: explicit enrollment incorrectly used ordinary catalog admission|
|`archive-resume-20261104-smoke02`|4 PASS/13 FAIL: self-delete contract and one fixture helper; original failure evidence preserved|
|`archive-resume-20261104-build20`|Release production/test solution, zero warnings/errors; source inputs unchanged|
|`archive-resume-20261104-established01`|14 PASS/1 fixture FAIL, zero skips; 2,315 captured inputs unchanged; not an accepted aggregate run|
|`archive-resume-20261104-retirement01`|6 PASS, zero failures/skips; 2,315 captured inputs unchanged; corrected two retirement-tamper cases and four Initial-owned native-audit classification cases|
|`archive-resume-20261104-route02`|Stopped diagnostic: 43 PASS/2 FAIL, 18 of 63 expected cases without completed results; original receipts and diagnostic stop retained|

Core02 covers 29 storage cases (both implementations, exact stale/missing
guard rejection, callbacks, crash/cold recovery and cancellation), plus actual
two-session enrollment/registration fencing and refusal to reconstruct a missing
already-adopted archive root. Earlier ordinary native send/receive, import and
Hello completion smoke cases passed, but their receipt is not a combined full gate.

The current WIP implements the DR-0178 kind6 decision, 1136-byte reducer,
bounded route-history source closure, F7/F8 indexes and count8 owner/service
path. It depends on Protocol commit `1e8de9658d22bcdaa2de02e8d463afa20bcc39f4`.
That earlier dependency is historical; the current follow-up dependency is
listed above. It must not activate an intermediate schema6 allocation on
retained profiles.

DR-0179 removes repeated original Device/PreKey SQL opens from established
segments. Admission instead joins actual native import/activation and archive
ancestry to the fresh protected retirement entry. Original-source verification
remains on Initial transfer/recovery, source use and explicit full-source audit.
Automatic native audit still checks every established scope; only positively
classified canonical Initial-owned states defer to their owning recovery path.

The established01 run passed real signed-page/cold-replay and public-fork
rejection, and a real send/receive/route/cold-ACK case with original source files
locked. Its sole failure mutated the sender retirement preclaim field instead
of the original TRS hash required by native provenance. The corrected fixture
changes exactly one byte in the selected entry's TRS hash; both tamper cases
then passed in retirement01. The original failed receipt remains unchanged.
Production binaries were unchanged between these two runs.

The former signed public-fork fixture timed out after 416.160 seconds; it now
passes in 102.107 seconds. These are whole-fixture durations including account
setup, not message-delivery timings. A 30-second route02 stack trace attributed
about 97% of sampled active-send time to repeated original-source open/validation.

Still required: hostile wrong-anchor full/incremental and application/ACK
checks; mixed Initial/established automatic audit and unselected-corruption
checks; retained never-native 6/7 ordering; actual source bounds and old-conflict
selection; enrollment/crash/source matrices, full source/package gates and
retained CLI enrollment/catch-up. Large explicit original-source audit
inventories also remain open. No general runtime qualification follows from
the focused results above.

## Subsequent bounded qualification and corrections

Internal atomic guarded reads retain the public batch32 limit while checking
complete dependency inventories. Initial cancellation releases source/native SQL
and key/TRS loans before provider boundaries and reopens actual custody before
deletion/readback. Mailbox custody now binds the independent archive root.
Fresh Braid controls at63 authenticate before existing bounded maintenance;
exact original retries do not schedule a new batch.

| Artifact | Result |
| --- | --- |
| `archive-resume-20261104-qualification02` | 37 PASS/1 fixture FAIL; all16 guarded-read cases PASS; 2327 inputs unchanged; aggregate not accepted |
| `archive-resume-20261104-qualification04` | 23 PASS/0 FAIL/SKIP; 2327 inputs unchanged; cancellation/source and enrollment corrections |
| `archive-resume-20261104-build30` | Zero warnings/errors; 2186 source inputs unchanged |
| `archive-resume-20261104-qualification05` | 7 PASS/8 FAIL; original evidence retained; 2327 inputs unchanged |
| `archive-resume-20261104-qualification06` | 4 PASS/4 FAIL; structural100/1000/10000 and actual page corruption PASS; 2328 inputs unchanged |
| `archive-resume-20261104-qualification07` | 12 PASS/6 FAIL; wrong-anchor4, mixed Initial/established2 and four pending/SQL crash cuts PASS; 2328 inputs unchanged |
| `archive-resume-20261104-qualification08` | 3 PASS/0 FAIL/SKIP; actual source closure and hostile overcount boundaries; 2328 inputs unchanged |
| `archive-resume-20261104-qualification09` | 1 PASS/0 FAIL/SKIP; expired-inventory publication maintenance before dispatch; 2328 inputs unchanged |
| `archive-resume-20261104-build32` | Zero warnings/errors; 2186 source inputs unchanged |
| `archive-resume-20261104-qualification10` | 3 PASS/1 FAIL; Braid capacity/retry and pending receiver recovery PASS; 2328 inputs unchanged |
| `archive-resume-20261104-qualification11` | 4 PASS/2 FAIL; monotonic same-endpoint warm/cold replay, expired delivery rejection and stable recovery PASS; 2328 inputs unchanged |
| `archive-resume-20261104-qualification12` | 1 PASS/13 FAIL; component opened-floor and archived consumer fixture corrections required; 2328 inputs unchanged |
| `archive-resume-20261104-qualification13` | 9 PASS/2 FAIL; historical Store/maintenance/reintroduction/stopped work PASS, snapshot fixture corrections required; 2328 inputs unchanged |
| `archive-resume-20261104-build33` | Zero warnings/errors; 2186 source inputs unchanged |
| `archive-resume-20261104-qualification14` | 2 PASS/1 FAIL; same-owner warm endpoint and final prefix PASS; actual gap generation assertion needs the genuine automatic mode4 request; 2328 inputs unchanged |
| `archive-resume-20261104-qualification15` | 11 PASS/0 FAIL/SKIP; actual opened-floor component cases and selected/cold full Braid audit negatives; 2328 inputs unchanged |
| `archive-resume-20261104-qualification16` | Interrupted by the 20-minute watchdog, no TRX/native terminal; supplementary canonical comparison found all2328 inputs unchanged; not qualified |
| `archive-resume-20261104-build34` | Zero warnings/errors; 2186 source inputs unchanged |
| `archive-resume-20261104-qualification17` | 1 PASS/0 FAIL/SKIP; exact automatic native request and gap continuation/promotion/cold replay; 2328 inputs unchanged |

Q08 constructs twelve actual F7 C/P facts at lawful active suffix63. Current,
catch-up and conflict reads qualify respectively4/49/49 outgoing originals;
the same counts and protected floor survive cold reopen. These observations
do not claim that the conservative ceilings71/95 are reachable populations.

The next correction packet fixes an actual same-endpoint promotion regression:
an older distinct announcement must not replace L or append another promotion.
It compares authenticated sender sequences from paired actual originals after
full current qualification, preserving the final freshness/snapshot recheck.
Astra reviewed this source boundary; q11 passed nine warm/cold replays without
another append and a newer announcement promoting exactly once. Higher public endpoints can still
advance after their missing history arrives.

Fixture corrections preserve real signed windows: construct the publication
chain before minting120-second history controls, install receiver fault hooks
before pending recovery, test expiry at actual delivery rather than draft queue,
bind actual archive roots and use the captured pre-compaction archive root for
rollback tests. Fresh count8 outcomes are immutable stage3; retained6/7 readers
retain their existing boundaries. Braid capacity setup must prove actual epoch
agreement, not infer it from equal journal occupancy.

Publication journal capacity refusal remains accepted under DR-0078/0091.
Endpoint history tests stop before the next reservation/time advance exceeds
the actual owner budget, require genuine archived sources and cold verification,
and do not claim25 successful renewals. Existing actual owner admission negatives
retain zero threshold callbacks and exact unchanged journal checks. Independent
owner/Registry/XPS long-history progress remains open under DR-0178; native
archive compaction grants no authority to shorten the original retirement horizon.

The remaining fixture-only corrections after build32 use the same service owner
for cold admission and warm measurement, a genuine bounded publication chain,
the actual protected floor before SQL opens, and selected current native sources
for archived payload checks. DR-0177 bounded tip verification is not a whole
archived payload scan; explicit full audit and affected-source negatives remain.
Mr. X explicitly reordered goal measurement before the full Shared gate. Next
steps are a coherent WIP commit and matching retained CLI enrollment/catch-up/round60,
then warm delivery/ACK measurements. Run the required full Shared gate after
the target is demonstrated and changes stabilize; diagnostic E2E is not full
source or release qualification. The interrupted12 route-read variants and
the unlaunched6 snapshot variants remain required in that full gate, without
waivers or timeout changes. Independent runtime source audits, authenticated
currentness, replay checks and retained-state guards are not deferred.
The exact gap correction passed q17: the authenticated outgoing native event
exists before the owned-command retry, which must match operation and DMC hash
without changing the floor. The two generation equations remain exact; no
unchecked increment or widened range replaces the original assertion.
The full reference declaration now resolves2256 identities from60 original TRX
with all34 accepted replacement bindings; failed references remain failures.

No retained CLI profile, production service, Windows client or Android client was
changed by these tests. Cursor60 and previous original operations remain intact.
No delivery-latency, sustained recovery or release claim follows from this checkpoint.
