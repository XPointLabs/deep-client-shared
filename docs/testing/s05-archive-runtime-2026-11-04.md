# Archive runtime development checkpoint — 2026-11-04

This is an isolated WIP checkpoint, not runtime activation or release acceptance.
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
It must not activate an intermediate schema6 allocation on retained profiles.

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

No retained CLI profile, production service, Windows client or Android client was
changed by these tests. Cursor60 and previous original operations remain intact.
No delivery-latency, sustained recovery or release claim follows from this checkpoint.
