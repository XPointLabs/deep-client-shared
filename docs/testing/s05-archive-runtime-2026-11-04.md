# Archive runtime development checkpoint — 2026-11-04

This is an isolated WIP checkpoint, not runtime activation or release acceptance.
The normative owners are
[DR-0177](../../../docs/survival-program/decisions/DR-0177-authenticated-native-archive-index.md)
and its [DR-0178 amendment](../../../docs/survival-program/decisions/DR-0178-paged-route-history-and-current-promotion.md).

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

Core02 covers 29 storage cases (both implementations, exact stale/missing
guard rejection, callbacks, crash/cold recovery and cancellation), plus actual
two-session enrollment/registration fencing and refusal to reconstruct a missing
already-adopted archive root. Earlier ordinary native send/receive, import and
Hello completion smoke cases passed, but their receipt is not a combined full gate.

The ten enrollment-cutpoint matrix, broader archive/prefix/source selection,
full source/package gates and retained CLI enrollment are still unqualified.
The subsequent DR-0178 kind6/1136-byte reducer/F7-F8 cutover is not implemented
in this checkpoint; this earlier schema6 allocation must not be activated as an
additional supported profile. Existing initial-source DeviceV1/PreKeyV2 provider
boundaries also require separate closure before general acceptance.

No retained CLI profile, production service, Windows client or Android client was
changed by these tests. Cursor60 and previous original operations remain intact.
No delivery-latency, sustained recovery or release claim follows from this checkpoint.
