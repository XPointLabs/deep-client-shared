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

## Retained DMB1 schema portability

Matching CLI candidate build/publish and29 focused cases passed. Local retained
operator renewal also passed with stable keys, volumes and nine healthy services.
Actual retained maintenance stopped before archive enrollment at application
schema validation. Closed diagnostics observed32 expected/actual objects, zero
missing/extra/type changes, and32 DDL differences, all CRLF-only
(`deep-cli/artifacts/retained-goal-20261104-02/maintenance01/terminal.json`).
Thus source checkout line endings caused a false reset requirement.

The candidate fix compares only unquoted CRLF/LF equivalently under DR-0028.
Quoted SQL contents/escapes, every other character and exact object identity
remain enforced. Raw stored schema and authored/compaction fingerprint inputs
are unchanged; no profile migration, reset or SQL repair is performed. Focused
SQLCipher reopen/data-preservation and tamper/quoted-text checks are required
before retrying the retained diagnostic. No business round has been authored.

Build35 passed with zero warnings/errors and unchanged source inputs.
`archive-resume-20261104-qualification18` passed all18 focused cases, including
the existing four schema-refusal cases; no skips, inputs unchanged. Real LF/CRLF
reopens preserved message data and stored schema bytes; quoted contents,
escaped delimiters, comment quote handling and structural tampering retained
their exact boundaries. The next evidence is the same retained CLI profiles.

## Empty archive enrollment recovery

The matching retained candidate passed all three original-source snapshots but
stopped in the first profile's actual enrollment. Read-only authenticated
inspection found SchemaStaged revision2, with zero history/cursor/count and a
nonzero active source floor. The producer attempted FinalReady directly, skipping
the required Building transition; the transition validator correctly rejected it.

The producer now records Building after checking the genuinely empty batch,
the frozen zero history/cursor/count and the complete source guards. Advance,
Decode and final-root checks are unchanged. Build36 passed with zero warnings
and errors. q19 passed all24 cases, including two real encrypted cold-resume
cases interrupted after SchemaStaged/Building, exact original preservation,
idempotent full audit and fresh native send/receive;2330 inputs unchanged.

The actual first-attempt external RAM snapshots were lost when that run failed.
Retained recovery must use the protected frozen source guards and existing owner,
then capture a new external baseline; it must not claim the first snapshot was
reconstructed. No reset or new business round has occurred. The complete Shared
reference union now contains2272 identities; full qualification remains deferred
until the user's goal-first measurement and stabilization are complete.

## Retained enrollment completed; route delivery still open

`deep-cli/artifacts/retained-goal-20261104-04/maintenance01/archive-enrollment.json`
passed for all three retained profiles:11 scopes and874 original native events,
exact original/authored/counter/group preservation, completed full owner audits,
no reset, no new business messages and unchanged group cursor60. The overall
1800-second operator budget expired later in route catch-up; the enclosing run
is therefore not a PASS. Its runtime and helper inputs remained unchanged.

The separately reviewed already-indexed mode positively admits actual signed
account plus atomic registration/catalog/progress, requires V2/all-indexed/no
progress inside each fresh source baseline, and never invokes enrollment.
`retained-goal-20261104-04/catchup01/already-indexed-baseline.json` passed all
three profiles with290/320/269 native events after partial control recovery.
It explicitly records a new baseline, not reconstruction of the prior RAM
snapshot. The route attempt then stopped on IOException in the first role's
ReintroduceContactRoute/DeliverOwnedMailbox path. Original pending work remains;
no new business round or latency qualification follows from these receipts.

A five-second CPU trace of the earlier one-time drain attributed all sampled
active work to DrainOldArchiveEnrollmentPrefix, about69% to original-source
verification. Source review found12 full source admissions per drain pass.
Established DR-0179 operations already use native provenance instead; this
measurement describes enrollment, not message delivery. Astra reviewed a
possible transaction-local receiver ledger reuse (three traversals to two),
preserving every surrounding admission/integrity check. It is deferred: it does
not reduce SQLCipher opens and is not needed after the completed enrollment.

## Prepared route reintroduction resumes its original operation

The second dedicated catch-up completed one direction, then retained an unknown
Store outcome when the deployed node's public network observation changed during
the operation. That source fence remains mandatory: effects may already exist.
Reintroduction now invokes the existing bounded mailbox recovery around the
already authored and encrypted operation, using an owned operation copy. Recovery
opens a fresh independent authority read, checks historical completion and the
original deadline before a new recipient lookup, and resumes existing custody.
Selection, authoring and native encryption are not repeated. Verified expired
attempt rollover follows its existing contract; a live attempt keeps exact MAU
bytes, grant, counter and nonce.

Build38 passed with zero warnings/errors. Qualification20 passed all30 cases
(two actual encrypted reintroduction regressions plus28 mailbox recovery cases),
zero skips/failures and2331 unchanged inputs, native duration127.865s. The new
cases prove exact prepared-request recovery after a lost reply, no second native
send, and original-deadline refusal before fresh recipient lookup or dispatch.
This is focused source evidence; matching retained CLI execution and full Shared
qualification remain open under the user's goal-first order.

## Expired route maintenance continues after its authenticated stop

The matching runtime05 completed one maintenance direction in95.750s, then
stopped the next after34.238s at the original logical retry deadline. All16 HTTP
responses observed across those two operations were200. This was a local
lifecycle refusal, not the background Registry proof warnings. The three
already-indexed profiles and their original business counters remained intact.

The selector already excluded stopped work. It selected an active expired
control, whose existing owner correctly closed uncertainty and durably stopped
it, but the delivery guard's exception aborted maintenance before Sync/Request.
Selection now recognizes a private owner-derived completed-stop outcome as no
runnable work. Direct delivery retains its original throwing behavior. No new
control, Store success, current route or deletion authority is inferred.

A fresh authenticated read must prove either the exact retained RetryExpired
command or its retired terminal audit, with the captured scope counter unchanged.
Pending dependencies can retain a stopped payload; retirement rules still apply.
The actual original attempt, native/authored identity, lower-time deadline and
uncertainty closure remain mandatory. Missing-attempt expiry is not guessed.

Build39 passed; q21 passed16 cases and failed one new negative fixture because
its supposed deadline mutation could be a no-op. That receipt remains unchanged.
The corrected fixture asserts an actually different canonical deadline before
exercising semantic rejection. Build40 passed with zero warnings/errors and2189
unchanged inputs. q22 passed all4 affected cases, zero failures/skips,2331 unchanged
inputs, native270.001s. Coverage includes legitimate fresh request scheduling,
unique committed response retention, changed original deadline refusal, and a
genuine pending control preserving stopped payload, pending bytes and counters.
The response fixture does not claim to force a particular response mode.

After q22, one public return-value XML comment was clarified; executable behavior
was unchanged. Publish06 captures that final source. Retained runtime verification,
warm delivery and full qualification remain open.

## Recorded-renewal archive read provenance

Non-destructive retained reading now accepts the existing direct intent or at
most three exact protected recorded-renewal links. The latter bind the normalized
actual completed archive, permanent intent, account/instance, old intent and
adjacent proposal hashes; intermediate journal locators must be absent. All
eligible polling archives remain checked. Captured closure hashes and the route
root are atomically rejoined before use and on every publication custody recheck;
private decoded closure bytes do not cross the next provider await. No successor
publication is required to remain present solely to authenticate an older archive.

Destructive recorded-archive retirement remains direct-only and fail-closed.
Its stored plan/recovery dependency binding is still a separate open obligation;
the reader proof grants no deletion, Store or current-route permission.

Build41 passed with zero warnings/errors and2191 unchanged source inputs,
native UTC2026-11-04T22:57:08.899–22:57:40.907 (32.008s).
Qualification23 passed7/7, zero failures/skips, native exit0 and2333 unchanged
source/binary inputs, UTC2026-11-04T22:58:05.402–22:58:48.179 (42.776s).
Receipts are `artifacts/archive-resume-20261104-build41` and
`artifacts/archive-resume-20261104-qualification23/smoke.trx`.
The actual signed-owner fixtures cover cold current/archive Retrieve, missing,
tampered and foreign-instance closures, an issuer callback deleting a captured
closure, and two-link success plus canonical proposal-adjacency corruption.

These receipts establish the bounded source correction, not the precise cause
of the retained runtime06 profile refusal or its successful recovery. No retained
profile execution, warm latency result or full Shared qualification is claimed
by this focused packet. Full Shared has not been run under the goal-first order.

## Current route maintenance and immutable control lifetimes

The read-only current-route API verifies actual native L through the existing
Protocol/source/consent fences. Fresh immediate history requests verify that
route before authoring; retained recovery and receive staging keep their owners.
Expired never-attempted count8 work can acquire only a denial-only stop after
actual authored/native identity, trusted lower expiry, send/evidence/transport
absence and retained grant roots are rejoined before and after its authored CAS.
No Store success, cleanup, grant deletion or replacement response is inferred.
Settled same-endpoint announcements use Protocol's upper-time window predicate.

Build45 passed with zero warnings/errors, native exit0 and2194 unchanged inputs,
UTC2026-11-05T00:15:03.197–00:15:10.516 (7.318s). Actual focused receipts:

| Receipt | Passed / failed / skipped | Native seconds | Inputs unchanged |
| --- | --- | ---: | --- |
| `artifacts/archive-resume-20261104-qualification24` | 8 / 3 / 0 | 448.108 | 2336 |
| `artifacts/archive-resume-20261104-qualification25` | 2 / 1 / 0 | 89.272 | 2336 |
| `artifacts/archive-resume-20261104-qualification26` | 1 / 0 / 0 | 6.116 | 2336 |

The original failed receipts remain unchanged. Their exact corrections were:

- `Did2RouteMaintenance_SettledExpiredAnnouncementAllowsFreshSameEndpointButPendingOriginalAlwaysWins`: q24 exposed the selector's lower/upper mismatch; the corrected production predicate passed q25.
- `Did2CurrentRoute_ReadOnlyAdmissionAndFreshRequestRejectExpiredActualAnnouncementBeforeAuthoring`: q24 confused signed DTT issuance expiry with the longer verified capability deadline. The corrected fixture passed q25 and also requires an actual announcement beyond120s, within signed ceilings, with fresh nonce verification and immutable original bytes.
- `Did2LogicalAssignment_RouteControlIgnoresExpiredSnapshotButNotSignedRouteExpiry`: q24's successor changed stable signed invite scope; q25 then reached the intended final callback but expected the base exception type. q26 passed with exact `AccountDirectoryFreshnessVerificationException` / `DirectoryFreshnessExpired` and two clock reads, plus signed-route expiry rejection and mode1 lifetime bounds.

All11 selected identities have passing evidence across these receipts; the eight
already passed cases were not repeated solely for the fixes. This is focused
source evidence. Matching retained target execution, warm delivery/ACK timing and
the canonical full Shared gate remain pending; no full or target pass is claimed.

## Count8 consent reuse and expired read recovery

The [DR0178](../../../docs/survival-program/decisions/DR-0178-paged-route-history-and-current-promotion.md)
count8 reader reuses actual bounded native consent facts while preserving final
and deferred native/floor/archive, protected winner and canonical application
projection joins, endpoint freshness and physical integrity checks. Both roles
are checked with test-only path counters; no measured speedup is claimed.
The [DR0133](../../../docs/survival-program/decisions/DR-0133-expired-owned-retrieve-attempt-closure.md)
read-recovery cases exercise exact expired-request custody, independent holders,
trusted lower-time closure and pagination restart without changing inbox/ACK
ownership. Existing malformed, overlap and callback refusals remain enforced.

- Build47, build48 and build49 passed with native exit0 and2198 unchanged source
  inputs each; these build-only receipts do not qualify runtime or full behavior.
- Qualification27 hit its20-minute watchdog without a TRX or native/final test
  receipt and remains unqualified. All2340 captured Path/Sha256 rows compared equal
  afterward. Its projection/fork callbacks had reacquired the account lease held
  by the tested owner. They now capture the same full application digest on the
  existing mutation connection; rejection/no-repair assertions are unchanged.
- Qualification28 recorded7 passed /1 failed /0 skipped, native exit1 and2340
  unchanged inputs. Its winner fixture removed the sole entry with a noncanonical
  empty revision and failed before CAS. The correction round-trips a canonical
  missing-winner journal before actual CAS, preserving strict rejection checks.
- Qualification29 recorded10 passed /0 failed /0 skipped, native exit0 and2340
  unchanged inputs, but its wrapper exited1 and `focusedAccepted` remains false:
  the declared count was8. `DisplayName~winner` also matched the method name's
  `Winner`, selecting all three projection/fork/winner rows plus seven new read
  cases. The original declaration/count failure is preserved, not relabeled as
  an accepted gate; no rerun was performed solely to change its count.

Across q28/q29 all15 distinct new identities have actual passing test evidence.
Receipts remain under `artifacts/archive-resume-20261104-build47`, `-build48`,
`-build49`, `-qualification27`, `-qualification28` and `-qualification29`.
Historical failures are retained without waiver. Previously covered transitive
cases remain mandatory in the canonical full gate. Retained target diagnostics,
warm delivery/ACK measurements and full Shared qualification remain pending;
this packet claims no target, warm, full or release qualification.
