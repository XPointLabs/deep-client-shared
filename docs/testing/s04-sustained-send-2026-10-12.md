# S04 sustained send — 2026-10-12 working checkpoint

Owner: Mr. X. The root implementation plan remains the sole execution order.
S04 is not accepted; no physical delivery or release readiness is claimed.

## Connected scenario

`Did2SustainedSend_PublicSendCrosses512WithoutResetAndPreservesColdExactReplay`
targets513 unique public `SendTextAsync` operations, genuine owned native
encryption/receive, signed in-process grant/Store evidence, SQLCipher and
automatic maintenance. Every fourth receive produces an actual native peer
reply; every32 sends cold-reopens the sender's protected storage. The final
checks cover both histories, independent receipt obligations, cached first-send
Store, changed-text rejection and exact receive replay without a second effect.
No account reset, synthetic occupied send rows or larger journal bound is
introduced. This scenario uses the existing controlled fixture clock, advanced
by actual parsed object creation and signed node acceptance times. It does not
call `TrackMailboxDispatchClock`; the optional `Stopwatch` elapsed term is
therefore inactive. An earlier live status incorrectly treated the presence of
that getter as proof that this scenario enabled it. This run cannot qualify
wall-clock liveness or real elapsed-budget behavior. A successor-backed timed
qualification remains required; do not freeze time or extend old authority to
obtain it. These are in-process services, not physical Windows/Android
or production socket evidence. This scenario alone cannot qualify128 distinct
grant scopes, pending/rejected/unknown saturation or the complete S04 gate.

Public history and receipt readers return at most100 items. The fixture checks
those actual bounded projections separately, then reads the actual Application
SQL under the account lease and registered key. It verifies every retained
canonical message/hash/endpoint, the exact expected text sets and independent
receipt joins/counts. A bounded page is not treated as the entire history.

## Preserved run history

All run directories below are relative to this repository.

- `artifacts/s04-sustained-20261012/send513-01`: build0, zero warnings/errors,
  2026-10-11T19:30:24.2010895Z–19:30:40.7329406Z. Native declared7 cases.
  The owner explicitly stopped its live test host after finding that the new
  fixture's final assertions incorrectly expected all513 rows from bounded
  public readers. Terminal native1/wrapper1, test
  19:31:33.0031175Z–19:32:45.1460633Z;6 results,6 passed,0 failed,0 skipped;
  1944 inputs unchanged. Receipt SHA256
  `4DB92FEA7EE1DE23B1D25D0FC57FE2DD034A7A078DD88B298269D7D0BE0E46DB`.
  This is interrupted/incomplete, **not PASS**. No product assertion or bound
  was weakened; the fixture now distinguishes bounded projection from all rows.
- `artifacts/s04-sustained-20261012/send513-02`: build1,
  19:34:25.2478005Z–19:34:32.1222493Z, zero warnings/one error: CS1674 from
  treating `ParsedDmc2` as `IDisposable` in the new fixture. No test launched.
  Corrected the fixture to use the actual immutable parsed-record contract.
- `artifacts/s04-sustained-20261012/send513-03`: build0, zero warnings/errors,
  19:34:52.1779678Z–19:34:57.9107865Z. Windows PowerShell5.1.26100.9457,
  SDK10.0.301, production `.slnx`, Release/no-restore/warnings-as-errors.
  The native exact declaration contains7 cases: this new scenario plus all6
  `FixturePreflight=true` cases. The owner intentionally stopped its verified
  test host to address the reproduced repeated SQL-read performance defect.
  Native1/wrapper1, test19:35:12.4211732Z–23:13:56.8624314Z;6 results,
  6 passed,0 failed,0 skipped, versus7 predeclared cases;1944 inputs unchanged.
  Receipt SHA256 `128AFAD26B4438BBCD007A35E67DB54F1D2B9ECFB0968C5DBB93E54C141226C3`.
  This is interrupted/incomplete, **not PASS** and not a completed513-send
  qualification. No source/normative inputs were changed while it was live.
  The complete513-send scenario remains mandatory after the connected fix.

## Live performance investigation

At 2026-10-11T21:19:26Z, the same native test host was still live. The
isolated fixture's18 files totalled14,250,934 bytes and had a latest write at
21:19:21.5592839Z. These are metadata-only progress observations, not a
completed-send count or a passing result.

Two managed method-stack samples from the same host showed
`Did2MessagingSqlJournal.VerifyRows`: first under the authenticated peer-route
reader, then under `Did2MessagingDurableCustody.ReconcileAsync` while retaining
ordinary Store evidence. The local official `dotnet-stack`10.0.750501 report
printed only filtered method/type names; no heap, payload, identifier, key or
private path was exported. Both reports exited0. The diagnostic tool and its
source configuration are confined to ignored artifacts, not product dependencies.

Source inspection confirms that `VerifyTip` independently verifies the retained
history prefix and current rows, and that several custody/read boundaries invoke
it during an ordinary send. This establishes repeated validation in the sampled
path, not its percentage of execution time or a proven speedup. A raw SQL key is
already encoded as a SQLCipher raw key; no passphrase-KDF fix is justified by
these samples. Do not replace authentication with an unsigned file timestamp,
`data_version` cache or a larger bound. Any eventual consolidation must retain
current protected-floor equality, exact event commitments, mutation/rollback
detection and independent authority checks. No runtime source or normative input
was changed during this live run.

The next bounded source investigation is local to the read path, not a new
authority/cache layer. `ReadVerifiedReceiveForEvent` currently performs a full
tip verification, selects an operation, then calls `ReadVerifiedOperation`,
which repeats the same full verification in the synchronous method. A single
selected-row query can avoid that repeat while retaining the full verification,
exact active-floor rules and bounded event materialization. Route-only consumers
also enumerate and decode every incoming ordinary message. Their existing
native route-processing metadata is authenticated by both current-row and
retained-prefix verification; a route-only query could narrow only the subsequent
enumeration, without omitting either full tip check. Any such change requires
negative coverage for a hidden/changed route marker, malformed unrelated events,
retained-prefix rollback, fault/fork preservation and enumeration cancellation.
These are candidates only: no speedup or implementation is claimed yet.

A third method-stack report also exited0 and sampled `VerifyRows` beneath
`ReadVerifiedEvents` in native peer-route history. At21:32:49Z the live host had
6339.44 CPU seconds and158.3 MiB working set; fixture metadata showed18 files,
14,964,558 bytes and a latest write at21:32:39.0339223Z. Windows process raw I/O
counters reported375,925.8 MiB read transfers and58,609,824 read operations;
a subsequent formatted sample reported43.06 MiB/s reads. These are process I/O
observations, not physical-disk throughput or attribution to a single query.

At that diagnostic baseline the DID2 connection opener sets a private, non-pooled connection but
does not explicitly configure `cache_size`. A bounded native page-cache experiment
is another candidate; unlike caching a verification result, it leaves every
journal/history/protected-floor check in place. The actual provider default and
cache footprint must be measured, not inferred. SQLite documents this as a
connection-local suggested maximum, with memory allocated on demand rather than
all at once ([official PRAGMA documentation](https://www.sqlite.org/pragma.html#pragma_cache_size)).
Any tuning must retain encrypted pages, durability/deletion settings and
rollback/corruption detection, and be checked for per-connection mobile memory
cost. Neither a cache-size change nor a speedup is claimed in this run.

An isolated candidate is now prepared under the ignored
`artifacts/s04-sustained-20261012/next-read-path-01` directory, with baseline
source hashes and apply/qualification conditions in its README. It contains
the single-query receive materializer, route-only enumeration for consumers
that previously ignored ordinary events, an experimental8192-KiB native cache
suggestion and13 new test cases. Review added explicit event storage-type checks
to both current rows and the retained prefix before the narrowed query: byte
commitments alone cannot establish the SQL type ([SQLite conversion semantics](https://www.sqlite.org/c3ref/column_blob.html)).
Four additional cases preserve the exact bytes/hash while changing an unrelated
plaintext/envelope cell to TEXT, before requiring fail-closed rejection. The
authored-position collision reader and
Braid progress reader must continue examining ordinary events. The working
source hashes of the first6 copied files were rechecked unchanged; the additional
history-verifier copy records its own baseline hash in the candidate README.
At that diagnostic point this candidate was
not applied, built or tested; it could not be counted as an implemented fix.
Subsequent review makes verification and point-row materialization share one
short deferred SQL read transaction, without an await or callback. The pending
tests additionally do point lookup from inside the full native event enumeration,
so the actual nested-reader/transaction behavior must pass before application
is accepted. The same live run was still active at22:15:03Z, with18 fixture files,
17,372,750 bytes and a latest write at22:15:02.7687428Z. A fourth method-only stack
report exited0 and sampled `VerifyRows` under route recheck during grant
acquisition. This is additional diagnostic evidence, not a terminal result or
proof of a completed-send count.

## Read-path source packet after diagnostic interruption

After terminal native1/wrapper1 and unchanged-input qualification of
`send513-03`, the minimal staged read-path/type-check/native-cache changes and
13 new test cases were applied to working source. All7 copied source baselines
were compared before applying; unrelated cumulative edits were preserved.
The authored-position collision algorithm remains an all-incoming-event reader.
`read-path-01` build1 at23:19:05.6880017Z–23:19:32.5152620Z, zero warnings/two
CS1061 errors in the new fixture: the actual `RouteProcessing` property already
returns `ReadOnlySpan<byte>` and must not use another `.Span`. Corrected both
fixture accesses. No tests launched on that build; no speedup/PASS is claimed.
`read-path-02` build0 at23:20:52.6844766Z–23:20:58.9452207Z, zero warnings/errors,
Windows PowerShell5.1.26100.9457/SDK10.0.301. The native focused declaration is64
cases: all13 new read/cache cases,6 fixture prerequisites and affected history,
route-processing/fault/historical-route, native SQL/key negatives and the genuine
automatic-outbox-maintenance scenario. Terminal native1/wrapper1 at
23:26:18.3015906Z–23:49:14.2770946Z:56 PASS/8 FAIL/0 skipped, exact64 results,
1946 unchanged inputs, TRX SHA256
`71BDE45C7A34B076D489A128F8A0805D3970E079816E06F457CA3D0C3F1F383E`.
All8 failures are in the new negative fixture. Two ordinary-plaintext cases
reject with the existing `ApplicationCoreFormatException`; two envelope cases
reject with the existing `MessagingWireFormatException`. The assertion had
incorrectly limited rejection to InvalidData/CryptographicException. Four
byte-preserving SQL-type tamper cases fail before the target call: the fixture
asks the authenticated compaction projection to describe already-hostile TEXT
cells, and that projection correctly rejects. This run is FAIL, not partial
qualification of the64-case scope or a measured speedup.

The fixture correction requires the exact parser exception for each damaged
record and InvalidDataException for hostile storage types. A separate test-only
raw SQL snapshot includes actual table definitions, every row/cell's storage
type and exact CAST-to-BLOB bytes, with length framing and temporary byte
zeroization. It is solely a no-mutation witness, never authenticated authority
or a substitute compaction commitment. The target call now precedes rejection
assertion and the unchanged raw snapshot comparison even for hostile TEXT.
No production verification rule or working bound was weakened.

`read-path-03` build0 at2026-10-12T00:00:35.1258999Z–00:00:52.1080376Z,
zero warnings/errors, Windows PowerShell5.1.26100.9457/SDK10.0.301. The focused
correction scope is exactly19 cases (all13 new read/cache cases plus6 fixture
prerequisites), not the previous64-case scope. Native0/wrapper0 at
00:01:53.7318917Z–00:13:18.7919851Z:19 PASS/0 FAIL/0 skipped, exact declared names,
1946 unchanged inputs, TRX SHA256
`93BBCE761FFF26C33BA8895DA4640285CAA984C066FB6480189B9C09DBD75A68`.
All four hostile-type cases now reach the target reader, require its exact
InvalidDataException and prove the complete raw SQL snapshot unchanged.
Nested reader/point lookup, positive route-only selection, cancellation,
compacted-prefix rollback and both existing parser refusals pass. The native
cache-policy case passes; its Console default-setting measurement was not
captured in TRX/log, so no provider-default value or mobile memory cost is
claimed. The64-case FAIL remains preserved and is not relabelled as PASS.
This is focused source evidence, not513 completed sends, whole S04 or devices.
Its private mapping belongs to the Shared authored/custody owner document.

The next run is the exact513-send case plus6 fixture prerequisites on the same
unchanged compiled source. No intervening unfiltered full or stage switch is
required for that diagnostic; final canonical gates remain mandatory after
the connected S04 implementation package is complete.

`send513-04` has launched with the exact native UTF-8 declaration of7 cases,
using the same zero-warning `read-path-03` build and the common captured-input/
receipt mechanism. Terminal native0/wrapper0 at
2026-10-12T00:15:24.0502387Z–02:45:07.1358119Z:7 PASS/0 FAIL/0 skipped,
exact declared names,1946 unchanged inputs, TRX SHA256
`77A3EE18ECA650344F3ECE06B5FA6A0A94A1817DD2D3F675D8D8537CCFC4BCF2`.
The genuine owned public-send case crossed512 without reset, completed513
send/receive effects plus128 peer-feedback messages, automatic cleanup,
encrypted cold reopen and first-message exact replay/changed-text refusal.
The final native/application history and receipt joins were checked; the
bounded100-item public projection was not mistaken for all513 rows.
Those128 feedback messages are not128 distinct grant namespaces. The clock
scope remains controlled signed in-process fixture time, not real timed
successor-backed authority or physical delivery. There is no matched before/
after throughput qualification, so no speedup is claimed. Unknown/pending/
rejected/backpressure matrix and other S04/physical requirements remain open.

### Read-only follow-up diagnosis during send513-04

The actual account `OpenConnection` delegates to `OpenRandomKeyConnection`;
messaging uses that same raw-key core. Existing `device-raw-01` measurement
records three authenticated device reopens at10.1ms, isolated raw-mode reopens
at5.2ms and isolated password-mode reopens at3060.4ms. These are historical
provider-probe measurements, not a current sustained speedup. Reintroducing a
key-mode change would fix an already-correct path and invalidate this run.

Two method-only snapshots of the verified current513-send host exited0. The
first sampled SqliteDataReader.NextResult/Dispose; the second sampled
JournaledDeepSecureStorage.Load under DeleteBatch/EraseStableOrphans/Reconcile
and the actual public SendText dispatch recheck. No heap dump, values, keys,
identifiers or completed-send count were captured. Two samples do not establish
a dominant bottleneck or measured speedup. The secure store is a protected
binary aggregate, not JSON; its MutateAsync already commits only if the
mutation reports a change, so missing-part deletion does not rewrite the file.

Stable orphan cleanup currently independently rereads the exact protected
floor and then invokes aggregate deletion, with two authenticated loads.
A possible next optimization is one atomic compare-and-delete primitive that
checks the same exact stable floor inside the deletion load. It must retain
authentication, no-op behavior, missing/malformed-floor refusal, cancellation,
buffer wiping and all current backend semantics; it is not a verification cache
or permission to omit stable-orphan recovery. This is a reviewed candidate,
not implemented or measured evidence, and changes none of the live run's inputs.

The connected candidate is now prepared in the ignored
`artifacts/s04-sustained-20261012/next-guarded-orphan-cleanup-01` directory:
the bounded owned-input helper, direct implementations in both actual backends,
checkpoint consumer and all seven current test-backend forwarders. It adds no
serialization, wire, journal, key mode, inventory limit or verification cache.
The post-erase lost-response test hook is preserved. Two additional partial
test files contain17 prepared cases, including one authenticated-load counting,
stable/pending/absent/malformed/corrupt floor, idempotent no-write, owned input,
cancellation during load and failed protection. They are component/backend
tests, not native message or authority evidence. All12 original source hashes
were rechecked unchanged; exact apply conditions/baselines are in the candidate
README. The candidate is not applied, built or tested, and no performance/PASS
claim follows from preparing it.

### Guarded cleanup source application after terminal send513-04

After terminal0/exact7/unchanged1946 qualification, all12 original source
baselines were rechecked and the complete guarded-cleanup packet applied as
minimal hunks, plus both new partial test files. Unrelated cumulative edits
were preserved. Source review confirmed the production compile include and
all current backend implementations/forwarders; the pending-floor negative
now stages and reads back a matching real segmented checkpoint payload before
guard refusal. Fresh build/focused qualification is pending. Preparing/applying
this code does not preserve the earlier7-case qualification on changed inputs
or prove faster sustained behavior, complete retention or whole S04.

`guarded-cleanup-01` build0 at2026-10-12T02:49:15.5231216Z–02:49:50.8859892Z,
zero warnings/errors, Windows PowerShell5.1.26100.9457/SDK10.0.301. Exact native
UTF-8 declaration is82 cases: all17 new cases, existing secure-storage CAS,
checkpoint, compaction-plan and initial-session custody cases, six prerequisites
and the genuine old/new historical-route Store/cold-cleanup scenario. The common
immutable-input/exact-receipt runner finished native1/wrapper1 at
2026-10-12T02:51:39.9620900Z–02:54:42.6763680Z:81 PASS/1 FAIL/0 skipped,
exact82 results,1948 unchanged inputs, TRX SHA256
`8783071C6B622DD30DF2C93663D76CEDB5FEBAF7DD9F77616F6F3396CF42940B`.
The only FAIL is the new malformed-floor assertion: existing Did2MessagingFloor
Decode rejects the changed closed shape/version/scope with CryptographicException,
not InvalidDataException. The checkpoint's failed-guard diagnostic correctly
reaches that same existing decoder before any deletion. Corrected only this
fixture's expected rejection family; missing-floor still requires InvalidDataException
and unchanged ciphertext/parts assertions remain. No production rejection,
native/time/retention bound or mutation rule was weakened. Fresh matching
qualification remains pending; the82-case FAIL is preserved.

`guarded-cleanup-02` build0 at2026-10-12T02:55:51.5707469Z–02:55:58.6932177Z,
zero warnings/errors. Matching exact82-case qualification is native0/wrapper0
at02:56:59.1150727Z–02:59:05.0501652Z:82 PASS/0 FAIL/0 skipped, all1948 inputs
unchanged, TRX SHA256
`CFE8E87BDBB60ED7A060CB9F1D183B2CC7490643B5D82E12A60F506110113D0E`.
All17 new backend/component cases, the six prerequisites and the genuine
old/new-route Store/cold cleanup pass. The counting protector proves one
authenticated load for the checkpoint's successful cleanup/no-op; unchanged
ciphertext proves no rewrite on no-op/refusal. The pending case first stages
and reads back matching parts, then proves they survive refusal. Owned input,
pre/during-load cancellation, protection failure, tampered aggregate and all
existing cleanup/initial/compaction-plan lost-response cases pass. The original
82-case FAIL is not rewritten. No unfiltered full, sustained speedup,128-distinct
grant outcome matrix, full contact/object-key retention or physical result is
claimed by this scope.

## Distinct Retrieve grant candidate

Added a public synchronization scenario for129 distinct signed Retrieve grants,
actual SQL/protected installation, completed empty reads, ordinary maintenance,
periodic disk reopen and an interrupted committed page at grant65. Its issuer
chooses a shorter34-second signed interval inside the existing authority; no
production lifetime, capacity, wire or journal generation changes. The scenario
uses the original retained path under a real signed network successor and a
controlled authenticated fixture clock, not wall-clock soak or device transport.
It never fabricates protected grant/floor entries. Build and focused qualification
are pending; no129-grant success is claimed yet.

First grant129-01 build failed with CS1061 in the new fixture: a compaction
recovery method was called on the account service rather than its existing
owner. Correcting that call yielded grant129-02 build0, zero warnings/errors,
05:36:06.6759688Z–05:36:16.6177818Z. Its exact32-case focused run completed
native1/wrapper1 at05:37:05.4626068Z–05:48:02.5132999Z:31 PASS/1 FAIL/0 skipped,
all1949 inputs unchanged, SHA256
`84FFB1E8B1309D64EA46344BD6921CCEB3E17D70288BB5951F89D228CF627369`.
The new129-grant fixture alone failed on its first public read: a20-second
grant cannot fit the actual10-second Retrieve timeout,5-second retry margin
and signed time uncertainty. Existing RetryAt correctly rejected it before
dispatch. The fixture now signs34-second grants and starts after a genuinely
shorter initial authority's expiry, leaving its129 renewals inside the same
existing6000-second signed head/root bounds. No production validation is
relaxed and no runtime lifetime is extended. The prior31/1 is retained; the
corrected matching focused result is still pending.

grant129-03 rebuilt successfully at05:50:26.7430435Z–05:50:43.6026520Z with
zero warnings/errors and declared seven cases before test. Subsequent inspection
found no live native/wrapper process, no TRX and no native terminal receipt; the
test log contains only the run header. This is interrupted/unqualified, not PASS
or proof of how many grant iterations ran. The interruption cause is unknown.
The next run retains wrapper stdout/stderr independently of the conversational
tool session and continues to use the common TestGate runner/input/TRX logic.

grant129-04 built0 with zero warnings/errors at08:21:08.8457374Z–08:21:12.2330734Z.
Its detached wrapper declared seven cases but failed during BEFORE-input capture:
Get-FileHash was unavailable in that Windows PowerShell module-loading context.
No native test launched, no TRX was produced, and this is not a product FAIL/PASS.
grant129-05 uses the same unchanged compiled/source candidate and explicitly
imports the stock Windows PowerShell Utility manifest before the common module.
The native test was confirmed running after exact seven-case declaration; wrapper
stdout/stderr are retained in its run directory. Its terminal native1/error
wrapper completed at08:23:52.1509318Z–08:29:25.4679377Z with6 PASS/1 FAIL/0 skipped,
exact7 and1949 unchanged inputs, SHA256
`F568F1379BBB07E3AA4906ABDDB53DA108E4B5AEE951C9DF12F393D071813A82`.
The new positive fixture exhausted128 actual Retrieve counter floors before the
next issuer callback. Investigation does NOT establish a runtime defect: its
assumed retirement after short grant expiry contradicts the protected original
possible-issuance ceiling, derived from actual original PMA2. That ceiling stays
6000 even when an individual result has a shorter interval. The specification
requires both epoch exclusion and that ceiling, then dependency closure.

The next connected fixture package preserves this boundary as an explicit
128-actual-grant backpressure/no-root-mutation negative scenario. Its positive
129-grant scenario now performs genuine signed authority/head/network rollover
while the old policy is still live, keeps an actual completed replacement read
valid across the original6000 ceiling, then lets ordinary maintenance retire
eligible original namespaces. The current original path stays retained. No
production ceiling, floor/holder consumer, count or lifetime is changed. The
existing rollover fixture gains an optional authenticated transition time and
can reuse its already verified epoch successor; its default2100 path is unchanged.
grant129-06 built0 at08:39:09.1412886Z–08:39:26.4399193Z, zero warnings/errors.
The native exact declaration contains nine cases: both sustained grant scenarios,
the existing actual contact/text/lost-ACK authority rollover and six prerequisites.
The detached wrapper and its native test host are confirmed live; final TRX,
unchanged-input and terminal qualification of this corrected package are pending.

That run completed native1/wrapper1 at08:40:23.1145321Z–08:48:54.6741424Z:
8 PASS/1 FAIL/0 skipped, exact9,1949 unchanged inputs, SHA256
`22492F47CE581D316CBC06D1927887B14461A6CC85F41C89D62EEB1413657297`.
The128-actual-grant backpressure/no-root-mutation scenario and existing contact
authority rollover passed. The positive129 scenario reached actual retirement
after the old ceiling and failed in original namespace verification: Shared
paired the captured retained Retrieve issuance PMA2 with the older route PMT2,
although DR-0104 intentionally separates these namespaces.

The connected correction retains the source's bounded owned public record
snapshot as UNTRUSTED lookup metadata. For Retrieve the owner passes two exact
pairs through the unchanged strict DR-0108 Protocol verifier: captured issuance
PMA2 with the retained PMT2 naming it, and original route PMT2 with its named
PMA2. Deposit is unchanged. No new public Protocol API, serialization, generation,
ceiling, current authority or cached authentication result is introduced.
Added a genuine mixed-authority/cold-source metadata scenario checking the
positive distinct joins and bad signature, missing policy/projection, changed
projection, wrong role and cancellation; all must preserve the protected grant
root and issue/dispatch counts. grant129-07 build1 found inaccessible internal
XPointNetworkCodec use in the new Shared lookup. The correction uses the existing
Source pattern: the closed PMT2 decoder already validates its complete typed PMA2
CoreRef header, so lookup compares the decoded core hash; Protocol still checks
the complete exact signed pair. No public encoder is added or reference invented.
grant129-08 built0 at09:04:51.6400987Z–09:05:02.8729393Z, zero warnings/errors.
Matching focused ten-case run completed native1/wrapper1 at
09:09:08.3451814Z–09:16:13.8867133Z:9 PASS/1 FAIL/0 skipped, exact10 and1949
unchanged inputs, SHA256
`44B4B4DC04A14E0228CCD9BC4586B351476FEDAE71B625655F5BD817CA73305D`.
Both metadata joins and their hostile/missing/cancel/no-mutation checks passed,
as did actual128-grant backpressure and the existing contact rollover. Positive129
now passes namespace authentication and fails later in replacement credential
interval checking during holder retirement. The original combined error does not
identify which bound closed. Split its sanitized constant diagnostic reasons
without changing ANY rejection condition; the next focused run keeps the genuine
129 path plus prerequisites. This is diagnosis, not a claimed second runtime fix.

grant129-09 build0 at09:22:09.1902441Z–09:22:36.5795541Z, zero warnings/errors;
exact focused7 native1/wrapper1 at09:23:18.1045641Z–09:28:19.1532800Z,
6 PASS/1 FAIL/0 skipped,1949 unchanged inputs, SHA256
`6BE4D784C46B78BD311F05F418106AB6039E7589FC0B966E186C816F926F6568`.
Positive129 now fails earlier in actual current replacement grant verification
inside superseded-holder retirement. The varying failure position establishes
that an ineligible selected replacement is being used before normal renewal;
it does not identify every combined installation-bound failure from run08.

The next connected runtime correction makes current replacement interval/role
eligibility a deferral-only maintenance hint BEFORE any exclusion/floor effect.
It never authorizes deletion, skips signature errors after effects or drops
original custody. New-read renewal proceeds only with actual spare capacity.
Each business call processes one namespace pair, not32 separate transitions
sharing a short proof. Added an actual three-grant/cold-reopen scenario proving
an expired replacement defers retirement, preserves the original holder/floor,
and allows genuine fresh acquisition/read. grant129-10 built0 at
09:39:56.3844489Z–09:40:32.5332097Z with zero warnings/errors. The connected
focused36 candidate includes all four new sustained/metadata/expired-replacement
cases, existing automatic namespace retirement and grant renewal, actual contact
authority rollover and the six prerequisites. The matching run completed
native1/wrapper1 at09:45:43.5849704Z–10:00:04.3690624Z:34 PASS/2 FAIL/0 skipped,
exact36 and1949 unchanged inputs, SHA256
`DB1656DF7F9370B94B8C3B5968D115B53EDCDDCBF15F3676A8D09ED903167EE1`.
The expired-replacement preservation/renewal test passed. Idle-reader regression
failed because coincident issuance/route namespaces unnecessarily required a
redundant distributed old policy; the new same-exact-pair branch retains strict
Protocol verification without lookup. Positive129 progressed to its second
public poll but the34-second selected grant lacked transport retry room after
maintenance, before its proportional refresh point. New-work scheduling now
also considers the unchanged operation timeout+5 retry window. Added eight
deterministic threshold/role/interval/overflow cases. Positive stress's final two
fixture grants use120-second signed intervals inside the same existing policy,
leaving actual maintenance/retry room; no runtime TTL or capacity is increased.
grant129-11 built0 at10:10:28.0799884Z–10:10:59.1936845Z, zero warnings/errors.
Matching corrected focused16 qualified native0/wrapper0 at
10:12:02.0875762Z–10:16:30.4324031Z:16 PASS/0 FAIL/0 skipped, exact16,1950
unchanged inputs, SHA256
`F369279229BF2071B163EC3D2E697F77206A3138E5ECA49BE6C9592610FA5115`.
Both prior failing cases, eight scheduling boundaries and six prerequisites pass.
Positive129 completes genuine distinct request/grant issuance, two public polls
per grant, periodic encrypted cold reopen, committed-page recovery at grant65,
signed authority rollover and automatic bounded cleanup without account reset.
Its last two fixture grants have120-second signed intervals for actual retry
room; this is a controlled-clock in-process scenario, not physical/wall-clock soak.
Idle-reader keeps its last holder until the actual replacement read completes.
This is not a new36-case PASS. The unchanged compiled candidate next runs the
whole connected44-case union, including existing automatic renewal/retirement,
the other three new cases and current-authority contact rollover. Prior failures
are preserved; full S04/retention/unfiltered/device acceptance remains open.

grant129-12 on the same unchanged compiled candidate qualified native0/wrapper0
at10:19:29.1806508Z–10:29:50.2802509Z:44 PASS/0 FAIL/0 skipped, exact44 and1950
unchanged inputs, SHA256
`460571D6960B7E4B04689C9445F766A4101BC81BA07A1E92F181265D883A2C56`.
This closes the connected regression scope for the new grant namespace/renewal
package, including all automatic renewal/namespace cases, actual contact rollover,
129 distinct grants, genuine128-grant backpressure, expired-replacement cold
preservation, hostile namespace metadata and scheduling boundaries. It does not
close the full pending/rejected/unknown matrix, contact/object/audit retention,
required unfiltered/frozen/package qualification or physical endpoints.

## Residual scope

The129-distinct-grant connected scope is recorded above; it must still participate
in fresh full qualification. Genuine unknown/pending/rejected boundary work,
remaining retention consumers, final frozen/preflight/unfiltered qualification,
review, commits/push and physical contacts/messages/attachments/groups E2E remain
open. No deployment, release publication or main promotion belongs to this run.

## Connected outcome boundary candidate (2026-10-13)

Review of the failed full-02 receipt found that the genuine513-send scenario
passed, but its loop covered successful Store only. The current source now uses
the same owned public Queue/Retry, native SQLCipher, grant/Store and receiver
path for a33-send diagnostic and the required513-send scenario. On the final
operation it rejects a changed-command retry before authoring/dispatch, interrupts
at actual BeforeDispatch, cold-reopens the prepared command, loses an actual
signed Store reply, receives that ciphertext at the peer, cold-reopens again,
checks retry-lease refusal, then retries the exact request and cached completion.
The ordinary message and original prepared ratchet floor must remain exact;
normal final receive/history assertions must prove only one semantic effect.
The short case proves no512-boundary claim. Rejection here is local command
validation, not a simulated remote terminal or proof of non-delivery. Both
use the existing controlled signed fixture clock; retry-lease advancement
renews neither the original body nor its logical retry deadline. Fresh build,
short-case qualification and the changed513-case/full terminal remain pending.

The connected outcome candidate built0/zero warnings/errors at
2026-10-13T10:46:19.7596209Z–10:46:40.0026340Z. Matching connected-01 qualified
12/0/0, native0/wrapper0 and1971 unchanged inputs at
2026-10-13T10:48:45.1550521Z–10:56:42.1503489Z. TRX SHA256
`3602E6000AC937EC032F1983685CE71F0ECD88E35F645E9A23CD89C5660BAE34`.
Exact scope: the genuine33-send connected outcome case, four owned pre-encryption
backpressure rows, actual committed-text/lost-reply/cold-fault case and six
prerequisites. This proves the short business-path diagnostic, not the changed
513-case or complete S04. The next required terminal is the canonical current
unfiltered full with the actual complete case declaration, no outcome exceptions.
