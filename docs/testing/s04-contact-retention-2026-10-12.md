# S04 contact-control retention — implementation checkpoint

Status: incomplete source package; not retention, release or physical acceptance.

The sole semantics are [retention](../../../docs/architecture/RETENTION-AND-RECOVERY-V1.md)
and [owned settlement](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#84-owned-attempt-settlement-renewal-and-retirement).
The Shared implementation boundary is [the local owner](../architecture/owned-authored-counter-custody.md#s04-contact-control-working-payload-retirement--implementation-in-progress).

## Historical reader-preparation evidence (contact-retention-01)

The preparation's protected ContactAccept journal was generation2 with full canonical
payload. It supplies the independent explicit-command winner used by local
acceptance/history, historical routes, native authoring and retained Store.
Existing completed-contact-send compaction removes its prepared send commitment,
not this consent source. Initial secret retirement has a different transfer
purpose and cannot serve as outbox expiry/audit authority.

Centralized exact command comparison in the journal entry; native and semantic
checks remain independent. The joined retained acceptance reader now returns
only ContactPolicy from its verified semantic event. Historical route reading
uses that result rather than decoding the working copy again. No new public API,
wire, journal generation, stopped-state or cleanup permission is introduced.

## Compilation

contact-retention-01 native build0 at2026-10-12T10:57:43.6458287Z–
10:58:31.0403415Z, zero warnings/errors, actual production solution and Release.
No focused/full test run launched for this unfinished package. The earlier
grant129-12 exact44 PASS receipt predates these inputs and does not qualify them.

## Next connected implementation

Finish the consent-only protected transition, history/authoring/retry readers,
actual terminal/dependency producer and existing account-held plan/recovery.
Then test terminal payload removal separately from consent/history preservation,
unknown attempt/floor protection and the content-free audit deadline. Initial,
cancel/expiry, object-only keys and full S04 qualification remain open; no
deployment, reset, commit/push or Release was performed by this preparation.

## Stored ContactAccept transition candidate

Implemented the same protected slot's sole generation3 codec: full working
payload or exactly504-byte consent-only commitment, keeping operation/scope/
HelloHash/EventHash. Generation1/2 reject. This is local framing, not a new
network protocol, signature, suite or journal. Actual history/native joins stay
mandatory; a consent-only entry cannot first-encrypt a missing native operation.

The existing completed-contact owner now stages a closed ten-root protected-only
profile, changing only its send commitment and consent payload in ordered CAS/
readback steps. Recovery checks deterministic successors and all independent
guards; finishing checks the aggregate and surviving parts before disposal.
Updated current codec/retention tests assert actual payload absence separately
from unchanged consent identity and native/application/source/replay facts.
The disposable fault fixture restores both exact predecessors between runs;
it now includes interruption after the second root adoption. Unknown Store
remains ineligible. Separate audit/Initial/cancel/expiry/key closure is not claimed.

contact-retention-02 build0 at11:17:29.1238359Z–11:17:51.7308697Z; final connected
contact-retention-03 build0 at11:22:00.8669509Z–11:22:08.2489445Z, both zero
warnings/errors. Matching focused03 completed77 PASS/2 FAIL/0 skipped, exact79
cases, native1/wrapper1,1951 unchanged inputs at11:24:59.4947838Z–11:27:59.6746872Z.
TRX SHA256 `76919A09EFF266941CB971FEE7C298E3E3C4673E7C653E310AE36AF693FBB6E1`.
Both responder failures reveal a source defect: the supposedly unchanged Root12
also hashed the ContactAccept payload being retired, rejecting recovery after its
adoption. Candidate now keeps Root12 unchanged for other profiles and uses closed
Root16 MailboxContactCustody alongside independent changed Root15. This guard
covers all other complete mailbox-state inputs; plan tests reject substitution,
missing/changed guards and non-prefix adoption, and the real owner test rejects
a canonical consent-root revision change without mutating send/plan. Matching
qualification for this fix is pending. No deployed/client
account reset performed; all gated fixtures create disposable current accounts.

## Matching corrected connected qualification

contact-retention-04 build0 at2026-10-12T11:36:27.4806827Z–11:37:08.2569843Z,
zero warnings/errors. Matching focused04 passed89/0/0, exact89 declared cases,
native0/wrapper0 at11:38:05.3937118Z–11:42:00.4026974Z,1951 unchanged inputs.
TRX SHA256 `3D36A1936EAF3D642629CBAB4529AC7BB808BFDD189C2549435750F11E53E94F`.
The common TestGate mechanism captured the native list before launch, checked
exact result identities and immutable source/binary/normative inputs afterward.
The original03 FAIL remains above; receipts from differing inputs are not merged.

This closes the connected codec/completed Store/unknown-child/lost-reply/ordered
cold recovery scope, including both consent and independent responder/device
source mutation refusal. It does not close all contact-control lifecycle:
explicit pre-commit abandon for this new joint profile, first fresh user send
after retirement, Initial/cancel/expiry, object-only keys and the independent
content-free audit deadline remain open. No full gate, commit/push, production
deployment, physical client delivery or release acceptance is claimed.

## Pre-commit abandon / fresh user-send candidate

The same owner now dispatches the closed contact profile to exact predecessor/
successor checks before writing an abandoning marker. Phase3 recovery validates
all surviving staged parts, keeps both working predecessor roots unchanged and
clears only the plan/parts. Post-commit abandon is rejected. No new wire, journal,
legacy reader, network authority or encryption in recovery was introduced.

Added three actual owned Store/SQLCipher cold abandon cases: normal completion,
interruption after atomic parts disposal and after plan clearing. Corrupt staging
rejects before changing the prepared plan; reselecting genuine completed work after
abandon remains possible. Existing completed handovers now explicitly reject
post-commit abandon. A fourth new case checks consent-only cold account reading,
exact native acceptance replay without encryption, fresh owned user text, genuine
peer receive and duplicate materialization with one receipt and no payload
restoration. These are in-process authenticated fixtures, not physical E2E.
contact-retention-05 build0 at11:50:32.5866649Z–11:51:19.8426495Z, zero warnings/
errors. Matching focused05 completed92/1/0, exact93 declared cases, native1/
wrapper1,1952 unchanged inputs at11:52:33.8194532Z–11:58:07.2705884Z.
TRX SHA256 `61D86AC3C7FA3A1B4B3CEA65B580E12563BFF99391425A04761F4AC901E4C555`.
All three new abandon cases passed. Fresh-send case stopped earlier at exact
ContactAccept replay: AuthenticatedContactAcceptDmc2 still read the retired full
working-copy property. That handoff now uses the common exact-consent check after
its actual directional native event/hash and Hello join; endpoint/route/recheck
verification remains unchanged. The new text case now additionally exercises
actual owned mailbox Store before peer receive, not native-send-only delivery.
Matching corrected qualification is pending; original05 FAIL is retained.
The accepted private grammar in DR-0063 and DR-0029's authority reference were
also synchronized before the corrected gate. The obsolete fixed/LP32 predecessor
grammar is not another supported reader. This normative-input change still needs
the stage's reviewed anchor repin/full/package checks; it is not release activation.

## Matching abandon / fresh owned Store qualification

contact-retention-06 build0 at2026-10-12T11:59:55.5884734Z–12:00:19.9194443Z,
zero warnings/errors. Matching connected focused06 passed93/0/0, exact93 declared
cases, native0/wrapper0 at12:03:17.7913181Z–12:08:59.3004624Z,1952 unchanged
source/binary/normative inputs.
TRX SHA256 `AAFA8A59398F8EA8D6D59D9644CD6D2C56A492A2FCB6163EC5158C42F88BFC20`.
The common TestGate declaration, exact TRX mapping and before/after checks passed;
the detached wrapper and native child reached terminal exits and are no longer live.

This includes the complete prior89 connected scope plus all four new cases.
Abandon keeps exact send/consent/application/native/source facts, rejects damaged
staging before changing the plan and cold-recovers parts-deleted/plan-cleared
handover. Existing committed handovers reject abandon. The consent-only account
retains both parties' acceptance states, replays exact native acceptance without
another encryption, authors/encrypts/stores new text through the owned mailbox
API, receives it once despite native replay, retains one due receipt and never
restores the removed acceptance working copy. All are current authenticated
in-process fixtures using SQLCipher/native providers, not installed-device/socket
or production transport evidence.

Stored ContactAccept payload/consent recovery is connected-qualified in this
scope. Initial working-payload retirement is the next same-S04 business task;
terminal cancel/expiry, object-only-key retirement and separate content-free audit
remain open. Stage-wide sustained/outcome/frozen/full/review/commit/push and
physical contacts/messages/files/groups still must close. No Release was published.

## Stored Initial candidate

Implemented the same held transaction for Initial working payload: current
contact-start generation2, exact canonical event commitments and projection,
448-byte no-payload marker. Old generation1 rejects. The slot/cardinality/byte
bound remains unchanged. Central Init/Hello comparison, existing completed-source
and native joins replace working-copy dependencies in retained Store, operation
projection, normal draft reads and used-grant selection; a marker never authorizes
a new claim or repairs missing native/source custody.

InitialPayload changes only exact Send and ContactStart successors; the guarded
remaining complete-state digest has a separate Initial domain. The current ten-
root profile shares actual ordered CAS/readback, abandon and finishing validation
with ContactAccept. Both original cold-handover cases now cover the second
adoption and explicit-command mutation; both controls have three cold abandon
cases. Added Initial marker cached replay followed by actual peer handshake,
fresh text/Store/receive/dedup/receipt. Private codec/profile negatives include
retired generation, lengths, no-payload shape, altered canonical events and
borrowed/changed guards. These are in-process fixtures, not physical delivery.
DR-0064 and Shared owner were synchronized; build/qualification and reviewed
stage anchor repin/full/review/commit/push are pending. Earlier93 receipt predates
these inputs and does not qualify them. No deployed/client account data changed.
initial-retention-01 build1 at12:34:10.9279290Z–12:34:37.0461349Z: four missing
arguments (eight errors across the production targets) after narrowing a shared
guard-reader signature. No tests launched. Corrected by an explicit closed profile
selection with Complete as the unchanged current default for other retirement
owners; Initial/Accept select their independent guards explicitly. New command
insertion also advances the protected revision after prior payload retirement.

## Matching Stored Initial connected qualification

initial-retention-02 build0 at2026-10-12T12:38:29.7115648Z–12:38:42.9388376Z,
zero warnings/errors. Matching connected focused02 passed107/0/0, exact107
declared cases, native0/wrapper0 at12:43:21.1676127Z–12:49:53.7925620Z,
1952 unchanged source/binary/normative inputs.
TRX SHA256 `B80FC34BDBB4057FF8AF2BB2CFCCB5E7A74C159DC890CF8A038CD17F77B066CC`.
The common declaration/result/input mechanism passed and wrapper reached terminal.
Original build01 FAIL remains above. This covers both control payloads, ordered
handover/abandon/unknown/corruption and cached Initial followed by contact acceptance
and genuine fresh text/Store/receive/dedup/receipt. Protected working payload stays
absent while original native/source/history and independent consent remain.

This is in-process source evidence, not physical delivery or complete S04.
The related used-Deposit, superseded/unused-Retrieve and Braid control retirement
regression used the same compiled inputs in a separate common gate.
initial-retention-regression-01 passed13/0/0, exact13 declared cases,
native0/wrapper0 at2026-10-12T12:53:31.7040503Z–12:57:23.6157090Z,
1952 unchanged inputs. TRX SHA256
`ACAE70A0C37FBE4F66B6DB9607C252044CF33259B2226D499E1618C1DEF26A88`.
No source/normative edits during that run. This includes used-Deposit retirement
after actual Initial/Accept payload removal, its missing-SQL refusal, original
live-object preservation/cached Store, superseded/unused-Retrieve cold recovery
and obsolete Braid control retirement with retained ACK/unknown work.
Receipts remain separate scopes, not an added full-test total.

Stored Initial/ContactAccept payload retirement is connected-qualified in these
source scopes. The next same-S04 lifecycle work is control terminal cancel/expiry;
independent object-only-key and content-free audit retirement, sustained outcome
matrix, reviewed frozen repin/unfiltered full/review/commit/push and the entire
installed Windows/Android contacts/messages/files/groups release scope remain
open. No production deployment or GitHub Release publication in this package.

## Control terminal fence — incomplete lifecycle candidate

Current formats are Initial generation3/prefix456 and ContactAccept generation4/
prefix512, same slots/bounds/owners; all predecessor generations reject. Added
closed stop reason/final authenticated upper time/audit-disposition framing for
the same lifecycle, not a new journal, wire or cryptographic primitive. Accepted
DR-0063/0064 and local owner were synchronized before candidate qualification.

Actual held cancel now selects an existing control winner, validates native/
semantic/source custody or the unencrypted acceptance's independently verified
absence of native/semantic/transport work, then publishes stop by exact CAS/
readback. Expiry's authenticated lower crossing may commit the same fence after
original attempt closure. Dispatch/claim/author/encryption readers reject stopped
work; history and possible-forwarding custody remain intact. Current verifier
remains held through original completed-Store verification; no cached permission.

Added unknown/cold/committed-stop-response-loss and unencrypted acceptance cases,
structural terminal metadata negatives and expiry reason checks. Build/tests are
pending. This is ONLY the irreversible fence candidate: stopped payload/audit
joint deletion, audit deadline/completeness and preclaim Initial cancellation
without an admitted native scope remain open in this same lifecycle task.
Previous107/13 receipts predate these inputs and do not qualify them.

control-stop-01 build0 at2026-10-12T13:37:20.1733693Z–13:38:05.4977036Z,
zero warnings/errors. Matching focused01 passed37/0/0, exact37 declared cases,
native0/wrapper0 at13:40:05.1228786Z–13:43:10.4483867Z,1956 unchanged inputs.
TRX SHA256 `89CEE6D098CB0102B337B911389FD15F3BD438EB899569464C1C9D474ACF4408`.
This covers structural state negatives, unknown control cancellation/cold/lost-
stop-reply, unencrypted acceptance first-encryption refusal and actual expiry
preflight with unavailable recipient. Original send/native/source/application
facts remain exact and no extra issuer/transport/recipient lookup occurs on retry.
It does not prove payload/audit deletion. The connected Stored+stop regression
on this same compiled candidate declared135 cases. No source/normative edits
while it ran. Audit continuation will reuse the
existing SQL table/registered derived authentication key, not create a new service.

control-stop-connected-01 passed135/0/0, exact135 declared cases,
native0/wrapper0 at2026-10-12T13:46:33.5511413Z–13:53:29.6090886Z,
1956 unchanged inputs. TRX SHA256
`5BC720102B45F72D1079C350C770EEA41F3FA4D5AC39119299FC32874D5D0396`.
This is the connected union of current Stored-control/plan/recovery and new
terminal-fence/expiry cases, not an unfiltered full or a sum of unrelated receipts.
Normal working/replayed contact acceptance, Initial cached outcome and fresh
owned text/Store/receive/dedup still pass with sole current generations4/3.

The fence is source-qualified in this scope, but the business task remains
incomplete: stopped control payload and its independent content-free audit must
transition together, verify completeness/deadline and cold-recover SQL/CAS.
Initial preclaim cancellation without an admitted native scope remains open.
The existing `stopped_work_audit`/registered derived authentication key and
complete application SQL projection are available for that continuation;
ordinary audit validation currently covers only its own journal and must be
extended with independently bound control custody, not a fake ordinary command.
No stage/full/commit/push/production/physical/release acceptance is claimed.

## Control audit custody / virtual effect capture — incomplete candidate

The actual registered application factory now binds stopped control metadata
from mandatory current protected roots. Opaque domain-separated HMAC IDs use
random operation and owner kind, not scope/plaintext/content hash. Existing
audit row framing/table/authentication remain; bound derives from512+128+128
actual owner slots, not extra work allowance or eviction. Completeness validates
control and ordinary rows together; idle factory opening detects missing/foreign/
corrupt audit before publishing a store. Exact active-plan intermediate agreement
remains the existing recovery owner's responsibility.

New capture API authenticates actual bound control stop and existing audit set,
then predicts complete before/after SQL for insertion or expiry without mutation.
Two genuine stopped-control fixtures check deterministic repeated capture and
unchanged actual SQL. Existing hostile ordinary-audit fixture now explicitly
asserts earlier factory refusal and uses read-only raw diagnostic SQL hashes
before/after the already damaged database; it does not bypass production refusal.

Build/tests pending. This is foundation for the same unfinished lifecycle,
not actual stopped payload/audit deletion. Joint producer/SQL/CAS handovers,
control audit deadline/negative matrix and preclaim Initial cancellation remain
open. Earlier135 receipt does not qualify these changed inputs; no physical,
stage-full, commit/push, production or release acceptance is claimed.

control-audit-01 build0 at2026-10-12T14:16:15.0681795Z–14:17:02.9734913Z,
zero warnings/errors. Matching focused01 passed53/0/0, exact53 declared cases,
native0/wrapper0 at14:19:30.8936707Z–14:33:11.7178531Z,1957 unchanged inputs.
TRX SHA256 `5A13A8DC0E87CA5B2A32864766694805FF9DC66E45D84F8710481A4471DE1854`.
The common declaration/result/input mechanism passed and native/wrapper are
terminal. Both actual stopped-control virtual-capture cases passed, as did all
existing ordinary audit crash/cancel/expiry/hostile-SQL cases in this scope,
control stop/expiry and prerequisites. No mutation by capture or audit repair.

This qualifies custody/completeness/capture in the declared source scope only.
Next required implementation is the actual joint control-root payload/audit SQL
transaction, ordered CAS/readback/crash recovery and own audit-deadline expiry.
Its closed plan must guard original unknown send/holder/counter/history and all
unrelated audit owners; caller/row/hash alone cannot authorize it. No new table,
journal, service or fake ordinary command is required. Full Stored/control graph
regression on these inputs, preclaim Initial cancellation, object-only keys,
successful audit, complete S04/frozen/full/review/commit/push and physical
Windows/Android contacts/messages/files/groups remain open.

## Joint stopped-control payload / audit candidate — qualification in progress

The held owner now uses the existing Application plan and SQL audit table for
stopped Initial/Accept payload retirement and later authenticated audit expiry.
The single changed root is the selected control journal; send/native/source and
all unrelated custody are guards. Complete audit SQL commits before deterministic
payload CAS/readback. Exact unchanged SQL/roots and complete staged successors
permit pre-commit abandon without reversing stop. Post-commit recovery must finish.
Acceptance also pins whether stop had actual native work or proved first-encryption
absence; neither state may excuse lost or substituted native work.

The new source fixtures exercise both owners, cleanup/expiry and all six SQL/CAS/
staging handovers, alternating interruption and cancellation. A real unknown
Store remains pinned with unchanged original send, native floor and source SQL.
Only disposable fixture predecessor/audit rows are restored between independent
fault boundaries; runtime has no repair/reset path. Hostile audit row checks
assert refusal and unchanged damaged SQL/command, not recreation. Closed plan
shape tests require Application SQL and exactly one payload successor, never a
changed send. Admission before native Initial and object-key dependencies remain
separate open requirements.

control-audit-02 build0 at2026-10-12T14:47:50.0842664Z–14:48:42.0000297Z,
zero warnings/errors. Matching focused02 passed65/0/0, exact65 declared cases,
native0/wrapper0 at2026-10-12T14:49:28.9896343Z–15:02:53.8852337Z,
1958 unchanged inputs. TRX SHA256
`CF6A44049C09F15F796171BAAE224654A56FFDA4632C7439109C35940F72A433`.
Both native and wrapper are terminal. This qualifies the declared actual joint
handover/expiry/hostile-audit and connected stop/ordinary-audit scope, not an
unfiltered full. Exact deadline edges, hostile successor parts and broader
Stored/control graph regression remain open, alongside preclaim cancellation,
object-key/successful-audit retention and the remaining S04 matrix.
No full S04, commit/push, production, physical E2E or release acceptance is claimed.

## Exact control audit deadline / hostile staging — focused extension

Four new source cases exercise both owners. The deadline fixture carries elapsed
monotonic time forward before freezing only its own test clock, obtains real signed
current proofs and explicitly asserts their authenticated lower bound. At deadline-1,
despite upper crossing, the exact row/deadline and SQL stay unchanged after cold
reopen; at the deadline audit expiry occurs; subsequent maintenance is idempotent.
Hostile staging removes, changes or adds a disposable successor part and checks
that neither recovery nor abandonment can alter SQL, plan or command.

control-audit-03 build0 at2026-10-12T15:06:04.1078236Z–15:06:23.1531620Z,
zero warnings/errors. Matching focused03 completed8/2/0, exact10,
native1/wrapper1 at2026-10-12T15:07:17.8752781Z–15:08:57.7349082Z,
1958 unchanged inputs; TRX SHA256
`58BD1AF0F6461BBBD849DE5F20C79FD24FE02ACDF19786569F0BE2926CCA13EC`.
Both exact deadline cases and all six prerequisites passed. Both hostile staging
cases reached the changed-part refusal, then failed at fixture restoration:
insert-only WriteBatch cannot replace an existing part. Corrected only this
disposable restore to CAS; assertions and production code are unchanged. Extra-part
closure was not reached in this failed receipt. Corrected focused extension pending.

control-audit-04 build0 at2026-10-12T15:09:53.0779692Z–15:10:05.7471153Z,
zero warnings/errors. Matching focused04 passed10/0/0, exact10 declared cases,
native0/wrapper0 at2026-10-12T15:10:45.1352924Z–15:12:31.0407112Z,
1958 unchanged inputs. TRX SHA256
`9C77E5985CEB9E8F50CA523B5E6B87E382B5FDDDB02EB3F8F781BDFF4ED35631`.
Both native/wrapper are terminal. All missing/changed/extra-part refusal checks
now reached completion without SQL/payload/plan mutation, and genuine recovery
completed once only the disposable original part was restored. Deadline-1,
exact-deadline and later-idempotent source checks pass for both owners. The
failed03 receipt remains preserved and classified, not rewritten as PASS.

The joint65 and extension10 are separate declared scopes on their own unchanged
inputs, not a combined75-case/full receipt. Production implementation did not
change after joint02; extension03/04 changed only tests. Remaining acceptance:
expiry pre-commit abandonment/abort handovers, broader Stored/control graph
regression, preclaim cancellation, independent object-key/successful-audit
retention, full S04 matrix, frozen/package/review/unfiltered gates and commits/push.
Physical Windows/Android and production/release activation remain unqualified.

## Control audit pre-commit abort / cold recovery extension

The test-only hook after durable abandon recording exposes the existing phase3
boundary; it changes no production wire, storage format or cleanup authority.
Four source fixtures cover Initial/Accept crossed with payload cleanup/audit
expiry. Each uses real unknown Store and checks abort recording, staging disposal
and plan clearing (including cancellation after parts deletion), cold/idempotent
recovery, exact unchanged command/audit SQL/send/native floor, and absence of all
staging slots. A subsequent separately selected transition completes legitimately.
No fixture predecessor restoration is needed for these abort tests.

control-audit-05 build0 at2026-10-12T15:14:11.8841053Z–15:14:35.7371726Z,
zero warnings/errors. Matching focused05 passed16/0/0, exact16 declared cases,
native0/wrapper0 at2026-10-12T15:14:56.9827298Z–15:18:19.2128464Z,
1958 unchanged inputs. TRX SHA256
`0848C5AA0BB122ED2895EA61C45A3C02F042C5E89BAFC3E510727CC08690D2E5`.
Both native and wrapper are terminal. This scope also reran prior pre-commit
cleanup abandon, exact deadline/hostile staging and all six prerequisites.
It is not a combined/full receipt for earlier inputs or whole S04 acceptance.
Broader Stored/control graph regression, preclaim cancellation and independent
key/successful-audit retention remain open; no commit/push, production or physical
release qualification is inferred from these source gates.

## Pre-session Initial cancellation — connected implementation candidate

The same account owner now selects an actual Initial intent without fabricating
a messaging scope. It distinguishes draft-only, sealed/unknown public claim,
completed sender source before import, actual reserved empty native storage and
an already committed import. Committed native work follows the existing local
transfer/stop path. Pre-session stop prevents claim creation/completion/import;
its existing key journal uses distinct cancellation role3, never a transfer receipt.
Actual source metadata/burn/claim replay remains, while sealed preclaim and source
TRS keys are deleted with pending/stable local recovery and no fresh network proof.
Only completed key destruction allows the existing Application plan to retire
working payload and insert/expire the content-free audit using an account-derived
opaque SQL selector, not a synthetic session hash. Staging/recovery/abandon use
complete SQL and independent source/native guards.

Current-only local cutover: Initial draft4, preclaim3, key-retirement2; rejected
predecessors have no migration/reader. This candidate is not accepted by earlier
receipts. Initial tests cover three pre-session setups plus all four key-deletion
and six payload/audit handovers; negative/deadline/import-reservation matrix and
connected regressions remain required before business acceptance.

initial-cancel-01 build1 at2026-10-12T15:46:09.8206447Z–15:46:17.5297436Z:
two repeated compile diagnostics for the missing verifier namespace. Fixed the
namespace and a known fixture reference to a private constant. initial-cancel-02
build1 at2026-10-12T15:47:11.9327270Z–15:47:48.9139734Z: production compiled,
four fixture private-field access errors. Replaced only those references with
existing fixture methods; build03 pending. No tests/full/production/device/release
qualification is claimed for this unverified cutover.

initial-cancel-03 build0 at2026-10-12T15:48:56.7170804Z–15:49:01.6811772Z,
zero warnings/errors. Matching focused03 is running with the pre-session source
cases, existing admitted control stop/expiry and prerequisites. Inputs remain
frozen while the run is live; no terminal test result yet. Both compile failures
above remain separate receipts. Codec/schema/negative/deadline/empty-reservation
and full connected S04 acceptance are not inferred from compilation.

initial-cancel-03 focused completed17/13/0, exact30, native1/wrapper1 at
2026-10-12T15:51:08.5010401Z–15:59:29.1379074Z,1963 unchanged inputs.
TRX SHA256 `30E3AE1769060BBBBE9FEDB01E3F1AB37D6123F87C25DD74B7CBD716AEAC8C2B`.
The six prerequisites and all existing admitted-control stop/expiry cases passed.
Every new failure shares the same product defect: before any native business
message the application registration can still be uninitialized; pre-session
cleanup incorrectly invoked the existing-only recovery opener. Added actual
account-owned Application initialization before stop CAS. Recovery remains
existing-only, never creates/repairs an uninitialized or missing file. No assertions
were changed. Corrected build/focused package pending; failed receipt is preserved.

initial-cancel-04 build0 at2026-10-12T16:01:04.6896398Z–16:01:51.0087426Z,
zero warnings/errors. Matching focused04 completed6/13/0, exact19,
native1/wrapper1 at2026-10-12T16:04:03.6806480Z–16:07:41.8464033Z,
1963 unchanged inputs. TRX SHA256
`2F6ED2D2CC079E1E13714F192015A3B7F683A4931855C873F70286409339DACD`.
The initialization fix let the new path reach actual audit SQL commit, exposing
the next common defect: audit rows cannot exist before the actual inbox owner is
bound. Added producer binding from the closed verified current account before
stop CAS; missing intent now rejects before Application initialization. Recovery
still never binds/recreates owners. The stale SQL audit bound512 was also replaced
by the existing derived three-owner bound, not an increase in work inventory.
No assertions/expected fault points changed. Both product FAIL receipts remain;
corrected source package still requires matching qualification.

initial-cancel-05 build1 at2026-10-12T16:10:41.2568636Z–16:10:51.7610781Z:
the new binding used UInt64 where the existing owner codec requires its exact
8-byte big-endian generation. Fixed the representation and wiped temporary
account/generation copies. initial-cancel-06 build0 at
2026-10-12T16:12:34.0414012Z–16:12:51.8193600Z, zero warnings/errors.
Matching focused06 reruns all13 new cases plus6 prerequisites; running, no terminal
test qualification yet. Prior failed receipts remain unchanged.

initial-cancel-06 matching focused completed18/1/0, exact19, native1/wrapper1
at2026-10-12T16:14:14.2807365Z–16:17:10.4773103Z,1963 unchanged inputs.
TRX SHA256 `07191050CAC07B63CA4405E0381B2D6969DB10A0BE09EFAB17B4AA4603A31FC9`.
All four key and six payload/audit handovers passed, as did draft-only/unknown
claim and prerequisites. Completed-source positive case completed cleanup, then
failed its unchanged stop-denial assertion: the higher BeginPreclaim owner took
its completed-source shortcut before checking stop and returned InvalidOperation
instead of IOException. Moved actual stop readback before that shortcut; active
completed intents retain the original completed-custody rejection. No assertion
was weakened. Corrected matching source gate remains required.

initial-cancel-07 build0 at2026-10-12T16:20:01.9468789Z–16:20:20.3434694Z,
zero warnings/errors. Matching focused07 includes all pre-session cases,
prerequisites and the prior active completed-source/receiver deletion/native seed
retry case. Running, no terminal receipt yet; no production or physical claim.

initial-cancel-07 focused passed20/0/0, exact20 declared cases,
native0/wrapper0 at2026-10-12T16:22:20.8334231Z–16:25:40.9407931Z,
1963 unchanged inputs. TRX SHA256
`272F3CDF22AFD9BA1C4EFE8A8C8521262E3D0532B17C4FD440697BEDE793DE82`.
Both native and wrapper are terminal. All three pre-session cases passed with
exact unchanged catalog, deleted source/preclaim keys, retired working payload,
independent content-free audit, cold/idempotent reopen and stop-denied BeginClaim.
All four key-deletion and six Application-plan handovers passed without fresh
proof requests during local recovery. The prior active completed-source case
still rejects new preclaim, preserves original source/native replay, and verifies
both sender/receiver deletion and seed isolation. Compilation/fixture/product
FAIL receipts above remain preserved and classified.

This qualifies only the declared source/custody handover package, not the complete
pre-session or S04 release matrix. Remaining: cancellation/expiry deadline edges,
lost stop-CAS reply, actual reserved empty/native imported selection, negative
missing/corrupt source/claim/catalog/keys/audit, stable key resurrection/no-repair,
pre-commit payload/audit abort, codec/private-generation negative tests and broader
Stored/control/source regression. No physical Windows/Android, production upgrade,
unfiltered full, commit/push, frozen/package review or release acceptance is claimed.

## Pre-session cancellation boundary matrix extension

The test-only extension exercises lost stop replies and cancellation immediately
after the stop CAS; actual registered empty stores with and without initialized
SQL; intent selection after a real native import; three pre-commit abort
handovers; the signed lower deadline for audit expiry; and loss of five mandatory
custody roots/markers. Codec cases reject retired local generations, mixed source
absence and seed-bearing or transferred cancellation records. No synthetic
messaging scope or replacement positive authority was introduced.

initial-cancel-08 build0 at2026-10-12T16:38:33.1018790Z–16:38:54.0722543Z,
zero warnings/errors. Its common focused runner declared exactly45 cases before
execution: the extension, the prior pre-session cases, active completed-source
regression and six prerequisites. The run is currently live; no terminal test
qualification or broader S04/device/release acceptance is inferred from build0.

initial-cancel-08 focused passed45/0/0, exactly45 declared cases,
native0/wrapper0 at2026-10-12T16:46:15.6129751Z–16:52:45.1394790Z,
1964 unchanged inputs. TRX SHA256
`5358BB3C724BDF7044371F7988CDBE13E97AED6A80800D51FED8E0433F85CB60`.
Both native and wrapper are terminal. Membership is28 pre-session cases,
10 codec cases, six prerequisites and the prior active source/receiver case.
Both actual empty registrations remain empty and refuse reimport; actual native
import takes the original native stop path without cancellation-key custody.
Lost stop replies/token cancellation recover locally; abort never reverses stop
or key destruction. Signed lower deadline-1 retains the exact audit; the exact
deadline expires it without extending the original stop time or resurrecting
the intent. Missing mandatory roots/marker fail closed without regeneration.
The reviewed reimport-order concern was not reproduced: both existing tests
received the required IOException and preserved the exact empty floor.

This is source qualification of the stated boundary matrix, not whole-S04,
unfiltered, package, production or physical evidence. Corrupt/stable-resurrected
key/source/preclaim/audit cases and broader current Stored/control regressions,
independent object-key/successful-audit retention and final stage gates remain.

The next test-only extension adds nine stable hostile-custody cases using a real
registered empty store: sealed preclaim resurrection, key-manifest/draft rollback,
source TRS resurrection, source record corruption and four audit-row defects.
It asserts unchanged damaged state rather than runtime repair. Codec predecessor
rejection now requires the exact CryptographicException instead of any exception.
initial-cancel-09 build1 at2026-10-12T16:56:31.7620685Z–16:56:49.7861295Z,
zero warnings and one CS4007 test compilation error: span conversion in an
argument before await. Split awaited diagnostic readback from the span comparison
and wipe its temporary digest. No runtime/assertion relaxation; matching build
and tests for this extension remain pending.

initial-cancel-10 build0 at2026-10-12T16:57:38.1023059Z–16:57:48.4488525Z,
zero warnings/errors. Focused10 completed22/3/0, exactly25 declared cases,
native1/wrapper1 at2026-10-12T16:58:32.9250358Z–17:03:33.6530601Z,
1964 unchanged inputs. TRX SHA256
`EA4F68CFE0A11A22DC0A543EA14DAF43FACF0F52146FBA54E824FBCDC0178954`.
All nine stable hostile-custody scenarios passed, as did seven codec cases and
six prerequisites. No key resurrection, audit repair, protected-root mutation or
native import occurred after refusal. The only failures are the three draft
generation cases: the decoder's actual incompatible-generation refusal is
InvalidDataException, not CryptographicException. Corrected each decoder's exact
expected exception; no catch-all, positive decoding or runtime change introduced.
This failed receipt remains FAIL; matching corrected codec gate is pending.

initial-cancel-11 build0 at2026-10-12T17:05:14.1816125Z–17:05:22.5449850Z,
zero warnings/errors. Corrected codec/prerequisite focused11 passed16/0/0,
exactly16 declared cases, native0/wrapper0 at
2026-10-12T17:06:18.0422190Z–17:06:22.3781481Z,1964 unchanged inputs.
TRX SHA256 `E803940C2593720EDCAE072943514AAF346F6379C9DCA7625D26FCFCDC2EF846`.
Both processes are terminal. Runtime has not changed since focused08; extension10
added only hostile-state fixtures and corrected11 changed only the exact codec
exception assertions. These are separate receipts, not a combined54-case PASS.
All failed compile/test receipts remain preserved. Broader current Stored/control
regression, pre-session retry-expiry ownership/deadline, independent object-key/
successful-audit retention and final S04 acceptance remain required.

## Proven control expiry boundary

Review found the stop predicate reused floor division of millisecond event
expiry for a lower-UTC proof. That can classify a fractional-second event expiry
as proven early. Terminal expiry now uses ceiling seconds in pre-session Initial,
admitted Initial and both actual ContactAccept branches. Zero remains no expiry;
the bounded conversion avoids adding999 to an arbitrary UInt64. The conservative
upper-time admission/retry calculation remains unchanged. This introduces no
format, journal, time authority or compatibility path. Current Initial authoring
uses whole-second expiry, so fractional inputs are a boundary defect rather than
a claim that every previous Initial case stopped early.

Six structural cases cover zero, positive subsecond, exact second, fractional
next second and UInt64 maximum. initial-cancel-12 build0 at
2026-10-12T17:10:56.8113513Z–17:11:16.1460012Z, zero warnings/errors.
Matching focused scope includes control metadata/codecs, all six actual contact
unknown-retry/cold-recovery scenarios and prerequisites. Running; no terminal
qualification of this changed runtime yet. Earlier receipts remain prior inputs.

initial-cancel-12 focused passed45/0/0, exactly45 declared cases,
native0/wrapper0 at2026-10-12T17:12:09.3260463Z–17:17:38.0969640Z,
1964 unchanged inputs. TRX SHA256
`0F595EC0C18B425FE5BC3A031117830B294506BC12D00C22CAEF410830C850C2`.
Both native and wrapper are terminal. Membership is23 control metadata/expiry
cases,10 cancellation codec cases, six actual Initial/Accept unknown-retry/cold
recovery cases and six prerequisites. No native, transport, storage or assertion
fallback was added. This receipt qualifies the rounding correction's declared
scope only; it does not combine prior45 pre-session or nine hostile cases into a
current full PASS. Next source acceptance still requires pre-session retry-expiry
entry-point/deadline coverage and broader current Stored/control regression,
followed by remaining S04 retention/outcomes/PQ and canonical stage/release gates.
No commit/push, deployment, physical E2E or GitHub Release happened in this batch.

## Pre-session retry expiry and complete audit-expiry handovers

The account service now offers separate internal user-cancel and proven-expiry
commands through the same private owned-intent pipeline. No raw reason, deadline,
proof, seed or scope input enters either facade. Active working expiry is checked
from independently current lower time before provisioning Application state;
local recovery, source/native distinction, key destruction and audit custody are
the existing implementation. A later cancel must not rewrite an expired intent's
original reason/time. This is source composition, not scheduler/UI activation.

Fifteen new cases cover actual draft/unknown-claim/completed-source crossed with
lost stop reply, signed deadline-1/exact deadline, all six audit-expiry handovers
and three pre-commit audit-expiry abort handovers. They use actual protected roots,
native crypto/SQLCipher and signed successor/time proofs, not caller-selected
absence or a synthetic session. Guard equality includes Application registration
before the early expiry refusal. Audit recovery/abort must be local and preserve
original stop/replay/key destruction; no new proof requests may occur there.

initial-cancel-13 build0 at2026-10-12T17:24:33.5559183Z–17:25:11.3806344Z,
zero warnings/errors. Its focused package includes the new matrix, prior actual
pre-session/key/payload handovers, actual native intent selection, metadata/codec,
contact unknown-retry/cold-recovery and prerequisites. Running, no terminal result.
Broader current Stored/control regression, independent object-key/successful-audit
retention and complete S04/full/package/frozen/review/device gates remain open.

initial-cancel-13 focused completed68/6/0, exactly74 declared cases,
native1/wrapper1 at2026-10-12T17:26:45.0112839Z–17:35:44.4024954Z,
1965 unchanged inputs. TRX SHA256
`B953F12E2CB0A2DD4E3FA41A58925A850F9A28A9EBE8CCE8BB43D3EDE8D7587D`.
All six audit-expiry and three audit-abort handovers passed, as did the selected
prior key/payload/native/contact-retry/codec/prerequisite scopes. The six Initial
deadline failures are fixture setup, before the expiry command: the reused audit
helper authors ADH1 against a future root/DTS generation that is not yet current
at Initial's short deadline. Protocol correctly rejected the candidate interval.
The Initial-only helper now retains actual bootstrap authority and its genuine
signed epoch successor within the existing short window; it does not borrow the
audit's future renewal, widen a policy or skip verification. Runtime/assertions
are unchanged. Matching corrected deadline/prerequisite gate remains pending;
the original74-case receipt remains FAIL, not a combined pass.

initial-cancel-14 build0 at2026-10-12T17:37:54.1023695Z–17:38:13.5083457Z,
zero warnings/errors. Corrected Initial-deadline/prerequisite focused14 passed
12/0/0, exactly12 declared cases, native0/wrapper0 at
2026-10-12T17:38:59.8802261Z–17:41:42.8995838Z,1965 unchanged inputs.
TRX SHA256 `05C0647FCEEF2553C72C9D016B2CF626C7C62C8E7AB0698563F4C7F26FDF775C`.
Both processes are terminal. All three actual pre-session cuts crossed with
normal/lost stop reply passed: lower deadline-1 rejects despite upper crossing,
with exact unchanged draft/preclaim/key/catalog/Application/plan guards; the
exact signed lower deadline stops once with RetryExpired. Local key recovery
needs no fresh proof, keys/payload retire, and new BeginClaim rejects. Later
UserCancelled selection preserves the original expiry reason and stop/audit time.
The nine new audit-expiry/abort cases passed in the separate failed13 receipt;
runtime did not change after13, only the short-window fixture helper changed.
Do not report either receipt as a combined74/full PASS.

The pre-session cancellation/expiry source package is now implemented and has
the stated focused boundary/recovery evidence. Broader current Stored/control
and negative source regression, independent object-key/successful-audit retention,
complete S04 outcomes/PQ/full/frozen/package/review/commit/push and physical
Windows/Android release qualification remain open. No deployment/release occurred.
