# S04 Braid durable custody source checkpoint — 2026-10-11

Scope: the closed Protocol control plan joined to the actual DID2 account owner,
account lease, current endpoint/freshness checks, SQLCipher and independent
protected pending/stable floor. Contract/mapping owner:
[DR-0113](../../../docs/survival-program/decisions/DR-0113-owned-braid-durable-boundary.md).
No shipping transport/ACK, physical E2E, whole-S04 or release acceptance.

## Implemented path

The internal service and account owner prepare actual approved native controls;
the sealed plan authors a distinct mutation in the same messaging journal.
Its event shares the operation namespace with data but never creates DMC2,
message history, message-key deletion evidence or application receipt work.
The current-only DMS2 schema rejects prior generations, including generation4;
no migration, extra journal, extra table, native dependency or data-limit increase.
No existing device/database was reset or deployed by this packet.

Send retry reads the original authenticated exact row before native preparation.
Receive replay is selected only by verified SQL/history and its protected floor.
Pending crash reconciliation imports the protected exact mutation and never
re-authors a control flight. The owner checks the same actual current scope at
preparation, commit and final read-back. Normal semantic selectors remain data-only.
Journal/history verification includes control rows rather than misclassifying
them as plaintext receives; history compaction retains their exact frame metadata.
Control dependency/key retirement and compaction scenario acceptance remain open.

## Native receipts and interpretation

All commands used Windows PowerShell5.1.26100.9457, SDK10.0.301 and the shared
`scripts/TestGate.psm1` runner. Builds target
`Deep.Client.Shared.Production.slnx -c Release --no-restore -m:1 -warnaserror`.
Exact UTF-8 native case lists preceded tests. Input capture includes the actual
solution binaries plus Shared, Protocol and root normative/tooling inputs.

Run directory base: `artifacts/s04-lifecycle-20261011/`.

- `braid-durable-01`: preserved build FAIL, missing verifier namespace; no tests.
- `braid-durable-02`: preserved build FAIL, explicit production service include
  missing and tests referenced internal Protocol error types; no tests.
- `braid-durable-03`: zero-warning/error build. Declared44,36passed/8failed,
  native1/wrapper1;1932unchanged inputs. All eight new cases failed at route
  fixture setup, before the new control path: proposal expiry exceeded the signed
  default network window. Use the existing genuinely signed long-window fixture
  and encrypted protected storage; runtime checks were not relaxed.
  TRX SHA256 `3F06D25B6641530824282BC1DF37D0803FEE2E5D634EF3699FF90A3917506582`.
- `braid-durable-04`: zero-warning/error build. Declared44,43passed/1failed,
  native1/wrapper1;1932unchanged inputs. Native interval
  `15:43:45.9880961Z`–`15:51:25.7419666Z`.
  TRX SHA256 `C49B102B3191D4C0A4E785EC56E863F07D5BFC0FF7AB3892CE7111B0C348983B`.
  The actual exhausted-peer scenario passed, followed by bidirectional fresh
  data and all63original pending data envelopes (one prior ContactAccept already
  consumes the remaining data32 slot). All six send/receive AfterPending,
  AfterSql and AfterStable crash cases passed with cold owner/SQL reopen, exact
  retry and exactly one generation/ordinal increment. Controls did not add
  message history. The failing negative test expected a data/control operation
  collision to reject on send; the owner already rejected it earlier at draft
  creation. This run remains FAIL; it is not classified as whole-scope PASS.
- `braid-durable-05`: only that negative test was changed, retaining the early
  rejection and adding explicit send plus reverse data-to-control collision
  assertions and unchanged native floors. Production source was not changed.
  Zero-warning/error build `15:52:45.9860164Z`–`15:52:55.1502458Z`.
  Declared7,7passed/0failed/0skipped, native0/wrapper0;1932unchanged inputs.
  Native interval `15:54:05.6398049Z`–`15:55:13.4563953Z`.
  TRX SHA256 `700B1D714774E3A6D3FA800053FFF5207276A058E34A1C3DF2BBC3F2D3808339`.
  Scope: changed replay/reflection/namespace negative plus all six current fixture
  prerequisites. This qualifies that focused scope, not a matching44-case/full run.

The44-case filter was `FullyQualifiedName~OwnedBraidRecovery_` plus
`Did2MessagingSqlJournalTests`, `Did2MessagingMutationBoundsTests`, the existing
`Did2ReceiverCustody_LastResortSignedLimitDeletionAndExactRestart` and
`FixturePreflight=true`. The7-case filter replaces those business/storage cases
with `OwnedBraidRecovery_ChangedReplayReflectionAndDataNamespaceCollisionsReject`
and keeps `FixturePreflight=true`. Use the actual preserved receipts in the final
unfiltered stage gate; do not aggregate different source/binary snapshots into
a claimed current44/44 qualification.

## Matching control/history source package

`artifacts/s04-lifecycle-20261011/braid-history-01`: build0 with zero
warnings/errors, `16:24:56.2718825Z`–`16:25:05.0100291Z`.
Declared47,47passed/0failed/0skipped, native0/wrapper0;1933 unchanged inputs.
Native interval `16:26:25.9171680Z`–`16:36:05.7334488Z`.
TRX SHA256 `F48A1DF9D5E0EBAF19F28D527808129814AF3DB8C225CD608E00236409AFCEB9`.
Exact predeclared UTF-8 native case identities match the receipt. Scope is the
previous44-case filter, all current `OwnedBraidRecovery_` cases including two
new history cases, and the existing actual encrypted compaction/cancellation
owner case. This is one current47-case run; earlier FAIL receipts remain FAIL.

The exhausted peers, all63original pending envelopes, six native commit-crash
handover cases and operation/scope/replay negatives pass in this snapshot.
The new history cases use actual account owners, native crypto, SQLCipher and
encrypted protected storage, not a substitute transaction authority:

- Every actual prefix-compaction handover is faulted and cold-resumed. Original
  send retry and receive replay keep their exact controls and native floors;
  control records never add a semantic message. New ordinary suffix events
  permit the next compaction without reminting old controls.
- Two real Braid outputs with intervening bidirectional fresh data install
  native links1/2; test-only numeric inspection confirms link0 is absent.
  After actual compaction and encrypted cold reopen, the original authenticated
  link0 control replays from protected exact history without a ratchet increment.
  Changed-frame replay, protected-history rollback and exact SQL-frame
  substitution reject. Fixture restoration does not provide runtime recovery.

The matching Protocol85-case snapshot tests early pinned-frontier rejection and
ordinary receive deriving old skipped keys before next-link retirement. Public
wire/KDF/layout and data32 remain unchanged. This does not authorize retiring
unknown transport-control dependencies; those frames in the positive retired-key
test were already committed by the peer. This is focused source evidence, not
whole-S04/full/API/package/transport/device acceptance.

## Actual control cancellation and affected commit-hook consumers

The next connected test package uses one real encrypted two-account exchange,
not six separate account setups. Cancellation before either endpoint's commit
does not invoke a mutation hook or change its protected floor. The same exchange
then cancels send and receive at each AfterPending/AfterSql/AfterStable handover.
Before cancellation it captures only the public exact control from the actual
protected pending mutation under the already-held account lease. After reopening
the corresponding encrypted backend, the owner returns that exact frame, advances
the original operation's generation/ordinal once, and replays without another
advance. Controls add no semantic messages; genuine bidirectional data resumes.

The commit hook now permits asynchronous inspection inside `DEEP_TEST_INTERNALS`
only. All three call sites await it; ordinary synchronous crash hooks retain their
immediate exception semantics. No shipping behavior, wire, KDF, layout or retention
authority changes. There is no blocking task wait, lease reacquisition, raw TRS1
export, alternate store or substitute durable authority in the capture helper.

Fresh `artifacts/s04-lifecycle-20261011/braid-cancel-01`:
build0/zero warnings/errors, `16:43:53.5575833Z`–`16:44:40.2059835Z`;
declared20,20passed/0failed/0skipped,native0/wrapper0,1934 unchanged inputs;
native interval `16:45:40.9477603Z`–`16:53:00.1539573Z`.
TRX SHA256 `71D280E3B1DD187E5008A4563DC8874D99CD0ECCAA07B905EB4E2680DC7DAC45`.
Exact predeclared UTF-8 native case identities match the receipt. Filter includes
the new cancellation-matrix fact, all six `OwnedBraidRecovery_CrashAtEveryCommitHandoverRetainsExactOperation`
cases, all six `Did2RouteProcessing_ActualOwnedControlCommitsFirstOutcomeAndColdExactReplay`
cases, `Did2MessagingOwner_OrdinarySendReceiveReopenGapAndExactReplay` and all six
current `FixturePreflight=true` cases. This qualifies that current20-case scope,
not a sum with the earlier47-case snapshot or unfiltered full acceptance.

## Still required

Unknown transport operations retain exact control/request and independent
transport dependencies. Native-key purpose exclusion is separately governed by
[DR-0114](../../../docs/survival-program/decisions/DR-0114-owned-braid-mailbox-lifecycle.md),
not a Store, delivery/non-delivery or transport-retirement claim. The current20-case
scope supplies control-commit cancellation evidence; complete the entire required
unknown/crash/cancel/retirement matrix and API/package/downstream gates.
Then complete the remaining S04 lifecycle/sustained requirements and canonical
unfiltered full/review/commit/push. Physical Windows/Android contacts, messages,
files and groups still require their later connected stage evidence.

## Connected owned mailbox candidate — 2026-10-11

DR-0114's existing Store/attempt/read/ACK owners now join actual SQL kind5 controls
without DMC2, authored stop/completion markers, extra journals or caller-supplied
authority. Only verified direction3 original frames enter the distinct control
dispatch facade. Exact MAU/body/grant/counter and original retry windows stay in
their existing custody. Terminal historical Store rechecks original policy,
route, protected evidence commitment, holder-signed request, replicas and retained
coordinator; it neither dispatches again nor claims native receive/AppAck.
Current same-peer authenticated data progress denies further control dispatch,
but does not erase unknown outcome or original attempts. Late original replies
retain the existing independent authentication/settlement owner.

Incoming catalog lookup is not authentication. Current native commit or original
exact direction4 custody authorizes authenticated control receive. Obsolete-purpose
disposal instead rederives protected peer-data progress, or the separately closed
installed-output/original-MAC proof. ACK repeats that classification under its
actual lease and exact captured page; it writes no fake direction4/DMC2/AppAck.

`OwnedBraidRecovery_ExhaustedPeersUseMailboxStoreReadAckWithExactLostReplies`
exhausts both data32 fences, transfers all four recovery flights through actual
owned Store/Retrieve/ACK with held onion preparation, loses Store and ACK replies,
cold-reopens and retries original bytes, then decrypts fresh bidirectional and all
63 pending envelopes. Controls add no semantic messages or receipt obligations.
In-process signed issuer/terminal fixtures are not sockets or physical E2E.

`OwnedBraidRecovery_FirstObsoleteControlAckSurvivesRootRetirementWithoutClaimingReceiveOrErasingUnknownStore`
first completes the actual Braid through ordinary data, rejects a changed control
MAC, disposes the original first control using live-root proof and loses ACK reply.
Actual peer data and a second Braid output then retire root0 (numeric actual TRC1
links1/2, not a test flag). Cold exact ACK succeeds using protected peer history
without another native receive/generation/message/receipt. Original unknown Store
remains prepared/open with unchanged frame/MAU hashes; further dispatch is denied
before issuer/ingress. No non-delivery or Store success is fabricated.

Fresh native Windows PowerShell5.1/SDK10.0.301 records:

- `artifacts/s04-lifecycle-20261011/braid-mailbox-01`: build1, missing existing
  `MailboxStoreReplicaEvidenceVerifier` namespace import. Preserved; import fixed.
- `braid-mailbox-02`: build0/zero warnings/errors,
  `17:52:08.5484618Z`–`17:52:30.3074322Z`. Exact50/0/0,native0/wrapper0,
  `17:54:54.5744908Z`–`18:06:05.1491047Z`,1940 unchanged inputs;
  TRX SHA256 `EE56BA46AD1D54B539BCAEC0345FC9FEFE1F30E45A4290194B6E91D0A122D127`.
  Scope: new exhausted mailbox case, all `Did2OwnedMailboxSend_` and
  `Did2OwnedMailboxReceive_`, SQL journal/mutation-bound tests and six prerequisites.
- `braid-mailbox-03`: build0/zero warnings/errors,
  `18:13:10.3919993Z`–`18:13:26.9961908Z`. Exact7/0/0,native0/wrapper0,
  `18:15:15.2202443Z`–`18:16:40.4943616Z`,1940 unchanged inputs;
  TRX SHA256 `F1E0F720ACFFDECBC48301033155669804C54B053E68371CC8383A182DE5CCF9`.
  Scope: new first-obsolete/root-retirement/unknown-Store case and six prerequisites.

Both declare exact UTF-8 native cases before execution and compare receipt names
with SetEquals; common actual solution input captures remain unchanged. SQL/crypto
production source did not change between these runs; additional Shared fixture
coverage and Protocol assertion/API tests did. These remain separate matching
snapshots, not aggregate57/full qualification. Protocol's matching91-case scope is
in its linked checkpoint. All processes are terminal. No commit/push, production,
Release or main promotion occurred. S04 acceptance is still open.

## Original control settlement, bounded admission and redundant-send retirement

The control business facade now retires only redundant protected send
commitments after independently verifying original Stored custody and every
attempt's native/frame, request/acquisition, counter, quorum and coordinator
joins. It reuses the existing protected-only Audit plan and its nine guard roots;
it does not remove SQL/native history, exact frames, original requests/evidence,
grant/holder/object/read/ACK dependencies or replay floors. Unknown Store and
obsolete native purpose cannot qualify this retirement. Interrupted maintenance
resumes the exact existing plan, without dispatch, reenrollment or new encryption.

The connected fault/cancellation theory uses the same original control through
all five real Store-preparation handovers, lost Store reply, both late-settlement
SQL handovers and all five protected-only Audit handovers. Encrypted cold reopen
preserves the exact MAU/control and counter floor. Captured-page interruption,
native receive after SQL, lost ACK reply, cancelled ACK retry and cold exact ACK
retain one receive and no semantic message/AppAck obligation. Protected-only
Audit has no SQL mutation, so no fictitious AfterSql handover is claimed.

New controls also use the existing transport capacity/operation preflight before
native entropy or occupying a Braid slot. Recovery bypasses data32, not bounded
transport custody; already committed native exact retry bypasses new-work
admission. The two negative fixtures stage structurally valid adversarial
protected custody only. They are not genuine512-send/128-grant sustained evidence.

Fresh Windows PowerShell5.1/SDK10.0.301 runs, all terminal:

- `braid-retirement-01`: build0/zero warnings/errors,
  `18:33:54.8490406Z`–`18:34:43.1282931Z`; declared16,16/0/0,native0/wrapper0,
  `18:36:46.4708583Z`–`18:47:03.2940812Z`,1942 unchanged inputs;
  TRX SHA256 `74CDD21EF0856F1B883C6C94A208C306155DF2BB4A805B5B2596FA1DD959B2B5`.
  Scope: the two new control fault/cancellation cases, exhausted mailbox and
  first-obsolete-control cases, all six completed-contact-send cases and six
  current prerequisites. This snapshot predates new-control admission preflight.
- `braid-retirement-02`: build0/zero warnings/errors,
  `18:51:41.6967212Z`–`18:52:00.7519870Z`; declared18,16/2/0,native1/wrapper1,
  `18:57:00.3368936Z`–`19:06:19.8239717Z`,1942 unchanged inputs;
  TRX SHA256 `A5D718158C0BF645C4193FD787194B3E951F0C1AAA58101CCE53435F827029E2`.
  Both new negatives failed while preparing their too-short fixture ciphertext,
  before the owner/preflight. All previous16 cases passed. Preserve this FAIL;
  only the fixture ciphertext size was corrected, with no weakened assertion.
- `braid-retirement-03`: build0/zero warnings/errors,
  `19:06:53.2510709Z`–`19:07:09.5342682Z`; declared8,8/0/0,native0/wrapper0,
  `19:07:30.2555806Z`–`19:08:56.7262070Z`,1942 unchanged inputs;
  TRX SHA256 `64758FC8DFDB266C507A0DBBD46BE360D7BA562A4C3AC542E793F0CA3F340B26`.
  Scope: the two corrected admission negatives and six current prerequisites.

Exact UTF-8 native identities are declared before execution and match passing
receipts by SetEquals; actual solution input captures remain unchanged. These
are separate snapshots/scopes, not a combined18/full PASS. Production source
did not change between retirement-02 and retirement-03. Full/API/package/
downstream and all remaining S04 requirements remain unqualified. No physical,
production deployment, commit/push, Release or main promotion is claimed.
