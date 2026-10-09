# Owned mailbox grant custody — current local layout

Owner: Mr. X, delegated architecture authority. This is the Shared producer's
closed local serialization/API for acquisition and closed-unresolved custody in S01. Semantic
transitions remain owned by
[TRANSPORT-NEUTRAL-MESSAGING §8.4](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#84-owned-attempt-settlement-renewal-and-retirement).
It does not allocate wire bytes, an algorithm, a network authority or a renewal
policy. Runtime/test acceptance is recorded separately in the
[checkpoint](../testing/s01-grant-acquisition-contract-2026-10-05.md).

## Serialization

The protected slot remains `deep.store.v2.mailbox-grant-journal`. Its sole reader
accepts local generation5; every earlier generation rejects, including empty
state. Existing incompatible test accounts require explicit reset. There is no
migration, fallback or initialization by a reader. Account creation is the sole
empty-state producer.

All integers are unsigned big-endian. The closed header is96 bytes:

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 1 | Generation5 |
| 1 | 1 | Zero flags |
| 2 | 2 | Acquisition count |
| 4 | 8 | Revision, at least acquisition count +1 |
| 12 | 16 | Exact nonzero network |
| 28 | 32 | Exact nonzero account |
| 60 | 32 | Exact nonzero account instance |
| 92 | 2 | Selection count |
| 94 | 2 | Zero reserved |

Then follow length-prefixed acquisition records, sorted strictly by
`SHA256(exact XMG2)`. This is the existing XMC2 tag5 request binding, not a new
hash domain. The identity is derived, not stored as a second mutable field.
Each prefix is u32be and is checked against5737..25561 before slicing or copying.
The record has a1097-byte fixed region and exact original policy/route evidence:

| Offset within acquisition | Width | Field |
| --- | --- | --- |
| 0 | 32 | Existing route/locator/direction scope commitment |
| 32 | 32 | Exact nonzero independent holder seed |
| 64 | 32 | Exact nonzero route-closure hash |
| 96 | 1 | Phase1 pending, phase2 ordinary winner, phase3 closed-unresolved, phase4 received late winner, phase5 adopted late winner |
| 97 | 3 | Zero reserved |
| 100 | 435 | Exact original XMG2 |
| 535 | 510 | All zero for phases1/3; exact successful XMC2 for phases2/4/5 |
| 1045 | 32 | Predecessor acquisition identity; zero only for first acquisition |
| 1077 | 8 | Conservative possible-grant expiry from original signed evidence |
| 1085 | 8 | Authenticated lower Unix bound of closure; zero for phases1/2, retained for phases3/4/5 |
| 1093 | 2 | Original PMA2 length497..1169 |
| 1095 | 2 | Original route-closure length4143..23295 |
| 1097 | Variable | Exact original PMA2, then exact original six-record route closure |

The last region consists of128-byte selections sorted strictly by scope:
scope32, current acquisition32, pending acquisition32, retained tail32.
Zero means no pointer. Pending or tail is required. Pending may reference an
exact request or received winner and must name retained tail as its predecessor.
The retained chain contains ordinary/adopted late winners, received late results
and closed-unresolved acquisitions in the same scope. Current is exactly its
most recent adopted winner (phase2/5), or zero if none; phase4 cannot select itself.
selecting an older retained winner rejects. Every acquisition is reached exactly
once from pending or retained history, including an initial closed acquisition.
Dangling, cyclic, cross-scope, orphaned or duplicate acquisitions/grants reject.
No selection is inferred from sort order, time, row count or SQL.

There are at most128 acquisitions; selections cannot exceed acquisitions. Exact
length is `96 + sum(4 + record length) + selections*128`, at most3288800 bytes.
The count bounds remain128; the additional bytes retain actual original evidence,
not extra acquisitions. A mismatched prefix/evidence length rejects before copying.
Unknown flags/phases, noncanonical counts/revision/order, trailing bytes, wrong
account instance, holder/request mismatch and response binding mismatch reject.
Ceiling is recomputed from the exact evidence; request PMT2/PMS2, route hash
and network must match. Deposit additionally requires the original projection's
PMA2 reference and its admission interval. The DR-0104 Retrieve source increment
captures the current acquisition PMA2 with the exact original selection: its
conservative ceiling is the lesser of that policy expiry and original six-record
admission end plus the normative maximum retained-object horizon. This is a
custody ceiling only, not a TTL extension or issuance/admission permission.
A received winner cannot exceed that ceiling. This changes Retrieve evidence
validation in the sole current reader; an incompatible old nonempty record
rejects, without a second reader, a migration or automatic reset.
Phase3 retains exact holder/request/evidence with no winner; phases4/5 retain the
same closure proof with one immutable late result. Their closure lower bound
cannot precede XMG expiry. These checks establish custody shape, not current
or historical issuer/time authorization.

## Owned transitions and consumers

The working-tree DR-0104 `AcquireOwnPermanentContactRetrieveGrantAsync` joins the actual
held account, account instance and permanent phase7 publication to current
proof/network/PMA2/host checks. The original private capability is read only from
that exact protected completed publication; the publisher must still be an
active device of the current exact DID2. Original signatures are not interpreted
as current admission. The separate current-only initial-contact/Deposit paths
are unchanged. Signing is confined to the original route/locator/Retrieve scope.
Pending holder/request custody is CAS-persisted and independently read back
before the bounded selected ContactResolve courier. Returned bytes are untrusted
until the current closed host verifies the retained result; winner and selection
have separate protected CAS/read-back fences. A cold retry restores exact XMG2,
not its operation/window; a selected winner is not reissued. Post-callback
publication/source loss rejects adoption. The owner installs and independently
reads back the exact credential in SQLCipher under that same held lease. The
returned Protocol proof remains issuer evidence, not an exported SQL signer or
native dispatch/ACK permission. The actual Retrieve and ACK operations reopen
that protected winner and original pair with the current host/PMA2/proof, not
current admission of the original publication. Their private transport loan is
bounded by the complete current interval. Semantic durable materialization still
precedes ACK and its tombstone quorum. Late-result adoption retains the same
two-phase protected settlement and SQL failpoints. Deposit and initial-contact
admission stay current-only; no current-to-history fallback exists. The standalone
candidate acquisition API was removed. This connected source is not full-gate
accepted; native original-selection/object/replay and physical qualification
remain required.

Publication promotion retains its exact completed predecessor under the local
renewal intent in the existing bounded journal. Active Retrieve/ACK reopens the
unique original route from that custody, bound to the current permanent intent,
account instance and unchanged private owner capability. Archived intent binding
is independently rederived from the predecessor bytes; arbitrary completed reusable
entries do not become permanent-account read custody. Missing/ambiguous custody
rejects before acquisition or dispatch, with no fallback to the new publication.
Superseded-holder selection likewise opens the actual acquisition's original route.
Current host/proof/time, holder, SQL and native checks are unchanged. A new idle
cycle chooses one least-polled route among the actual current and independently
bound archived permanent publications, using existing protected traversal poll
generations. Active original work always takes precedence. One page per call
keeps the existing bounds; absent traversal metadata is not absence of objects,
and no route/grant is evicted or reminted. This owner selection does not introduce
a background scheduler or dependency-closed retirement.

Semantic rematerialization of actual native-committed Hello/Accept follows
[DR-0063's retained-event clarification](../../../docs/survival-program/decisions/DR-0063-did2-contact-reply-route-embedding.md),
not current admission of its old return publication. The Shared handoff joins
actual protected native floor and exact committed events, checks original route
signatures through the closed historical predecessor verifier, and rechecks the
same native source before returning. Current endpoint/DCA/XUR authority remains
required; unsupported PMT/device/delegation rollover rejects. No public trust
flag, live route or Store permission leaves that reader. Current retained
Retrieve/ACK authority is verified independently and is not relaxed.

The matching accepted-object increment uses the sole
[retention matrix](../../../docs/architecture/RETENTION-AND-RECOVERY-V1.md#1-service-and-protocol-retention)
for MEO1, native blob admission and the shared SQL/in-memory state machine's
inbox/coordinator-statement bounds. Short grant expiry authorizes an attempt,
not payload retention. A new send persists its original object deadline before
dispatch; exact retry keeps that deadline and ciphertext. A signed Store receipt
does not become accepted local settlement unless its exact coordinator statement
can be durably recorded. Retained Retrieve still requires current issuance and
held ownership; longer payload retention never permits stale Store or extends
an existing pending/unknown operation. This changes no journal generation or
working-set capacity and does not activate runtime renewal or compaction.

`AddPending` preserves an existing current winner and records one candidate with
its exact retained predecessor. It cannot replace another pending candidate. No callback
occurs before the account owner's protected CAS and exact read-back.
`WithWinner` changes only a pending record's phase/response. The actual owner
independently verifies the issuer/route/result before persisting it. A received
winner remains pending through a separate protected read-back and verification;
only then can `PromoteWinner` change current/tail and clear pending. Promotion is a
separate CAS/read-back before SQL installation or returning usable authority.

Cold reopen of a received initial pending winner re-verifies and adopts that exact
candidate without reissuing. Installation interruptions recover the selected
winner; expired original requests are never re-windowed. Initial owner revisions
are empty1, pending2, received3, selected4. Revision is a protected transition
counter, not a derived replay floor.

Ordinary acquisition uses `AcquisitionForNewWork`: current if selected, otherwise
the initial pending candidate. A pending successor cannot replace current merely
because a new message/poll arrives; renewal adoption remains a separate owner
lane. If a scope has only closed history, ordinary acquisition returns bounded
backpressure, not a new initial request. `CurrentWinner` is used after owned
acquisition. `RequireRetainedWinner` searches retained winners by exact MCG3 hash and scope;
it excludes an unpromoted candidate. Missing original custody rejects.
Existing Store attempts, active Retrieve cycles and ACK pages use this exact
lookup, without a new acquisition or substituting the current winner. They still
require the ordinary actual route, issuer, holder, time, revocation and replay
checks; retained lookup does not authorize expired/historical transport.

`AcceptOwnPermanentContactRetrieveGrantResultAsync` and
`AcceptPermanentContactDepositGrantResultAsync` are internal owned incoming-result
entries. The510-byte packet is untrusted, copied before asynchronous verification;
it cannot supply a clock, holder, policy, route or disposition. Own publication
or independently current peer resolution supplies the actual route/capability
under the account lease. XMC2's existing exact-request binding must name actual
protected acquisition custody in that exact route/locator/direction scope.
Pending requests must first close using the independent time transition above.

Existing `VerifyRetainedSuccessAsync` independently verifies the exact original
XMG/XMC, root-signed current issuer policy and complete current grant/route interval.
It does not restore an expired request. Only then may `WithLateWinner` record
phase3→4 by protected CAS/read-back; the closure lower bound and original
holder/request/policy/route/ceiling remain unchanged. No issuer callback occurs.
The owner reads and verifies the protected result again before a separate
phase4→5 CAS/read-back (`AdoptLateWinner`), and only then installs/reopens actual
SQL credentials with current authority checks. Received phase4 is excluded from
current and exact-original Store/read/ACK selection. A different result cannot
replace an existing ordinary or late winner.

Adoption never changes acquisition identity, predecessor, pending or retained
tail. Current remains the latest adopted acquisition in the retained predecessor
chain: a late result behind a newer adopted winner cannot roll selection back;
a newer pending candidate is not overwritten. Closure evidence survives adoption.
`ResumeOwnPermanentContactRetrieveGrantResultAsync` and
`ResumePermanentContactDepositGrantResultAsync` explicitly resume from the actual
protected late result, preferring a retained phase4 candidate, otherwise a retained
phase5 result for interrupted SQL installation. They accept no response packet or
issuer callback. The private codec lookup establishes custody shape only; the
same independent verification/read-back/SQL fences still apply on cold reopen.

Ordinary acquisition still checks its original XMG window before forwarding.
An exact reply arriving after that window can use the same retained-success
verification while the actual grant/issuer/route remain independently current.
Timeout/cancellation does not fabricate a reply, extend a request or reissue a
closed acquisition. Unsupported historical authority remains unavailable.

`DeepIdV2AccountService.CloseExpiredMailboxAcquisitionsAsync` is internal and
accepts only the actual own source plus cancellation. It obtains independently
current own directory/network authority; the account owner holds the actual lease
and rechecks the own proof/protected network floor. It never restores the expired
request and does not require the old route/issuer to be current. Only an
authenticated lower bound reaching request expiry closes a phase1 candidate.
One bounded protected CAS/read-back retains its original evidence, sets phase3,
clears pending and advances retained tail without changing current. The final
root and own authority are checked again before returning an aggregate count.
No SQL, issuer callback, key/floor deletion or replacement request is involved.
Before/after closure interruption resumes from exact pending/closed custody.
The codec helpers themselves establish shape, not permission to close.

## Held epoch-exclusion prerequisite

`OpenMailboxEpochExclusionAsync(originalAcquisitionHash, ownSource, ct)` is an
internal account-owned entry, not an adapter/UI permission. The nonzero32-byte
hash is copied before asynchronous reads and selects exact original custody.
The actual owner/source independently obtains current complete network, PMA2
and own proof; the returned `MailboxEpochExclusion` retains the actual account
writer lease, current verified account, original root/instance/acquisition,
current host authority and first monotonic reading. Its constructor is private;
the producer always performs the native floor and original-custody checks.
Its epoch/scalar/hash properties are facts, not a separate verification API.

`RecheckAsync(ct)` is the consumer boundary under that same lease: it rechecks
the exact account-owned directory/network floor, independently current PMA2,
actual instance and byte-exact grant root. The original generation5 decoder
still enforces canonical original policy/request/route/ceiling and holder
custody. Known results additionally use the existing exact route/result binding;
closed-unresolved custody cannot invent an observed serial/generation. Dispose
releases the lease and zeros captured grant/instance/acquisition buffers; a
disposed capability cannot be consumed. Cancellation or failure releases no
exclusion authority and changes no grant/counter/cleanup state. Normal source
verification may advance its independently verified directory/network floors
before the exclusion producer rejects; those floors are not rolled back.

No additional persistent floor/marker is introduced. On reopen,
the producer remints only from actual native DNH2/anchor and retained original
grant root, with independently current signed evidence. The source cannot
replace an existing full-history floor with a tuple or cache. Semantics, time,
strict epoch advance and unavailable rollover rules have one owner:
[TRANSPORT-NEUTRAL-MESSAGING §8.4.2](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#842-grant-and-route-transitions).
This lease is only a prerequisite for a future dependency-closed protected
plan; the API has no deletion, mutation, issuer callback or scheduler entry.

## Native replay-fence guard readback

`MailboxEpochExclusion.CaptureDurableReplayFenceAsync(ct)` captures an unchanged
`Did2CompactionPlan.NativeFence` guard under the same actual account lease.
It rechecks the exclusion before and after reading the already-committed native
DNH2 floor. It does not commit another floor, stage a plan or retire custody.
The local selector is SHA256(network16 || account32 || account-instance32).
The digest is SHA256(local binding commitment32 || u64be(native revision) ||
exact XLK1 || exact DNH2). The binding commitment uses the local
`Deep/STORE-V2/native-replay-fence-account` domain plus zero separator,
network/account/instance, DID2/DAB2/device/certificate/directory hashes, then
u32be-length-prefixed UTF-8 display name and permanent ID. It is not a network
credential. Adding it before the first installed retirement profile prevents
a changed SQL account/device projection from matching the captured guard.
Before and After are identical; no successor bytes are present.

The private SQL reader opens the already-registered account database without
initialization and reads both native floor rows in one transaction. The existing
network marker and independent full-history anchor authenticate the SQL-derived
genesis pin and exact history; a tuple/hash supplied by a caller is not accepted.
Missing/split history, noncanonical SQL scalar types, anchor mismatch, rollback
or fork-latched state reject without repair. Revision must be a SQLite integer;
conversion of a fractional REAL value to an integer is not accepted.

`ReadOwnMailboxReplayFenceAsync(ct)` is an internal cold local fact reader. It
acquires the real account lease and uses that same SQL/marker/anchor reader,
without a current directory proof, network fetch, signing or issuer callback.
It returns metadata only, not a reminted exclusion or deletion capability.
Recovery still needs the closed owner profile and all dependency readbacks;
capturing this guard alone cannot remove grant/send/read/ACK or receipt state.
The [focused checkpoint](../testing/s01-native-replay-fence-2026-10-06.md)
records the tested source boundary. Full S01 retirement remains unaccepted.

## Held retirement dependency capture

`MailboxEpochExclusion.CaptureRetirementDependenciesAsync(ct)` reads actual
ordinary, send, grant, read, session-catalog, attachment and account-registration
roots plus the native replay fence. The seven protected roots are canonically
decoded/validated under the same real account lease; the grant root remains the
exclusion's exact original root. The returned private-constructed snapshot is
bound to that live exclusion, not reconstructed from a caller's root/digest.
Exported guard metadata is copied and cannot mutate the captured commitments.

`RetirementDependencies.RecheckAsync(ct)` rechecks current epoch exclusion and
every byte-exact captured root/native fence. Changed or missing custody, expired
proof, discontinuous clock, cancellation or a disposed exclusion rejects before
any effect. No plan is staged, no SQL is deleted and no holder/floor is removed.

Observed dependency reasons distinguish acquisition links, matching send work
and floors, active read/ACK work, read floors/traversal, ordinary commands and
attachment work. Ordinary/attachment roots currently lack a complete
grant-to-receipt/object index, so their nonempty work is not assumed unrelated.
A known winner or existing session remains unresolved for receipt/object
closure; Retrieve retains a path obligation even for an unresolved acquisition.
Empty journals or an empty poll are not remote non-issuance/non-delivery proof.
These reasons are transient local observations, not serialized settlement flags.
Even `None` is not retirement eligibility or a deletion capability: the actual
closed retirement profile still needs complete SQL/native/receipt/object
readbacks and the §8.4.4 retained-route fence. Those consumers remain unfinished.

## Closed unused deposit retirement profile — working implementation

`MailboxEpochExclusion.RetireUnusedClosedDepositAcquisitionAsync(ct)` privately
reselects under the same held lease; it accepts no supplied preparation or
dependency flags. This profile requires a sole closed-unresolved Deposit entry
in its selection, no winner/pending/predecessor link, and no observed dependency.
The held producer rechecks current policy/time/exclusion, every exact dependency
root and the committed native fence before atomically staging the plan/parts.
Unsupported outcome/path closure remains pinned, not declared successful.

The existing plan generation has a closed ProtectedOnly profile: one ReplayScope
row selecting the exact acquisition, eight roots, only Grant changed, and zero
SQL effects. The exact successor removes only that acquisition and selection,
increments its root revision, and retains every unrelated acquisition/root.
It does not unenroll a send/read floor or remove object/history/receipt state.
No new journal/root/wire generation is allocated and no scheduler/UI enables it.

Startup dispatches that already-stored profile without refreshing directory or
network authority. It opens the registered SQLCipher database without creation,
validates canonical bounded local account/device rows and the existing native
marker/history anchor, and compares the complete binding/floor guard to the
staged commitment. These are readback facts, not self-verified SQL identity or
a reminted exclusion. Third root states, changed guards, missing required parts
or missing bindings reject. The existing local commit-marker phase precedes
grant CAS/readback; this profile makes no SQL mutation. Once the successor is
adopted, only matching remaining parts may be disposed, then the plan clears.

`AbandonUncommittedMailboxRetirementAsync(ct)` permits only phase1
with all exact predecessors/guards intact, persisting the existing abort phase
before disposal. A committed phase2 cannot abort/reselect even before grant
adoption. Cancellation leaves the already-staged plan owning exact recovery.
The [current coupled full source gate](../testing/s01-closed-deposit-retirement-2026-10-06.md#current-coupled-full--accepted-unused-deposit-profile)
qualifies this narrow profile:706/0/0, observed terminal0, all200 current/all687
prior cases Passed and62/62 frozen inputs exact. The broader S01/S04
lifecycle/receipt/object consumers remain unfinished. The encrypted-journal reopen fixture uses
its own protector, not Windows/Android platform custody. The focused
checkpoint records evidence separately; this qualification is not release
activation or a declaration that every replay namespace can be retired.

The acquisition runtime still creates only an initial candidate. The internal
closure entry is not autonomous scheduler activation. This layout does not
activate autonomous renewal/cleanup, historic read/ACK
or a longer object horizon. The narrow explicit held producer above removes only
an eligible closed unused deposit acquisition; no known grant/send/read entries
or replay floors are evicted and no128/512 bound is raised. Send/read independent
replay floors are unchanged by that acquisition profile. The separate
[idle counter profile](owned-mailbox-counter-retirement.md) changes no grant or
retained path and has its own qualification boundary. Full lifecycle contracts
and the linked retention fence remain unfinished S01/S04/S05 work.

The expired/unknown semantic and retirement boundary remain specified only in
the semantic owner linked above, §8.4.2. Generation5 retains original evidence,
closed uncertainty and two-phase late adoption, not proof of non-issuance or an irreversible retirement
fence. No new network wire, magic, authority or public verification API is added.
The earlier generation3 receipt is historical evidence for its exact source.

[DR-0106](../../../docs/survival-program/decisions/DR-0106-retained-store-public-evidence.md)
owns the separate original public Store outcome dependency. Shared inserts the
immutable original public records before ordinary Stored permits compaction;
selection never repairs them. Its historical reader joins native/semantic/MAU/
quorum/coordinator custody without issuing a new grant. It reads a completed
protected Stored ordinary command both before and after compaction, without
renewed peer admission; pending/authored-only work remains current-only.
ContactAccept uses the same original outcome closure with its retained explicit
winner, actual native Hello/send and semantic acceptance. Its public evidence
is retained before ingress; evidence alone cannot return success. A durable
candidate with missing evidence fails without reconstruction. Acceptance and
initial-message working-slot retirement remain unactivated. Initial evidence
also fails before a new peer resolve: its original recipient DCR/route/ADP
records are retained in the same SQL row and independently joined to protected
draft, key-retired sender source, native events and pinned peer DID2. Public
StartContact and initial dispatch retries share that historical reader. No
Hello return route substitutes for the original recipient route. Losing
mandatory send registration is corruption, not successful retirement. Dispatch
rechecks current authority after awaited local completion before returning;
expiry leaves an independently verifiable durable outcome, not new admission.
Application schema10 rejects its predecessor and earlier, unqualified schema10
candidate layouts. Its initial-recipient extension is a pre-production reset
boundary, not a migration or an additional journal generation.
The [current source checkpoint](../testing/s01-idle-mailbox-floors-2026-10-09.md#original-public-store-outcome-source--dr-0106)
records qualification and remaining gates; it permits no known acquisition or
last retained Retrieve/ACK deletion.

## Used Deposit holder retirement — S01 source candidate

`DeepIdV2AccountService.RetireUsedDepositAcquisitionAsync(acquisition, source, ct)`
is a closed internal maintenance entry, not runtime activation. The service owns
the real verifier for the entire held epoch-exclusion/selection operation. No
caller clock, successor, SQL-count or terminal flag grants permission.

This implements a different disposition from object deletion: an independently
excluded **write holder** can retire after every original Store is positively
verified and its accepted-object/read/history/receipt dependencies remain in
independent, byte-exact custody. It does not wait for or shorten object expiry,
delete an object/read route, or synthesize recipient Delivered/Read. The
historical Store reader already verifies without any private Deposit holder;
all custody that reader consumes remains unchanged. Sole semantics are
[messaging §8.4.3](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#843-compaction-and-boundedness)
and [DR-0106](../../../docs/survival-program/decisions/DR-0106-retained-store-public-evidence.md).

The selected acquisition must be the oldest adopted phase2/5 Deposit in its
canonical chain. Pending, unresolved or unadopted links pin the chain; a later
winner cannot be selected around them. A remaining successor loses only its
local predecessor link; its seed, request/result, original policy/route and
current/tail selection remain exact. A sole acquisition removes its selection.
This structural helper is not a deletion capability.

Matching send work/floors, active read/ACK, read counter/traversal and ordinary
or attachment work pin selection. The owner then joins both directions:

- Stream all outgoing events, including compacted prefix history, from each
  independently verified relevant native session; include initial DPH2 through
  its actual protected draft/source rather than assume it is a direction1 row.
- Independently authenticate native/semantic/source, original public policy,
  grant/holder signature, exact MAU3/body, quorum and coordinator for each Store.
  Initial recipient DCR/ADP/route and ordinary/acceptance native peer routes are
  preserved, not reconstructed from the newest roster or grant journal.
- Stream every actual request for the selected holder/grant in bounded SQL pages
  and require its exact initialized native session and original Store binding.
  Missing/ambiguous evidence, unknown work, an empty result or orphan request
  pins selection. No lifetime-sized set or new128/512 capacity is introduced.

The existing ProtectedOnly plan stores one ReplayScope row, zero SQL effects,
the original eight root mappings and the mandatory unchanged MailboxStoreState
ninth guard. Only Grant changes. Complete application/native/history/device/
prekey/source/receipt custody is rechecked before staging and by cold recovery.
The existing private dispatcher distinguishes this nine-root used-Deposit
profile from the eight-root unused closed-Deposit profile; no reader guesses a
missing guard. Recovery rederives the exact oldest-acquisition successor before
commit/adoption and uses the shared CAS/parts/abort protocol without fresh
proofs, signing, transport callbacks or reissuing the request.

The matching targeted source packet passed65/0/0/native0; exact evidence is
in the [checkpoint](../testing/s01-idle-mailbox-floors-2026-10-09.md#used-deposit-holder-retirement--targeted-source-checkpoint).
The subsequent [actual chain-owner packet](../testing/s01-idle-mailbox-floors-2026-10-09.md#used-deposit-chain--actual-owner-checkpoint)
passed9/0/0/native0: two original Stores under distinct adopted holders,
oldest-first cold recovery, preserved successor custody and pinning by an
unknown successor send. Its signed selection setup uses the controlled producer
fixture; it does not qualify autonomous runtime renewal.
The [issuer-rotation/index packet](../testing/s01-idle-mailbox-floors-2026-10-09.md#original-issuer-rotation-and-actual-traversal-dependency-index)
additionally checks genuine root-signed issuer-key replacement for original
initial/acceptance Stores, refusal of current-policy substitution and preserved
original outcomes after cold holder retirement. It does not qualify independent
node receipt-key rollover or current issuance/renewal activation.
This candidate still requires matching full qualification; it
does not close remaining S01 traversal/last-path/rotation/sustained requirements,
activate the S04 scheduler, or qualify a physical client/release.
Generation4's layout/closure and original Store/read/ACK passed their own final
full source gate570/0/0; the exact receipt and source boundaries are recorded in
the checkpoint. The subsequent generation5 late-result/connected-consumer gate
completed575/0/0 terminal0 with all20 selected cases Passed and matching frozen
inputs. Its own exact receipt is recorded separately in the checkpoint. Neither
slice closes S01 or qualifies a signed installed client or physical transport.

## Superseded Retrieve holder retirement — S01 source candidate

`DeepIdV2AccountService.RetireSupersededRetrieveAcquisitionAsync(acquisition, source, ct)`
removes only the oldest adopted Retrieve acquisition after actual epoch exclusion
and its separate idle-counter retirement. It never removes a current/sole holder,
original route, capability, traversal, SQL request/outcome, semantic state or object.
Pending, unresolved or unadopted acquisition links, matching active read/ACK,
remaining old counters and unresolved ordinary/attachment work pin selection.

The live held owner opens the actual completed permanent publication, rechecks
private locator/capability custody and verifies the protected current successor
with the current retained-read host/PMA2. The replacement keeps the exact original
route and ranked node pair, has a distinct replay namespace, and must already be
installed with exact SQL grant/generation/scope/replica-key readback. Selection
cannot install or repair credentials, sign a request, allocate a counter, contact
an issuer or rerank a mailbox path. Its local installation policy is not native
MGR1 admission authority; node revocation/holder/replay checks remain mandatory.

Both original and replacement holders need positive completed owned-read custody.
The protected read journal must be idle and its original-scope traversal must
agree with SQL. Bounded SQL enumeration verifies each exact grant, holder-signed
request, operation/route binding and durable outcome shape. Each nonempty Retrieve
joins its exact ACK operation derived from scope/grant/request/page commitments;
missing or orphan ACK, unknown request or missing read custody rejects. MRSO/MCO1
remain SQL facts, not new independent quorum or application receipt authorities.
Semantic/native/history/source custody is independently checked and preserved
by the complete unchanged MailboxStoreState guard. No Delivered/Read is invented.

The existing nine-root ProtectedOnly plan changes only Grant and clears only the
immediate successor's predecessor link. Every other root and complete application/
native SQL stays exact. MailboxStoreState also binds the canonically decoded
publication journal and bounded resolver-capability custody digest; cold recovery
cannot proceed after loss/change of that original path, even with unchanged SQL.
Stored recovery rederives the same structural successor under unchanged guards,
without a fresh proof, network/signing callback or holder reconstruction. No new
wire, journal generation, compatibility reader or namespace tombstone is added.

This is same-original-path holder replacement, not retirement of a traversal or
the last retained path. Autonomous renewal/cleanup remains S04; source receipts,
matching full and remaining S01/physical/release status belong to the
[checkpoint](../testing/s01-idle-mailbox-floors-2026-10-09.md).

## Closed unused Retrieve retirement — S01 source candidate

`MailboxEpochExclusion.RetireUnusedClosedRetrieveAcquisitionAsync(ct)` removes
one actual phase3 closed-unresolved acquisition only after the held producer
independently passes its original possible-issuance ceiling and irreversible
native epoch exclusion. It does not assert non-issuance, successful reading,
BeforeForward or a remote terminal outcome. Pending/received/adopted winners,
linked candidates, counters, any original active read/ACK, traversal and unresolved
ordinary/attachment/native-session work remain pinned. The dependency capture
must contain only the conservative RetainedRetrievePath flag.

Selection discharges that one flag by reopening the exact actual completed
permanent publication, including an independently bound archived predecessor.
The original route bytes, private locator and owner Retrieve capability must
match the original protected XMG2. Current account/device/network/host/time
checks remain mandatory. Missing/corrupt/substituted custody rejects without
staging; no holder, request, publication, issuer result or SQL credential is
created or repaired during selection. Original publication and resolver-capability
custody remain independently guarded, so deleting this never-used holder is not
deleting the last retained-object path.

The existing nine-root ProtectedOnly plan changes only Grant, uses one exact
ReplayScope selector/commitment and preserves complete MailboxStoreState.
Recovery rederives the same phase3/domain-specific successor before commit/CAS;
eight-root closed-Deposit plans cannot select Retrieve. Original application,
native/history, device/prekey/source, publication, resolver custody and replay
fence stay unchanged. All existing handover/abort/parts guards apply without new
network authority or callbacks. No wire, generation, public API, tombstone set,
runtime scheduler or increased128/512 capacity is introduced.

The owned retained courier also loans the existing Protocol-minted
`VerifiedMailboxRetainedReadRequestV2` through its private dispatch context.
Only its byte-exact XMG2 can pass the retained projection prerequisite while
the three-hop ingress/relay/ContactResolve exit and service placement remain
current. The path provider rechecks the closed request/time capability before
guard access and after asynchronous guard writes; the real courier rechecks it
before HTTP forwarding and after reply authentication. A parsed historical PMT2,
request boolean or copied projection cannot bypass current-only placement.
Deposit and non-owned/public courier paths keep the current projection check.
This reuses DR-0100/0104 authority; it adds no Protocol API or wire allocation
and does not grant retained mailbox mutation, issuer success or deletion.

This closes a never-used excluded acquisition, not an original completed read,
known holder, traversal or last-path disposition. An independent current issuer
may subsequently create a new acquisition through the ordinary owned reader;
it cannot restore the retired expired response. Focused/full, sustained and
physical acceptance are recorded separately in the checkpoint.

## Explicit owned Retrieve successor — S01 source candidate

The internal `RenewOwnPermanentContactRetrieveGrantAsync(originalAcquisition,
source, transport, ct)` implements one explicit transition, not an autonomous
renewal policy or S04 scheduler. Its only caller input is the original XMG2 hash
selector. The owner reopens that acquisition and its exact completed permanent
publication (including an independently bound archived predecessor) under the
actual account lease. Current proof/network/host/time, private capability and
holder authority still come from their original closed owners.

The original must be an adopted Retrieve winner in the same scope. With current
and retained tail both naming it, renewal either creates one pending successor
or resumes that exact pending request. A closed-unresolved/late intervening tail
pins renewal. After promotion, retrying the same original selector returns only
its immediate adopted successor, with no further pending/tail continuation.
An absent original, Deposit, unrelated selector or advanced chain rejects before
request authoring. Ordinary acquisition keeps selecting current while renewal
is pending; it never implicitly adopts or forwards the renewal candidate.

The existing generation5 journal already encodes this predecessor/pending/current
transition. No layout, magic, Protocol public API or capacity change is added.
New signing occurs only before the pending request CAS/read-back. Lost reply,
cancellation and cold retry preserve the exact operation/window/holder. A current
host independently verifies the returned result before winner persistence;
selection and SQL installation remain separate existing read-back fences.
Retry after selection/SQL interruption installs the same winner without another
issuer call. Expired pending requests are not regenerated or silently discarded;
their existing explicit closure/reconciliation lane remains mandatory.

Original holder/request/result, publication/private path, read/traversal/counters,
send, native session and attachment custody remain retained. This transition
does not delete the original grant, complete a read/ACK/application receipt or
authorize last-path retirement. The superseded-holder fixtures now obtain their
replacement through this actual owner lane rather than directly staging the
protected journal. Targeted, full and physical qualification remain separate.
