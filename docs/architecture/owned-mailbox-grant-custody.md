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
accepts local generation6; every earlier generation rejects, including empty
state. Existing incompatible test accounts require explicit reset. There is no
migration, fallback or initialization by a reader. Account creation is the sole
empty-state producer.

All integers are unsigned big-endian. The closed header is96 bytes:

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 1 | Generation6 |
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
| 97 | 1 | Read-intent reservation: 0 never reserved, 1 reserved by the held read producer; 1 only for an adopted Retrieve winner |
| 98 | 2 | Zero reserved |
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
Generation6 consumes one previously reserved byte without increasing any size
or count bound. Before the first MAU signing/SQL reservation the actual read
owner durably saves its exact phase1 cycle, then monotonically records read-intent
reservation in that cycle's exact adopted grant and reads it back. Cold phase1
resumes this same sequence; later phases and ACK require the retained reservation.
It never clears with a standalone counter-floor retirement. Request, holder,
issuer response and original evidence stay immutable. The reservation means
possible use, not successful reading, non-delivery or authenticated settlement.
A reader cannot initialize, infer, set or repair it from SQL. No wire value,
public authority, extra journal/tombstone collection or compatibility reader.

A never-used superseded Retrieve consumer requires the original reservation to
be absent, no original counter/active cycle and zero exact original SQL requests,
plus the same independently verified current replacement, positive completed
replacement read/ACK, original private path and native namespace exclusion as
the used producer. Missing SQL after any reservation rejects; SQL absence alone
is never authorization. The current/last holder remains pinned. The existing
grant-only protected plan owns effect/recovery; deleting a grant is not deleting
its original traversal or accepted-object path. Qualification remains separate.
Normal maintenance processes at most one namespace pair per business call,
rather than multiple separate plans borrowing the same short freshness loan.
An expired/not-yet-live/old-issuer selected replacement is a pinned candidate,
not retirement authority or a crypto error swallowed after an effect. Numeric
interval/role hints can only defer cleanup; the actual producer still performs
all current signature, custody, completed-read and native/SQL guard checks.
When capacity permits, ordinary new-read acquisition can renew the selected
grant first. Full capacity still applies backpressure without losing custody.
New-work renewal also observes the existing operation's HTTP timeout+retry
window: a short grant can become unusable before its proportional refresh margin.
This scheduling hint cannot extend a grant or alter a pending/active request.
Ceiling is recomputed from the exact evidence; request PMT2/PMS2, route hash
and network must match. DR-0122 binds Deposit issuance policy to the actual
current projection while retaining the exact original logical assignment.
The ceiling uses the five signed logical route/resource intervals, never the
original PMT2 snapshot's short operational window. For Deposit it is capped
by that logical end and captured issuance policy expiry. DR-0104 Retrieve adds
the normative maximum retained-object horizon to that logical end, capped by
its current acquisition policy expiry. This is a
custody ceiling only, not a TTL extension or issuance/admission permission.
A received winner cannot exceed that ceiling. Epoch exclusion must authenticate
its captured issuance PMA2 against an exact retained PMT2 naming that policy,
and separately authenticate the original route PMT2 against its own named PMA2.
The source retains only bounded owned public record lookup inputs; each exact
pair passes the existing current host's strict historical namespace verifier.
Lookup bytes are not a verified cache or authority. Missing/changed records
reject before effect. Both roles authenticate the captured issuance policy and
the original assignment policy through their exact retained projection joins;
neither historical fact admits a new Store or read. Current Deposit acquisition,
SQL installation and Store dispatch independently bind the winner's policy to
the exact CURRENT projection and retain all logical-route time/holder checks.
The issuance ceiling and all native/dependency/replacement-read guards remain.
When the captured issuance policy already is the route projection's named policy,
the same strict pair supplies both facts; redundant distribution lookup is not
required. This is not a fallback or an alternative policy reader. Distinct
namespaces still require both exact joins and reject missing lookup inputs.
This is a Shared consumer correction, not a wire/API/journal generation change.
This changes evidence validation in the sole current reader; an incompatible old nonempty record
rejects, without a second reader, a migration or automatic reset.
Protected network and directory floor validation uses the existing atomic
inventory batch for its related current/future markers. Each call independently
reacquires its snapshot and preserves every marker/anchor/rollback check; no
retained plaintext or authority cache is involved. [Source receipt and scope](../testing/s05-protected-floor-batch-2026-10-16.md).
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

The S04 publication-owner candidate triggers renewal from authenticated original
XRA1/DCB1 intervals and independently current upper time, using the proactive
policy owned by [CONTACT-RESOLVER](../../../docs/architecture/CONTACT-RESOLVER-V1.md).
The earliest signed interval controls the trigger; conservative integer rounding
does not extend any interval. Pending successor work is resumed first and never
replaces current until the existing complete protected promotion. This does not
activate automatic grant renewal, rotation or retirement; current verification
status belongs to the [S04 checkpoint](../testing/s04-lifecycle-2026-10-11.md).
The day-long initial-service cap exposed a DCB successor rejection during this
existing route renewal. [DR-0127](../../../docs/survival-program/decisions/DR-0127-capped-contact-object-successor-validity.md)
owns the corrected predicate; Shared adds no alternative author, journal or retry.
The signed default-service regression failed at ContactSuccessorAdvance before
the Protocol correction (`s05-capped-contact-renewal-20261016/red-02` and
`red-03`); `red-01` instead failed its fixture DTS boundary and is not the product
reproduction. Corrected source `green-04` passed1/0/0/native0, and expanded
`shared-05` passed6/0/0/native0, including equal-cap owner/issuer publication,
retained predecessor and exact cold replay plus the existing renewal fault cases.
All use Windows PowerShell5.1 / SDK10.0.301; full and matched-device acceptance
remain open. No service expiry/key replacement or account reset was performed.
Superseded-holder selection likewise opens the actual acquisition's original route.
Current host/proof/time, holder, SQL and native checks are unchanged. A new idle
cycle chooses one least-polled route among the actual current and independently
bound archived permanent publications, using existing protected traversal poll
generations. Active original work always takes precedence. One page per call
keeps the existing bounds; absent traversal metadata is not absence of objects,
and no route/grant is evicted or reminted. This owner selection does not introduce
a background scheduler or dependency-closed retirement.

New owned Retrieve pages request at most two events, keeping native per-event
replication/ACK work inside the existing unchanged transport deadline. The
closed read owner still accepts its already captured exact requests/pages up
to eight events: pending original Retrieve/ACK work is never resized, reminted
or treated as absent. Each call still processes one page; `HasMore` describes
its actual authenticated continuation. The CLI three-client driver drains at
most four successful pages, stopping immediately on any failed/unknown result
or non-final page without durable progress. This is pagination after successful
ACKs, not an error retry, cursor projection or deadline extension.

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

Store dispatch carries only a conservative upper-time floor captured while the
private signing/preparation clock was live. It does not keep that clock as a
dispatch dependency. The new signer-free dispatch scope independently checks
its own bounded lifetime, current authority, held lease and all original grant/
route expiries; its clock cannot rewind below the captured preparation floor.
Both the fresh upper bound and the captured floor advance by the ceiling of
dispatch elapsed time. Keeping the captured floor constant would pause its
clock when the fresh sample is lower, potentially crossing an original expiry.
An expired preparation still rejects before opening dispatch, and expiry or
lost confirmation after ingress remains unknown with the exact request retained.

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
lane. Under [DR-0126](../../../docs/survival-program/decisions/DR-0126-independent-grant-after-unresolved-acquisition.md),
a scope with only authenticated closed-unresolved history may append an
independent new-work acquisition. Every old row remains linked and counted;
an unadopted late candidate requires its existing exact recovery first.
`CurrentWinner` is used after owned
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
actual instance and byte-exact grant root. The current generation6 decoder
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
strict epoch advance and exact historical namespace continuity have one owner:
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
Application schema11 rejects schema10 and earlier layouts. The same original
public-evidence table now separates native operation from attempt identity:
`(scope_hash,attempt_id)` is its primary key, `native_operation_id` is an immutable
association checked on read/write, and `(account_scope,logical_id)` cannot alias
another attempt. Every first attempt uses its actual native operation as its
attempt ID; a linked successor keeps the native operation but uses its own ID.
The held owner obtains the writer's ID from mandatory current protected prepared
custody, exact native ciphertext and the independent reserved counter floor.
Neither SQL association, a parsed descriptor nor these original records is
positive Store/dispatch authority. The historical Initial/ContactAccept/ordinary
reader now selects bounded candidates across attempts, rejecting an unlinked SQL
candidate while the protected chain exists and checking missing attempted
evidence even after discovering a possible Durable result. It independently
verifies the selected native/signature/quorum/coordinator binding and repeats
exact evidence/root checks; selection alone never reports success. Interrupted
ordinary completion uses that selected prepared attempt/floor/acquisition.
It does not discard predecessor/successor uncertainty or authorize dependency
retirement. New successor dispatch, changed-route custody and linked cleanup
still require their connected producers/consumers and matching gates.
This is a pre-production reset boundary in the same SQLCipher database, not a
migration, another runtime reader or extra journal slot.
The [current source checkpoint](../testing/s01-idle-mailbox-floors-2026-10-09.md#original-public-store-outcome-source--dr-0106)
records qualification and remaining gates; it permits no known acquisition or
last retained Retrieve/ACK deletion.

## S04 new-work namespace maintenance — source candidate

The existing owned new-authoring capacity gate, new Initial/ContactAccept draft
and idle mailbox reader invoke private `MaintainMailboxNamespacesUnderLeaseAsync`
before new mutation/acquisition. Existing authored/native exact retries bypass
maintenance; captured active read/ACK makes it return without retirement effects. Ordinary working-set cleanup
remains its separate producer. Maintenance uses a bounded batch with the existing
plan row bound, re-reading actual roots after every transition; it never raises
128/512 limits or starts another background scheduler.

The same new-work entry first applies the existing expired-acquisition closure
under its already-held account lease, without recursive acquisition. A protected
active read/ACK bypasses this step too. Only independently authenticated lower
time reaching the original request expiry may close a pending candidate; the
original request, holder seed, route, policy and possible-grant ceiling remain.
The ordinary epoch/dependency-closed retirement selection then rereads actual
roots. Request expiry alone still cannot retire the old namespace. DR-0126 permits
an independent new-work authorization while retaining that exact uncertainty;
it never reissues the original request or replaces a prepared transport attempt.
Only the complete exclusion/dependency-closed retirement producer can remove an
eligible closed unused holder. Before/after closure failure stops new work; cold retry reads the actual
pending/closed root. No journal layout, generation, bounds, grant/request lifetime,
wire or signature change is introduced by this composition.

The 2026-10-15 focused run `artifacts/s05-current-publication-20261015/pending-maintenance-focused-01`
passed6/0/0/native0 with actual SQLCipher/native custody; the affected grant,
renewal and retirement regression in `pending-maintenance-regression-01` passed
48/0/0/native0. These are source diagnostics, not canonical full qualification or
proof that an installed retained device has satisfied its exclusion prerequisites.
The unconditional new-work refusal in that checkpoint is superseded by DR-0126.
The matching `independent-grant-focused-03` passed16/0/0/native0 and
`independent-grant-regression-01` passed58/0/0/native0 with actual SQLCipher/native
custody. They cover independent Deposit/Retrieve holders, exact pending replay,
late-original non-overwrite, reply/CAS/cold handovers, expired-route rejection,
and the unchanged128-entry bound rejecting before issuer/read callbacks. The
capacity fixture's signed closed metadata is not remote non-issuance evidence.
The first new capacity-fixture build failed on a test argument type; its receipt
is retained as `independent-grant-focused-02`, not a product/runtime failure.
Source diagnostics are not canonical full or installed-device qualification.
Mixed closed/adopted predecessor retirement remains a release blocker: current
closed-tail retirement does not reclaim such ancestors. No eviction, reset or
bound increase is permitted to hide that missing lifecycle qualification.

`MailboxEpochExclusion.OpenUnderLeaseAsync` loans the actual held lease/current
account to the same original-policy/current-host/native-DNH2 verifier. Only the
standalone opener owns their lifetime; disposing a loan cannot release its
business caller's lease or dispose its account. Selection timestamps, pure
structural eligibility and positive SQL presence are scheduling hints, not
verification or deletion authority. SQL absence skips this maintenance lane;
it never authorizes holder deletion. After selection every original verification,
dependency guard and recovery plan remains independently mandatory. IO,
corruption, cancellation and plan faults are not swallowed as ineligible work.

Known used Deposit holders and superseded Retrieve holders retire through their
existing oldest-first owners after separate idle-counter disposition. Current/
sole Retrieve and original publication/read paths remain. The first replacement
read is permitted to establish positive coverage before superseded-holder cleanup;
SQL credential installation alone does not qualify it. Existing sole closed-unused
Deposit and sole/linked closed-unused Retrieve dispositions use their own complete
guards; unresolved links cannot borrow the used-holder profile. Known winners
without any original transport work remain pinned in this candidate, not treated
as successful Store/read or negative remote issuance.

Fault after a floor effect leaves it retired under irreversible exclusion, while
the holder and original SQL remain independently verifiable. Cold retry resumes
the actual staged plan before new work, then reselects from current roots. Missing
floor alone cannot grant deletion: the actual holder/native/public/SQL closure
still runs. No new journal, layout, wire, receipt, repaired counter or clock
authority is added. Final source/physical acceptance is owned by the S04 checkpoint.

## Used Deposit holder retirement — S01 source candidate

`DeepIdV2AccountService.RetireUsedDepositAcquisitionAsync(acquisition, source, ct)`
is a closed internal maintenance entry, not a scheduler or shipping activation. The service owns
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
- One native operation may own several original Store attempts after a permitted
  successor. The owner joins every bounded public attempt to the same actual
  native ciphertext and independently verifies its original request, policy,
  replicas, quorum and coordinator; Initial recipient evidence is checked for
  each sibling. A verified predecessor is not evidence for its successor.
  `IsOriginalStoreForGrantRetirementAsync` receives both actual operation and
  attempt selectors and supplies exact-grant membership only after that
  verification. Verification does not stop at the first matching grant. This
  also applies after working send-chain compaction; all original public/SQL
  attempts remain, and missing or unknown sibling evidence pins retirement.
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
non-tail/intervening candidates, any original active read/ACK and unresolved
ordinary/attachment work remain pinned. The sole never-used acquisition profile
allows only the conservative RetainedRetrievePath flag. Its linked renewal-tail
extension is specified below; it never deletes a selected holder or traversal.

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

The original must be an adopted Retrieve winner in the same scope. Renewal
either creates one independent pending successor or resumes that exact pending
request. DR-0126 permits intervening closed-unresolved rows without removing them;
an unadopted late result still pins new scheduling. After promotion, retrying the
same original selector returns only the adopted successor whose intervening
predecessors are all closed-unresolved, with no further pending/tail continuation.
An absent original, Deposit in this explicit Retrieve lane, unrelated selector
or advanced chain rejects before request authoring. The explicit Retrieve
acquisition API keeps selecting current while renewal is pending; it never
implicitly adopts or forwards the renewal candidate.

The current journal already encodes this predecessor/pending/current
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

### S04 automatic new-work consumer — source candidate

The ordinary Deposit acquisition owner and a new phase0 mailbox read invoke the
private `SelectNewWorkMailboxGrantRenewalUnderLeaseAsync` selector. It reads the
actual adopted current winner, rechecks the actual grant root around independently
current own proof/time and uses the trigger owned by
[TRANSPORT-NEUTRAL-MESSAGING §8.4.2](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#842-grant-and-route-transitions).
These protected timestamps are scheduling custody, not a current-grant proof.
Successor request authoring, issuer/route/host checks, winner verification, SQL
installation and final currentness remain independent and mandatory.

The existing internal acquisition selector also admits an explicitly closed
Deposit direction for this owner; the explicit Retrieve method stays Retrieve-only.
Each new acquisition retains its immutable original and protected predecessor.
Pending work resumes its same XMG2; DR-0126 keeps closed uncertainty linked while
allowing a distinct independent new-work grant. Unadopted late work still pins
the scope until its exact owner recovery completes.
Selection changes only after exact successor verification/read-back. A cold retry
after promotion installs that selected winner without another acquisition.
There is no new local generation, wire, public selector or legacy reader.

Prepared Store attempts and active read/ACK cycles never enter this scheduling
lane; they keep their exact retained grant/request. Full new-work capacity checks
account for a required successor, rather than treating a due old winner as a free
slot. Missing custody and exhausted bounds reject without regeneration, eviction,
increased limits or unsigned expiry. A new-read owner checks its exact protected
read root before grant acquisition: active work cannot enter this lane; a new
counter or traversal must fit before signing/issuer callback. The traversal scope
uses the retained route hash, blinded mailbox and selection epoch, exactly as the
actual SQL reader does. Existing exact scope/counter reuse remains possible at a
full bound; a full journal is not blanket permission to block retained work.
No retirement, rotation or autonomous worker
is activated by this source increment; qualification remains in the
[S04 checkpoint](../testing/s04-lifecycle-2026-10-11.md).

## Closed unused renewal-tail disposition — S01 source candidate

The same internal `RetireUnusedClosedRetrieveAcquisitionAsync` may remove one
closed phase3 renewal tail when its direct predecessor is the exact selected
adopted Retrieve winner. Pending must be absent, retained tail must name that
closed candidate, and original route/locator/private capability must match the
selected predecessor. Intervening unknown/late work or a non-tail selector
rejects. The actual held original ceiling/native epoch exclusion is still
mandatory; expiry of XMG2 alone cannot authorize this disposition.

The linked producer discharges AcquisitionChain by preserving the complete
selected predecessor chain and changing only its retained-tail pointer back to
current. Original publication/private read custody remains mandatory. Original
read journal must be idle. When a traversal exists, it must match independent
SQL, and bounded enumeration requires positive settled original Retrieve/ACK
coverage; pending/unknown/orphan ACK rejects. A native semantic dependency
without that completed original read is pinned. Complete source/native history,
consent, application receipt obligations, SQL and read/send counters remain
byte-exact under the existing ninth guard. No native/session, traversal, selected
grant, payload, receipt work or accepted-object path is deleted.

This extends only the existing nine-root ProtectedOnly/Grant/ReplayScope shape.
Cold recovery rederives the sole-or-linked structural successor from actual
predecessor custody before commit/CAS; no supplied linked flag, new layout,
generation, wire, Protocol API, tombstone or callback is added. Clearing the
closed candidate is not a remote non-issuance assertion or a successful read.
Once recovered, the explicit owner may create a new independently current
request on the same original path, never revive the discarded expired request.
All existing prefix, guard, parts, cancellation and phase1-only abandonment
rules remain in force. Runtime scheduling and final S01 acceptance stay gated.

Native-committed contact projection uses the read-only historical metadata/route
checks owned by CONTACT-AND-GROUP and DR-0072, independently of this grant
disposition. First ContactAccept send/receive instead checks the exact retained
Hello, current endpoint/XUR metadata and current full route before committing
its native mutation. An expired first attempt cannot create native history and
then recover through the historical reader. Actual native exact replay skips
fresh admission and retains its original event/hash; held lease and final
native readbacks remain mandatory. This changes no journal generation or API.

## Explicit contact retry stop — consumer mapping

The existing account-bound `CancelOwnInitialContactAsync` is publicly callable
by the UI adapter with its independently current contact-path authority source.
Its held-lease stop, native/pre-session distinction, idempotent crash recovery,
key/payload retirement and preserved outcome/audit floors are unchanged.
`ListContactStartOperationsAsync` now projects read-only `IsStopped` from the
actual protected draft; it never supplies stop or new-send authority. Consumers
must not select a stopped original for retry. A separate explicit user command
may create a different intent after confirmed stop; neither stop nor expiry
proves remote noncommit. No wire, schema, journal generation or expiry changes.

## Joint archived read-path disposition — qualified source profile

`MailboxEpochExclusion.RetireArchivedReadPathAsync(ct)` is an internal held
owner transition, not a runtime scheduler or public deletion authority. It
selects exactly one phase7 archived permanent publication, independently bound
to this account's promotion intent. The current permanent entry cannot be
selected and remains byte-exact. Pending publication work pins selection.

The producer requires independently protected epoch exclusion for every
original adopted Retrieve winner, its original possible-issuance ceiling and
matching private locator/capability. Each scope must have one selected winner,
no pending/unknown/intervening predecessor; its exact SQL credential and
positive completed original Retrieve/ACK coverage must exist. An idle protected
traversal must agree with SQL. Active reads, ordinary/attachment work and sends
on the original path pin disposition. The producer conservatively waits until
original XRA1 expiry plus the existing maximum object TTL; short Retrieve-grant
expiry does not shorten accepted-object retention. Actual source/native roots,
history, consent and replay exclusion remain mandatory under the live lease.

The private plan uses the existing framing/part bounds and one closed new
Application profile. Local root kinds13/14 and disposition5 are not wire values.
The ordered roots are Ordinary, Send, Grant, Read, SessionCatalog, Attachment,
AccountRegistration, NativeFence, ContactPublication, MailboxLocalCustody.
Only Grant/Read/ContactPublication change, in that order. ReplayScope rows here
select exact MCG3 digests and commit exact acquisition entries; one final
RetainedPath row selects the original route hash and commits the archived entry.
Other profiles cannot borrow these kinds/action. SQL selector is the original
route hash. No bounds, namespace aliases or compatibility readers are added.

MailboxLocalCustody has its own domain/selector and guards all source/native
custody from MailboxStoreState except publication and application SQL: those
have independent exact before/after effects in this joint profile. Root12's
complete unchanged semantics are preserved for existing profiles. Root14 still
binds registered device/prekey SQL, resolver capability, contact drafts,
preclaims, initial-key custody, the complete native catalog, authenticated
history/tip, floor and peer records. It cannot stand in for application SQL.

Read-only virtual SQL omission predicts the exact complete successor before
staging; no delete-and-rollback preview is used. Mutation deletes only selected
credential scopes/epochs/grants/replay counters and original traversal/poll
clock. Inbox, dedup, quarantine, history, terminal attempts, exact prepared
transport requests and application receipt work remain. The complete SQL
successor is rechecked inside the transaction before commit. Grant/read/archive
successors remove only exact selected custody; the cursor is never removed
while its original private publication remains independently pollable.

Cold recovery rederives all three successors from actual predecessors before
SQL. SQL may be exactly-before or exactly-after; adopted roots must form a
contiguous ordered prefix. Remaining read adoption derives its scope from the
still-original publication, not an already deleted acquisition. Fully-after
recovery authenticates successor parts against the concatenated actual adopted
roots; explicit before-SQL abandonment regenerates them from unchanged actual
predecessors. Missing parts are legal only at that verified finishing boundary.
No signing, network callback, current proof fetch, re-encryption or repaired
root is a recovery step. Cancellation after SQL cannot abandon the plan.

The current DR-0108 source authenticates the original namespace under its actual
retained ancestor, while independently requiring a current host and native epoch
exclusion. Actual empty/nonempty owner fixtures reach the object horizon using
genuine signed head/view and DTS1/XNA1 successors, never enlarged validity windows
or an expired current authority. The nonempty case completes a non-final
Retrieve/ACK page and preserves its actual cursor/token and native accepted
contact through disposition/replay. Cold/cancel handovers, missing dependency
refusals and exact SQL/protected readbacks are included in the matching accepted
Shared full895/0/0. Model tests alone are not deletion authority. Exact native
exits, unchanged-input proof, prior FAILs and the remaining whole-S01 review are
owned by the [checkpoint](../testing/s01-idle-mailbox-floors-2026-10-09.md#matching-full03--current-shared-source-qualified).
This source profile does not activate the S04 scheduler or qualify production,
physical clients, shipping packages or a release.

## S04 known Deposit without original transport work

The transition authority remains solely
[TRANSPORT-NEUTRAL-MESSAGING §8.4](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#84-owned-attempt-settlement-renewal-and-retirement).
The existing held epoch-exclusion consumer now covers an adopted Deposit winner
that was never used. Maintenance's SQL-existence query selects only a candidate;
it cannot authorize cleanup. The private owner independently traverses complete
protected native outgoing history, verifies every original attempt/route/MAC,
and checks the reverse exact-grant SQL/native join. Missing SQL for genuine
native work rejects. Native and SQL selected-work observations must agree.
The used producer still requires positive original work; the unused producer
requires none. No counter is removed before selecting the unused producer.

Both use the existing protected-only adopted-acquisition plan, complete mailbox
state guard and exact cold recovery; no table, wire, reader generation, journal,
bound or public capability is added. Original Store evidence/history and accepted
objects are preserved even when another holder's never-used successor retires.
Known unused Retrieve and archived-path automatic consumption are separate
S04 joins, not granted permission by this Deposit consumer. Their current
consumers and source qualification are described below.
Exact local native cases and preserved compile failure are in the
[lifecycle checkpoint](../testing/s04-lifecycle-2026-10-11.md#known-unused-adopted-deposit).

## S04 automatic archived-path maintenance — focused source qualification

The new-work maintenance owner invokes the existing joint archived-path producer
before unrelated counter/holder maintenance, under the same actual account lease.
The transition contract remains solely TRANSPORT-NEUTRAL-MESSAGING §8.4 and the
joint profile above. The scheduling selector skips current/pending publications,
active reads, working ordinary/attachment/original sends, incomplete acquisition
chains, missing completed traversal/floors/SQL hints and an outstanding original
object horizon. These checks select candidates, never authorize deletion.

The actual producer independently reopens original private publication/capability,
all selected grants and positive completed Retrieve/ACK coverage, current authority
and native namespace exclusion, and stages its existing application-SQL/three-root
plan. No effect error is swallowed. After one transition maintenance reloads all
actual roots. Ordinary new read resumes a stored plan before acquiring or forwarding
another request and then polls the remaining current path. The last current path,
original native contact/history/ACK and other custody survive; no synthetic receipt,
new journal/wire/API/generation, bound increase or background worker is introduced.

Matching native cases verify ordinary reads, early-retention refusal and all eight
cold handovers. The preserved fixture FAIL and actual elapsed-time correction,
exact receipts and source/physical scope are in the
[checkpoint](../testing/s04-lifecycle-2026-10-11.md#automatic-archived-path-consumer).
This is not whole-S04, deployed/runtime package or Windows/Android qualification.

## S04 never-used superseded Retrieve — focused source qualification

The generation6 reservation above is actual possible-use custody, not a signed
terminal outcome or supplied deletion flag. The normal reader checks it against
existing protected counters/active cycles before acquisition, SQL installation
or cycle mutation. Phase1 cold recovery preserves the original body and completes
the same reservation sequence before MAU signing; later phases and ACK cannot
repair a missing reservation. An installed but not-yet-read replacement remains
an ordinary unfinished prerequisite, not corrupted completed custody.

Maintenance invokes the private never-used superseded producer only after actual
replacement SQL work exists. The common held producer independently requires
zero original read reservation/counter/active work and exact zero original SQL
requests, positive settled replacement read/ACK, current installed replacement,
same private publication/path, current authority and native epoch exclusion.
The SQL hint and complete read coverage select the exact grant, not merely its
holder, so holder reuse is not a second grant's work. Other signed holder requests
are not reclassified as this grant's completion. The used producer still requires
its original reservation and positive original coverage. Missing used SQL after
floor retirement rejects before any plan/new read effect.

The existing grant-only protected plan removes only the exact old acquisition
and preserves replacement, traversal, original object path, complete SQL/native
history and other roots. Staging/adoption/parts/plan interruptions use its existing
encrypted cold recovery. The current/last holder still cannot retire; a fresh
replacement credential alone cannot authorize it. No new journal, bound, wire,
public authority or background scheduler. Exact affected23/native receipts,
preserved connected43 FAIL and current-source limitations are owned by the
[checkpoint](../testing/s04-lifecycle-2026-10-11.md#never-used-superseded-retrieve).

## S05 expired active Retrieve — source candidate, not device acceptance

[DR-0133](../../../docs/survival-program/decisions/DR-0133-expired-owned-retrieve-attempt-closure.md)
owns the uncaptured-attempt closure allocation; transport-neutral transitions
remain the semantic owner. `ReconcileExpiredUncapturedReadUnderLeaseAsync` runs
before ordinary namespace maintenance. It joins actual protected publication,
original holder/acquisition and native SQL with current authenticated lower time,
then preserves the original request as closed-unknown before allowing ordinary
independent new work. The Protocol historical check returns no live credential.
Closed attempts pin grants, floors and archived paths; capacity is backpressure,
not permission to evict them. Captured-page and ACK recovery are separate scopes;
the current final-page continuation is described below, not by this producer.

The current source receipts and remaining acceptance work are recorded in the
[focused checkpoint](../testing/s05-expired-active-retrieve-2026-10-16.md).
No account reset, old-frame renewal or physical delivery claim is implied.

## Current final-page ACK continuation

[DR-0158](../../../docs/survival-program/decisions/DR-0158-expired-prepared-final-ack.md)
owns admission closure and current successor ACK; do not duplicate its grammar
here. Rebuild consumers together: an older binary refuses the new private
continuation states instead of interpreting them as ordinary pending work.
No user/account reset, new storage slot or compatibility reader is required.
Original signed SQL requests, page, ratchets and counter floors remain pinned.
Closed capacity is backpressure, never eviction. Known durable replies and
non-final pagination are not reclassified as unknown prepared final ACKs.

The endpoint-set acquisition retry is pre-ACK only: discard the entire unused
set, acquire fresh own plus every peer once, and repeat all current checks.
It cannot retry an effect or retain half of an old set. Source tests and real
retained CLI evidence are separate from full/package/device acceptance; see
[the CLI checkpoint](../../../deep-cli/docs/testing/cli-atomic-reservation-2026-10-20.md).
