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
`SHA256(exact XMG1)`. This is the existing XMC2 tag5 request binding, not a new
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
| 100 | 435 | Exact original XMG1 |
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
Ceiling is recomputed from the exact evidence; request PMT2/PMS2, PMA2 reference,
route hash and network must match. A received winner cannot exceed that ceiling.
Phase3 retains exact holder/request/evidence with no winner; phases4/5 retain the
same closure proof with one immutable late result. Their closure lower bound
cannot precede XMG expiry. These checks establish custody shape, not current
or historical issuer/time authorization.

## Owned transitions and consumers

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

`AbandonUncommittedClosedAcquisitionRetirementAsync(ct)` permits only phase1
with all exact predecessors/guards intact, persisting the existing abort phase
before disposal. A committed phase2 cannot abort/reselect even before grant
adoption. Cancellation leaves the already-staged plan owning exact recovery.
Full profile qualification and the broader S01/S04 lifecycle/receipt/object
consumers remain unfinished. The focused encrypted-journal reopen fixture uses
its own protector, not Windows/Android platform custody. The focused
checkpoint records evidence separately; this implementation is not release
activation or a declaration that every replay namespace can be retired.

The acquisition runtime still creates only an initial candidate. The internal
closure entry is not autonomous scheduler activation. This layout does not
activate autonomous renewal/cleanup, historic read/ACK
or a longer object horizon. The narrow explicit held producer above removes only
an eligible closed unused deposit acquisition; no known grant/send/read entries
or replay floors are evicted and no128/512 bound is raised. Send/read independent
replay floors are unchanged. Their full lifecycle
contracts and the linked retention fence remain unfinished S01/S04/S05 work.

The expired/unknown semantic and retirement boundary remain specified only in
the semantic owner linked above, §8.4.2. Generation5 retains original evidence,
closed uncertainty and two-phase late adoption, not proof of non-issuance or an irreversible retirement
fence. No new network wire, magic, authority or public verification API is added.
The earlier generation3 receipt is historical evidence for its exact source.
Generation4's layout/closure and original Store/read/ACK passed their own final
full source gate570/0/0; the exact receipt and source boundaries are recorded in
the checkpoint. The subsequent generation5 late-result/connected-consumer gate
completed575/0/0 terminal0 with all20 selected cases Passed and matching frozen
inputs. Its own exact receipt is recorded separately in the checkpoint. Neither
slice closes S01 or qualifies a signed installed client or physical transport.
