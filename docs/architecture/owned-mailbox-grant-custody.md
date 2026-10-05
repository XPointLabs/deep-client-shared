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

The acquisition runtime still creates only an initial candidate. The internal
closure entry is not autonomous scheduler activation. This layout does not
activate renewal, retirement/compaction, historic read/ACK
or a longer object horizon. No entries/floors are evicted and no128/512 bound is
raised. Send/read independent replay floors are unchanged. Their full lifecycle
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
