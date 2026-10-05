# Owned mailbox grant custody — current local layout

Owner: Mr. X, delegated architecture authority. This is the Shared producer's
closed local serialization/API for the acquisition slice of S01. Semantic
transitions remain owned by
[TRANSPORT-NEUTRAL-MESSAGING §8.4](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#84-owned-attempt-settlement-renewal-and-retirement).
It does not allocate wire bytes, an algorithm, a network authority or a renewal
policy. Runtime/test acceptance is recorded separately in the
[checkpoint](../testing/s01-grant-acquisition-contract-2026-10-05.md).

## Serialization

The protected slot remains `deep.store.v2.mailbox-grant-journal`. Its sole reader
accepts local generation3; every earlier generation rejects, including empty
state. Existing incompatible test accounts require explicit reset. There is no
migration, fallback or initialization by a reader. Account creation is the sole
empty-state producer.

All integers are unsigned big-endian. The closed header is96 bytes:

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 1 | Generation3 |
| 1 | 1 | Zero flags |
| 2 | 2 | Acquisition count |
| 4 | 8 | Revision, at least acquisition count +1 |
| 12 | 16 | Exact nonzero network |
| 28 | 32 | Exact nonzero account |
| 60 | 32 | Exact nonzero account instance |
| 92 | 2 | Selection count |
| 94 | 2 | Zero reserved |

Then follow acquisition records, each1077 bytes, sorted strictly by
`SHA256(exact XMG1)`. This is the existing XMC2 tag5 request binding, not a new
hash domain. The identity is derived, not stored as a second mutable field.

| Offset within acquisition | Width | Field |
| --- | --- | --- |
| 0 | 32 | Existing route/locator/direction scope commitment |
| 32 | 32 | Exact nonzero independent holder seed |
| 64 | 32 | Exact nonzero route-closure hash |
| 96 | 1 | Phase1 pending request or phase2 received winner |
| 97 | 3 | Zero reserved |
| 100 | 435 | Exact original XMG1 |
| 535 | 510 | All zero for pending; exact successful XMC2 for winner |
| 1045 | 32 | Predecessor acquisition identity; zero only for first acquisition |

The last region consists of96-byte selections sorted strictly by scope:
scope32, current acquisition32, pending acquisition32. Zero means no pointer.
At least one pointer is required. Current references a winner. Pending may
reference an exact request or received winner and must name current as its
predecessor. Each predecessor is an immutable winner in the same scope; every
retained acquisition is reached exactly once from a selection/current chain.
Dangling, cyclic, cross-scope, orphaned or duplicate acquisitions/grants reject.
No selection is inferred from sort order, time, row count or SQL.

There are at most128 acquisitions; selections cannot exceed acquisitions. Exact
length is `96 + count*1077 + selections*96`, bounded by the closed maximum.
Unknown flags/phases, noncanonical counts/revision/order, trailing bytes, wrong
account instance, holder/request mismatch and response binding mismatch reject.
These checks establish custody shape, not current issuer/time authorization.

## Owned transitions and consumers

`AddPending` preserves an existing current winner and records one candidate with
its exact predecessor. It cannot replace another pending candidate. No callback
occurs before the account owner's protected CAS and exact read-back.
`WithWinner` changes only a pending record's phase/response. The actual owner
independently verifies the issuer/route/result before persisting it. A received
winner remains pending through a separate protected read-back and verification;
only then can `PromoteWinner` change current and clear pending. Promotion is a
separate CAS/read-back before SQL installation or returning usable authority.

Cold reopen of a received initial pending winner re-verifies and adopts that exact
candidate without reissuing. Installation interruptions recover the selected
winner; expired original requests are never re-windowed. Initial owner revisions
are empty1, pending2, received3, selected4. Revision is a protected transition
counter, not a derived replay floor.

Ordinary acquisition uses `AcquisitionForNewWork`: current if selected, otherwise
the initial pending candidate. A pending successor cannot replace current merely
because a new message/poll arrives; renewal adoption remains a separate owner
lane. `CurrentWinner` is used after that owned acquisition. `RequireRetainedWinner` searches the
selected winner and its retained predecessors by exact MCG3 hash and scope;
it excludes an unpromoted candidate. Missing original custody rejects.
Existing Store attempts, active Retrieve cycles and ACK pages use this exact
lookup, without a new acquisition or substituting the current winner. They still
require the ordinary actual route, issuer, holder, time, revocation and replay
checks; retained lookup does not authorize expired/historical transport.

The acquisition runtime still creates only an initial candidate. This layout
does not activate renewal, settlement, retirement/compaction, historic read/ACK
or a longer object horizon. No entries/floors are evicted and no128/512 bound is
raised. Send/read independent replay floors are unchanged. Their full lifecycle
contracts and the linked retention fence remain unfinished S01/S04/S05 work.

The expired/unknown acquisition evidence and retirement boundary are specified
only in the semantic owner linked above, §8.4.2. Generation3 does not yet retain
that original signed-policy ceiling or an explicit closed-unresolved disposition;
its two phases must not be interpreted as that settlement contract. No lifecycle
layout/API or runtime acceptance is claimed from the acquisition-slice receipt.
