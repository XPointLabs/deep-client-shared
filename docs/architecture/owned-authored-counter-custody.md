# Account-owned ordinary authored counter custody

Semantic owner: [TRANSPORT-NEUTRAL-MESSAGING §8.4.3](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#843-compaction-and-boundedness).
Local format/API decision: [DR-0098](../../../docs/survival-program/decisions/DR-0098-owned-authored-counter-floors.md).
This describes the current private Shared implementation, not wire authority,
cleanup activation, a semantic receipt, a new session or device qualification.

## One local reader and bounded layout

`ProtectedDid2DirectTextJournal` keeps the existing required protected slot
`deep.store.v2.direct-text-journal`. Its only reader is generation3; generations1/2
reject, including empty roots. No migration, initialization by a reader, optional
marker or compatibility path exists. Account registration creates the empty
current root atomically through the existing SQL-generation producer; application
registration3 and account/SQL generations are otherwise unchanged. Existing
accounts with prior text roots require explicit local reset, not a silent rewrite.

Header96: generation3:u8, reserved-zero:u8, entryCount:u16be, revision:u64be,
network16/account32/instance32, floorCount:u16be, reserved-zero2. The floor region
contains at most512 records of412 bytes: exact existing scope metadata404 and
next authored sequence:u64be. Strict sorting/uniqueness is by conversation32 +
local author device32 from the scope. Network/account/instance and role baseline
must match; the stored next value is above the role baseline and at most
`Int64.MaxValue`. A floor cannot silently move to another exact session scope.
The current single-session owner has no multi-device/session-rollover join here.

Entry prefix524 and its phases remain unchanged: pending1 retains the canonical
event; authored2 and verified-Store3 retain metadata only. There are at most512
entries and one pending payload of at most16668 bytes. Entries follow the floors,
sorted strictly by operation32. Maximum exact root is495996 bytes; bounds are
checked before copying. Unknown/reserved values, foreign scope, duplicate logical
position, missing floor, gaps within a retained sequence suffix, a suffix not
ending at `floor.next - 1`, or non-final pending position reject. An empty working
set can retain floors; it does not reset their counters or revision.

Revision starts at1 and advances on each protected pending, stable and Store
transition. It is no longer reconstructed from retained entry count. The decoder
checks its conservative minimum against reserved positions in the independent
floors, pending phase and retained Store completions. Historical completed
transitions can make revision higher than this minimum after compaction. A root
without any floors can only be the registered empty revision1. This shape check
does not prove that a parsed deletion or terminal disposition was authorized.

## Actual producer and SQL consumers

The account owner still independently verifies own/peer freshness, initialized
session, retirement and explicit responder acceptance under the actual writer
lease. Before authoring it checks both working-entry and new-floor capacity.
Only `State.AddPending` reserves the exact next position in that same root as
the original pending event. New work for an unused scope starts from the existing
role baseline; SQL never supplies a new value. Pending CAS has exact protected
read-back before SQL. Stable CAS and the final returned root have exact read-back;
Store adoption keeps its existing authenticated adapter/receipt guards.

`SqliteDeepMailboxStore.ReconcileOwnedTextOutboxAsync` checks all retained rows
against the protected events and every enrolled authored floor, even if that
floor has no remaining working rows. SQL counter is exactly the floor's next
value, except for the one exact pending event absent from SQL: only its preceding
counter is allowed before roll-forward. An unused initiator baseline may be
absent; the responder baseline still requires actual retained ContactAccept.
Once an authored position exists, missing/regressed/advanced SQL counters reject
without repairing them. No stable row is regenerated. Text, AttachmentOffer and
retries use one counter namespace and original canonical event.

Pending-text projection checks the initialized catalog for all floor scopes and
reconciles SQL even with an empty working set. Parsed scope metadata remains a
selector/fact, not independently current endpoint or signing authority.

## Remaining closure

There is no production cleanup, floor unenrollment, compaction plan or reset
method in this slice. Tests may model authorized removal in isolated SQL fixtures;
that is a counter-survival check, not deletion authority or a sustained delivery
qualification. Protected compaction-plan/predecessor recovery, terminal/audit
dispositions, messaging journal checkpoints, outstanding receipt work and
accepted-object/retained-route obligations must still close before S04 cleanup.
Capacity remains bounded backpressure; floors are not evicted to create space.
Local history, ratchet, inbox/dedup, mailbox grant/replay floors and remote objects
are not removed or extended by this change.
