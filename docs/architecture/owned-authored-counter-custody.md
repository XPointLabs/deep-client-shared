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

## Compaction dependency/API target (not runtime activation)

The sole semantics are the dependency-closed batch/recovery contract in
[§8.4.3](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#843-compaction-and-boundedness).
The following maps it to current consumers; it is not another outbox, an
implemented plan codec or permission to delete current rows.

| Current custody / consumer | Required integration consequence |
| --- | --- |
| `ProtectedDid2DirectTextJournal`, `ReconcileOwnedTextOutboxAsync` | Keep every authored floor. SQL currently requires each retained stable command row; coordinated outbox cleanup must replace this expectation only for exact selected dispositions, preserving separately verified history and receipt work. |
| `ProtectedDid2MailboxSendJournal`, `DeliverOwnedMailboxAsync` | Keep replay enrollment/high counters and original request/body/grant/ciphertext dependencies. Prepared is not settled. A verified ordinary Store phase does not authorize deleting unknown transport work. |
| `ProtectedDid2MailboxGrantJournal`, `MailboxEpochExclusion` | Pin original winners/acquisitions referenced by send/read/ACK or object horizons. Recheck held exclusion and complete dependency closure before committing a retirement fence; changed grant roots cannot be hidden behind their old digest. |
| `ProtectedDid2MailboxReadJournal`, owned Retrieve/ACK | Pin the active cycle through authenticated materialization, SQL outcome/traversal agreement and ACK completion. Keep counter/traversal floors even after clearing a cycle. |
| `Did2MessagingSqlJournal`, `Did2MessagingFloor`, session catalog | Current schema2 verifies all journal-bound events from the registered empty floor. Prefix cleanup requires an independently protected checkpoint and retained-history verifier; an SQL-only checkpoint or renumbered ordinal is forbidden. |
| Owned local-history/contact/acceptance consumers | Preserve `initial_events`, verified receive/send acceptance, peer bootstrap and catalog binding, or replace them through the same authenticated checkpoint contract. Deleting a ratchet journal row cannot silently invalidate a previously accepted contact. |
| Owned attachment journal/application store | Outbox-only payload/key disposition must not delete keys still required by a retained offer, transfer or local-history object. |

The target owner API has three responsibilities, under the same actual account
lease: capture/select an exact dependency-closed batch from real protected/SQL
custody; resume only its stored predecessor/successor transition; and prevent
ordinary mutation/projection from bypassing an active plan. There is no public
`CanDelete` setter, caller-supplied verified tuple, replacement clock or transport
callback. Parsed metadata is not the owned mutation capability.

Each batch names one database selected through the existing protected account/
scope registration, never a caller file path. Guards for other databases/roots
remain unchanged. One SQL transaction commits selected outbox cleanup plus any
required counters/dedup/history/receipt effects. Checkpoint cleanup of a ratchet
database is a separate batch, not an implied cross-database transaction.

Recovery classifies only exact before/after SQL and an ordered prefix of root
adoptions. It must verify complete effects, not counts or missing rows. Aborting
before SQL requires every predecessor unchanged; after SQL the same plan must
finish adoption before clearing. SQL rollback, foreign instance, missing root,
changed dependency or mixed non-prefix adoption rejects without repair. Neither
retry nor cancellation invokes a signer/encryptor or reconstructs deleted data.

Before S04 activation, the mandatory plan registration/closed local generation,
bounded byte layout, checkpoint/history commitments and exact owner API must be
implemented together with every affected reader. No optional missing-plan
fallback is authorized. Positive and hostile/fault fixtures must cover the
actual account, SQLCipher and protected storage, all handovers, cancellation,
cold reopen and capacity; codec-only fixtures cannot qualify deletion. These
APIs/layout and fixtures remain unfinished; this mapping does not close S01.

Contract review2026-10-06: normative source normalized SHA256
`42096b862e1d00e44f85d562acf76dc97b36772508c7f2201b00c45f637d2d77`.
Protocol repin changes only this source hash and its two derived registry
identities; allocations, all175 anchors and production inventory are unchanged.
Strict generator/registry checks pass; actual Protocol Release build has zero
warnings/errors. Focused registry/parity12/0/0 terminal0, independently mapped
to Passed in `artifacts/s01-compaction-contract-registry/s01-compaction-contract-registry.trx`
(Protocol-relative), SHA256
`8CEBFDCA1EE00DEFB921858281792CF00C2E38B1913225B6917377886AA112F3`;
start09:59:09.0349240+05, finish09:59:10.2355120+05.
Root documentation174 and governance helper22/0/0 pass. This is contract-only
evidence, not a fresh full Shared/package/installed or cleanup qualification;
the authored-floor591 receipt belongs to its own frozen Protocol4fa9f95 inputs.

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
