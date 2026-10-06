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

When an ordinary working entry is absent, `PrepareDirectAuthoredAsync` reads the
actual native committed operation against the reconciled protected stable floor
before capacity checks, authored reservation or SQL materialization. A retained
operation rejects instead of minting a new logical event or reconstructing its
working payload. This covers the same exact session scope while native event
custody remains verifiable; it is not a namespace-retirement fence or permission
to remove that custody. The [focused replay receipt](../testing/s01-authored-counter-floors-2026-10-06.md#outbox-replay-prerequisite--focused-only)
is separate from the earlier full-qualified counter-floor input.

Pending-text projection checks the initialized catalog for all floor scopes and
reconciles SQL even with an empty working set. Parsed scope metadata remains a
selector/fact, not independently current endpoint or signing authority.

## Compaction dependency/API target (not runtime activation)

The sole semantics are the dependency-closed batch/recovery contract in
[§8.4.3](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#843-compaction-and-boundedness).
The following maps it to current consumers; it is not another outbox or
permission to delete current rows. The narrow held messaging-prefix owner
described below is implemented; the other dispositions are still targets.

| Current custody / consumer | Required integration consequence |
| --- | --- |
| `ProtectedDid2DirectTextJournal`, `ReconcileOwnedTextOutboxAsync` | Keep every authored floor. SQL currently requires each retained stable command row; coordinated outbox cleanup must replace this expectation only for exact selected dispositions, preserving separately verified history and receipt work. |
| `ProtectedDid2MailboxSendJournal`, `DeliverOwnedMailboxAsync` | Keep replay enrollment/high counters and original request/body/grant/ciphertext dependencies. Prepared is not settled. A verified ordinary Store phase does not authorize deleting unknown transport work. |
| `ProtectedDid2MailboxGrantJournal`, `MailboxEpochExclusion` | Pin original winners/acquisitions referenced by send/read/ACK or object horizons. Recheck held exclusion and complete dependency closure before committing a retirement fence; changed grant roots cannot be hidden behind their old digest. |
| `ProtectedDid2MailboxReadJournal`, owned Retrieve/ACK | Pin the active cycle through authenticated materialization, SQL outcome/traversal agreement and ACK completion. Keep counter/traversal floors even after clearing a cycle. |
| `Did2MessagingSqlJournal`, `Did2MessagingFloor`, session catalog | Current schema3 verifies the retained suffix from its mandatory protected history basis, plus the committed retained-event prefix. Lifetime ordinal/ratchet generation do not reset. An SQL-only checkpoint or renumbered ordinal is forbidden. Actual prefix disposition still requires the held plan owner. |
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
cold reopen and capacity; codec-only fixtures cannot qualify deletion.
The envelope/readback model, mandatory registration/protected staging, history
registration, schema3 checkpoint reader and actual held prefix owner are
implemented in working source. Complete producer/consumer qualification,
other dispositions and retained-object closure remain unfinished. This mapping
does not close S01 or activate S04 runtime cleanup.

The existing registration/reopen join is
`SqliteDeepIdV2AccountGeneration.EnsureAsync`: creation atomically writes the
account SQL key/instance and required protected roots in one storage batch;
reopen reads and validates those roots without filling missing ones. Mandatory
plan registration belongs in that same producer, not a later optional marker.
`ProtectedDeepIdV2AccountOwner.ReadCurrentAsync` now resumes the exact stored
prefix under its actual lease before calling the registration verifier and
receiver reconciliation. Other ordinary under-lease opens still require an idle
plan; they fail closed rather than bypassing active recovery. Existing explicit
reset purges the V2 storage namespace; staging is not a separate reset bypass.

## Local plan envelope and successor custody

`Did2CompactionPlan` is private S01 metadata and a structural readback model.
The working registration producer now inserts `deep.store.v2.compaction-plan`
atomically with the existing account instance key and mandatory roots. Reopen
requires its exact current scope and idle phase before receiver reconciliation
or ordinary account projection. Missing/foreign state rejects without reader
initialization; startup resumes only the installed exact prefix profile. Existing
account/SQL/application record layouts are unchanged; accounts missing this
mandatory root require explicit reset, not a migration. Model factories do not
write storage, delete SQL, authorize a namespace, initialize a missing slot or
bypass the protected history/suffix reader. There is one generation1
grammar, no old reader, protocol/wire allocation, network call or crypto provider.

Header264: generation:u8, phase:u8 (0idle/1prepared/2SQL-observed/
3abandoning-before-SQL), SQL target:u8,
rootCount:u8, rowCount:u16be, reserved-zero2, revision:u64be, network16/account32/
instance32, nonce32, SQL selector32, SQL predecessor32/successor32, successor
bundle hash32, bundle length:u32be, partCount:u8, reserved-zero3. SQL targets are
application1, transport2, messaging3 and protected-only4; the last has no SQL
effect and both SQL digests are zero. Other active targets require distinct
nonzero before/after digests. Idle retains its monotonic revision and clears
every active field. Revision starts1, then increments at prepare, SQL-observed
or durable pre-SQL abort, and clear; overflow rejects.

At most32 root descriptors of104 bytes follow: kind:u8, changed1/guard2:u8,
reserved-zero2, selector32, predecessor32, successor32, successor length:u32be.
Kinds map only to the enum's closed current/target custody families, including
guard-only peer bootstrap11. Ordering
is kind then selector; global roots cannot repeat. Guards have equal before/
after digests and no replacement bytes. Account registration, session catalog
native fences and peer bootstrap are guards, not roots writable by this plan. Every plan pins
account registration. Replay-scope disposition also pins a native fence;
messaging-prefix disposition requires the separate history checkpoint plus
current messaging floor/catalog guards. These references are not verified
capabilities; the actual owner must still authenticate complete dependency closure.

At most32 row descriptors of72 bytes follow: disposition:u8 (outbox payload1,
audit2, journal prefix3, replay scope4), reserved-zero7, selector32, original
commitment32. Ordering is disposition then selector, with selectors unique across
dispositions. Target/disposition/root-family mismatches reject. Maximum envelope
is5896 bytes; these batch limits do not raise send/grant limits or create a new
product retention policy.

The active protected successor bundle contains exact replacement roots in
descriptor order, not data reconstructed after SQL deletion. Guards contribute
no bytes. Each root is at most1MiB; total at most2MiB, staged in at most16 existing
128KiB-size parts. The envelope commits its exact length, part count, whole
bundle hash and every replacement root hash. Missing/substituted/truncated
bytes reject before use. Owned copies are disposed/zeroed. These bytes may
contain still-required private custody and belong in protected active staging,
never logs, artifacts or audit tombstones. The current secure-storage bounds
are not increased; insufficient staging capacity must reject before SQL.

`ObserveReadback` accepts only complete, ordered exact root readbacks and SQL
before/after commitments. Prepared roots must all remain predecessors; SQL
successor then permits recording the observed commit. Afterwards only an
ordered prefix of changed-root adoptions is recognized; guards never change.
Third outcomes, missing/foreign roots, changed guards, premature/non-prefix
adoption and SQL rollback reject. Abandoning phase3 accepts only complete
predecessors and unchanged SQL; its durable intent permits crash-safe staging
disposal without guessing whether missing parts were corruption. SQL successor
cannot enter this abort path. `WithSqlCommitted`/`WithAbandoningBeforeSql`/`Cleared` are phase encoders,
not permission to persist. `OwnSuccessor` first validates the whole bundle;
neither it nor a returned recovery observation grants CAS/deletion authority.

`ProtectedDid2CompactionPlan` takes the actual matching file lease, borrows it
across awaits and captures owned plan/successor copies before the first await.
One existing CAS-and-insert atomically publishes the exact plan and insert-only
successor parts. Existing capacity/protection/conflict checks are unchanged;
no separate write sequence, orphan cleanup or delete fallback exists. Exact
plan and whole-bundle/individual-root read-back precede return. Cold exact retry
requires all original parts; missing/tampered/truncated/extra parts reject and
are not recreated. Another/disposed lease or cancellation cannot release a
successful result. Lost publication response leaves the same complete plan.
This storage component has no SQL writer, signer, native-fence factory or
adoption/clear API accepting supplied digests as permission.

Structural fixtures remain metadata-only; storage fixtures exercise actual
file locks and encrypted storage, and a separate real DID2-account fixture
verifies registration/reopen rejection. They do not qualify SQL cleanup.
The actual prefix owner below has a separate encrypted-storage/native recovery
fixture. Other dispositions/fences and retained-object integration remain
required before runtime compaction is installed. The earlier model full gate
has frozen pre-registration binaries; current source cannot inherit that full
receipt. [Exact source/testing boundary](../testing/s01-compaction-plan-model-2026-10-06.md#registrationstaging-working-source--separate-matrix).

## Messaging history checkpoint consumer

The existing atomic session-catalog producer registers the mandatory empty
`Did2MessagingHistoryCheckpoint` together with the messaging floor and peer
bootstrap. Reopen requires it; there is no missing-root initializer. Existing
sessions lacking the root or schema3 require explicit reset, never migration.

The private304-byte generation1 root commits the scope, monotonic revision,
stable active prefix floor, initial metadata hash and retained-history
projection digest/count. It is metadata, not permission to trim SQL. Forward
projections cannot regress lifetime ordinal, ratchet generation or history
count, or replace the initial evidence. Closed decode rejects absent/foreign/
pending/latched/overflow/noncanonical commitments.

Schema3 keeps the exact committed event metadata in the existing `events` and
`initial_events` tables; it does not add another event store or a key archive.
The working journal stays bounded4096. The independently verified lifetime
ordinal is bounded by SQLite's signed integer, not the working row count.
Capacity is checked before protected pending publication, while exact retries
remain possible. Only the narrow internal held prefix API below can remove
redundant journal rows; no application/service/scheduler activates it yet.

Every read verifies both the protected prefix projection and its actual
ciphertext/plaintext commitments before folding the contiguous working suffix.
ContactAccept, original contact init/hello, local history and exact replay no
longer require a retained join to a removed prefix journal row. The active
ratchet hash/generation still agrees with the protected messaging floor.

`CaptureHistoryPrefix` reads one bounded prefix candidate within one SQL
transaction after verifying the complete current SQL and exact protected tip.
It writes neither SQL nor a root. The earlier genuine native reader fixture
simulates the post-compaction SQL/root outcome explicitly; that receipt qualifies
reader and next-ratchet behavior, not the actual owner. The separate recovery
fixture exercises the installed private owner API described next.

The held read-only `PrepareOwnedMessagingPrefixCompactionAsync` now derives a
plan from the actual verified account, initialized catalog, native-retired owned
session and SQLCipher, not supplied rows/hashes or a callback. It pins account
registration, catalog, stable messaging floor and exact peer bootstrap; only
the history root changes. Returning the metadata neither stages it nor grants
deletion authority. An active plan forbids new selection.

`CaptureHistoryPrefixEffects` computes predecessor and virtual-successor SQL
commitments inside the same verified transaction. Canonical ordered schema and
every cell in all five tables contribute; only the selected bounded journal
prefix is absent in the virtual successor. Null/integer/blob types and blob
lengths are checked before copying, and unexpected zero-ordinal rows cannot be
hidden by the projection. These active reconciliation commitments are not
payload-derived audit tombstones. Complete-effect hashing alone cannot
authorize SQL; the actual owner additionally performs the following steps.

`CompactOwnedMessagingPrefixAsync` selects at most32 already-committed redundant
crypto-journal rows under the actual verified account/session and native-owned
retirement join. It atomically stages the exact plan and history successor. An
active plan can only resume its stored SQL selector, never select another batch
in the same retry. No service or UI calls this fresh-cleanup API yet.

The actual SQL writer re-captures every row descriptor, protected dependency
and complete SQL predecessor/successor in one SQLCipher transaction, deletes
only the selected prefix, verifies the complete successor before commit and
rechecks dependencies. It preserves all event payloads/metadata, initial
evidence, peer state, keys, counters, receipts and the live ratchet.

`ResumeOwnedLocalCompactionAsync` uses the existing protected account instance,
catalog key and exact stored scope; there is no supplied SQL path/key/hash,
fresh network proof, signer, encryptor or deleted-row reconstruction. It records
the observed SQL commit, adopts only the committed history root with CAS and
read-back, then disposes staging and clears the same plan. Dependency and SQL
read-back precede adoption/disposal and final clear. Missing staging before
adoption rejects; missing parts are legal only after all roots are adopted or
the unchanged predecessor is owned by durable abort phase3. Cold startup uses
this same recovery before ordinary reconciliation.

`AbandonUncommittedOwnedPrefixAsync` verifies every actual predecessor and SQL
Before, persists/read-backs phase3, then disposes staging and clears. SQL After
must finish its original plan, even after cancellation. This is local prefix
custody, not a claim that remote pending/unknown work has settled.

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

There is no production scheduler cleanup or floor unenrollment in this slice.
Actual local prefix recovery is implemented, but required plan registration and
its narrow owner API are not sustained lifecycle activation. The encrypted
native fixture closes/reopens real storage handles at each handover and retains
acceptance replay and subsequent text; it is not physical device qualification.
Terminal/audit/replay dispositions, durable retirement fences, outstanding
receipt work and accepted-object/retained-route obligations must still close
before S04 cleanup. Fresh full-source acceptance is recorded separately.
Capacity remains bounded backpressure; floors are not evicted to create space.
Local history, ratchet, inbox/dedup, mailbox grant/replay floors and remote objects
are not removed or extended by this change.
