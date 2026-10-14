# Account-owned ordinary authored counter custody

Semantic owner: [TRANSPORT-NEUTRAL-MESSAGING §8.4.3](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#843-compaction-and-boundedness).
Local format/API decisions: [DR-0098](../../../docs/survival-program/decisions/DR-0098-owned-authored-counter-floors.md)
and [DR-0110](../../../docs/survival-program/decisions/DR-0110-did2-private-route-update-custody.md).
This describes the current private Shared implementation, not wire authority,
cleanup activation, a semantic receipt, a new session or device qualification.

Device SQLCipher interpretation and current schema belong to
[DR-0109](../../../docs/survival-program/decisions/DR-0109-device-sqlcipher-random-key.md).
Writable custody and read-only compaction projection share that key mode and
retain independent native/SQL/protected checks. Prior device state requires
explicit whole-account reset, never selective deletion/recreation of source
burns or replay floors. This does not change journal slots or their authority.

## One local reader and bounded layout

### S04 creation/retry API cutover in progress

The semantic owner above separates new command creation from retained retry.
The account owner now has closed creation entry points for text, attachment
offers and route controls; it selects a new random operation under its actual
lease after current account/scope/freshness checks. The shared private producer
accepts no supplied operation on those entry points. Supplied-operation entry
points refuse missing custody instead of authoring a new event. Creation still
uses the existing pending SQL/stable CAS flow and independent authored floor.

The public text application boundary is QueueTextAsync plus RetryTextAsync;
the combined SendTextAsync overload is removed. The MAUI runtime and composer
select this pair, retain the owner-returned operation and never allocate a text
operation themselves. This is a current source increment, not matching build,
full, device or release evidence. Typed-event producer callers and connected
fixtures must all use genuine owner-generated operations; no test alias or
caller-operation creation fallback is permitted. Terminal working-set cleanup
and its exact protected/SQL recovery remain unfinished. This API cutover alone
does not by itself grant deletion authority. The connected generation8 terminal
layout below replaces the prior root; consumer qualification is still pending.

### S04 ordinary terminal working-set clean-break target

The connected package replaces ordinary generation7 with8 in the same required
slot `deep.store.v2.direct-text-journal`. Generations1–7 reject, including empty
roots. There is no migration, dual reader, optional root or reader-created state.
Client activation requires an explicit local account reset; no operational node
identity, genesis, holder or replay-floor reset is authorized. Application SQL16,
its five-column audit table, account registration and existing random SQL key
mode are unchanged. Source qualification is in the S04 checkpoint, not implied
by this target or the earlier generation7 receipts.

Header100: generation8:u8, reserved-zero:u8, entryCount:u16be, revision:u64be,
network16/account32/instance32, floorCount:u16be, reserved-zero2,
terminalAuditCount:u16be, reserved-zero2. The independent floor region contains
at most512 records: exact scope metadata404 plus next authored sequence:u64be.
Its canonical order is conversation32 + local author device32. Exact
network/account/instance/role must agree; next is above the role baseline and at
most Int64.MaxValue. A floor cannot move to another exact session scope or derive
its counter/revision from the surviving row count. Empty working sets retain
floors. Actual SQL counters must match even after every working row is removed.

Working prefix540 retains operation32, scope404, logical32, sequence:u64be,
created-ms:u64be and exact-event hash32 at the existing offsets. Phase byte516
is pending1, authored2 or independently verified Store3; kind517 is exactly
MessageCreate, AttachmentOffer or ContactRouteUpdate. Stop reason518 is active0,
user-cancelled1 or retry-expired2. Byte519 is reserved-zero, not an old retired
payload flag. Pending length:u32be stays at520, stoppedAtUpper:u64be at524 and
firstSuccessfulStoreUpper:u64be at532; pending payload begins at540.
Pending requires active work and its exact canonical event; other phases have
no embedded event. Only Store3/active work has a positive first-success upper.
Stopped work has its positive first-stop upper and zero first-success field;
late Store never changes that earlier stop reason/time. Terminal times must be
representable with the retention-owner audit duration. The actual held owner
captures current authenticated upper time, never caller UTC or event creation.
Already successful work cannot acquire a later stop reason.

There are at most512 working entries and one pending payload, bounded at23649
bytes. Entries are strictly operation-sorted and logical positions are unique.
Surviving authored sequences are strictly increasing within an exact scope and
below its independent next floor. Owned terminal cleanup may leave gaps; a parsed
gap is not deletion authority. Pending remains the latest reserved sequence in
its scope. Route-control expiry/relationship and all other exact DMC2 constraints
remain independently enforced. No second typed-event counter is introduced.

After floors and working entries, at most8192 strictly operation-sorted terminal
audits contain exactly48 bytes: original random operation32, first terminal
upper:u64be, reason:u8 at40 (cancel1, expiry2, successful Store3), reserved-zero7.
They contain no scope, event/content hash, manifest/key, request or ciphertext.
Audit and working operations are disjoint; audits cannot exceed lifetime reserved
positions. Cancelling or completing work never evicts a live audit to make space.
The complete root remains bounded at904389 bytes; working512, floor512, grant128
and event bounds are unchanged. Unknown/reserved/foreign/duplicate values reject
before copying or mutation. Revision survives cleanup and is checked against
independent lifetime reservations, pending and retained terminal commitments;
it is never reset from row counts. A floorless root is only empty revision1.

Stopped payload retirement atomically deletes selected exact working SQL rows
and inserts their independently MAC-bound audit rows, then adopts a protected
successor with those working entries removed and the audits added. Successful
cleanup uses the same region with reason3. No retired ordinary entry remains
to pin a successful suffix. Original transport uncertainty, exact requests and
ciphertexts, replay/grant floors, authenticated local history, receipt obligations,
assets, catalog, account registration and native checkpoints remain independently
guarded. Audit expiry uses one terminal-audit disposition in the existing
ten-root Application plan after current authenticated lower time reaches each
original deadline. SQL deletes first, protected membership second; cold recovery
uses the exact persisted plan without new network authority or event recreation.

Audit metadata alone never proves Store, delivery, dispatch or namespace
retirement. A repeated cancellation can observe an authenticated retained stop
audit; after its legitimate expiry absent work is explicitly unavailable, not a
new command. Cached historical Store requires independently verified original
native/history/transport evidence and does not recreate an audit or extend its
deadline. Retry of absent work refuses even after audit expiry; only a separately
explicit owner-generated creation can reserve a new command. Independent local
asset/history keys and remote BLOB lifecycle remain their separate owners.

## Actual producer and SQL consumers

### S04 stopped ordinary sender work — current source candidate

The actual held account owner stabilizes only an existing pending command and
its exact SQL mirror before cancellation. It then captures the first current
authenticated upper time in a protected stop CAS, never invoking an author,
signer, issuer, ingress or ratchet to stop work. Before that CAS work remains
active; after it the first stop is irreversible. Cancellation of a request token
alone is not this product transition. Expiry independently proves the original
effective retry deadline with authenticated lower time and retains the exact
possibly forwarded request; it never invents non-delivery or another attempt.

For native work, selection joins the actual outgoing event/hash and independent
local authored history. For a never-encrypted draft it verifies the guarded
native tip, exact stable protected/SQL payload and absence of native operation,
send custody and authored history. Stored or transport/history-bearing work
cannot masquerade as a draft. Missing/changed stable SQL rejects before stop or
encryption. Role baselines, the common sequence floor and local asset ownership
remain independent; cancellation consumes its reserved position permanently.

The existing Application disposition6 removes selected exact working payload
rows and inserts their minimal MAC-bound audits in one transaction. The protected
successor removes those working entries and adds terminal audits as defined in
the sole layout above. Its nine unchanged guards are send, grant, read, catalog,
native floor, attachment, account registration, history checkpoint and peer
bootstrap. Unknown request/ciphertext/holder custody, native history, application
receipts and independent asset keys are not deletion targets. SQL commits before
protected adoption. Cold recovery uses the original closed plan, complete SQL
effects, current root commitments and unchanged guards, never reconstructing
payload/hash/scope from a diagnostic audit or making a fresh network callback.
After exact root adoption the working entry is absent; the committed plan and
unchanged dependencies own disposal, not an audit-derived deletion capability.

Automatic new-work maintenance completes already-stopped cleanup before choosing
successful work, so a cancelled prefix cannot pin a settled suffix. Existing
pending author recovery has priority and is not blocked by read-only selection.
Audit capacity stays bounded; no live audit is evicted. Dispatch requires either
a retained active ordinary command or the actual independently owned control
command. Missing ordinary work cannot fall through to dispatch merely because
its native ciphertext or a diagnostic marker still exists. Historical Store is
verified independently before this dispatch path and never recreates a command.

### S04 independent terminal audit — current source candidate

The existing Application SQL16 `stopped_work_audit` retains only operation,
reason, first terminal upper, retention-owner deadline and authenticator. Its
account-registered separately derived audit key, MAC domain, five columns and
canonical reason1/2/3 grammar are unchanged. No payload, plaintext-derived content,
scope, manifest/key, request or ciphertext belongs here. The protected ordinary
terminal region plus independently bound Initial/ContactAccept custody determine
the complete permitted SQL membership. Missing, extra, foreign, altered-time,
wrong-reason or invalid-MAC rows reject without repair.

One Application disposition14 expires ordinary terminal audits of all three
reasons after independently current lower time proves their original deadlines.
It changes only the ordinary root and retains the same nine guards, complete
SQL before/after and exact protected membership commitments. The old ordinary
entry-based disposition7 is removed and rejects; it is not a compatibility
reader. Recovery resumes an already persisted plan without a new clock, callback,
signature or encryption. Legitimate deletion removes SQL before protected
membership; neither cold recovery nor cached Store recreates an audit or extends
its deadline. Replay-namespace retirement and unknown reconciliation obligations
are separate and remain pinned unless their own owner closes them.

Repeated cancellation of an authenticated retained stop is idempotent. A
compacted success needs independently verified original Store, not its audit,
to remain a success. After audit expiry, absent never-encrypted work is explicitly
unavailable; retry cannot mint it again. Source receipts and their historical
failures are preserved in the dated S04 checkpoints. Current generation8/API
consumer and fault/reopen qualification is still pending; earlier generation7
receipts do not qualify this cutover or physical delivery.

### S04 private route-control authoring candidate

The key-free Protocol author consumes the closed current own publication route,
derives event creation/expiry from its continuous protected time and all signed
windows, frames the existing control kind and independently verifies its exact
successor. Parsed predecessor selectors are comparison data, not native custody.
Shared must derive the advertised head from its actual committed local events,
join the adopted own publication and peer consent, reserve the one common authored
position and preserve the resulting command exactly across SQL/protected handovers.
The current codec/SQL mirror accepts this closed kind. The actual owned
command preparation is connected to the actual adopted publication and native
advertised head under the same lease, using the existing pending/SQL/stable CAS
and sequence floor. Existing intents resume their exact kind/scope/bytes without
reopening the latest publication or reminting; a fresh native operation is never
reauthored after working custody disappears. Historical original-attempt cleanup
joins remain open. Own control
history now has a separate closed handoff: the real owner joins its protected
command/complete SQL mirror, actual outgoing native commit, common sequence floor,
actual consent and ordered independently signed advertised history. It materializes
into the existing account inbox in both SQLite and its in-memory parity model,
without user text or application receipt work. Historical reconstruction no longer
requires the latest peer mailbox to be current or reopens the latest own publication.
Missing working custody requires independently retained history; it cannot be
recreated. Dedicated internal `SendOwnRouteUpdateAsync` prepares only the actual
owned command, then independently rechecks it before encryption and actual native
commit. Generic raw send remains disabled for route controls. Connected local
evidence is in the S04 checkpoint; it does not qualify shipping or physical delivery.

The receiver's real sealed transition records its protected first processing
outcome atomically in existing native metadata. Ordered peer head reconstruction
uses this outcome and independently verifies historical signatures/consent; an
application row or current-route cache cannot qualify it. Closed positive peer
handoff reconstructs the actual native member and materializes only accepted
controls, without text or AppAck. Rejected outcomes remain native evidence and
fence only this route's new sends. Control transport ACK and the complete
negative/fork/prefix matrix remain open; no unqualified control authorizes ACK.
See DR-0027/0110; no second journal or destructive route-fork session latch exists.

### S04 original late Store reply — local owner/API candidate

The existing owned Store ingress copies only its bounded returned quorum before
the post-ingress current-grant fence. A rejected dispatch fence does not discard
this untrusted historical input. The same held account owner independently joins
the actual native envelope, exact original SQL MAU, protected attempt/acquisition,
original policy/holder signatures, replica view/keys and signed quorum times.
Every Initial attempt also authenticates its own DCR/ADP against the pinned DID2
credential, actual original draft/DPH and each signed acceptance time; verifying
the selected predecessor alone cannot retire another sibling.

`AdoptOwnOriginalMailboxStoreReplyAsync` is an internal selector/raw-response
entry for the same owner checks after cold reopen. It accepts no verification,
deletion, transport or signing capability. Only the exact supported two-replica
Ed25519 quorum size is copied. Current own network/time authority remains
mandatory; original grant expiry never authorizes signing or renewed dispatch.
No journal/schema/wire generation is added by this API.

The original coordinator statement and existing Attempted -> Accepted -> Durable
transitions commit in one SQL transaction, with exact public evidence/request
read-back and unchanged native/protected roots under the same lease. A matching
existing coordinator statement must retain both its digest and exact object
expiry. This path never prunes unrelated statements, renews object lifetime,
creates a missing attempt, replaces accepted evidence or infers AppAck/Delivered.
Before-commit failure rolls back; after-commit recovery independently re-verifies
the original Durable fact. Unknown/missing/invalid replies still pin cleanup.
Source qualification and whole-chain cleanup remain separate from physical E2E.

New Store preparation gives its SQL item the immutable accepted-object expiry
from the signed body, not the shorter grant expiry. Grant/route/request admission
and the logical/application retry ceiling remain independent fences. Historical
Store verification requires this exact SQL/body expiry join. Already prepared
items are never extended, backdated or rewritten; incompatible clipped test
state rejects and requires explicit reset, not a repair/migration reader.

### S04 send-attempt local clean break — implementation target

The same mandatory mailbox-send slot has one generation4 reader, rejecting
prior roots even when empty. Header96, replay floor72 and the512 entry/floor
bounds remain; each attempt record is432 bytes. The former commitment prefix
keeps its original native operation/ciphertext, request, grant, route and
counter. The suffix binds attempt ID32, reciprocal predecessor/successor IDs32,
immutable logical retry deadline:u64, authenticated closure lower time:u64,
chain ordinal:u64 and original admission ceiling:u64. Phases distinguish pending,
prepared, closed-pending-unknown and closed-prepared-unknown. Closure is not
non-delivery, Store, retirement or authority to erase the predecessor.

One canonical chain has one current tail per native operation/session; links
cannot fork, disappear, cycle, change ciphertext/logical deadline/object expiry,
or begin a successor before its predecessor is closed. The owner must prove
original admission ended from independently protected lower time, reconcile
any actual SQL Durable fact first, and adopt both reciprocal links before a
successor dispatch. Parsed records cannot authorize this transition. The codec
is only its bounded local representation. The held-owner closure candidate now
joins actual retained native ciphertext, original protected acquisition/PMA/route,
holder/issuer signatures, original pending body and SQL request. Independent
authenticated lower time must reach the rederived admission ceiling. A pending
descriptor with an actual SQL-prepared MAU adopts that exact request/counter and
advances its existing protected floor in the same closure CAS; a prepared
descriptor with missing/corrupt SQL rejects. An actual SQL Durable/Delivered
outcome requires original-outcome reconciliation, not closed-unknown conversion.
Closure precedes current peer-route/grant installation and has before/after CAS
fault hooks plus exact read-back; no expired signer/transport is opened. It
neither discards uncertainty nor retires dependencies. The current owner now
connects a closed ordinary/session-based send to a distinct independently
current Deposit grant on the same authenticated native recipient route. Before
issuance, and again before signer/ingress callbacks, it verifies the complete
closed prefix against original acquisition/policy/holder/request SQL, native
ciphertext, authenticated closure time and independent counter floors. The
original logical retry deadline and fixed capacity reject replacement work
before issuance. A newly selected attempt ID and mailbox operation are distinct;
object expiry and committed ciphertext are unchanged. Both reciprocal links,
the new grant enrollment and pending descriptor are adopted/read back in one
send-root CAS before SQL preparation. Cold recovery resumes that tail's exact
request and counter without renewing its grant or ratchet-encrypting again.
Before/after successor-root and after-SQL fault coverage uses genuine producers.
Initial-contact replacement on the same original recipient route now uses the
actual retired sender source and immutable initial draft, exact DCR digest,
DPH ciphertext and protected permanent credential. The current independently
verified recipient DCR/ADP/route is joined to those facts before issuance and
again before callbacks. Changing the recipient route remains unavailable;
current route signatures alone cannot replace native consent/draft facts.
The working retry deadline is bounded by the authenticated native application
event expiry (both SessionInit and Hello for an initial send), separately from
the immutable accepted-object horizon. Original prepared work may close unknown
after that deadline, but no successor can issue or dispatch. A stored working
deadline inconsistent with the actual source rejects; it is never repaired or
extended. Admission is the minimum of this retry deadline and the actual grant
expiry. Non-expiring events retain the existing object-bound ceiling. No
reencryption, wire change, extra slot or fallback reader is introduced.
The existing SQL
public-evidence table now has separate immutable native
and attempt identities in application schema11. Before-ingress writers derive
the attempt from current protected prepared/native/floor custody, not UI input;
historical Initial/ContactAccept/ordinary readers now discover bounded attempt
candidates, preserving native identity separately from the selected attempt.
While the working chain exists, SQL cannot append an unlinked candidate. The
reader checks every candidate for missing attempted public evidence, then joins
the selected original signed request/policy/pair/coordinator to actual native
ciphertext and rechecks exact roots/SQL evidence. Interrupted ordinary completion
joins that selected protected prepared attempt, independent replay floor and
original acquisition before adopting only the Stored marker. A late original
Store neither removes another attempt nor resolves its uncertainty. Candidate
IDs, SQL terminal flags and protected links alone are not Store authority.
Advancing an SQL item from Durable to Delivered preserves its original Durable
attempt's signed Store evidence. Historical selection, outcome verification and
send cleanup accept either item state but independently reverify that same
holder-signed request, native ciphertext, original policy/keys, replica quorum
and coordinator. Delivered is not substituted for any of those proofs, and
this reader returns only Store facts, never a recipient application ACK.
Prepared/Attempted/Accepted/Expired states do not qualify through this selection.
Retirement/compaction consumers select and verify the whole attempt chain as
specified below. A genuine known child with an unresolved parent pins the
chain without changing application SQL, native/authored custody or counters.
This is not settlement of that parent or an all-known chain retirement proof.
Matching full qualification, replacement-recipient/route-rollover custody,
irreversible namespace/dependency retirement and sustained bounds remain S04 work.
No extra slot, wire, ratchet generation or compatibility reader.

The account owner still independently verifies own/peer freshness, initialized
session, retirement and explicit responder acceptance under the actual writer
lease. Before authoring it checks both working-entry and new-floor capacity.
Only `State.AddPending` reserves the exact next position in that same root as
the original pending event. New work for an unused scope starts from the existing
role baseline; SQL never supplies a new value. Pending CAS has exact protected
read-back before SQL. Stable CAS and the final returned root have exact read-back;
Store adoption keeps its existing authenticated adapter/receipt guards.

The S04 working candidate also checks existing protected transport-send and
grant capacity before a new ordinary event is reserved. The native sender
repeats that denial-only check before a new ratchet transition, since capacity
can change after draft preparation. Full working entries reject immediately;
full acquisition/replay-floor sets require an actual authenticated retained
peer route and an already reusable exact scope. Parsed winner metadata is only
a capacity hint, never signing/admission authority. Roots are rechecked after
route callbacks. Missing custody and an orphan transport commitment reject;
the reader does not initialize, evict, compact or raise a bound. Exact already
committed ratchet replay bypasses this new-work capacity check, not the existing
integrity/receipt checks. A refused new operation preserves any prior draft,
authored sequence, native ratchet, history and transport dependencies. This
capacity candidate introduces no local generation, wire value, background scheduler or
retirement permission. Source qualification remains separate from sustained
capacity/lifecycle and installed clients.

### S04 interrupted Store completion — source candidate

Ordinary dispatch now preserves the original public Store evidence before a
callback can become durable, after joining the stable protected command,
authored SQL and actual native/history event under the account lease. Completion
requires those exact existing records; it cannot recreate evidence deleted or
substituted during ingress. A prepared public-evidence row is not a Store fact.

If SQL has the exact original Durable request/quorum but the ordinary protected
Stored marker was interrupted, the historical reader verifies its original
policy, holder signature, signed pair, sole-writer coordinator and native event
before adopting only that marker. Cold recovery can outlive original admission;
it still requires independently current own/network/time and never signs,
acquires a replacement grant, dispatches or encrypts again. Missing evidence or
an actually unknown SQL outcome remains unresolved and cannot gain this result.
Source-only regression candidates cover both local completion handovers with
and without original policy/epoch expiry; qualification is tracked in the
[S04 checkpoint](../testing/s04-lifecycle-2026-10-11.md).

Local recovery of an already-owned compaction plan uses caller cancellation.
The separate existing network freshness budget starts after that local peer
credential read; it is not lengthened or used as compaction authority.

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

### S04 ordinary business-owner maintenance — source candidate

Before a new ordinary command, the current owner may select one existing bounded
batch when the ordinary working set reaches the batch size or send entries are
full. It selects only the earliest settled prefix of that exact session scope;
an unknown earlier position pins later completed commands. Pending commands and
exact retries are not maintenance selectors. Selection, protected staging,
complete SQL projection, ordered root CAS/read-back and recovery use the existing
outbox-only producer; no new journal, limit, signature or deletion authority.

Public text continuation resumes an existing protected plan before ordinary
account reopen. After outbox-only removal, an exact public text retry verifies
the retained native operation, independent authored history and original Store
through the existing historical verifier. It does not reconstruct working
custody or encrypt again. Changed requested payload rejects for both retained
and compacted commands. Local history, application receipt obligations, original
transport outcomes, counter enrollment and protected floors remain independent.
This source activation is not namespace retirement, a background scheduler,
the full S04 sustained qualification or device delivery; matching evidence lives
in the [S04 checkpoint](../testing/s04-lifecycle-2026-10-11.md).

### Existing dependency owners

The sole semantics are the dependency-closed batch/recovery contract in
[§8.4.3](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#843-compaction-and-boundedness).
The following maps it to current consumers; it is not another outbox or
permission to delete current rows. The narrow held messaging-prefix owner
described below and the outbox-only owner are implemented; the other dispositions
are still targets. The outbox affected readers and narrow owner/recovery are
qualified by the [current coupled full receipt](../testing/s01-ordinary-outbox-disposition-2026-10-06.md#current-coupled-full-gate--accepted-outbox-only-slice).

| Current custody / consumer | Required integration consequence |
| --- | --- |
| `ProtectedDid2DirectTextJournal`, `ReconcileOwnedTextOutboxAsync` | Keep every authored floor. SQL currently requires each retained stable command row; coordinated outbox cleanup must replace this expectation only for exact selected dispositions, preserving separately verified history and receipt work. |
| `ProtectedDid2MailboxSendJournal`, `DeliverOwnedMailboxAsync` | Keep replay enrollment/high counters and original request/body/grant/ciphertext dependencies. Prepared is not settled. A verified ordinary Store phase does not authorize deleting unknown transport work. |
| `ProtectedDid2MailboxGrantJournal`, `MailboxEpochExclusion` | Pin original winners/acquisitions referenced by send/read/ACK or object horizons. Recheck held exclusion and complete dependency closure before committing a retirement fence; changed grant roots cannot be hidden behind their old digest. |
| `ProtectedDid2MailboxReadJournal`, owned Retrieve/ACK | Pin the active cycle through authenticated materialization, SQL outcome/traversal agreement and ACK completion. Keep counter/traversal floors even after clearing a cycle. |
| `Did2MessagingSqlJournal`, `Did2MessagingFloor`, session catalog | Current schema4 verifies the retained suffix from its mandatory protected history basis, plus the committed retained-event prefix. Lifetime ordinal/ratchet generation do not reset. An SQL-only checkpoint or renumbered ordinal is forbidden. Actual prefix disposition still requires the held plan owner. |
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
registration, schema4 checkpoint reader and actual held prefix owner are
implemented and their narrow prefix/outbox owner paths separately qualified.
Other dispositions and retained-object closure remain unfinished. This mapping
does not close S01 or activate S04 runtime cleanup.

The existing registration/reopen join is
`SqliteDeepIdV2AccountGeneration.EnsureAsync`: creation atomically writes the
account SQL key/instance and required protected roots in one storage batch;
reopen reads and validates those roots without filling missing ones. Mandatory
plan registration belongs in that same producer, not a later optional marker.
`ProtectedDeepIdV2AccountOwner.ReadCurrentAsync` now resumes the exact stored
batch through its closed SQL profile under the actual lease before calling the registration verifier and
receiver reconciliation. Other ordinary under-lease opens still require an idle
plan; they fail closed rather than bypassing active recovery. Existing explicit
reset purges the V2 storage namespace; staging is not a separate reset bypass.

## Local plan envelope and successor custody

`Did2CompactionPlan` is private S01 metadata and a structural readback model.
The working registration producer now inserts `deep.store.v2.compaction-plan`
atomically with the existing account instance key and mandatory roots. Reopen
requires its exact current scope and idle phase before receiver reconciliation
or ordinary account projection. Missing/foreign state rejects without reader
initialization; startup resumes only the installed exact prefix or ordinary
application profile. Existing
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
sessions lacking the current root or schema4 require explicit reset, never migration.

The private304-byte generation2 root commits the scope, monotonic revision,
stable active prefix floor, initial metadata hash and retained-history
projection digest/count. It is metadata, not permission to trim SQL. Forward
projections cannot regress lifetime ordinal, ratchet generation or history
count, or replace the initial evidence. Closed decode rejects absent/foreign/
pending/latched/overflow/noncanonical commitments.

Schema4 keeps the exact committed event metadata in the existing `events` and
`initial_events` tables; it does not add another event store or a key archive.
The working journal stays bounded4096. The independently verified lifetime
ordinal is bounded by SQLite's signed integer, not the working row count.
Capacity is checked before protected pending publication, while exact retries
remain possible. Only the narrow internal held prefix API below can remove
redundant journal rows; no application/service/scheduler activates it yet.

Every read verifies both the protected prefix projection and its actual
ciphertext/plaintext commitments before folding the contiguous working suffix.
DR-0027 owns the current672-byte native header and its route-processing
extension. Pending recovery, full working SQL and protected-prefix reads share
the closed validation; received controls require their original processing
outcome. The actual account's sealed fresh receive producer commits it through
the same pending/SQL/cleanup/stable path. No application projection supplies
classification or time. Exact replay retains the first outcome. Independently
verified peer history fences new sends after a rejection without latching or
erasing the live ratchet. Closed positive semantic handoff is separate from a
current delivery route and creates no AppAck. The genuine owned native positive
cycle and one after-SQL interruption are locally exercised in the S04 checkpoint;
the complete rejection/fork/prefix/ACK qualification remains open. Structural
codec tests do not prove this cycle.
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

## Owned ordinary outbox-only API

The internal account service `CompactOwnOrdinaryOutboxAsync` joins independently
current own authority/time and the original Store closure of
[DR-0106](../../../docs/survival-program/decisions/DR-0106-retained-store-public-evidence.md)
to the held owner. It does not require renewed peer or issuer admission merely
to remove completed working commitments. `PrepareOwnedOrdinaryOutboxCompactionAsync`
is read-only metadata; its returned preparation is never accepted as a caller's
deletion capability. The writer reselects, verifies and stages under the same
account lease. No UI or background scheduler activates this cleanup yet.

The candidate is a bounded oldest consecutive Stored prefix in one owned
session. Stored alone is insufficient: the owner joins the original protected
send/grant/counter/request, actual SQL MAU3 and signed durable quorum, committed
native event, independent semantic history and any retained attachment keys.
Original signed policy/projection/replica bindings remain required; unavailable
historical bindings pin the scope. The same independent historical Store reader
checks the complete native/semantic/MAU/quorum/coordinator joins before selection.
Every removed send field additionally matches the actual retained MAU/body/grant,
original acquisition and independent replay floor. Original accepted timestamps
are checked against the original grant, not used to authorize a fresh dispatch.
Existing-only application/native readers never provision or promote state.

This profile changes the ordinary root and removes only its selected completed
entries from the send root. Every send counter floor and unselected entry is
preserved. Grant, read, catalog, native floor, attachment, account registration,
history checkpoint and peer bootstrap remain exact guards. Its SQL target is the
existing application database. Complete
ordered schema/cell commitments include every table, not just working-row
counts; the virtual successor omits only the selected ordinary working rows.
The SQL writer independently recaptures that selection and complete effects
in one transaction, rechecks the actual protected plan/roots before deletion
and commit, then adopts the exact ordinary successor followed by the exact send
successor with CAS/read-back. Send-first adoption is a forbidden non-prefix.

Startup uses the same local recovery dispatcher as prefix recovery, with a
separate closed application profile and its already-initialized account key
registration. Recovery does not initialize a database, promote registration,
refresh network authority, sign/encrypt, reselect or reconstruct deleted work.
The closed application profile requires both changed roots; the former
single-root plan is rejected, without a compatibility reader. Staging disposal
supports the two roots' bounded successor parts. Only
verified complete adoption, or the unchanged predecessor owned by durable
abort, can clear the plan. `AbandonUncommittedOwnedOrdinaryOutboxAsync` rejects
SQL After, including a cancellation after commit but before its marker.

Exact Store and E2EE-send replay after cleanup verify retained native/history custody and
the independent authored floor without recreating the ordinary command or its
SQL working copy. Cached encryption additionally requires the supplied exact
event bytes to match that history and its existing native send; absent native
custody cannot enter a new encryption transition. Store replay joins the original
SQL MAU3, signed durable quorum and independently recorded coordinator statement
to the original grant, route, retained counter and native event. It never enrolls
a replacement send entry, signs or dispatches, nor inserts/prunes/repairs the
coordinator ledger. Missing or changed evidence rejects. Original issuer/route
bindings and the independently current own account/network/time guard still apply; cached Store is not
new admission or current-route evidence. Old operation authoring still rejects;
new operations retain monotonic sequence allocation. Original SQL attempts,
grant attempts, receipts, native events, history, dedup, counters, asset keys and
remote obligations are not retired.
Implementation/build and focused fault evidence do not themselves qualify the
required coupled full gate. The [historical single-root checkpoint](../testing/s01-ordinary-outbox-disposition-2026-10-06.md#current-coupled-full-gate--accepted-outbox-only-slice)
records full687/0/0 terminal0, all161 current/all678 prior cases Passed and55/55
frozen inputs exact for Shared `574d934347fb21f48453def7541a0a7a7a86d06d`.
This qualifies only that former single-root profile, not the current two-root
increment, namespace/floor retirement or scheduler activation. Current source
qualification is tracked in [the S01 checkpoint](../testing/s01-idle-mailbox-floors-2026-10-09.md).

## Completed initial / ContactAccept send working entries

Private S01 `RetireOwnCompletedContactMailboxSendAsync(scope, operation,
initialIntent, source, ct)` accepts selectors only. An initiator must select its
exact initial intent/operation; a receiver must select its actual protected
explicit ContactAccept command. It obtains independently current own authority
and keeps the approved verifier alive throughout held selection. It does not
request a current peer route or renew an original grant.

The owner reuses the genuine historical Store reader: actual retired initial
sender source/draft/peer/ADP/DCR or native ContactAccept and semantic projection,
original signed public policy/view/descriptors/pair, exact holder-signed MAU,
durable quorum and independent coordinator. It additionally joins every removed
send field, counter/replay floor and original XMG/XMC acquisition. A prepared
flag, SQL Durable alone, caller assertion or cache miss cannot authorize removal.
Every attempt in the reciprocal native chain must have independently verified
original Store, holder/request, replica quorum/coordinator, acquisition and
counter-floor custody before staging. A late parent Store does not settle a
pending or unknown child. Pending/unknown Store remains pinned before staging. An absent entry is
idempotent only after the independent original Store closure succeeds; no reader
reenrolls a missing send, floor, holder or request.

The current protected-only profile uses one InitialPayload or ContactAcceptPayload row selecting the original native
send key and SHA256 of all fixed-width attempt records in reciprocal root-to-tail
order. A single-attempt chain has the same commitment as its one record; no
format/version/fallback changes. The exact native scope hash is the SQL selector,
with zero SQL before/after. The selected Send chain and its working control-payload root change; every
floor and unrelated entry remains unchanged. The existing32-row plan bound is
not enlarged for a chain containing up to the existing512 working entries.
The shared protected-retirement dispatcher explicitly distinguishes these control
dispositions from ReplayScope counter/acquisition disposition; no fallback tries
to reinterpret a failed profile. Shape requires Send plus exactly one control
root change and both NativeFence and independent complete-state guards. The owner
requires the closed ten-root mapping and rederives the exact successor from the original
complete prepared chain and retained replay floors before the protected commit marker/CAS.
Ordinary outbox compaction similarly removes every selected native chain, not
only the root; its existing guarded exact send successor binds the whole batch.
All structural selections/duplicates/floors/revision overflow are checked before
mutating a decoded selection. Structural chain hashes never authorize deletion.

The unchanged mailbox-state guard excludes only the independently changed
contact-start or acceptance root. It includes the other control root, preclaim and
initial-key retirement roots, actual protected device-source marker/checkpoint,
complete read-only existing device SQL, responder checkpoint and prekey
install/inventory/commit markers, complete existing encrypted prekey file,
application SQL and every catalogued native SQL/history/floor/peer.
The prekey guard streams ciphertext with fixed memory under the lease and a
write-excluding file handle. It does not authenticate a source: selection's
original Store/source verification remains independently required. Even a
logically equivalent ciphertext rewrite pins the stored plan; recovery cannot
repair/recreate the file or assume equivalence. Missing/empty files, orphan or
pending sidecars, foreign markers and pending responder checkpoints reject.
Device readback uses the exact current schema,
SQLCipher profile and registered key scope, without source reconciliation,
creation, key deletion, PRAGMA mutation or current-proof callbacks. Missing,
changed, pending or foreign source custody pins recovery. All native/application
source, grant/holder/route, counters, receipts/objects and Retrieve/ACK paths stay
intact. Existing crash handovers, pre-commit abort and cancellation ownership
apply; the stored plan finishes without acquiring fresh network authority.

This profile removes one completed native send's settled attempt chain, not its original acquisition
or semantic/receipt/object source. S04 scheduler activation and whole S01/source,
connected, package and device qualification remain separate. Exact evidence is
tracked in the [S01 checkpoint](../testing/s01-idle-mailbox-floors-2026-10-09.md).

## Remaining closure

### S04 contact-control working payload retirement — implementation in progress

The successful grant/read lifecycle package is qualified separately in the
[sustained checkpoint](../testing/s04-sustained-send-2026-10-12.md). It does not
close contact-control retention. An active ContactAccept command retains full
canonical content and is an independent explicit-consent source. Removing that
entry based on Store, expiry or an empty SQL query would lose consent authority.

The connected implementation must preserve a protected consent commitment,
exact command/Hello/scope and actual native send plus independently authenticated
semantic history, while retiring only redundant working payload. Consent/history
facts are NOT the metadata-only outbox audit; plaintext-derived content must not
enter that audit. Initial source/transfer commitments, object-only key dependencies,
unknown original attempts and replay floors remain separate protected obligations.
The existing account-held compaction/recovery owner must close the effect before
any source deletion. No new wire, legacy reader or expiry-based deletion shortcut.

Current acceptance grammar and successful/stopped control terminal metadata are
owned solely by [DR-0063](../../../docs/survival-program/decisions/DR-0063-did2-contact-reply-route-embedding.md#protected-acceptance-clean-break);
Initial framing is owned by [DR-0064](../../../docs/survival-program/decisions/DR-0064-did2-owned-initial-contact-draft.md).
The existing protected slots use their sole current reader, without migration,
compatibility readers or automatic regeneration. Independent consent/history
commitments are not content-free audit. No public wire or Protocol API changes.

The held owner authenticates actual native operation/event, semantic acceptance,
original Store/public/quorum/coordinator and complete attempt chain before staging.
The existing plan has a closed ContactAcceptPayload action with exactly10 roots:
ordinary/send/grant/read/catalog/attachment/account/native-fence/ContactAccept/
MailboxContactCustody. Only send and ContactAccept change, in that order. The
separate guarded private root16 uses domain-separated selector/digest and covers
all existing mailbox-state sources except the independently changed ContactAccept
root15. Root12 retains its original complete meaning in other profiles. Root16
cannot be borrowed by another action or change itself. Other guards,
SQL/native history, replay floors and receipt obligations remain unchanged.
The two exact successors are owned staged bytes. Cold recovery verifies exact
source guards, deterministic chain removal and consent-only successor, adopts
each by CAS/readback, then verifies staging against both adopted roots before
disposal. Unknown/incomplete Store and missing sources cannot initialize deletion.

Consent-only readers require actual native hash and semantic canonical event.
They may expose a temporary verified history copy for exact cached retry, never
recreate working custody or perform fresh ratchet encryption without that original
native operation. Historical route policy comes only from the fully joined event.
Stored ContactAccept working-copy retirement has matching connected source
qualification in [the contact checkpoint](../testing/s04-contact-retention-2026-10-12.md#matching-corrected-connected-qualification).
The current connected candidate also supports explicit pre-commit abandon through
the same owner: exact unchanged roots, complete staged bytes and deterministic
send/consent successors are required before the phase3 marker. Recovery discards
only staging, preserving both predecessor roots; an atomic batch's lost reply may
leave all parts absent, but partial/foreign parts reject. Phase2 cannot abandon.
Matching abandon and first fresh user-send evidence belongs to that checkpoint;
neither older89 nor earlier44 cases qualifies new inputs. Initial, cancel/expiry, object-only-key and
separate metadata-only audit retirement remain open. Earlier44 receipts do not
qualify these changed inputs; whole S04/full/device acceptance is separate.

### S04 Stored Initial working-payload retirement — source candidate

The current contact-start slot follows the sole current grammar in
[DR-0064](../../../docs/survival-program/decisions/DR-0064-did2-owned-initial-contact-draft.md#protected-local-grammar).
Its explicit draft commitment/projection survives payload retirement; native
source/key-transfer, canonical Init/Hello, independent original Store and every
attempt remain mandatory. No new slot, network record, crypto, migration or
compatibility reader. Projection metadata grants no send/claim permission.

InitialPayload uses the same ten-root protected transaction/recovery as Accept:
the first eight roots remain ordinary/send/grant/read/catalog/attachment/account/
native-fence, then guarded MailboxContactCustody16 and changed ContactStart17.
Only Send and ContactStart change. Root16's Initial domain differs from its Accept
domain and excludes only the separately changed draft; all other complete-state
sources remain guarded. Deterministic successors, ordered adoption, pre-commit
abandon and post-commit completion share the actual existing held owner.

Retained Store and used-grant selection now join exact draft commitments with
independently transferred source and native initial events. A normal draft read
may return a disposable verified history copy, not recreate durable working
custody. A retired draft cannot authorize another prekey claim. Matching native
handover, marker corruption, cached Initial replay and fresh text/Store/receive
evidence belongs to the [contact checkpoint](../testing/s04-contact-retention-2026-10-12.md);
that checkpoint is the evidence owner. Whole S04, independent audit/key and physical claims stay open.

### S04 control audit custody and joint recovery — source candidate, qualification pending

The registered held application factory binds actual current stopped Initial/
Accept roots alongside the independently derived audit key. It captures only
operation/owner-kind/stop-time/disposition metadata, not payload, scope or content
hash. A separate HMAC domain maps random control operations to opaque SQL audit
IDs; audit rows retain the existing reason/time/deadline/authenticator grammar.
The existing count bound derives from the three actual owner capacities, rather
than evicting a row: ordinary512 plus Initial128 plus Accept128.

Idle factory opening and ordinary reconciliation verify the complete audit set:
exact protected retired controls require their MAC-bound row, working/expired
controls cannot have one, and remaining rows must match ordinary custody.
An exact active plan owns intermediate SQL/root agreement; normal business
orchestration still must resume it. No row/hash/parsed snapshot grants deletion.

Control effect capture validates actual bound stop custody and complete existing
audit state, then computes deterministic whole-application before/virtual-after
projections for insertion or expiry without writing SQL. The actual held owner
now stages the existing Application plan with one closed stopped-control action,
one deterministic payload successor and independent guarded send/native/source
custody. SQL audit commit precedes payload adoption. Current authenticated lower
time alone selects expiry; staged local recovery needs no renewed network proof.
Only exact unchanged SQL/roots and complete deterministic staging allow pre-commit
abandon; stop remains irreversible. Committed SQL requires completion. Cleanup
removes no original unknown request, holder, ciphertext, history or replay floor.
Idle maintenance validates complete audit custody even before its deadline and
after audit retirement, never repairing missing or hostile SQL rows.
Matching qualification of this joint candidate remains pending in the
[contact checkpoint](../testing/s04-contact-retention-2026-10-12.md); the earlier
53-case foundation does not qualify these changed inputs. Preclaim cancellation,
independent object-key retirement, whole S04 and physical E2E remain open.

### S04 contact-control retry preflight — source candidate

The pre-session cancellation candidate follows the exact local grammars in
[DR-0064](../../../docs/survival-program/decisions/DR-0064-did2-owned-initial-contact-draft.md)
and [DR-0027](../../../docs/survival-program/decisions/DR-0027-did2-messaging-session-ownership.md#source-custody-clean-break-and-retirement-frozen-before-implementation).
The existing key journal distinguishes cancellation from transfer. Actual
registered account/source/claim/catalog/native state is read before deletion;
an imported ratchet follows the existing native stop instead. Source key deletion
and sealed-preclaim retirement locally recover without fresh account/network
proof, do not reset burns/replay and cannot activate a session. Source/claim/import
entry points check the actual stop fence before new encryption or mutation.
Only completed key destruction permits the existing protected Application plan
to retire Initial payload and content-free audit. Its SQL selector is derived
under the registered audit key, never a fabricated native scope. Earlier source
receipts do not qualify this cutover; current evidence/remaining matrix lives in
the [contact checkpoint](../testing/s04-contact-retention-2026-10-12.md).

Initial and explicit ContactAccept retry now check their original authenticated
application deadline before current-recipient refresh. The business facade first
uses independently verified historical Stored; expiry cannot downgrade that
fact. Initial denial joins actual native Init/Hello, the retained key-retired
sender source, protected draft and original recipient DCR. ContactAccept joins
its existing protected command and retained native/semantic event. Only the
owned current time upper bound denies dispatch; only the lower bound permits
original attempt closure through the existing original request/acquisition/
counter-floor producer. A changed/missing source cannot mint closure or extend
the deadline. Before/after closure interruption reuses original protected custody.

This is local mapping of the existing
[settlement owner](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#84-owned-attempt-settlement-renewal-and-retirement),
not a new generation, journal, wire or public Protocol allocation. It removes no
payload/key/history, original request or replay floor; it proves no non-delivery
and authorizes no successor. Full contact stopped payload/key/audit retention
remains open. Matching source evidence is in the
[S04 lifecycle checkpoint](../testing/s04-lifecycle-2026-10-11.md#initial--contactaccept-original-retry-expiry-before-recipient-refresh).

## S04 native SQL read-path performance — source candidate

Exact operation/receive point reads authenticate the complete current journal
and independently protected history against the expected stable floor, then
materialize the selected bounded row inside the same short deferred SQL read
transaction. No network await/callback or verification-result cache lives inside
that transaction. Current and retained event validation explicitly checks SQL
storage types before materialization; converted bytes alone do not establish
the canonical representation.

Stable-orphan cleanup checks the same exact protected floor and deletes only
its designated pending-part slots inside one authenticated secure-storage
transaction. The guard itself and unrelated slots are unchanged; missing or
conflicting guards refuse before deletion. No-op cleanup still authenticates the
aggregate but does not re-protect/rewrite it. The checkpoint preserves explicit
missing/malformed-floor refusal on a failed guard and never retries that refusal.
This storage primitive supplies neither retirement nor currentness authority.
It changes no serialized record, key mode, inventory limit or pending recovery
transition; full SQL/history/protected-tip checks remain mandatory.

Route-only consumers use an authenticated native-metadata filter only after
the complete tip check; they keep the final complete check, per-row validation,
cancellation and owned-event disposal. Authored-position collision checks and
Braid purpose progress still read ordinary incoming events. No route fault,
unknown operation or retained prefix is evicted by the filter.

The messaging connection opener currently requests a connection-local native
page-cache suggestion of8192 KiB, verifies the provider retained that setting,
and still disables pooling. This is an experimental performance setting, not
a working-journal bound, schema/wire generation or cached authorization. Cipher,
raw-key, durability/deletion policy and protected-floor checks are unchanged.
Actual performance/mobile memory qualification and source acceptance remain
pending in the [sustained-send checkpoint](../testing/s04-sustained-send-2026-10-12.md).

There is no production scheduler cleanup or floor unenrollment in this slice.
Actual local prefix and outbox-only recovery are implemented, but plan registration and
its narrow owner API are not sustained lifecycle activation. The encrypted
native fixture closes/reopens real storage handles at each handover and retains
acceptance replay and subsequent text; it is not physical device qualification.
The [unused Deposit owner/recovery profile](../testing/s01-closed-deposit-retirement-2026-10-06.md#current-coupled-full--accepted-unused-deposit-profile)
is qualified on source25204bf/full706; it removes no known send/read/replay floor.
Other terminal/audit/replay dispositions, outstanding
receipt work and accepted-object/retained-route obligations must still close
before S04 cleanup. Fresh full-source acceptance is recorded separately.
The accepted S01 recipient block is the
[recipient application-receipt obligation](owned-application-receipt-obligations.md).
Its atomic inbox/due-work source and local reader are qualified on source6e9d2b3,
full726/0/0 terminal0. They do not activate receipt
sending or settle the sender's outstanding receipt/remote-object dependencies.
Capacity remains bounded backpressure; floors are not evicted to create space.
Local history, ratchet, inbox/dedup, mailbox grant/replay floors and remote objects
are not removed or extended by this change.
