# P11A persistent transport-neutral outbox

Owner: Mr. X

Status: persistent contract plus an explicitly activated, bounded runtime
dispatcher. No production network adapter or P03 opaque-bundle producer is
shipped by this slice, so both default profiles keep the feature disabled.

## Runtime dispatcher boundary

`TransportOutboxDispatcher` consumes only a caller-prepared opaque ciphertext
bundle through `ITransportOutboxAdapter`. It is intentionally below the message
domain boundary: `MessageService` sees plaintext before `E2eeClientTransport`,
so wiring the repository there would persist plaintext and is forbidden.

`ClientRuntime` creates the dispatcher only when
`PersistentTransportOutboxEnabled` is true, the local store implements
`ITransportOutboxRepository`, and an adapter is supplied explicitly. Any
partial configuration fails closed. The dispatcher performs one bounded,
caller-owned pass and never creates a polling loop, recurring timer, or
background wakeup. The platform lifecycle remains responsible for deciding
when to run a pass.

Ready-list admission excludes items whose bounded attempt budget is exhausted
before ordering and `LIMIT`, so an old exhausted item cannot starve later work.
Each adapter call has a bounded cooperative timeout using a linked cancellation
token, capped by the item lifetime remaining immediately before I/O. The
dispatcher awaits cancellation completion and disposes the timeout source before
moving on; adapters must honor cancellation. The clock is refreshed per item and
immediately before adapter I/O, preventing a stale batch timestamp from
dispatching an already expired bundle.

An attempt is committed before adapter I/O. Adapter exceptions become only a
typed retry count so endpoint or identifier text cannot escape through this
boundary. `Accepted` is persisted as retryable and is never promoted to
`Durable` without separate bounded durable evidence. Cancellation propagates;
the precommitted attempt remains retryable. Commit-outcome-unknown errors are
reconciled by scoped point read before more I/O. Bundles that expire while an
adapter is running are marked expired instead of receiving a late success
claim.

## State and identity model

One logical item represents one opaque end-to-end bundle and one logical quota
event. It owns immutable opaque account scope, logical ID, end-to-end dedup
material, ciphertext bundle bytes, creation time, expiry, and zero or more
attempts. An attempt has an adapter-local opaque ID and its own progress. A
second transport attempt never creates a second logical item or quota event.
Persisted identity is the composite `(account scope, logical ID)`: the same
logical ID may exist independently in different account scopes. Point reads
and compare-and-swap mutations always require the scope; a foreign-scope read
is missing and a foreign-scope mutation is a conflict.

The monotonic logical states are:

`Prepared -> Attempted -> Accepted -> Durable -> Delivered`

`Expired` is terminal and may replace any non-terminal state only when the
stored expiry has elapsed. All non-expired timestamps use the canonical
half-open lifetime `[CreatedAt, ExpiresAt)`: prepared not-before, retry
not-before, acknowledgement time, and a delivered transition must be strictly
earlier than expiry. An expired transition is legal only at or after expiry.
`Accepted` means only that an adapter accepted an attempt. It is never
interpreted as durable. `Delivered` requires a bounded, typed recipient-device
acknowledgement whose logical ID and dedup digest match the stored item.

Each mutation stores a bounded source and reason code, retry/not-before time,
revision, and attempt-local evidence. The repository uses revision compare-and-
swap. Exact legal duplicates are idempotent. Regressions, divergent reuse of a
logical or attempt ID, and transitions over corrupt state fail closed.

## Atomicity and uncertain outcomes

Every SQLite write validates the complete persisted logical item and all its
attempts inside the same transaction before deciding success, conflict, or
idempotency. The in-memory implementation applies the same validation and
rollback rules.

Point reads bind the item row and its bounded attempt graph to one SQLite read
transaction. A mutation updates only mutable item metadata and inserts or
updates the single affected attempt row under a revision predicate. It never
rewrites ciphertext or other immutable columns and never deletes/reinserts the
attempt graph.

Cancellation before the transaction's durable point leaves no change.
Cancellation or injected failure after commit can produce an explicit
outcome-unknown error; callers must read by logical ID and reconcile using
revision and immutable transition evidence. Retrying the identical mutation is
safe.

## Bounds and privacy

All opaque identifiers, ciphertext, evidence, acknowledgement and diagnostic
reason fields have explicit byte or character limits. SQLite reads project
lengths and reject oversized or malformed rows before materializing BLOB or
TEXT values. Returned objects and byte buffers are defensive copies.

New-item admission also has per-account-scope engineering limits:

- at most 200 concurrent logical items;
- at most 8 MiB of immutable ciphertext-bundle bytes.

The byte budget deliberately counts only the logical item's immutable
ciphertext bundle. Attempt evidence and acknowledgements remain governed by
their per-value and per-item bounds. The limits are enforced atomically with
the insert: SQLite uses an immediate transaction and a bounded metadata-only
scan, while the in-memory implementation evaluates the same rule under its
existing lock. Same-ID reconciliation happens first. Rows already at or above
a limit remain readable, reconcilable, transitionable, and purgeable, but a
new logical item is rejected with the typed `CapacityExceeded` result.

These are storage-safety limits, not subscription, billing, entitlement, or
token-accounting policy. Changing either value requires an explicit decision
record covering migration and storage impact; commercial tiers must not
silently weaken the persistence safety boundary.

Opaque identifiers deliberately redact `ToString()`. Exceptions and transition
diagnostics use state, source and reason code only. They do not contain bundle
bytes, account identifiers, logical IDs, attempt IDs, dedup material, recipient
identity, or plaintext. SQLite store options also redact the encryption key from
their string and debugger representation and exclude it from JSON diagnostics.

## Mobile write and WAL budget

Incremental writes deliberately minimize dirty pages, WAL growth, flash
traffic, and checkpoint work. This is part of the mobile battery contract:
one transition must not rewrite the ciphertext bundle or every historical
attempt. WAL checkpoint policy remains owned by the shared SQLite store; the
outbox does not introduce per-message checkpoints, polling, background loops,
or extra wakeups. Attempts are read with a `MaxAttemptsPerItem + 1` sentinel,
never an unbounded query or `COUNT(*)` pre-scan.

P11A still reads and copies the ciphertext bundle while validating and cloning
a transition candidate. That CPU/allocation cost is a documented P3 for P11B;
it is not optimized here because changing the atomic state-machine boundary
would broaden this persistence-only correction.

The file-backed in-memory development store validates every outbox item and its
contract-bounded attempt list before admitting any outbox state. Its existing
whole-file JSON read remains an explicit P3 development/test limitation: it is
not a production persistence backend and currently has no declared whole-file
admission quota. P11B may replace that read with a bounded streaming format,
but P11A does not add an arbitrary quota that could reject snapshots the same
store just wrote or interfere with unrelated persisted domains.

## Migration and rollback window

P11A moves the physical SQLite schema from v7 to v9. A v7 database creates the
current composite-scope outbox tables while preserving unrelated rows. The
unpublished v8 draft lacked acknowledgement time and exact latest-transition
identity, so its rows cannot be upgraded by fabricating security metadata.
Empty v8 outbox tables are replaced transactionally. Non-empty v8 tables are
renamed to deterministic `transport_outbox_*_v8_recovery` quarantine tables and
empty v9 tables are created in the same transaction. Recovery-table name
conflicts or incompatible v8 layouts fail closed and leave version and rows
unchanged. Databases newer than v9 fail closed.

Migration attests the exact legacy table, foreign-key, and optional-index
layouts before any rename or drop. A same-name index owned by another table or
with a different key order is hostile state, not an index to replace. Row
presence uses a bounded `EXISTS` probe. At v9 open, both required indexes are
attested as non-unique, non-partial indexes owned by the item table with their
exact ordered keys. The attempts foreign key must be one two-column composite
constraint in account-scope/logical-ID order with `NO ACTION` update,
`CASCADE` delete, and `NONE` match semantics.

Schema attestation uses `table_xinfo`, rejects hidden or generated columns, and
enumerates the complete index set. Only the exact primary-key autoindexes and,
for the active item table, the two named ordered indexes are accepted.
Additional unique, non-unique, partial, expression, collation-altered, or
descending indexes fail closed. Active, v8, and quarantine outbox tables must
have no triggers of any timing or operation; this is checked before migration,
open, and purge so a trigger cannot suppress, redirect, copy, or mutate a
delete.

Quarantine does not exempt legacy ciphertext from the privacy lifecycle.
Scope purge first validates the active and recovery objects, explicitly deletes
active attempts before active items, then deletes legacy attempts by joining
their logical IDs through the scoped recovery item rows and deletes those items
in one transaction. The explicit active-attempt delete removes scoped orphan
evidence that a database writer could otherwise leave behind with foreign keys
disabled. Full account purge uses
the existing secure-delete transaction and removes every recovery attempt and
item before the active account tables. Missing recovery tables are normal;
partial, view-backed, or schema-incompatible recovery objects fail closed
before any active or recovery row is deleted. Recovery purge additionally
runs a bounded foreign-key integrity probe before the first delete. An orphaned
attempt therefore preserves all active and recovery rows for forensic
inspection, and the probe does not materialize ciphertext.

Scope purge enables SQLite `secure_delete` before its transaction and attempts
a best-effort `TRUNCATE` WAL checkpoint after commit with zero lock-wait
timeout. The checkpoint result is consumed: when another reader or writer
holds the WAL, maintenance is deferred and does not reverse or misreport the
already committed logical purge. A later purge or normal store maintenance can
retry truncation. These measures reduce ordinary page and WAL residue; they do
not promise physical erasure from flash translation layers, backups,
snapshots, or a WAL held by another reader. SQLCipher protects residual pages
while the database key remains secret. Robust account erasure ultimately
depends on database-key destruction and the surrounding database/backup
lifecycle, not on an unverifiable claim that storage media has overwritten
every prior copy. The current `Task` completion contract reports logical purge
only; it does not claim that post-commit WAL maintenance completed. A typed
maintenance-status surface is an explicit P3 before any product UI may claim
immediate forensic erasure.

The feature remains disabled in both default profiles. Runtime composition is
available only with an explicit opaque-bundle adapter; the current direct and
routed storage transports do not implement that producer/receipt contract yet.
During the declared rollback window, an older binary may open only a copied
pre-migration database. The authoritative v9 file must not be opened by an older writer.
Operational rollback therefore restores the pre-migration file backup, never
edits `user_version` and never drops or renames P11A tables in place.
