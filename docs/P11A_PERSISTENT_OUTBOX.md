# P11A persistent transport-neutral outbox

Owner: Mr. X

Status: dormant contract and local storage only. No runtime composition or
network adapter consumes this API in P11A.

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
stored expiry has elapsed. `Accepted` means only that an adapter accepted an
attempt. It is never interpreted as durable. `Delivered` requires a bounded,
typed recipient-device acknowledgement whose logical ID and dedup digest match
the stored item.

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

Opaque identifiers deliberately redact `ToString()`. Exceptions and transition
diagnostics use state, source and reason code only. They do not contain bundle
bytes, account identifiers, logical IDs, attempt IDs, dedup material, recipient
identity, or plaintext.

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

Quarantine does not exempt legacy ciphertext from the privacy lifecycle.
Scope purge first validates the recovery objects, deletes legacy attempts by
joining their logical IDs through the scoped recovery item rows, deletes those
items, and then deletes active rows in one transaction. Full account purge uses
the existing secure-delete transaction and removes every recovery attempt and
item before the active account tables. Missing recovery tables are normal;
partial, view-backed, or schema-incompatible recovery objects fail closed
before any active or recovery row is deleted.

The feature remains dormant and `PersistentTransportOutboxEnabled` is false in
both default profiles; no runtime composition reads this repository. During the
declared rollback window, an older binary may open only a copied pre-migration
database. The authoritative v9 file must not be opened by an older writer.
Operational rollback therefore restores the pre-migration file backup, never
edits `user_version` and never drops or renames P11A tables in place.
