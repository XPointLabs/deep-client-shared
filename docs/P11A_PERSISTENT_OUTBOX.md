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

## Migration and rollback window

P11A moves the physical SQLite schema from v7 to v8 by adding only
`transport_outbox_items` and `transport_outbox_attempts` plus bounded lookup
indexes. Existing v7 tables and rows are not rewritten or deleted. Databases
newer than v8 fail closed.

The feature remains dormant and disabled at runtime. During the declared
rollback window, a v7 binary may open a copied pre-migration database; the
authoritative v8 file must not be opened by an older writer. Operational
rollback therefore restores the pre-migration file backup, never edits
`user_version` and never drops P11A tables in place.

