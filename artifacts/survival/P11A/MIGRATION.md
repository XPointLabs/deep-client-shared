# P11A SQLite migration evidence

## Forward migration

Physical schema version changes from 7 to 8. The v8 transaction creates:

- `transport_outbox_items`;
- `transport_outbox_attempts`;
- `idx_transport_outbox_ready`;
- `idx_transport_outbox_expiry`.

No legacy table is dropped, renamed, rewritten or deleted. The migration test
creates a populated v7 database, opens it through `SqliteSessionStore`, confirms
the legacy marker is byte-for-byte present, confirms the new table exists and
confirms physical version 8.

Databases reporting physical version 9 or newer throw before mutation.

## Rollback window

P11A is dormant in both default profiles. The rollback window remains open until
runtime wiring is enabled in a later accepted wave. Rollback uses a preserved
pre-migration v7 database copy. Operators must not decrement `user_version`,
drop P11A tables in place, or let a v7 writer open the authoritative v8 file.

## Transaction properties

- schema creation and version advance share one SQLite transaction;
- item/attempt mutations validate persisted state inside an immediate write
  transaction;
- item and all attempts are replaced atomically;
- expiry batches are bounded and atomic;
- foreign-key cascade keeps attempts subordinate to one logical item;
- account purge includes both P11A tables in its existing all-or-fail delete
  transaction.
