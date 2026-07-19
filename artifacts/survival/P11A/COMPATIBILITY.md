# P11A compatibility note

The public addition is append-only:

- `ITransportOutboxRepository` is added to `ILocalSessionStore`;
- existing concrete stores implement it;
- `AccountGenerationSessionStore` delegates it through the existing account
  mutation barrier;
- the new feature flag is appended as the final optional positional parameter,
  preserving existing positional source calls;
- no existing message, group, inbox, transport or routing API is changed.

The physical database change is additive. Existing v7 tables, indexes and rows
retain their names and content. P11A adds two tables and two indexes, then
advances `PRAGMA user_version` to 8 in the same schema transaction.

Golden JSON fixtures are now explicitly checked out with LF endings through
`.gitattributes`, matching their already pinned raw-byte SHA-256 on Windows.

The outbox contract stores only opaque binary IDs, dedup material and ciphertext
bundle bytes. It does not assume MAUI, Android, Windows, HTTP, QUIC, P2P, LoRa,
mailbox or node-specific types.
