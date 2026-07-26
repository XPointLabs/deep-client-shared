# Deep Client Shared

`deep-client-shared` is the portable .NET domain/state/services layer for a Session-style client.
It intentionally ports shared behavior and boundaries rather than UI line-by-line.

## Agent Specs

- Start with [`AGENTS.md`](AGENTS.md) before changing shared runtime behavior.
- Use [`docs/SESSION_PORTING.md`](docs/SESSION_PORTING.md) when migrating Session domain, storage, sync, push, attachment, group, or call semantics.
- UI-specific behavior belongs in `deep-client-maui`; this repo owns portable contracts and runtime state.

## Scope

- Conversation, contact, group, message, attachment, read receipt, and disappearing-message domain models.
- Sync orchestration primitives matching Session config/message namespaces.
- Local persistence abstractions with production `SqliteSessionStore` (SQLCipher-compatible key hook) plus in-memory implementation for tests.
- Notification planning abstractions.
- Platform service boundaries for push, media codec, permissions, background tasks, share extension equivalents, and calls.
- P03 opaque personal storage transport (`SessionStorageMessageTransport`) using explicit reviewed-provider boundaries for canonical DPB1/MCP1 deposit and retrieval. The raw Session-compatible wire shape remains available only through explicit `SessionStorageMetadataMode.LegacyCompatibility` for Debug/survival lanes; release defaults reject it.
- Session-compatible group sync transport (`SessionStorageGroupSyncTransport`) for local real group-state and group-message exchange via `/storage/store` and `/storage/retrieve`.
- Encrypted attachment file transport (`HttpAttachmentFileTransport`) for local real upload/download via `/file`.
- HTTP call signaling transport (`HttpCallSignalingTransport`) for real call offer/answer/bye exchange via `/api/calls`.
- HTTP transport integration (`HttpSessionTransport`) for custom production message APIs, plus `StubSessionBackend` for isolated tests.
- Opt-in P11 persistent outbox dispatcher for already-opaque ciphertext bundles. Activation requires the feature flag, an outbox-capable store, and an explicit `IBoundedTransportOutboxAdapter`; outcome-unknown attempts are persistently quarantined from redispatch. No default profile enables it and no current adapter is presented as production-ready.

Persistent runtime includes:

- SQLite-backed local store (`ClientRuntime.CreatePersistent`)
- optional SQLCipher key path (`sqlCipherKey`)
- legacy in-memory JSON snapshot migration (`legacyInMemoryStatePath`) without data loss (backup `.migrated.bak`)
- read-receipt cursor sync and disappearing-message pruning helpers in `MessageService`
- durable incoming-message notification handoff in `MessageService`, carrying message and conversation IDs and acknowledged only after platform presentation or active-foreground suppression

## Verify

```powershell
dotnet test Deep.Client.Shared.slnx
```

To include the live local storage round-trip tests for 1:1 messages, group state, and group messages, start the main repository docker stack and set:

```powershell
$env:DEEP_STORAGE_URL = "http://127.0.0.1:18100"
dotnet test Deep.Client.Shared.slnx --configuration Release
```

To include the live local push subscribe/unsubscribe test as well, set:

```powershell
$env:DEEP_PUSH_URL = "http://127.0.0.1:18102"
dotnet test Deep.Client.Shared.slnx --configuration Release
```

To include the live local encrypted attachment upload/download test and the message-with-attachment e2e, set:

```powershell
$env:DEEP_FILE_URL = "http://127.0.0.1:18101"
dotnet test Deep.Client.Shared.slnx --configuration Release
```

To include the live local call signaling lifecycle test, set:

```powershell
$env:DEEP_CALL_SIGNALING_BASE_URL = "http://127.0.0.1:18103"
dotnet test Deep.Client.Shared.slnx --configuration Release
```
