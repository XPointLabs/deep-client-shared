# Deep Client Shared

`deep-client-shared` is the portable .NET domain, state, persistence, and
service layer for Deep clients.

## Agent Specs

- Start with [`AGENTS.md`](AGENTS.md) before changing shared runtime behavior.
- UI-specific behavior belongs in `deep-client-maui`; this repo owns portable contracts and runtime state.

## Scope

- Conversation, contact, group, message, attachment, read receipt, and disappearing-message domain models.
- Sync orchestration primitives matching Session config/message namespaces.
- Local persistence abstractions with production `SqliteSessionStore` (SQLCipher-compatible key hook) plus in-memory implementation for tests.
- Notification planning abstractions.
- Platform service boundaries for push, media codec, permissions, background tasks, share extension equivalents, and calls.
- Encrypted attachment file transport (`HttpAttachmentFileTransport`) using the authenticated chunked `DEEPATT2` format for local real upload/download via `/file`.
- HTTP call signaling transport (`HttpCallSignalingTransport`) for real call offer/answer/bye exchange via `/api/calls`. The transport fails closed without active identity material. Its clean-break `deep-call-*-v2` canonical contract gives every signal, inbox read, and ICE request a fresh signed 128-bit nonce; GET signatures also bind method and absolute path. There is no unauthenticated or v1 wire fallback.
- `StubSessionBackend` remains only as a deterministic in-memory test transport;
  no Session HTTP/storage/onion implementation is shipped by this assembly.
- Deep-native authenticated mailbox delivery through
  `PrivacyRoutedMailboxBinaryIngress`: exact canonical MAU2 is sealed over one
  of two pinned, router-disjoint three-hop routes. Only a proven
  before-forward rejection may select the fallback; ambiguous outcomes remain
  attached to the durable outbox attempt. Public entry transport is strict
  HTTP/2 HTTPS with platform trust and has no direct-replica fallback.
- Opt-in P11 persistent outbox dispatcher for already-opaque ciphertext bundles. Activation requires the feature flag, an outbox-capable store, and an explicit `IExternalTransportOutboxExecutor` backed by an independently killable bounded worker process; an in-process task/thread adapter is rejected as insufficient. Outcome-unknown attempts retain a persisted `NotBefore` lease and become retryable only after that bounded lease expires; accepted-only receipts remain retryable until the currently authorized attempt becomes durable. No default profile enables it and no platform executor is currently shipped.

Persistent runtime includes:

- SQLite-backed local store (`ClientRuntime.CreatePersistent`)
- optional SQLCipher key path (`sqlCipherKey`)
- read-receipt cursor sync and disappearing-message pruning helpers in `MessageService`
- durable incoming-message notification handoff in `MessageService`, carrying message and conversation IDs and acknowledged only after platform presentation or active-foreground suppression

## Verify

```powershell
dotnet test Deep.Client.Shared.slnx
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
