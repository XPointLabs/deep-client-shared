# Session Porting Spec - Client Shared

Last updated: 2026-06-10.

## Scope

This document governs migration of Session client runtime behavior into `deep-client-shared`. It covers portable behavior only: identity/account state, conversation and group rules, message sync, attachments, read/disappearing semantics, notification planning, push registration, local persistence, and call signaling state.

## Reference Sources

Use local upstream checkouts first:

- `../source/session-android`
- `../source/session-ios`
- `../source/session-desktop`

Use `deep-protocol` for protocol and crypto semantics. Do not recreate protocol behavior here when a protocol abstraction exists.

## Porting Workflow

1. Extract the Session behavior contract from upstream source and tests.
2. Decide the target layer:
   - domain invariant,
   - service orchestration,
   - repository/persistence,
   - transport boundary,
   - platform boundary.
3. Add a focused unit test in `tests/Deep.Client.Shared.Tests`.
4. Implement with deterministic clock/test doubles where time or retry behavior matters.
5. Verify SQLite and in-memory implementations stay aligned.
6. Document deviations and missing upstream dependencies here.

## Domain Mapping

- Session IDs and account material -> `Domain/Identifiers.cs`, `Domain/SessionAccount.cs`, `Services/SessionIdentityMaterial.cs`. Restore accepts only the current canonical 13-word checksummed phrase.
- Contacts/conversations -> `Domain/Contacts.cs`, `Domain/ConversationDomain.cs`, `Services/ConversationService.cs`.
- Messages/read/disappearing -> `Domain/Messages.cs`, `Services/MessageService.cs`.
- Groups v2 scaffolding/member roles -> `Domain/Groups.cs`, `Services/ConversationService.cs`; legacy-group placeholders are not supported.
- Attachments -> `Domain/Attachments.cs` plus platform media boundaries; encrypted downloads accept only the authenticated chunked `DEEPATT2` format.
- Push -> `Services/PushSubscriptionTransport.cs`, notification planning, and MAUI push adapters.
- Calls -> `Services/RealtimeCallService.cs` and `Platform/PlatformServiceBoundaries.cs`.
- Local state -> `Persistence/*`.

## Current Accepted Deviations

- `StubSessionBackend` exists for deterministic unit/UI tests only.
- SQLite persistence is the production local-store shape; upstream client database schemas are not copied directly.
- Some crypto-sensitive behavior is represented behind protocol/transport abstractions until production adapters are available.
- P07 membership LKG is now consumed by a portable verified route-catalog provider. MRL1 members
  are selected locally as exact ingress/core/storage routes and disjoint retrieve fallback never
  sends prior route IDs. Production platform registration remains disabled until an external
  signer/indexer publishes a real artifact and the app receives reviewed genesis/delegation pins.
- Group and call behavior currently covers launch-critical scaffolding/state, not every upstream management or media edge.
- Native official-cloud MAU2 preparation resolves opaque self, peer, and group
  credential selectors. Replay counters, complete fan-out preparation, and
  transport-outbox rows commit in the single attested local-state transaction.
  Free direct P2P does not enter this resolver and requires the explicit
  non-official `IDirectP2pSessionMessageTransport` composition capability.

## Non-Negotiable Runtime Parity

- Sending a message must create/update the conversation and preserve delivery state transitions.
- Receiving messages must map sender to conversation and avoid expired messages.
- Disappearing-message pruning must be deterministic and testable.
- Read cursor behavior must not mark outgoing messages as read.
- Group admin/member rules must prevent last-admin destructive mistakes.
- Push subscription transport must preserve provider token/service identity and unregister path.
- Push subscribe/unsubscribe DTOs always emit `sig_v: 2`. Their Ed25519 payload is the LF-terminated,
  UTF-8 byte-length-prefixed `deep.push/{subscribe|unsubscribe}/v2` canonical form pinned by
  `tests/Deep.Client.Shared.Tests/Fixtures/push-signature-v2.golden.json`.
- Release feature flags must reject stub-only launch-critical behavior.

## Local-State Baseline Rules

- Before production launch, SQLite has one supported physical baseline:
  application ID `DEEP`, schema version 11.
- State is fresh only when its main database, `-wal`, and `-shm` are all absent.
- Existing state must pass exact key, version, integrity, catalog, column,
  foreign-key, and index attestation before runtime access.
- Older, newer, unreadable, corrupt, or tampered state requires an explicit
  local reset. Startup must not migrate, alter, backfill, import, repair,
  quarantine, delete, or rewrite it.
- Legacy JSON/in-memory snapshots are not an approved local-state import path.
- Resource failures such as busy/locked, I/O, full, read-only, cannot-open, and
  out-of-memory are operational errors, not reset authorization.

## Evidence Checklist

For every runtime port, record:

- upstream Session files reviewed,
- Deep domain/service files changed,
- new or updated tests,
- known deviations,
- release-profile impact.

## Backlog

- Full Session config namespace sync parity.
- Rich attachment upload/download lifecycle with encrypted remote pointers.
- Complete message request/approval state.
- Full open/community group handling.
- Native call media integration hooks once MAUI platform layer is ready.
