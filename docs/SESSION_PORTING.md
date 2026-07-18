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

- Session IDs and account material -> `Domain/Identifiers.cs`, `Domain/SessionAccount.cs`, `Services/SessionIdentityMaterial.cs`.
- Contacts/conversations -> `Domain/Contacts.cs`, `Domain/ConversationDomain.cs`, `Services/ConversationService.cs`.
- Messages/read/disappearing -> `Domain/Messages.cs`, `Services/MessageService.cs`.
- Groups v2 scaffolding/member roles -> `Domain/Groups.cs`, `Services/ConversationService.cs`.
- Attachments -> `Domain/Attachments.cs` plus platform media boundaries.
- Push -> `Services/PushSubscriptionTransport.cs`, notification planning, and MAUI push adapters.
- Calls -> `Services/RealtimeCallService.cs` and `Platform/PlatformServiceBoundaries.cs`.
- Local state -> `Persistence/*`.

## Current Accepted Deviations

- `StubSessionBackend` exists for deterministic unit/UI tests only.
- SQLite persistence is the production local-store shape; upstream client database schemas are not copied directly.
- Some crypto-sensitive behavior is represented behind protocol/transport abstractions until production adapters are available.
- P07 membership trust is a dormant local contract/storage slice. It survives
  account sign-out as installation state, but has no production verifier,
  runtime registration, fetch source, or platform UX.
- Group and call behavior currently covers launch-critical scaffolding/state, not every upstream management or media edge.

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

## Persistence Migration Rules

- Add a migration test before changing schema or local-state migration.
- Never delete legacy state until the new store has been written and verified.
- Preserve a backup path for one-way migrations.
- Corruption handling should quarantine bad state where possible and expose diagnostics.

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
