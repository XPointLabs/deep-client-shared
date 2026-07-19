# Deep Client Shared Architecture

This library follows the Session clients at a domain boundary level:

- Desktop source: `ConversationModel`, Redux slices, `MessageQueue`, config wrappers, SOGS/community utilities, disappearing messages, attachment encryption pointers.
- Android source: config upload/download, database sync, message sender/receiver, notification and migration boundaries.
- iOS source: onboarding sync, push token sync, GRDB migrations, notification presenter/action handler, group screens.

## Layers

`Domain` contains immutable records for conversations, contacts, groups, messages, attachments, and settings.

`Persistence` defines repository abstractions for local storage and schema migrations. `SqliteSessionStore` is the production path (with SQLCipher-compatible key hook), while `InMemorySessionStore` remains test/dev only.
The dormant P14A boundary uses the existing settings table through the atomic,
bounded, account-generation capability documented in
[`P14A_ATOMIC_STAGING.md`](P14A_ATOMIC_STAGING.md); it remains staged,
unverified, non-activating, and absent from runtime composition.

`Services` contains account registration/login, conversation creation, message send/receive through an `ISessionMessageTransport` (`HttpSessionTransport` in production, stub in tests), group-state/group-message sync through `IGroupSyncTransport`, sync plan creation, read-receipt/state-sync helpers, notification planning, and realtime call signaling/state handling (`RealtimeCallService`).

Account restore uses recovery phrase input only. Session ID derivation is deterministic and crypto-backed (`PBKDF2-HMAC-SHA512` seed material -> Ed25519 keypair public key -> `05` Session ID), while raw Session ID login is intentionally blocked.
During restore, runtime attempts a network profile display-name lookup (`IRecoveryProfileLookup`) with timeout before falling back to manual display-name input.

E4 adds group admin/member-state lifecycle behavior into `ConversationService`: group rename, role promotion/demotion with last-admin safeguards, pending-removal updates, member removal, leave, destroy, group list/get APIs, and live local group-state publication/reception through Session storage.

`Platform` defines boundaries that MAUI implements per target: push notifications, media encode/decode, permissions, background work, share extension equivalents, and call lifecycle operations backed by shared realtime signaling.

## Session-Specific Decisions

- Account Session IDs use the `05` prefix; blinded IDs with `15`/`25` parse as valid contacts.
- Groups v2 use `03` conversation IDs. Legacy groups are modeled as read-only conversations.
- Groups v2 force disappearing messages to delete-after-send. Communities keep disappearing messages disabled.
- Local group sync publishes group state to member inbox storage and group messages to the group storage stream; `SessionStorageGroupSyncTransport` uses compat-service public namespaces for unsigned local e2e until the secure signed namespace layer is wired.
- Attachments are metadata/pointer records: local plaintext handling and encrypted upload/download belong behind platform/service implementations.
- Sync plans preserve the key Session ordering rule: group keys are requested last after group info and members.
- Local data migration path supports importing legacy in-memory JSON snapshots into SQLite on first production startup.
- E3 call quality strategy computes rolling quality metrics and records explicit degradation diagnostics, then applies reconnect attempts before terminal failure.
- E4 onboarding/recovery edge-cases are validated by runtime tests (restore flow, malformed Session ID guard, persistence across restart), and acceptance evidence is tracked in `docs/e4-acceptance-checklist.md`.
- Full upstream Session account-linking restore semantics (network/profile fetch stage handling) remain a parity follow-up beyond current local deterministic restore flow.

## Route Trust V1

Routed storage bootstrap uses `PinnedRouterEndpoint` values containing both the router base URL and expected Ed25519 RouterId. `XNodeRpcClient` sends a cryptographically random nonce and accepts only fresh `xpoint-rpc-response-v1` responses whose signature binds the responder pin, request id, method, nonce, canonical request digest, success state, and canonical result/error digest.

Storage routes are parsed as request-local immutable results before `CurrentRoute` is updated as a diagnostic snapshot. A valid route has exactly three nodes at indices 0, 1, and 2; unique RouterIds, X25519 keys, and peer RPC endpoints; a first RouterId matching the pinned responder; reachable contacts; required `onion-v1` and `session-rpc` capabilities; and fresh valid contact self-signatures. The returned target must exactly match the requested target.

Dynamic membership authorization currently comes from XNode's exact `NodeDb` registered catalog plus the pinned seed response. A relay contact self-signature establishes contact integrity and key possession, never registry authority. A future quorum-backed catalog checkpoint may replace this authorization source; route trust v1 intentionally does not add a Merkle or on-chain checkpoint.

## E3 MVP Notes

- Current signaling transport is in-memory and intended for deterministic runtime/tests until secure network signaling is wired.
- SDP/ICE payload objects are compatibility-level placeholders; native platform WebRTC media engines are a parity follow-up.
- Parity target is to connect secure signaling + native media stack + observability export without changing shared call state semantics.
# Dormant membership trust slice (P07)

`MembershipTrustService` is a portable, fixture-driven trust reducer for the
pinned P04 canonical contract. It is deliberately absent from `ClientRuntime`
and every platform composition. Installation-scoped profiles keep independent
authority, bridge, and membership LKG chains in SQLite or the in-memory store.
Immutable records and CAS heads bind all persisted metadata with a
domain-separated SHA-256 corruption digest.

The digest detects accidental corruption only. This slice does not claim local
tamper resistance, approved production cryptography, live bootstrap, transport
availability, or production readiness. Both membership and legacy rollback
feature flags remain disabled.
