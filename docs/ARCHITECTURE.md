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

The P11 transport outbox has an opt-in runtime boundary in
`TransportOutboxDispatcher`. It accepts only already-opaque ciphertext bundles,
records every attempt before adapter I/O, distinguishes adapter acceptance from
durability, and runs only bounded caller-owned passes. It is not wired above
E2EE in `MessageService`, because that layer contains plaintext. Default and
release profiles remain disabled until a reviewed P03 producer and production
adapter provide opaque bundles and durable receipts.

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

The survival development profile pins six endpoints but never lowers the
three-hop validation rule. Route acquisition has at most two attempts and may
use a different pinned responder after a connection/timeout failure. Once an
onion request is dispatched, `storage_retrieve` may use one disjoint fallback
after a connection/timeout failure or the signed exact
`onion-peer-transport-failed` result. `storage_store` never retries after onion
dispatch begins: any such ambiguous failure throws the sanitized typed
`StorageDispatchOutcomeUnknownException`, because a downstream commit response
may have been lost. Signature, responder identity, freshness, digest, contact,
replay/tamper, protocol, semantic, and storage-status failures always terminate
immediately. If a first route was acquired, all three of its RouterIds are sent
as exclusions and a retrieve fallback must be a disjoint signed three-hop
route. The storage body and deduplication material stay unchanged while the RPC
request id, route nonce, and route-attempt id rotate. This is bounded continuity
inside a fixed trust set, not dynamic discovery or proof of production anonymity.

Dynamic membership authorization currently comes from XNode's exact `NodeDb` registered catalog plus the pinned seed response. A relay contact self-signature establishes contact integrity and key possession, never registry authority. A future quorum-backed catalog checkpoint may replace this authorization source; route trust v1 intentionally does not add a Merkle or on-chain checkpoint.

## P03 opaque personal mailbox slice

Personal Session storage defaults to `SessionStorageMetadataMode.OpaqueP03`. Direct and routed
transports encode the existing DPE1 content envelope inside the authenticated P03A `DPB1`
compatibility envelope, present canonical P03B `MCP1` deposit/retrieve capabilities, and use a new
transport-attempt identifier for every storage request. Routed discovery uses the opaque placement
key rather than the raw Session ID. Repeated logical sends retain their end-to-end message ID only
inside authenticated encrypted content, so receiver deduplication remains unchanged while storage
correlation is attempt-local.

`OpaqueSessionStorageDependencies` is an explicit trust boundary. The shared assembly does not
ship a capability derivation, production P03A crypto adapter, or durable capability/replay
implementation. Release defaults therefore accept opaque metadata proof only from the two sealed
shared transport implementations in `OpaqueP03` mode; an arbitrary transport cannot forge a
marker interface. Production remains fail-closed until a reviewed producer supplies those
dependencies. A local Debug/survival lane may opt
into `SessionStorageMetadataMode.LegacyCompatibility` explicitly; it is never marked metadata
private and `ClientFeatureFlags.ReleaseDefaults` rejects it.

Route diagnostics expose only `TransportRouteSnapshot.TargetKeyDigest`, a lowercase SHA-256
digest; the raw Session ID, placement key, or other route target is never retained in
`CurrentRoute`. Capability providers are checked for strict domain, lifecycle, attempt binding,
current validity window, bounded key material, and obvious raw Session-ID addressing before
storage I/O. Provider, crypto, and server error text never crosses the client boundary.

## P09C staged client mailbox adapter

`ClientMailboxAdapter` is a portable, binary-only Store/Retrieve/Acknowledge
boundary for the pinned mailbox contract. It emits MST1/MRT1/MAK1 and accepts
only canonical MRR2/MQR3, MRP1, and MQR3-backed MAR1 responses. Durable
transitions require two distinct pinned placement replica IDs and two distinct
Ed25519 keys, exact membership
and placement commitments, exact operation/generation/expiry bindings, and
valid replica plus coordinator signatures. Accepted and durable are persistent
outbox states; this adapter never creates a delivered transition.

Activation is fail-closed and disabled by default through
`ClientMailboxAdapterEnabled`. Explicit issuer context, a pinned two-replica
placement, and a configured binary ingress are all required. Legacy mirror
overlap additionally requires both activation and decode-policy permission plus
a bounded expiry; the strict path does not downgrade to MQR2 or JSON.

Receive ciphertext, cursor, continuation token, deduplication, and ordered
acknowledgement state share one bounded atomic state machine across the
in-memory and SQLite repositories. A page is returned to its caller only after
the encrypted envelopes and its next traversal authority commit together. The
hot commit result contains only that committed page; recovery of the complete
unacknowledged inbox is an explicit operation, so normal polling never reloads
the full bounded store merely to report new items.
Crash-before-commit preserves the prior cursor/token; crash-after-commit
replays the durable inbox. Non-final XCT1 tokens persist across restart, while
a final empty-token MRP1 resets the next polling cycle to cursor zero.

SQLite state is available only through the keyed `SqliteSessionStoreOptions`
SQLCipher path. Scope keys are domain-separated hashes derived internally from
issuer context plus blinded mailbox ID; arbitrary production `FromBytes`
construction is unavailable. Runtime writes use normalized, indexed traversal,
inbox, expiry-quarantine, and coordinator-journal rows in atomic SQLCipher WAL
immediate-writer transactions with `synchronous=FULL`; this serializes
installation-global capacity checks across concurrent repository instances.
The legacy CMS1/CMS2 blob table is
migration-only and is never rewritten by the hot path. The coordinator journal
uses a separate installation/issuer-derived opaque scope, so a reused
membership/epoch/coordinator/sequence with a different statement is rejected
across mailbox IDs, epochs, issuer-context rotations, and restarts. Its 1024
statement capacity is installation-global rather than per issuer scope; exact
statements remain protected until their authenticated expiry, after which
expired rows are collected deterministically.

Before reads, retrieval, or acknowledgement, expired inbox rows are reconciled
deterministically across every mailbox/epoch scope in the installation.
Unacknowledged rows move atomically to a bounded encrypted
quarantine and are never converted to acknowledgements or delivered state;
acknowledged expired rows are removed. Quarantine count and ciphertext bytes
retain both per-scope and installation-global bounds; entries age out after 30
days with deterministic oldest-first pruning. Active inboxes retain their
per-scope 200-entry/8-MiB limits and additionally share a
1000-entry/32-MiB installation bound plus the canonical seven-day maximum
authenticated
lifetime. Capacity pressure first removes acknowledged rows from retired
scopes, then other acknowledged rows. If only live unacknowledged ciphertext
remains, the transaction fails closed instead of dropping or fabricating
state. Tombstone expiry is checked against the persisted retrieved envelope.
CMS1 could advance a cursor without retaining ciphertext, so migration first
backs up the old bytes and resets to a safe cursor-zero replay instead of
retaining a lossy cursor/dedup state. CMS2 migration backs up the original blob
before the atomic normalized cutover and is interruption-safe and idempotent.
Because a CMS2 mailbox-scoped coordinator journal cannot recover its original
issuer scope, its statements move to a separate opaque composite-key legacy
guard. The installation journal consults that guard until each statement
expires, preserving fail-closed equivocation detection without retaining raw
membership or coordinator identifiers in the normalized schema.
An installation accepts at most 1024 migrated mailbox scopes. Migration
backups plus corruption quarantine are jointly bounded to 1024 encrypted
artifacts and 64 MiB. A backup is collected only after the normalized
cutover has an atomic schema-v4 verification marker, the legacy row is gone,
and the 30-day recovery retention has elapsed. Schema-v3 completed migrations
backfill this marker from their committed backup-without-legacy invariant
before any GC. A corrupt sole recovery artifact is also retained for at least
30 days. If young recovery artifacts exceed either bound, startup rolls the
migration transaction back and leaves all legacy rows intact instead of
deleting evidence.
Length, overflow, and canonical-envelope decoder failures are normalized to
`InvalidDataException`; corrupt legacy rows are quarantined fail-closed.

## E3 MVP Notes

- Current signaling transport is in-memory and intended for deterministic runtime/tests until secure network signaling is wired.
- SDP/ICE payload objects are compatibility-level placeholders; native platform WebRTC media engines are a parity follow-up.
- Parity target is to connect secure signaling + native media stack + observability export without changing shared call state semantics.
# Membership trust and local route selection

`MembershipTrustService` is a portable, fixture-driven trust reducer for the
pinned P04 canonical contract. Installation-scoped profiles keep independent
authority, bridge, and membership LKG chains in SQLite or the in-memory store.
Immutable records and CAS heads bind all persisted metadata with a
domain-separated SHA-256 corruption digest.

`VerifiedMembershipRouteCatalogProvider` adds the activation boundary: it fetches an opaque
artifact only from migration bootstrap anchors, quorum-verifies the signed membership successor,
requires a complete sorted MRL1 catalog with one proof per member, and writes the verified artifact
to a bounded LKG cache. A directory outage may use that still-valid cache; a malformed, unsigned,
expired, rollback or fork candidate fails closed and never falls back to cache.

`XNodeRpcClient` can then select ingress/core/storage hops locally. Retrieve fallback keeps the
first route only in local memory and uses a disjoint second set from at least six members. No
mailbox target, route request or prior route IDs are disclosed to an ingress. Store dispatch still
has outcome-unknown/no-redispatch semantics for every timeout, cancellation, ordinary HTTP
failure, or signed downstream transport failure. A store may select one disjoint fallback only
when the injected HTTP transport raises the internal zero-byte pre-dispatch contract; the transport
must prove that no request bytes reached the selected first hop, and `XNodeRpcClient` never infers
that fact from an `HttpClient` exception. The failed three-node route is excluded locally before
the fallback is selected. Optional route evidence reports only operation/event/attempt plus
an independent random 128-bit per-call correlation ID and SHA-256 router-ID digests; it contains
no endpoint, target, account, mailbox, payload, response, exception data, or identifier derived
from them. One correlation ID spans every attempt/event for a logical `PostStorageAsync` call and
concurrent calls receive independent IDs. Evidence snapshots are immutable. The default observer
is a no-op; injected observers must be thread-safe, non-blocking, and prompt because calls may be
concurrent, while observer failures are ignored and cannot affect routing or delivery semantics.

Platform composition remains disabled until the external production signer/indexer publishes a
real artifact and MAUI supplies its pinned trust profile, verifier and durable cache path.
`RequireMembershipRouteSelection` is the release fail-closed switch; the legacy ingress-selected
route remains a migration-only compatibility path while that blocker is open.
