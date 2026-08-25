# Deep Client Shared Architecture

This library follows the Session clients at a domain boundary level:

- Desktop source: `ConversationModel`, Redux slices, `MessageQueue`, config wrappers, SOGS/community utilities, disappearing messages, attachment encryption pointers.
- Android source: config upload/download, database sync, message sender/receiver, notification and migration boundaries.
- iOS source: onboarding sync, push token sync, GRDB migrations, notification presenter/action handler, group screens.

## Layers

`Domain` contains immutable records for conversations, contacts, groups, messages, attachments, and settings.

`Persistence` defines repository abstractions for local storage. `SqliteSessionStore`
is the production path (with SQLCipher-compatible key hook), while
`InMemorySessionStore` remains test/dev only. The production database has one
physical baseline: application ID `DEEP` and schema version 15. There is no
logical schema store and no local migration API.
The dormant self-hosted profile boundary uses the existing settings table
through an atomic, bounded, account-generation capability. It stores at most
16 opaque candidates per account, 64 KiB per candidate and 512 KiB in total.
Sign-out closes the generation barrier before purging settings, so an
old-generation write cannot recreate state. Candidate verification is an
explicit in-memory operation over a defensive copy; there is no default DI,
network, UI, selection or activation path. A verified snapshot remains only a
snapshot and must be exported and re-verified inside a future approved atomic
activation transaction.

`Services` contains account registration/login, conversation creation, message send/receive through an `ISessionMessageTransport` (`HttpSessionTransport` in production, stub in tests), group-state/group-message sync through `IGroupSyncTransport`, sync plan creation, read-receipt/state-sync helpers, notification planning, and realtime call signaling/state handling (`RealtimeCallService`).

The P11 transport outbox has an opt-in runtime boundary in
`TransportOutboxDispatcher`. It accepts only already-opaque ciphertext bundles,
records every attempt before adapter I/O, distinguishes adapter acceptance from
durability, and runs only bounded caller-owned passes. Prepared, outcome-unknown
Attempted, and accepted-only items are eligible only at their persisted
`NotBefore`; repository revision CAS and the last-transition attempt identity
prevent overlapping or stale attempts from claiming acceptance or durability.
Durable, delivered, and expired items cannot start another attempt. It is not wired above
E2EE in `MessageService`, because that layer contains plaintext. Default and
release profiles remain disabled until a reviewed P03 producer and production
adapter provide opaque bundles and durable receipts.

Account restore accepts only the current canonical 13-word checksummed recovery
phrase. Twelve-word Deep phrases and raw Session ID login are intentionally
unsupported. Session ID derivation is deterministic and crypto-backed
(`PBKDF2-HMAC-SHA512` seed material -> Ed25519 keypair public key -> `05`
Session ID).
During restore, runtime attempts a network profile display-name lookup (`IRecoveryProfileLookup`) with timeout before falling back to manual display-name input.

E4 adds group admin/member-state lifecycle behavior into `ConversationService`: group rename, role promotion/demotion with last-admin safeguards, pending-removal updates, member removal, leave, destroy, group list/get APIs, and live local group-state publication/reception through Session storage.

`Platform` defines boundaries that MAUI implements per target: push notifications, media encode/decode, permissions, background work, share extension equivalents, and call lifecycle operations backed by shared realtime signaling.

## Session-Specific Decisions

- Account Session IDs use the `05` prefix; blinded IDs with `15`/`25` parse as valid contacts.
- Groups v2 use `03` conversation IDs. There is no legacy-group conversation
  placeholder or read-only compatibility branch.
- Groups v2 force disappearing messages to delete-after-send. Communities keep disappearing messages disabled.
- Local group sync publishes group state to member inbox storage and group messages to the group storage stream; `SessionStorageGroupSyncTransport` uses compat-service public namespaces for unsigned local e2e until the secure signed namespace layer is wired.
- Attachments are metadata/pointer records. Encrypted remote payloads use only
  the current `DEEPATT2` authenticated chunked format; other encrypted formats
  fail closed.
- Sync plans preserve the key Session ordering rule: group keys are requested last after group info and members.
- Persistent startup treats state as fresh only when the main database, WAL,
  and SHM files are all absent. Fresh state is created and attested as v13 in
  one transaction. Existing state is opened only after non-pooled key preflight
  and exact read-only attestation; runtime operations then use isolated pooled
  connections. Unsupported, corrupt, keyed incorrectly, or schema-tampered
  state raises `LocalStateResetRequiredException` and is never migrated,
  repaired, quarantined, deleted, or rewritten by startup.
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
dependencies. The clean-break runtime has no managed-storage compatibility mode: HTTP and routed
storage accept only opaque P03 metadata, and `ClientFeatureFlags.ReleaseDefaults` rejects any
transport that cannot prove that boundary.

The schema-v1 DEV-local mailbox credential importer is intentionally limited to one exact
Android↔Windows holder pair. Its Mr. X-signed approval pins the lane, platform, ownership,
authority, issuer, both holders and Session IDs, pair generation, manifest, and revocation
snapshot. A durable per-holder receipt permits exact idempotent replay and rejects same-epoch
replacement or epoch rollback. Schema v1 does not provision groups or third contacts.

Route diagnostics expose only `TransportRouteSnapshot.TargetKeyDigest`, a lowercase SHA-256
digest; the raw Session ID, placement key, or other route target is never retained in
`CurrentRoute`. Capability providers are checked for strict domain, lifecycle, attempt binding,
current validity window, bounded key material, and obvious raw Session-ID addressing before
storage I/O. Provider, crypto, and server error text never crosses the client boundary.

## Native authenticated client mailbox adapter

`ClientMailboxAdapter` is a portable, binary-only Store/Retrieve/Acknowledge
boundary for the pinned mailbox contract. Its public operations accept semantic
inputs plus the narrow `IMailboxOperationSigner`; the adapter obtains the sole
signed canonical MAU2 carrier from `MailboxAuthenticatedRequestFactory`.
The frame constructor remains assembly-internal, so callers cannot inject an
unsigned or alternate-version request. The binary ingress sends MAU2 only to
the exact mailbox-v2 Store/Retrieve/Acknowledge routes and accepts only exact
canonical MQR3, MRP1, and MQR3-backed MAR1 responses. Durable
transitions require two distinct pinned placement replica IDs and two distinct
Ed25519 keys, exact membership
and placement commitments, exact operation/generation/expiry bindings, and
valid replica plus coordinator signatures. Accepted and durable are persistent
outbox states; this adapter never creates a delivered transition.

Every MAU2 request is prepared in the durable transport outbox before network
I/O. Recovery looks up the operation ID first and reuses the byte-identical
persisted MAU2 frame, including the original replay counter, before it may ask
the credential repository to lease a counter. A bounded per-operation
single-flight covers read, credential lease, prepare, and dispatch inside the
process; persisted `NotBefore` plus repository revision CAS remains the
cross-instance authority. Every retry lease spans the operation HTTP deadline
plus a safety margin. Store persists the exact MQR3. Retrieve persists a strict
versioned MRSO summary containing the SHA-256 of the exact MRP1, epoch,
operation ID, request/response/result cursors, continuation authority, and item
count. Ack persists a domain-tagged SHA-256 commitment to exact MAR1. A
completed Retrieve is reconstructed only from its own validated MRSO summary,
never from mutable current traversal. A crash before outcome commit resends the
same MAU2. A crash after the accepted transition promotes the same attempt to
durable without allocating another counter.

`HttpClientMailboxBinaryIngress` owns its `SocketsHttpHandler`, disables
redirects before the first request byte can leave the pinned origin, disables
cookies and automatic decompression, and requires both platform TLS validation
and one of 1–16 configured SHA-256 SPKI pins. Cleartext is available only
through the explicit loopback-development factory; arbitrary remote `http://`
origins are rejected. The ingress also rejects origin changes, content
encoding, media-type parameters, wrong status/media/frame, truncated or
oversized bodies, and noncanonical round trips. Transport failures use a
closed enum with an explicit retryable bit; error bodies are forbidden. The
owned deadline covers request send plus success/error body reads, while caller
cancellation remains distinguishable and is never remapped.

Activation is fail-closed and disabled by default through
`ClientMailboxAdapterEnabled`. Explicit issuer context, a pinned two-replica
placement, and a configured binary ingress are all required. Only the current
native authenticated wire is accepted; the adapter has no downgrade, mirror,
or JSON path.

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
Traversal metadata is installation-bounded to 1024 live scopes and 128 KiB of
continuation tokens. A traversal row is reclaimable only at cursor zero with
an empty token, no inbox rows, and no expiry-quarantine evidence. If no such
row exists, admission of another scope rolls back rather than evicting live
replay authority.
In-memory acknowledgement commits clone and validate the complete installation
state plus expiry quarantine before publication, matching SQLite's global
transaction. A conflicting acknowledgement for an absent scope therefore
cannot allocate an empty scope or bypass these bounds. The coordinator journal
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
Length, overflow, and canonical-envelope decoder failures are normalized to
`InvalidDataException`. Mailbox inbox state, scoped official-cloud
credentials, replay counters, prepared fan-out headers/targets, and MAU2
outbox items share the exact physical schema version 15. Version 14 and every
older or incompatible catalog require an explicit
wipe/reset; none is dual-read, migrated, or retained for compatibility.

## Identity-authenticated mailbox seam

`E2eeClientTransport` retains the existing `ISessionMessageTransport` direct
send path. Official-cloud delivery requires the explicit derived capability
`IResumableMailboxIdentityAuthenticatedRawTransport`; a transport implementing
only `IMailboxIdentityAuthenticatedRawTransport` is rejected before encryption
or network I/O. The mailbox operation contract receives an
`IMailboxOperationSigner`, not a
`SessionIdentityProvider`: the facade exposes only the public identity and
exact domain-separated MCP2 presentation signing, never generic signing or
private-key access. It is invalidated before the operation's identity lease is
released, including on exceptions and cancellation.

For each send, E2EE first resolves and canonically orders the wire IDs and
transport decisions for the complete recipient set. Before encryption or any
network operation it atomically binds the semantic message to a local durable
plan containing every recipient, wire ID, Direct/Cloud choice, and cloud scope.
Exact retries are idempotent; recipient, route, or scope changes fail closed,
including all-direct retries of an earlier cloud batch. Outgoing group messages
also persist their exact notification-recipient snapshot in the message row and
reuse it after restart instead of consulting current membership.

The official-cloud subset is then canonically ordered by wire and credential
scope IDs and derives a fixed 16-byte domain-separated logical
batch ID from those selectors, the semantic message ID, and delivery kind.
It calls `TryResumeScopedMailboxBatchAsync` before generating randomized DPE1
ciphertext. A null result is exclusively a true durable miss; conflict,
corruption, stale holder/grant/epoch, lost outbox state, entitlement loss, and
revocation fail closed. Only that miss permits one
`PrepareScopedMailboxLogicalBatchAsync` transaction covering every
official-cloud fan-out target before any
`SendPreparedMailboxAuthenticatedAsync` dispatch. There is no per-target or
mixed resumed/new preparation path. Opaque prepared handles are created by the
transport and may be dispatched only through that transport. This producer contract
imposes the mailbox ciphertext bound of
81,768 bytes (`MailboxClientLimits.MaximumCiphertextLength`) on the decoded
DPE1 bytes after encryption, while ordinary DPE1 transports retain the
existing 512-KiB envelope limit. Every direct/group fan-out copy is built and
prepared before the first authenticated dispatch, preventing a later target
failure from producing a partial remote fan-out.

Free direct P2P and paid official-cloud delivery are selected only through an
explicit `IMailboxDeliveryPolicy`; transport failure never changes that choice.
The direct lane additionally requires an
`IDirectP2pSessionMessageTransport` capability. Generic storage/XNode
transports do not satisfy that capability merely because policy selected
`DirectP2p`, so a free operation cannot silently consume official managed
infrastructure.
`ClientRuntime.CreatePersistent` requires that policy whenever authenticated
E2EE transport is required and never supplies an implicit official-cloud
fallback. This keeps a caller's free-P2P choice distinct from infrastructure
usage at the composition boundary.
Official-cloud import verifies the canonical MCG2 bytes, issuer signature,
active lifecycle, independent monotonic generation floor, exact epoch validity
and placement/membership bindings, and unique grant serials before one atomic
commit. Trusted issuer entries have the protocol-defined key/domain,
lifecycle, generation range, and hard validity bounds. A deterministic digest
of the complete network/global-floor/issuer policy is persisted per scope and
must match after restart; a single issuer key is not a policy fingerprint.
Preparation and immediate
pre-I/O dispatch each revalidate the selected scoped grant against the current
clock, entitlement/authority, and revocation source. Prepared fan-out headers,
the exact ordered target catalog, replay counters, holder signatures, and
outbox rows are attested again on retry.

`ScopedMailboxCredentialRepository` over SQLCipher SQLite is the production
implementation. `InMemoryScopedMailboxCredentialRepository` is a test and
development fake only. It publishes a copy-on-write aggregate containing
credentials, counters, prepared batches, target catalogs, and outbox state
under one lock, so cancellation or an injected fault before publication leaves
the preceding state intact. A shared validation core and parameterized
conformance tests keep its import, counter, epoch-switch, resume, revocation,
and expiry behavior aligned with SQLite without creating a second production
storage path.

`OpaqueMailboxWireEntry`, `OpaqueMailboxContinuation`, and
`OpaqueMailboxInboxPage` remain portable opaque receive contracts.
An entry can be created only by strictly decoding and re-encoding MEO1 under
the operation's verified decode policy; its external digest is bound in
constant time to header bytes 96–127. They expose only a cursor, canonical
MEO1 bytes, digest, and continuation authority—never sender, recipient,
Session ID, or server hash. The retrieval seam is deliberately one-item: an
entry cursor must advance the requested cursor, a nonterminal continuation
must equal that entry cursor, and an empty page must be terminal. This reserves
the ordered one-item authenticated MBA2 acknowledgement shape without exposing
mailbox identity or plaintext through the portable receive seam.

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
