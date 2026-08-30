# Deep Client Shared architecture

## Scope

`Deep.Client.Shared` owns portable domain models, SQLCipher persistence,
durable mailbox state machines, E2EE orchestration, and transport interfaces.
MAUI composition and platform TLS/secure-storage integration live in
`deep-client-maui`; exact wire codecs and cryptography live in `deep-protocol`.

The release message path is Deep-native authenticated MAU2. The assembly no
longer contains Session storage, Session RPC, JSON/base64 onion routing,
membership-route bootstrap, direct replica MAU2 HTTP, or their fallback APIs.
`StubSessionBackend` is retained only for deterministic unit tests and is
rejected by release composition.

## Native authenticated mailbox

`NativeMau2MailboxTransport` and `ClientMailboxAdapter` are the portable
Store/Retrieve/Acknowledge boundary. `MailboxAuthenticatedRequestFactory`
creates the only signed canonical MAU2 carrier. Every request is persisted in
the durable transport outbox before network I/O; retries reuse the byte-exact
MAU2, including its replay counter. MQR3, MRP1, and MAR1 responses are decoded,
bound to the exact request and credential route, and committed monotonically.

The pinned mailbox placement still contains exactly two distinct replicas and
their Ed25519 receipt-verification keys. Storage durability remains the
existing two-replica quorum. Privacy routing changes only the outer transport,
not MAU2 bytes, credential selection, receipt verification, inbox traversal,
or outbox recovery.

## Deep-native privacy transport

`PrivacyRoutedMailboxBinaryIngress` seals exact MAU2 through an ordered
three-hop route:

```text
client -> entry relay -> core relay -> mailbox exit
```

Each hop is pinned by a nonzero 32-byte RouterId and a separately provisioned
32-byte X25519 public key. Ed25519-to-X25519 conversion is not present. The
primary and fallback routes must have distinct HTTPS entry origins and must be
fully disjoint across all six RouterIds and X25519 keys.

The protocol-owned `BuildForCanonicalMailboxRequest` derives a
domain-separated operation binding from exact MAU2 and generates a fresh CSPRNG
attempt ID, hop replay IDs, ephemeral hop keys, and end-to-end reply key. The
mailbox exit returns DPR1 inside authenticated DRS1. A success DPR1 carries the
canonical mailbox response; a closed failure code maps to a sanitized
`ClientMailboxTransportException`.

The public entry request uses exact HTTP/2 HTTPS with platform trust and the
P10B managed-ingress media contract. Redirects, cookies, decompression,
identity/correlation headers, early data, content coding, and direct-mailbox
fallback are absent. The host/proxy must suppress noncanonical response headers
including `Date` and `Server`.

This is the current implemented carrier boundary, not yet the final
anti-blocking composition. `PrivacyManagedIngressHttpTransport` opens a direct
HTTPS connection to the signed entry origin. The MAUI Reality/Xray runtime is
not injected into this transport, so current tests prove onion privacy but do
not prove traffic masking or operation when the entry HTTPS origin is blocked.
Release requires an explicit masked-carrier implementation of
`IPrivacyManagedIngressTransport` with no silent direct-HTTPS fallback.

Fallback is allowed only when the primary proves forwarding did not start:

- canonical DIE1 `BeforeForward` with retryable policy;
- DNS, TLS-handshake, or proxy-tunnel failure known to precede request-body
  forwarding.

Cancellation, timeout, connection reset, truncated or noncanonical response,
reply-authentication failure, and terminal `OutcomeUnknown` after dispatch
raise `ClientMailboxDispatchOutcomeUnknownException`. They never select the
fallback. The prepared outbox attempt and its persisted retry lease remain the
only reconciliation authority.

## Signed activation binding

DEV physical activation accepts an exact Mr. X-signed policy property set. In
addition to authority, issuer, holder pair, generation, manifest, and
revocation pins, the policy now binds `privacyRoutesSha256`. Import copies the
expected 32-byte hash, validates the signed lowercase-hex value with a
fixed-time comparison, and clears the copied pin after use. This prevents
substituting entry origins, RouterIds, or independent X25519 keys after policy
approval.

## Persistence and recovery

The production store is SQLCipher-backed schema v16. Unsupported schemas and
incorrect keys require explicit reset; there are no migrations or dual
readers. Mailbox request preparation, replay-counter leasing, outbox attempts,
durable receipts, traversal cursors, continuation tokens, encrypted inbox rows,
acknowledgements, expiry quarantine, and coordinator replay evidence use
atomic transactions and revision checks.

An accepted/durable outcome is reconstructed only from persisted canonical
evidence. A crash before local outcome commit may resend the same MAU2 after
the bounded retry lease; replica and operation idempotency handle the replay.
A crash after accepted evidence promotes the same attempt without allocating a
new counter.

## Transport profiles and future ownership

`MailboxDeliveryPolicy` keeps protocol and infrastructure ownership
orthogonal. `AuthenticatedMau2` may be `OfficialManaged` or `UserManaged`;
`DirectP2p` must carry neither official authority nor mailbox selectors. The
portable E2EE, group fanout and durable logical outbox paths already expose the
required seams, but there is no production
`IDirectP2pSessionMessageTransport` implementation.

Future `DirectP2p` is a peer mesh requirement, not only a one-hop socket. The
same transport boundary must support direct links and authenticated multi-hop
store-and-forward without changing E2EE message or group contracts. Relays
must not receive plaintext or conversation keys. Routing must define bounded
TTL/hop count, loop and replay suppression, duplicate handling, partition
healing, relay consent and resource/abuse limits. It must not silently fall
back to an official mailbox.

Future on-prem composition must provide a distinct user-managed
authority/acquisition provider. It must not weaken official public-address
policy or make Registry, PMA1, billing or Mr. X implicit dependencies of these
portable contracts.

## Other portable boundaries

Attachments, push, call signaling, profile carrier verification, notification
planning, and platform-service interfaces remain separate from mailbox privacy
routing. The former Session group transport was removed. Group state, routes,
messages, replies and reactions now fan out as authenticated E2EE copies to
members' personal mailbox selectors through the same delivery policy. This is
covered by local tests; current Android/Windows physical group evidence is
still missing and no Direct-P2P group transport is implemented.
