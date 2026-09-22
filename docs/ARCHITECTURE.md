# Deep Client Shared architecture

## Scope

`Deep.Client.Shared` owns portable domain models, SQLCipher persistence,
durable mailbox state machines, E2EE orchestration, and transport interfaces.
MAUI composition and platform TLS/secure-storage integration live in
`deep-client-maui`; exact wire codecs and cryptography live in `deep-protocol`.

The currently implemented transport path is Deep-native authenticated MAU2.
Its Session-derived static-key E2EE and revision-only group model are
pre-production evidence and must be replaced by the clean-break `DPE2/DMC2`
ratchet and `DeepSmallGroupV1` before any public release. The assembly no
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
32-byte X25519 traffic key. Ed25519-to-X25519 conversion is not present. The
three RouterIds and traffic keys inside one route are distinct. A fallback may
reuse routers in the initial three-node deployment and therefore provides only
best-effort liveness, not an independent failure domain. Full six-router
disjointness is a later topology capability and is not a v1 release claim.

The protocol-owned `BuildForCanonicalMailboxRequest` derives a
domain-separated operation binding from exact MAU2 and generates a fresh CSPRNG
attempt ID, hop replay IDs, ephemeral hop keys, and end-to-end reply key. The
mailbox exit returns XPR1 inside authenticated XRS1. A success XPR1 carries the
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

The retired Session-derived store used SQLCipher schema v16; it is not the
clean production mailbox store. The current account-scoped `DMB1` SQLCipher
store is schema generation 2. Unsupported schemas and incorrect keys require
explicit reset; there are no migrations or dual readers. It retains mailbox
traversal, encrypted transport inbox rows, and durable transport outbox state.
Generation 2 adds a separate account-wide semantic DMC2 inbox for initial
SessionInit/ContactHello and direct messages, edits, reactions, receipts, and
attachment offers/cancellations.
It binds one local account generation, exact canonical event bytes, and the
semantic key `(conversationId, logicalMessageId, authorDeviceId)`. Exact
cross-session replay is idempotent; changed bytes under the same key create a
durable fork latch. Group DMC2 kinds cannot enter this direct-only handoff.
The previous `DMB1` generation-1 database requires an explicit preproduction
reset.

Bounded authority clients now cover both halves of permanent Contact
publication. The route client accepts only a verifier-derived XRA1 proposal and
verifies exact PMS2/XRC1/XSS1. The publication client accepts only a
device-custody-authored request and independently verifies exact XPA1/XPU1,
current directory freshness and InviteResolver placement. HTTP success or
structurally valid records never create a publication capability.

The clean MAUI account owner opens DMB1 with a distinct protected SQLCipher
key scoped to the account's store instance. It refuses an existing database
without that key or a retained key without the database, and removes the
database family on local account reset.
The account-owned receiver can now run one bounded self-mailbox poll on demand:
it opens DPH2/DAO1 or DPE2/DAO1, commits the authenticated inner event, and
ACKs only when every item in the retrieved batch is durably materialized.
Established DPE2 selects only an active exact session from the protected
catalog, including after restart; header selection itself grants no plaintext
or ACK. A partial batch remains unacknowledged for exact replay. A bounded,
account- and conversation-scoped read projects only canonical, non-forked
MessageCreate text from the encrypted semantic inbox for the client UI. This
does not author outgoing text or run a background receive loop.

An accepted/durable outcome is reconstructed only from persisted canonical
evidence. A crash before local outcome commit may resend the same MAU2 after
the bounded retry lease; replica and operation idempotency handle the replay.
A crash after accepted evidence promotes the same attempt without allocating a
new counter.

The clean account-owned inbound mailbox bridge reuses the transport's exact
MEO1/DAO1 validator: current route epoch and blinded IDs, external digest,
derived operation ID, DAO1 hash and local network must match before the
protected recipient key opens the DAO1. This returns only an opened DPH2/DPE2;
it does not stage a session, materialize an inbox event or authorize ACK.
For an opened initial DPH2, the protected pre-key owner selects only the exact
public DPK2 hash named by the initiation and checks its local device scope and
selected-prekey tuple. This read does not reserve or reveal a private pre-key.
The responder pre-claim path also requires its verified DPK2 offering to equal
that stored row before it can restore secrets. The caller must still obtain
current initiator-directory and XPC1 threshold evidence; this is not yet wired
to MAUI mailbox receive.

The separate clean-break per-session messaging-crypto SQLCipher store is schema
generation 8. A fresh authenticated DPE2 receive stages its exact DMC2 in the
same transaction as the ratchet/replay/deletion journal and TRS1 update. After
restart, the exact operation ID and envelope hash retrieve that pending DMC2;
an exact ratchet replay itself does not decrypt it again. Responder initial
DPH2 now stages exact authenticated SessionInit and optional first DMC2 with
TRS1 in one transaction, binds both event hashes into the initialization
fingerprint, and recovers them after restart. This is only a
recoverable E2EE-to-application handoff, not by itself MSG-01 inbox
materialization or mailbox ACK authority. A verified direct-session owner can
replay both staged events into the account-wide semantic inbox atomically.
An exact DPE2 send now stages its outbound ciphertext in that same ratchet
transaction; a crash after commit cannot lose the only encrypted envelope.
Recovery requires the exact operation ID and envelope hash and does not itself
authorize network dispatch. Generation 7 is intentionally rejected rather than
silently upgraded; physical UAT must use the isolated clean-break app identity.
For ContactHello the owner first binds relationship ID, verified peer DAB1/DMD1
hashes, the conversation ID derived from the relationship and both accounts,
and embedded XUR1 network, author device, DPD1 and lifetime. The unsolicited
responder additionally requires the current initiator checkpoint and verified
recipient bundle retained by DPH2/XPC1 promotion, then checks the exact safety
number and XUR1 device signature before opening a conversation store. This
does not close XUR1 to its PMT2 placement or authorize UI projection.
The account-owned initial receive can commit and materialize the authenticated
SessionInit/ContactHello before it grants a bound mailbox ACK receipt. Contact
state projection and protected stage-retirement remain incomplete. An
established direct DPE2 can mint an exact DAO1 ACK receipt only
through the combined ratchet-commit and durable-materialization factory;
initial DPH2, group, and unverified
or forked DMC2 still cannot mint one.
The relationship-bound responder path still requires pre-existing verified
contact evidence. For unsolicited first contact, the account-owned Shared
responder can now defer store selection until authenticated SessionInit and
ContactHello establish the conversation scope. Final exact replay resolves an
existing matching protected-catalog entry without reopening prekey secrets.
This path stages the initial events but applies no contact state and grants no
ACK. The staged result is exposed through the account-owned MAUI runtime,
without exporting its internal saga authority. MAUI mailbox receive and the
ContactHello/inbox transition still need to use it before first-contact receive
works.
Existing generation-5 session stores require explicit
pre-production reset; there is no migration or dual reader.

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
members' personal mailbox selectors through the same delivery policy. This
current path has no owner-sequenced predecessor-bound epoch or fork latch and
is not release evidence. The target keeps pairwise fanout but submits up to
100 members/500 active devices as one bounded durable logical batch with
device revoke/rekey semantics. No Direct-P2P group transport is implemented.
