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

The isolated DID2 directory proof client uses only the exact DPQ2/DPP2
endpoint and bounded media types defined by the master
`ACCOUNT-DIRECTORY-TRANSPARENCY-V1.md` specification. It requires an already
verified DAB2-bound ADL1 V2 query, XPoint authority and a store-restored
protected reader-V2 LKG before network I/O. A fresh nonce and one boot-stable
monotonic request window bind the response; only the protocol's full PQ-backed
verifier can return a freshness capability. The HTTP client now withholds that
capability until an account-scoped protected store durably compare-exchanges
the exact next LKG. The DID2 account service now opens an account-scoped
SQLCipher implementation of that LKG contract from its verified current
account and a separately pinned, signed empty V2 head. A separate protected
add-only marker per revision pins the exact signed-head hash and SQL revision.
The next marker is written before each SQL commit, so a missing or rolled-back
SQL row fails closed; a
crash between the marker write and SQL commit requires explicit recovery or
reset rather than silently reopening an older floor. The existing account
lease serializes reset and compare/exchange; restart re-authenticates the
exact head against XPoint authority. A post-commit monotonic read prevents an
expired proof from escaping even when the durable floor advanced. The proof
client and store are not yet composed into MAUI. Registry issuance,
Contact/XPK consumers and physical E2E remain required before a release claim.
This marker scheme detects SQL-only rollback while protected storage remains
intact; it is not an independent monotonic anchor against a joint rollback of
both stores. The current journaled secure store is limited to 128 total slots,
so a scalable independent floor and crash recovery remain release gates.

An isolated V2-only protected genesis-contact slot now accepts already-verified
DAB2, DCA1 V2 and ADC1 V2 capabilities, checks their shared account/binding/
directory scope, and add-only persists the exact DPA1/DRS1/DPD1/DMD1/DID2/
DAB2/DCA1 V2/ADC1 V2 public closure as one record. Repeated exact writes are
idempotent; a different hedged DAB2 cannot replace the winner. A raw read is
explicitly untrusted; the separate verified read reconstructs DPA1/DRS1/DPD1
authority through the protocol's genesis-admission verifier and a pinned
ML-DSA verifier before returning the exact V2 lineage.
The focused restore test also disposes the recovery authority and phrase before
re-verifying the same hedged DAB2, so restoration cannot silently reissue it.
An adjacent V2-only add-only slot separately protects the four genesis device
secrets; it writes only against a verified DPD1 and restores only if the derived
public keys, device ID, revocation handle and account scope still match that
DPD1. Neither slot reads V1 state. A
two-slot bootstrap boundary now writes secrets first, writes the public closure
second and returns local authority only after a full verified read-back.
Either one-slot partial state fails closed; retry with the same exact inputs
completes it. It does not itself retain the phrase or implement account UI.
A separate V2-only protected phrase slot now checks the 24-word phrase against
the exact account ID. Explicit removal first requires a fresh verified
two-slot bootstrap, then leaves an add-only scoped deletion marker so stale
writers cannot restore the local phrase. Reads clean up any phrase bytes left
by a crash between the marker and physical deletion. MAUI settings/reveal and
app-level account lifecycle composition remain open.
The secure-storage contract now has an exact `deep.store.v2.` namespace purge,
implemented by the in-memory and journaled production adapters. The purge is
idempotent and leaves V1 and unrelated slots untouched. The isolated V2 owner
uses it during explicit local reset; MAUI reset wiring remains open.
DXP1 device issuance persistence now accepts an explicit store-generation
selection. Existing V1 callers keep the V1 namespace; a DID2 bootstrap selects
V2 and never reads the V1 profile/nonce/state slots. The focused DID2 fixture
uses V2 issuance and proves the V1 profile slot remains absent.
An isolated offline issuer now composes the protocol's real DPA1/DRS1/DPD1,
hedged ML-DSA-backed DID2/DAB2, DMD1/DCA1 V2/ADC1 V2, V2 phrase custody,
V2 DXP journal and verified two-slot bootstrap. Its test creates one account,
opens the exact same DID2/DAB2 from a new bootstrap instance, deletes the
phrase, and verifies the same binding again. This is not the release account
owner: it has no SQL generation, UI, contact transport or physical-device E2E.
An isolated add-only V2 current-account pointer now binds a canonical display
name, network and account ID only after a fresh verified bootstrap. Reads
reverify the entire bootstrap; a partial account cannot be published and a
different name/account cannot replace the winner. An isolated protected-state
owner now acquires an OS file lease and atomically writes normalized-name intent
and candidate account ID before issuing secrets. It publishes the index only
after verified bootstrap. If the exact public closure is durable but the index
write crashes, a fresh owner verifies the complete bootstrap and publishes the
same DID2/DAB2; reset is refused until that winner is recovered. If no public
closure exists, interrupted creation stays fail-closed until explicit V2 reset
under the lease purges the local V2 namespace. A public closure with incomplete
device secrets also refuses reset; exact repair remains open. Journaled-store
reopen tests cover both normal creation and a crash before index publication.
Phrase read and explicit deletion also run under the account lease against a
freshly verified current account; deletion survives another close/reopen without
changing DID2/DAB2.
The owner now also creates an incompatible `DSV2` SQLCipher generation before
publishing the V2 current-account index. A protected V2 key record binds its
random key and database instance to exact network/account scope; the encrypted
database atomically initializes account, device and local-profile rows plus
empty LKG, outbox, inbox and security-event roots. Every current-account read
revalidates the SQLCipher generation and exact DID2/DAB2/device projection.
An interrupted pre-index SQL temp file can be recreated from the same verified
genesis and protected key; a database missing after index publication cannot.
Explicit local reset removes the exact V2 database family before V2 namespace
purge. Focused tests cover encrypted bytes, journaled-key reopen, wrong scope,
wrong generation, corrupted pending state and missing database/key refusal.
This is not yet the MAUI account owner or a full mutable STORE-01 service:
app-private path provisioning, in-memory parity, restore-as-new-device,
directory/contact/messaging cutover and physical E2E remain open. No V1 contact
slot is read as V2.

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
