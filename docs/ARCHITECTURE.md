# Deep Client Shared architecture

## Typed DID2 genesis admission availability (2026-10-02)

The bounded DGA1 client throws `DeepIdV2GenesisAdmissionUnavailableException`
for an actual 429/503 response, preserving its closed status and transport-bounded
delta-seconds `RetryAfter`. This `IOException` subtype is not a DGR1 receipt,
proof, trusted clock or permission to retry. Other status/crypto/transport errors
remain independently rejected. The client sends once and does not replace
operation IDs, reset identity/floors or consume a server response body as evidence
on failure. Display consumers can distinguish admission availability from proof
availability and stream IO without inspecting private messages. Wire, TLS/H2,
byte limits, request deadline and reconnect scheduling are unchanged.

## Exact expired XRA1 rejection (2026-10-02)

The genuine DID2 route fixture checks Protocol's closed `XRA1 / Expiry`
failure with still-current account/network evidence before any threshold signer
callback. The exact proposal remains unchanged. This focused native regression
is not physical delivery or an expired-intent renewal implementation; the latter
remains governed by
[DR-0051](../../docs/survival-program/decisions/DR-0051-owned-permanent-contact-client-entry.md).

[DR-0071](../../docs/survival-program/decisions/DR-0071-did2-reachability-advertisement-successor.md)
adds only Protocol's owned-device XRA1 successor author. The genuine protected
account fixture exercises expired signed predecessor input, exact lineage and
immutable caller snapshots, strict rejection of the old live proposal, hostile
input/key bounds and discontinuous/stale clocks. No successor is inserted into
the protected route journal by this author; no threshold callback or publication
is authorized. Shared pending/CAS/restart adoption and connected renewal remain
the next implementation, not physical Android recovery evidence.

[DR-0072](../../docs/survival-program/decisions/DR-0072-did2-route-renewal-lineage.md)
now supplies the subsequent route-artifact phases. The real account fixture
advances to expired route time, authenticates only a historical predecessor,
authors/completes its current successor and verifies it through the ordinary
route verifier, then advances the lineage again. Prior route currentness still
rejects. Forged history, wrong/gapped lineage, wrong custody, cancellation and
clock faults fail closed; mutable inputs/witness arrays are snapshotted before
callbacks. These Protocol candidates still do not mutate the Shared journal or
activate private production issuance/publication/device recovery.

## Retained issuance candidate verification (2026-10-03)

[DR-0074](../../docs/survival-program/decisions/DR-0074-did2-retained-threshold-issuance-evidence.md)
adds the closed Protocol completion/object boundary for an exact signed winner
after independent directory advancement. The real account fixture checks signed
issuance-head authentication, intermediate-head recovery, successor completion,
exact encrypted object restoration and fresh XPA authoring. Publisher minimum
and current XPA witness head are verified separately.
[DR-0075](../../docs/survival-program/decisions/DR-0075-did2-issued-head-response-custody.md)
connects the complete private response to verified protected custody and owned
reopen. Lost response and post-adoption crash tests recover after real directory
advancement, then author/publish on the actual issuance head with fresh authority.
These in-process signature/SQLCipher checks do not establish matched deployment
or physical contacts/messages/assets/groups. The predecessor-aware request and
current-only route journal follow
[DR-0077](../../docs/survival-program/decisions/DR-0077-did2-route-successor-coordination.md).
The schema change alone does not make retained expiry recover automatically.

## Protected committed/pending renewal (2026-10-03)

[DR-0078](../../docs/survival-program/decisions/DR-0078-did2-owned-publication-renewal.md)
connects the account-owned permanent-contact entry to route/object/publication
successors under one actual account lease. The fully committed predecessor stays
unchanged while exact pending phases advance. Only verified two-replica success
replaces it in one whole-slot CAS with independent readback. No public intent,
secret, time or signing callback is added; the existing journal generation and
wire bounds remain current-only. Reopen after promotion restores the persisted
winner without another threshold/publication/replica callback.

The native regression uses a genuinely signed short genesis proposal, actual
SQLCipher custody, current independently signed proof and device/witness/node
signatures. It exercises response loss, every adopted phase, hostile history,
late proof expiry, bad receipts and lost promotion reply. Its signed in-process
replica results are not remote durability or physical device evidence. Expired
incomplete proposals are retained and rejected, not silently reminted. Registry
publication predecessor verification/generation reservation, service/PMT rollover,
matched deployment and physical contacts/text/assets/groups remain release gates.

## Retired identity consumer cutover (2026-10-02)

[DR-0069](../../docs/survival-program/decisions/DR-0069-did2-retired-identity-surface-removal.md)
removes the former account, directory, resolver, direct-message and group owners
from source rather than restoring V1 verifier types or hiding them behind a new
compile exclusion. Current DID2 ownership and neutral routing/crypto contracts
remain; a namespace containing `V1` is not itself a retired wire capability.
The separate retired initiator outbox, recovery reader and fork table are gone.
The retained ratchet SQLCipher store now requires schema generation **9**;
generation 8 requires explicit reset, with no migration or dual reader.
Account-owned DID2 initial-session custody is not replaced by a caller scope.
The initial semantic inbox batch has only the account-owned DID2 minting path;
the former raw caller-scope factory and DAB1-only Hello fixture are removed.
Neutral ratchet atomicity/CAS/restart tests remain; initial business behavior is
verified through the genuine owned Hello/Accept/mailbox recovery fixture.

[DR-0070](../../docs/survival-program/decisions/DR-0070-did2-operational-genesis-proof-order.md)
also applies to the connected native test fixture: it authors the signed network
candidate, independently verifies a genuine DID2 directory proof, then completes
the topology under the fixture's current monotonic clock. That fixture is not
socket TLS, physical device, remote attachment or current group evidence.
MAUI consumers, final package/API gates and deployment remain separate work.
The current source checkpoint passes 53 focused ratchet/exact-DPE2/retired-surface
and genuine native receiver recovery cases, without skipped tests. Local custody
and two history regressions also passed 48 focused cases. The connected native
mailbox recovery scenario passed individually in a diagnostic batch that was
not green overall until its obsolete test paths were removed; it is not physical
delivery evidence. Windows and DID2 UI-core compiler checks passed independently.
The full required release gate is still deferred until the linked slice is complete.

## Durable ordinary command retry (2026-10-02)

[DR-0067](../../docs/survival-program/decisions/DR-0067-did2-ordinary-store-completion-and-ui-retry.md)
extends the existing ordinary journal with protected verified Store completion.
The owner advances only after the real adapter and final guards; initial/Accept
commands do not enter that ordinary phase. Local retry snapshots read actual
account/instance/catalog and verify the whole SQL mirror once in one transaction,
not one database reopen per command. They return original text/operation only;
no route, ciphertext, key or public completion input. Completion is historical
mailbox storage, not peer delivery. UI performs explicit reconciliation, never
automatic resend or replacement on unknown outcome. Old isolated QA instances
require explicit reset; physical and final batch gates remain separate.
Native connected unknown-Store and before/after-completion crash/reopen tests
passed with the existing deadlines and original exact request; see
[SPRINT-HISTORY](../../docs/SPRINT-HISTORY.md). No device claim follows from this.

## Application/mailbox random-key generation (2026-10-02)

[DR-0066](../../docs/survival-program/decisions/DR-0066-did2-application-sqlcipher-random-key.md)
changes only DMB1 to raw random-key interpretation, SQL generation7 and the
mandatory application registration (subsequently advanced by DR-0067). Initialization stays
atomic with the account; generation6/password mode/registration1 require
explicit isolated QA reset. No migration or relaxed ACK fence/deadline.
The existing FULL/secure-delete/WAL connection policy remains unchanged;
the account/session DELETE policy is not copied to the application store.


## Owned contact application commands (2026-10-02)

[DR-0065](../../docs/survival-program/decisions/DR-0065-did2-contact-application-command-boundary.md)
exposes the existing owned draft/completion/import/retirement and mailbox engine
through StartContact, AcceptContact, SendText, ListConversations and ListMessages.
Conversation handles have only internally constructed protected-catalog metadata;
they grant no freshness, acceptance, transport or ACK authority. Every command
rechecks the current account instance and independent endpoints. Text authoring
requires actual authenticated acceptance before allocating an outbox event.
Local start-operation metadata enables original-intent reconciliation, not trust.

The connected native vertical now calls these business commands and verifies
actual reverse Accept and subsequent text receive, semantic interruption, exact
retry after lost ACK and empty next poll. Exact evidence belongs to
[SPRINT-HISTORY](../../docs/SPRINT-HISTORY.md). The signed in-process fixture is
not socket/device, remote BLOB or governed-group evidence. Full API/graph review,
consumer repins and live/device activation remain open.


## Current mailbox issuer and grant evidence

[DR-0052](../../docs/survival-program/decisions/DR-0052-did2-mailbox-authority-distribution.md)
requires the complete raw network bundle, including public mailbox issuer
authority. The account source selects it only through the NETCODEC-verified
current projection and verifies root signatures and actual projected proof
time before network advancement and before releasing its internal context.
Protocol verifies exact grant results directly against the current DID2 route.
[DR-0053](../../docs/survival-program/decisions/DR-0053-did2-mailbox-grant-restart-custody.md)
connects the account owner's mandatory protected holder/request/winner journal
and internal selected-entry grant transport. Seed/request custody is read back
before callbacks; pending retries retain exact bytes, while a persisted winner
is independently reverified without reissuing. Missing custody requires explicit
QA reset, not lazy repair. Owned Retrieve uses only the protected, verified
phase-7 own publication capability and rechecks exact publication custody under
the held lease; it never accepts a public-resolve or caller secret. Deposit and
Retrieve have independent holder keys.
[DR-0055](../../docs/survival-program/decisions/DR-0055-did2-owned-mailbox-credential-installation.md)
connects that read-back winner to current-only SQL credential installation under
the same account lease. Interrupted installation resumes without new issuance;
same-epoch changed SQL material rejects. No signer/runtime authority is exported.
Live private issuer activation and actual credential dispatch/use still remain
gates; installing verified bytes does not deliver messages.
No V1 identity owner is restored for this composition.

## Owned mailbox sender entry

[DR-0056](../../docs/survival-program/decisions/DR-0056-did2-owned-mailbox-message-dispatch.md)
owns the connected local dispatch/custody contract. The internal
`DeliverOwnMessagingAsync` reads the actual committed outgoing operation, obtains
the protected grant and prepares exact MAU2 with an owner-private loan; it never
accepts caller ciphertext or keys. The mandatory protected send root is created
atomically with the account instance; an older disposable QA instance requires
explicit reset, not lazy initialization. Repeated sends keep original bytes and
time bounds. Missing/changed prepared SQL rejects. Selected-entry dispatch stays
gated on connected interruption/restart tests, matched live activation and device
evidence; durable mailbox receipt is not recipient consent or semantic ACK.

Initial contact Store follows
[DR-0059](../../docs/survival-program/decisions/DR-0059-did2-owned-initial-mailbox-dispatch.md).
The owner derives its scope from the actual retired sender source and protected
catalog; it must not dispatch caller-supplied DPH2 or use an ordinary-send fallback.
The connected local initial Store/receipt/Hello/ACK plus text Store/Retrieve
recovery checkpoint has passed; see the exact current evidence in
[SPRINT-HISTORY](../../docs/SPRINT-HISTORY.md). This is not live/device delivery.
The initial preview uses Protocol's committed-recipient factory under
[DR-0061](../../docs/survival-program/decisions/DR-0061-did2-committed-claim-recipient-verification.md),
not its current initiator factory. A delayed committed allocation still requires
current endpoint/inventory/placement authority and durable atomic key consumption.

## Owned permanent-contact client entry

Ordinary incoming dispatch follows
[DR-0057](../../docs/survival-program/decisions/DR-0057-did2-owned-incoming-session-selection.md).
`ReceiveOwnMessagingEnvelopeAsync` copies/decodes DPE2, finds the initialized
key-free scope from the actual protected account catalog, releases the lookup
lease, independently refreshes both endpoints, then calls the existing owned
ratchet/SQL/semantic materialization path. Unknown sessions do not create stores
or authorize ACK. The scoped low-level receive API remains an internal engine
boundary, not the shipping incoming dispatcher. Mailbox/initial/device closure
remains gated on connected tests and deployment.

Platform composition may call `SynchronizeOwnMailboxAsync(source, cancellationToken)`
for one bounded page. Only the actual account-bound source is public input;
grant/terminal fixture overloads remain internal. The sealed read-only result
reports processed envelopes (including replay/contact events), tombstones and
`HasMore`, not plaintext or ACK authority. The platform owns scheduling and
must not report those counts as new messages or as proven physical peer delivery.

Owned mailbox polling follows
[DR-0058](../../docs/survival-program/decisions/DR-0058-did2-owned-mailbox-retrieve-and-ack.md).
`SynchronizeOwnMailboxAsync` obtains own evidence outside the lease, derives the
recipient mailbox from the verified own publication and retains the exact page
before SQL mutation. ACK reconstructs semantic handoffs from actual committed
native receive rows; it does not trust a successful callback or supplied cursor
list. Its required protected read root is initialized with the account; older QA
accounts need explicit reset. The initial consumer independently refreshes the
parsed initiator DID2, then verifies the actual own published closure and composes
atomic receiver commit/import and authenticated initial materialization. ACK
rereads source/catalog/active mutable custody, not a successful callback.
Connected fault/reopen and initial-consumer evidence are pending; this internal
entry does not yet activate the MAUI receive loop, initial sender or group paths.

[DR-0051](../../docs/survival-program/decisions/DR-0051-owned-permanent-contact-client-entry.md)
exposes publication with only the actual account-bound network source. The
protected owner derives a restart-stable local intent from its instance and
verified display name, internally composes DR49 carriers and requires the
existing durable two-replica commit. A changed account-instance/name plan cannot
release a completed result. The public resolver accepts only the address and
account-bound source; caller-selected transports remain internal. Neither entry
exports keys or permits a direct Registry/legacy fallback. Durable commit and
verified read are not contact acceptance, mailbox grants or message delivery.

## DID2 owned private coordination carrier

[DR-0049](../../docs/survival-program/decisions/DR-0049-did2-three-hop-coordination-carrier.md)
owns the wire and gateway binding. Internal owned route/publication sources use
the existing selected-entry ONION transport with an actual account-held custody
loan, not direct Registry HTTP or recursive proof acquisition. Guards and entropy
still commit protected floors and exact SQL state; disposed/foreign loans reject.
The parent independently rechecks current proofs and authenticates threshold or
replica results before durable adoption. Internal adapters alone do not expose
shipping UI publication or certify TLS/socket/device delivery.

## DID2 permanent read boundary

Following [DR-0041](../../docs/survival-program/decisions/DR-0041-did2-permanent-contact-resolution.md),
internal `ResolvePermanentContactAsync` authors a read from the owned current
authorization under the account lease, performs one bounded selected-coordinator
attempt, opens a descriptor-bound parsed candidate and independently fetches its
current peer proof. The account-bound source verifies current network/directory
floors; the owner rechecks both endpoint proofs and network custody under the
account lease before returning the closed read result. No persisted trust flag,
prekey inventory, acceptance/session/message or automatic fallback is created.
The existing exact ONION transport can carry the neutral read; no bare Registry
resolver or DID1 credential bridge is added. Old inactive resolver/recipient
consumers still require removal, and network/expiry route renewal plus shipping UI,
remote transport and physical devices remain gates. SQL2/application6 and node
keys are unchanged.
Following [DR-0042](../../docs/survival-program/decisions/DR-0042-did2-route-directory-issuance-anchor.md),
retained object/phase-7 custody uses a signed issuance anchor plus independent
current proof/floors. Unrelated account admission does not trigger republishing;
new issuance and fresh dispatch are not authorized by historical bytes.
The exact prekey claim transport now bounds its one coordinator attempt to
30 seconds and observes cancellation even if the adapter ignores its token
([DR-0043](../../docs/survival-program/decisions/DR-0043-did2-claim-current-network-and-clock.md)).
Request custody remains before dispatch and verified result custody before
return. Current recipient/placement authority and monotonic receipt use remain
separate Protocol checks; no automatic new operation or claim follows failure.
Under [DR-0045](../../docs/survival-program/decisions/DR-0045-did2-owned-resolved-contact-claim.md),
internal `PrepareOwnPermanentContactClaimAsync` re-verifies the original read
candidate and both endpoint/floor authorities before restoring its protected
preclaim intent. Under one account lease it derives the exact publisher XPS1
from the verified DCB and atomically restores/reserves XPK bytes with their
original timestamps. The held-floor/clock and complete validity interval are
rechecked after SQL readback. An expired or changed reservation rejects without
reminting; completed intents recover existing session custody, not a new claim.
This prepares local request custody only; result promotion, composed initial
events and authenticated remote/device delivery remain separate gates.
Following [DR-0046](../../docs/survival-program/decisions/DR-0046-did2-owned-attachment-offer.md),
the owned ordinary-event journal also accepts AttachmentOffer, never a parallel
counter. `PrepareOwnDirectAttachmentOfferAsync` selects a stable protected asset
by its operation, verifies SQL/chunks and derives the exact DAM1 payload under
the account lease. The send boundary independently requires both stable draft
and asset custody plus current expiry; raw caller offers do not pass. Text/offer
operation substitutions reject. Local ownership/SQL tests do not establish blob
upload/download, receiver lifecycle, groups or physical device integrity.
The internal bounded `ListOwnMessagingAttachmentOffersAsync` returns key-free
history metadata after the usual current endpoint/session/floor checks. Its
shared canonical SQL reader checks BLOB type/length before allocation, exact
hash/scope/sequence and absence of a fork, then disposes parsed DAM1. History
entries do not grant current cancel/download authority; blob consumers must
independently reconcile that lifecycle.
Under [DR-0047](../../docs/survival-program/decisions/DR-0047-did2-owned-peer-refresh.md),
the verified seed's original public DID2 is inserted atomically with catalog and
floor registration into mandatory immutable protected metadata. Registered scopes
never reconstruct a missing credential from old proofs. Ordinary contact state,
accept, text/offer, send/receive and history service methods no longer take a
caller-held peer proof: the account-bound source independently refreshes own/NET
and the exact protected peer credential before entering the operation lease.
The existing held account/session/device/DMD/floor gates remain authoritative.
Changed heads reject pending verified successor composition. Structural evidence
does not establish real-clock TTL or physical delivery; shipping remains gated.

## DID2 owned contact-object boundary

The internal `EnsureOwnContactObjectAsync` composes current owned device,
retained prekey descriptor and the exact completed route into a signed and
capability-encrypted genesis object following
[DR-0037](../../docs/survival-program/decisions/DR-0037-did2-owned-contact-object.md).
Phase 4 is CAS-adopted and read back under the account lease before return.
Lost response/reopen retains exact bundle, signature, nonce and ciphertext;
changed profile or descriptor under the same intent rejects. The mandatory
route journal accepts only the current generation under
[DR-0077](../../docs/survival-program/decisions/DR-0077-did2-route-successor-coordination.md),
retaining DR73's unchanged complete request and the authenticated issuance head;
old disposable QA accounts require an
explicit local reset, never migration or lazy repair. No node identity/network
genesis reset is implied. SQL account/application shapes are unchanged.
Protected phases 5/6 retain the complete DID2 publisher request and verified
threshold response, with exact CAS/read-back before callback/return. The slot
remains bounded to 1 MiB and reserves a complete phase-7 entry before callbacks.
`EnsureOwnContactPublicationCommitAsync` verifies both selected-node receipts,
rechecks dispatch authority/account/floors, then CAS/readbacks exact XPO in
phase 7 before return. Reopen independently verifies that historical result
without threshold or replica callbacks; it never renews expired dispatch
authority. Node opaque durability and account custody have distinct tests.
This remains a candidate: shipping private coordination, replica publication,
holder/grants, shipping UI and physical Windows/Android are not activated.

## DID2 route-coordination boundary

The Registry candidate's V2 threshold endpoint, actual ADA2/external-floor
validation and permanent PostgreSQL exact replay follow
[DR-0036](../../docs/survival-program/decisions/DR-0036-did2-route-threshold-coordination.md).
The unused Shared DID1 `ContactRouteAuthorityClient` and its options-only tests
are removed; no direct HTTP compatibility facade remains in the Shared assembly.
The account-owned DR-0034 route owner still independently verifies every
threshold response and commits exact proposal/threshold/completion before release.
The entire pending threshold request, including its original directory minimum,
is committed/read back before dispatch and retained in every later phase. Reopen
uses a fresh independent proof but does not rewrite nonce-bound request bytes.
Signed head-only renewal with response loss is covered by the real account
fixture; it does not prove live PostgreSQL or physical expiry renewal.
DR42 still rejects old-head threshold adoption/completion after response loss;
the exact request/winner remains pending without remint. That separate retained-
issuance completion gate is not closed by fixing request replay.
Its real server integration lane uses TestServer plus native account custody;
shipping XPoint/OHTTP authority coordination and publication are not activated
by that evidence. Test-only friend access for the cross-repository boundary is
compiled only with `DEEP_TEST_INTERNALS`, never in the production assembly.

## DID2 historical recovery candidate

The proof factory now requires distinct bounded proof and history HTTPS
transports. On a typed current-proof 503 it can consume up to sixteen
64-head historical pages, independently verify each page, atomically advance
the SQLCipher protected floor and read it back before requesting a **new nonce**
current proof. Historical heads, including expired heads, never authorize
traffic. A 429 does not trigger history; a corrupt/forked floor never resets to
genesis. Transport ownership and concurrent calls are serialized.

Source callers must update both factory transports and sealed
`CommitCatchupAsync` implementations. No incompatible user-store migration,
account reset or production package publish is implied. The normative owner
is [DR-0014](../../docs/survival-program/decisions/DR-0014-directory-historical-catchup.md),
not this consumer note. Shipping MSG composition and physical reconnect remain
separate unfinished gates.

## Scope

The DID2 account service now exposes `EnsureOwnContactRendezvousAsync` for a
stable intent and its account-owned path source. It persists independent
metadata custody and exact signed XUR1 before return and recovers the same
winner after a lost protected commit response or restart. The mandatory
protected journal is initialized with the SQL instance; older/missing local
state requires explicit isolated QA reset, not a migration. Raw metadata
scalars never leave the account owner. The exact local layout/security contract
is owned by [DR-0023](../../docs/survival-program/decisions/DR-0023-did2-owned-rendezvous-author.md).
This is issuer/time custody, not route/publication, accepted contact, inbox or
ACK. Protocol is also the sole conversation-ID hash implementation under
[DR-0022](../../docs/survival-program/decisions/DR-0022-did2-contact-control-events.md);
the Shared identifier wrapper delegates to it.

`PreviewOwnDph2InitialClaimAsync` uses the exact account-bound source and
protected-tip-verified local inventory to open only unverified XPK1/XPC1
prefix evidence with opaque keys. It owns ciphertext before awaits, rechecks
both current DID2 proofs and continuous protected time, and makes no inventory
mutation. Missing or inconsistent custody is rejected, never repaired by the
preview. The bounded API belongs to
[DR-0024](../../docs/survival-program/decisions/DR-0024-did2-owned-initial-claim-preview.md).
Current claim promotion, atomic responder completion, message projection and
physical delivery remain separate requirements; preview does not grant ACK.

The internal account-generation prerequisite can also restore the same exact
DPK2 under the account lease for Protocol's owned responder preparation
([DR-0025](../../docs/survival-program/decisions/DR-0025-did2-owned-responder-preparation.md)).
Only its closed atomic-store capability leaves that helper; no public Shared
prepare-to-UI API exists. The caller must retain the lease through the later
exact replay and reservation/session transaction. The atomic continuation is
now implemented by `CommitOwnInitialContactSessionAsync` under
[DR-0026](../../docs/survival-program/decisions/DR-0026-did2-atomic-responder-custody.md).
It requires the closed promoted claim and independently current own/peer
proofs, retains initial ratchet/events and consumes the selected prekey before
returning a closed stable custody result. `FindOwnInitialContactSessionAsync`
checks protected history first and recovers exact ciphertext replay without
restoring a spent prekey or acquiring new network proofs. A mandatory protected
checkpoint permits exact pending roll-forward, not rollback or regeneration.
Missing checkpoint or retired PKV2 schema requires explicit QA account reset.
Message/contact projection, network shipping composition and ACK remain gated.
Isolated preparation fixtures
immediately consume/dispose the capability and do not claim durable receive.

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

## DID2 claim path candidate

`ContactResolveCanonicalPathRequest` reads XPK1 only through the Protocol V2
codec. `DeepIdV2ContactPathAuthoritySource.GetCurrentForPreKeyClaimAsync` obtains
an independent account-owned proof and derives NETCODEC claim placement; the
path provider re-verifies it for the exact canonical request. The ONION terminal
validator accepts only its exact V2 XPC1 pair. No V1 XPK1 fallback remains in
this path. The new API is path authority only, not recipient authentication,
claim completion, DPH2 session authority or permission to report delivery.
Those are separate consumers of the
[normative claim contract](../../docs/architecture/CONTACT-RESOLVER-V1.md#34-atomic-pre-key-claim-xpk1--xpc1).
The signed-network/SQLCipher/ONION-codec tests are not socket or device E2E.
Downstream clients must rebuild/repin Protocol and Shared together. The path
API itself does not reset accounts; the local claim journal clean-break impact
is specified below.

The internal `DeepIdV2PreKeyClaimTransport` now requires account-owned
`DeepIdV2ClaimRequestCustody` and reserves the exact request before even requesting
path authority. DSV2 root kind 8 stores the version-3, bounded operation-sorted
exact request/optional padded result snapshot and irreversible local fork flag. It reuses the existing
account/device/database-instance-bound two-slot floor mechanism; floor writes
precede SQL commit and no secure-storage slot is allocated per request. Exact
replay and lookup survive owner reopen; request or whole-result substitution
under the same operation fork-latches this journal. Capacity is 1,024 retained
requests, with the byte bound calculated to accommodate the largest closed
XPC1 bucket for every reservation. Capacity cannot be exhausted only after
dispatch because space for its result was omitted. At the request limit the
store refuses new operations, rather than evicting or resetting. Explicit account
reset purges these scoped slots through the existing V2 namespace boundary.

Successful XPC1 is recorded only through Protocol's selected-replica signature
capability, after both signatures and inclusion have passed, before the result
escapes the transport. Refusals, malformed responses and cancellation before
verification do not become successful result records. After owner reopen the
transport rechecks current placement and both signatures over the retained
pair without a second network claim. A first observed `Replay` result can be
retained; once retained, no different status/time/padding wire may replace it.
Request-only version-2 snapshots are rejected with no migration or dual reader;
affected isolated QA accounts require explicit reset. Node keys, network genesis
and floors are not reset by this local change.

This is exact request/result custody, not current-recipient authorization,
independent replica storage evidence, durable DPH2 preparation or session state. In particular,
initiator ephemeral/ratchet secret persistence and recovery, logical contact
intent binding, authenticated completion and shipping MSG composition remain
open. A lost response can repeat the retained request; this component does not
claim that an interrupted initial session can already be fully resumed.

## Account-owned restart-safe network history

The production test solution explicitly lists its three source Protocol
projects so the solution's selected configuration applies to the complete
graph. A Release Shared/test build must not silently use Debug Protocol
dependencies. This changes build configuration mapping, not crypto assertions,
the test selection, package pins or the production wire.

`DeepIdV2ContactPathAuthoritySource` now consumes the account store's complete
protected history, not a process-local predecessor cache or tuple-only restart
fallback. Verification, exact predecessor CAS, SQLCipher projection/history
commit and durable read-back follow
[DR-0012 client custody](../../docs/survival-program/decisions/DR-0012-protected-network-history.md#client-account-custody-extension-2026-09-29).
The source checks the proof's account against the store, and rechecks the exact
history before releasing authoring authority. Raw `IXPointNetworkStateStore`
CAS cannot initialize or advance this DID2 store; it only preserves the exact
floor and can permanently latch a fork. General/V1 stores are not accepted by
this DID2 authority source.

An initialized account with only the previous projection is incompatible:
it rejects without rewriting, migration, silent re-key or empty bootstrap.
Disposable pre-activation QA accounts require explicit application-owned
reset before this candidate is installed. The schema/account generation,
network records, signatures, directory floors and registered node keys are
not migrated. Retaining an expired predecessor enables lineage verification,
not expired traffic authority. Coordinated restore/deletion of both SQL and
protected storage is not detectable by this local custody.

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

The separate bounded binary Registry/service POST adapter uses exact HTTP/2
for HTTPS origins, with no HTTP/1 downgrade or retry. Only an explicit local
cleartext test origin uses exact HTTP/1.1. This does not change canonical
request/proof bytes or authority verification. Response-body reading remains
inside the original request deadline: successful headers and a partial body
cannot produce a proof or extend the timeout. Physical proof/body completion
must still be verified; transport unit tests are not device evidence.

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

### DID2-only selected-entry publication candidate

The replacement diagnostic publication path follows
[`DR-0009`](../../docs/survival-program/decisions/DR-0009-did2-selected-entry-transport.md).
`DeepIdV2AccountService.OpenOwnOnionClientCustodyAsync` opens local guards and
entropy reservations bound to the verified current DID2 account and DSV2
database instance. `PublishOwnStagedPreKeyInventoryAsync` accepts only this
account-owned custody and its DID2 authority source, not a fixed-origin or V1
host. The entry's address, port and TLS SPKI come from Protocol's verified
exit-specific path. Registry HTTPS retains platform CA trust.

DSV2 protected roots 4 (guards) and 5 (entropy) use two fixed SecureStorage
floor slots each. A protected marker is committed before SQL. Replacement
of a reused slot uses exact-value atomic SecureStorage CAS, never
delete/recreate or an unconditional upsert. Both in-memory and journaled stores
enforce this operation; the initial write API remains create-only. Repeated
reservations exercise more than two slot writes and preserve rejection of SQL
rollback and marker-before-SQL crashes after replacement. Interrupted,
missing or rolled-back state fails closed and requires explicit account reset,
not silent regeneration. This detects SQL-only rollback while protected
storage remains intact, not joint rollback of both stores. Entropy commitments
are canonical and never evicted: the 262,144-commitment bound rejects further
reservations rather than risking reuse. Capacity retirement/recovery remains
a release gate; no automatic reset or key-epoch retirement is implemented.

Request ephemeral/reply keys remain Protocol-generated one-use material; the
client never acquires a node receive-key vault. Local frame sealing and native
SQLCipher tests are not TLS deployment, remote XIC1, masked-carrier or physical
messaging evidence. MAUI's HTTPS-only physical UAT diagnostic now mounts this
publisher; no successful live publication or device result is claimed yet.

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
store is schema generation 7 under DR-0066. Unsupported schemas and incorrect keys require
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

Retired DID1 route/publication HTTP clients are removed. The internal DID2
account owner verifies exact route and publication threshold records against
current directory freshness and NETCODEC placement, retaining its exact pending
request before coordination. Shipping XPoint/OHTTP sources are still required;
TestServer callbacks do not activate a direct Registry fallback. HTTP success
or structural parsing never proves replica publication or delivery.

The isolated DID2 directory proof client uses only the exact DPQ2/DPP2
endpoint and bounded media types defined by the master
`ACCOUNT-DIRECTORY-TRANSPARENCY-V1.md` specification.
The production HTTP factory owns its HTTPS transport and exposes only the
bounded DID2 proof endpoint; it rejects non-loopback HTTP origins and timeouts over
30 seconds. A 429/503 raises
`DeepIdV2DirectoryProofUnavailableException` (an `IOException`) with its status
and optional `RetryAfter`. The transport retains positive delta-seconds only,
bounded to five minutes; dates/invalid hints are ignored. This is a scheduling
hint, not authenticated time or freshness. It does not automatically replay a
request/nonce, reset accounts or erase a floor. The owning recovery loop uses
bounded monotonic backoff and generates a new nonce for the next proof attempt.
The caller retains ownership of the verifier, monotonic clock and
account-scoped protected floor. The public proof entry points reject an absent
deployment profile or reader below V2 before protected-state or network access.
Before network I/O, the proof client requires a verified DAB2-bound ADL1 V2
query, XPoint authority and a store-restored protected reader-V2 LKG. A fresh nonce and one boot-stable
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
client and store are composed only in the isolated MAUI DID2 diagnostic lane,
not the production message runtime. Registry issuance,
Contact/XPK consumers and physical E2E remain required before a release claim.
For the account-owned genesis path, the proof client derives XPoint-only ADL1
V2 from the exact verified DID2 and that protected head, never from a caller's
raw lookup or floor. The bounded V2 admission client accepts DGR1 only as an
untrusted receipt. `AdmitAndVerifyGenesisAsync` requires the independent
ADH1/DTT1/ADP1 current-value proof to match the exact local DID2/DAB2/ADC1,
then rechecks the local account after network I/O. An unavailable or mismatched
proof leaves admission unconfirmed even if Registry returned HTTP 200.
Public HTTPS client composition can explicitly set `HttpServiceClientOptions.UseSystemProxy`
to honor the platform's configured proxy (including a system-proxy VPN).
The default remains direct-only; an owned connect callback and this option
cannot be combined. Platform origin validation, online revocation, exact H2,
byte/deadline limits and signature verification remain unchanged. A rejected
proxy tunnel does not transmit the binary request body, retry directly or
downgrade HTTP. The independently selected/pinned ONION entry connector remains
direct-only and is not affected by this public Registry option.
The initial account-owned DID2 pre-key author uses its conservative local
publication policy intersected with signed DCA1/device expiry, not the
short-lived ADH1 witness expiry. This follows the separate witnessed-freshness
and signed-publication lifetimes in the normative
[resolver specification](../../docs/architecture/CONTACT-RESOLVER-V1.md).
It does not extend an already staged XPS1/XPI1 or replace its exact retry
operation. Before dispatching even its manifest, the account-owned publisher
also applies the complete inventory verifier to independently refreshed DID2
authorization; protected historical staging alone is not live permission.
A remote commit/claim still requires an independently refreshed
current proof; expired staged inventories need the separately implemented
successor lifecycle, not silent key replacement or relaxed verification.
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
publishing the V2 current-account index. Its generation3 random-key encoding
and mandatory old-account refusal follow
[DR-0060](../../docs/survival-program/decisions/DR-0060-did2-account-random-sqlcipher-key.md).
A protected key record binds its
random key and database instance to exact network/account scope; the encrypted
database atomically initializes account, device and local-profile rows plus
empty LKG, outbox, inbox and security-event roots. Every current-account read
revalidates the SQLCipher generation and exact DID2/DAB2/device projection.
An interrupted pre-index SQL temp file can be recreated from the same verified
genesis and protected key; a database missing after index publication cannot.
Explicit local reset removes the exact V2 database family before V2 namespace
purge. Focused tests cover encrypted bytes, journaled-key reopen, wrong scope,
wrong generation, corrupted pending state and missing database/key refusal.
The DID2 account service can now hand its freshly reverified genesis DMD1 to
the concrete durable current-device store with a deterministic, account-bound
operation ID. Exact replay after restart is idempotent, a foreign account
scope fails closed, and retained-phrase deletion does not remove the verified
public closure. The service now opens an account-scoped encrypted device-state
database with a key separated from DSV2, verifies the exact DSV2 account
projection, and installs that genesis DMD1 while holding the account lease.
A protected install marker rejects silent recreation if the device-state file
is lost. Creation installs this state, MAUI remounts it for an existing account
on startup, and explicit V2 reset deletes its file family. This is only a
durable store commit, not a DPH2 agreement grant: production callers still
need the separate one-use authorization transaction before a session starts.
The same account lease now owns a separate `PKV2` SQLCipher initial-inventory
generation. The V2 inventory author consumes one signed XPS1 service object;
it rejects mismatched device, generation, validity or policy before creating
private offerings, rather than accepting separate raw capability/reference.
`StageOwnInitialPreKeyInventoryAsync` accepts only locally authored
DID2 V2 XPS1/XPP1/DPK2 capabilities, verifies the exact signed XPS1 V2
reference and scope against XPI1, and stores XPS1 with sealed private members in one SQL
transaction, and adds a protected install marker plus an add-only exact-XPP1
tip before returning publication eligibility. A crash after SQL commit but
before the tip is recovered by verifying the complete staged inventory and
writing the missing tip; a crash before SQL commit leaves no partial rows.
An install marker with no SQL file and no inventory tip can recreate only an
empty database, so an interrupted first open does not force account reset.
Reopen checks the verified DSV2 projection, derived
account/device key scope, full SQL/member rows and the protected tip; loss or
rollback of the staged file fails closed. Explicit V2 reset removes this file
family and its protected markers. The account service can read a copy of the
exact public XPP1/DID2/DCA1/XPS1 package after current-account and protected-tip verification,
including after restart; it does not release sealed DPK2 secrets. This is
local inventory custody only. Initial publication bytes can now
be prepared through `EnsureOwnInitialPreKeyInventoryAsync`: the account owner
obtains a nonce-bound current DID2 proof and verified network closure from its
own `DeepIdV2ContactPathAuthoritySource`, derives the exact local DMD1/DRS1
bindings and random service/operation capabilities, authors the complete native
inventory, independently verifies it through the replica verifier, and seals
all members before releasing public bytes. The initial local policy uses the
minimum complete inventory and a single-use last-resort offering; its lifetime
is bounded by the authoring policy, device certificate and contact delegation,
not the short-lived renewable directory head. Monotonic proof freshness and exact protected network custody are
rechecked after native authoring and before staging. A retry, including after
restart or interrupted tip recovery, returns the same protected bytes and
operation without minting replacement keys; this historical read does not grant
fresh placement or dispatch authority. Concurrent initial authoring in one
account service is serialized; competing owners cannot replace an existing
inventory. Protocol semantics remain owned by
[`CONTACT-RESOLVER-V1 section 3.3`](../../docs/architecture/CONTACT-RESOLVER-V1.md).
The DID2 V2 client transport can then
turn exact public XPP1 plus exact DID2/DCA1/XPS1 support into bounded ONION
fragments, send each to both current selected exits, and return only after
the Protocol verifier accepts both XIC1 signatures. The account service
now composes that transport with the protected staged publication and records
the exact verified XIC1 pair in an add-only account-scoped secure-storage slot.
Repeated completion, including after reopening the account, obtains fresh
account-bound proof and verified network authority, validates the complete
inventory/current DCA1 and reauthenticates both stored XIC1 signatures against
the current ranked publication placement. It rechecks freshness and protected
network custody after asynchronous marker reads before returning the exact
pair without a new ONION dispatch. An invalid or incompatible stored pair
rejects; it is not replaced or silently retried. This records an already
completed operation, not present replica availability, inventory retention or
claim authority. Those require their own current DID2 claim path. No inventory
expiry, pre-key member or publication operation is changed by completion reuse.
Its public entry point takes `DeepIdV2ContactPathAuthoritySource`, not the
pre-cutover `ProductionContactResolvePathAuthoritySource`. The DID2 source
accepts bounded raw identity-neutral network records, verifies them from the
pinned XNA1 root, and obtains a fresh proof through the account-owned
`FetchOwnCurrentDirectoryProofAsync` path. That path checks the protected
local DAB2/DMD1 both before and after the exchange without replaying admission.
Placement is released only after the independently verified network context
is committed and reread from `IXPointNetworkStateStore`, with the directory
proof still fresh. Providers and durable-store lifetimes belong to the caller;
`VerifyCurrentNetworkAsync` exposes that same verification/custody boundary
without a service capability or publication placement. The publication method
holds the same source gate through verification and placement derivation;
a preceding network check is never substituted for its fresh proof.
The source never accepts a V1 ADP1 or caller-projected placement. On restart it
uses the complete account-owned protected network history;
missing predecessor/checkpoint evidence is an error, not a floor reset.
`HttpDeepIdV2NetworkClosureArtifactSource`, created by the owned HTTP factory,
now fetches public raw closure bytes without uploading an account or protected
floor. It enforces endpoint/media/size/timeout and response-network binding;
it does not replace the verification above or grant permission for direct
acquisition when signed privacy policy forbids it. Exact envelope ownership is
[`XPOINT-NETWORK-V1 section 8.1`](../../docs/architecture/XPOINT-NETWORK-V1.md#81-identity-neutral-network-closure-distribution-ncq2ncp2).
`OpenNetworkLkgStoreAsync` now opens that network floor inside the verified
DID2 account's DSV2 SQLCipher generation, not a pre-cutover standalone store.
Operations share the process-independent account lease, revalidate the key,
database instance and immutable account projection, and bind the row to the
separately pinned genesis authority. An add-only account/instance-scoped
SecureStorage marker precedes each exact SQL CAS; rollback, missing/corrupt
rows, repinning and interruption after the marker all fail closed. A fork
latch cannot be cleared by CAS. Explicit account reset purges these markers
with the V2 namespace and removes the existing account database family.
The floor is protected local history, never proof of current placement;
fresh directory/network verification remains mandatory on every mint.
Repeated live mints now bind full genesis-to-terminal distribution to the
exact previously verified DNH2 policy/PMT history through the existing
[DR-0012 boundary](../../docs/survival-program/decisions/DR-0012-protected-network-history.md).
They do not replay genesis as an incremental successor after the tip or revive
an expired time capability. The account-owned restart boundary is described in
[the custody section above](#account-owned-restart-safe-network-history), not
a process-local cache. Physical advancement across a changed tip still needs
device evidence.
Reopen binds the pair to the protected exact XPP1; the stored pair is historical
evidence, not fresh placement or claim authority. The isolated MAUI HTTPS lane
mounts this publisher; its actual device results belong to
[the owner evidence note](../../deep-client-maui/docs/DID2-HTTPS-DEVICE-2026-09-28.md).
Remote claim, DPH2 and message device E2E are not implied.

The pre-XPK1 initiator entry point now requires a stable logical intent and
protected-time authority as well as the independently current proof. Its
candidate account owner initializes a protected intent journal atomically
with the SQL instance key and commits the opaque Protocol state before
returning a restored capability. Retry/restart keeps the same operation and
commitment. An absent journal requires explicit isolated local reset, not
repair or an old-format reader. Format and custody semantics have one owner:
[DR-0019](../../docs/survival-program/decisions/DR-0019-did2-preclaim-secret-persistence.md).
The closed initial-session candidate now replaces the burn-then-return
preparation API. It owns preclaim restoration, private one-shot agreement,
Protocol completion and protected-pending/SQL/stable publication under the
account lease. Its device schema is generation 4 with no previous reader;
missing checkpoints or stable-history rollback require explicit QA reset.
Only ciphertext/identifiers escape, not TRS1 or a private lease. The sole
normative local contract is
[DR-0020](../../docs/survival-program/decisions/DR-0020-did2-atomic-device-initial-session.md).
This candidate does not yet connect the shipping messaging caller. Focused
structural custody coverage passes nine cases, including exact pending
roll-forward before/after SQL commit and rejection of stable rollback or
substituted burn. One real DID2/signed-proof/claim fixture passes approved
native completion, exact restart and all three commit crash boundaries
(6m49s, loopback recipient/HTTP fixture, not physical evidence). The final
complete Release batch gate runs in hosted CI against the fixed candidate SHA.
Additional preclaim coverage verifies structural snapshot
boundaries and a real DID2 fixture's restart, interrupted protected commit
return, cancellation and refusal of missing proof/journal. This is isolated
integration evidence, not physical delivery; final batch gates remain pending.
This is PKV2 schema generation 3 under DR-0026; previous generations are rejected
without migration and can only be removed by explicit test-account reset.
This is not yet a full mutable STORE-01 service:
in-memory parity, restore-as-new-device,
directory/contact/messaging cutover and physical E2E remain open. No V1 contact
slot is read as V2.

The DID2 Shared account owner now owns application SQL through
[DR-0028](../../docs/survival-program/decisions/DR-0028-did2-application-event-handoff.md).
MAUI does not yet compose this new application owner or DID2 mailbox polling.
Earlier mailbox/ACK/UI claims from the removed account composition are not
evidence for the current client. The current internal owner projects canonical,
non-forked direct text only after current endpoint and retirement checks;
this is not contact consent, transport delivery or ACK authority.

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

The current per-session messaging owner is the DID2 DR-0027 implementation
described below, not the previous per-session crypto-store generation. No
conversion of its V1 scope/key/catalog is permitted. Current DID2 Hello
validation binds relationship, exact current DID2 endpoints, conversation and
signed rendezvous under DR-0022. The unsolicited responder receives the
non-null V2 initiator checkpoint and recipient
closure from Protocol's closed current-endpoint promotion, and consumes only
the fully verified claim's two-lane handoff. Its API clean break is owned by
[DR-0017](../../docs/survival-program/decisions/DR-0017-did2-initial-claim-promotion.md).
Protocol's only sender completion is now the current V2 asynchronous contract
in [DR-0018](../../docs/survival-program/decisions/DR-0018-did2-initiator-completion.md).
The old Shared V1 orchestration cannot call or adapt it and fails before a
session store opens. Account-owned V2 pending secret preparation and
shipping sender composition are still required; this is not UI activation.
The closed DID2 initial-session result now checks its TRS1 local directory
against retained custody and derives conversation metadata only by rechecking
the exact hash-bound initial events. This is the projection prerequisite in
[DR-0020](../../docs/survival-program/decisions/DR-0020-did2-atomic-device-initial-session.md),
not a V1 contact-scope adapter or a completed messaging-store projection.
The old recipient/placement API cannot accept a parsed V2 request. The account
initial-completion entry point now applies the current DID2 Hello endpoint
boundary before completion and rechecks it before returning retained custody,
under [DR-0022](../../docs/survival-program/decisions/DR-0022-did2-contact-control-events.md).
This checks metadata, not contact publication/route or inbox/ACK authority.
Current account-owned crypto receive and intermediate application retention
are implemented, but durable contact consent and protected semantic/stage
retirement remain unfinished. The current DID2 path does not mint mailbox ACK
receipts from retention alone. MAUI first-contact receive, current transport
composition and group membership consumers remain release gates. Unsupported
local generations require explicit pre-production reset, with no migration,
old Session scope adapter or dual reader.

## Transport profiles and future ownership

The DID2-only internal `OwnedInitialMessagingSeed` consumes closed sender or
receiver custody and rechecks independently current endpoint authority through
the account-owned source. Its owned buffers are wiped on failure/disposal.
The ownership/deletion contract is
[DR-0027](../../docs/survival-program/decisions/DR-0027-did2-messaging-session-ownership.md).
It is not a durable mutable store, retirement authorization or dispatch/ACK
capability. Ordinary messages cannot activate until durable initial-state
transfer and deletion of obsolete handshake secrets are verified.
The internal DR-0027 components now capture closed seed/Protocol mutations,
stage bounded protected parts, persist only the latest TRS1 in a dedicated
SQLCipher journal, and coordinate exact pending/cleanup recovery. Account-owned
catalog/key registration now uses atomic CAS-and-insert with an empty floor;
the derived per-session SQL path supports exact interrupted initialization and
rejects missing phase2 SQL rather than reimporting old state. Account-level reopen
checks authenticated sender/receiver source history and completed retirement
before active state release. Shipping MSG/platform composition and verified
rollover remain gated.
The unpublished DMS2 diagnostic schema1 is replaced by schema2's supported
SQLCipher raw-key encoding for the independent random catalog key, as frozen
in DR-0027. Temporary encoded key buffers are wiped; no secret SQL/hex string
is constructed. Account/source databases are unchanged, and no password-keyed
DMS2 compatibility reader or migration is provided.
Operation read-back verifies the complete SQL/floor binding and owns retained
DPE2/receive-DMC2 buffers. Restart retry uses journal data, not process-local
replay memory; read-back alone grants no semantic or transport receipt.
The DID2 account service now composes initial-to-mutable import under one
actual account lease. It reads authenticated source custody itself, consults
the protected catalog before any seed capture, imports only an exact empty
session, retires source keys and activates using the closed deletion receipt.
Seed/source copies are disposed before activation; imported/active retry does
not require erased initial TRS. Held-lease freshness readers authenticate the
same protected network/directory data without recursively acquiring the lease
or source/fetch gates, and cannot provision absent floors. This internal
composition returns key-free scope metadata, not MSG/dispatch/ACK authority.
Its recovery integration test is separate from physical device evidence.
Ordinary DID2 sends/receives now have a private single-use account-owned
Protocol transaction authority, not the isolated fixture's replay map or
synthetic retention digest. It authenticates current scope/source retirement
under the actual lease, derives replay/retention from verified SQL, commits
sealed transitions and independently reads the retained event before release.
Exact send retry returns original ciphertext; receive replay recovers staged
DMC2 without advancing state. Changed owned local send content uses a closed
durable latch and erases the live TRS; unauthenticated remote tamper rejects
without authorizing deletion. Owner copies of prior TRS are disposed before
durable commit. Local formats and capacity policy remain solely in DR-0027.
The account owner now applies verified retained initial events atomically and
hands actual committed ordinary direct events into its independently keyed
application SQL, without a V1 scope adapter. Exact replay preserves one semantic
row; conflicting logical IDs at the same authenticated authored position latch
the incumbent and cannot enter history together. SQL and in-memory behavior
agree. Current-generation schema objects/DDL are exact; initialized missing SQL
is never recreated. Required protected registration precedes account publication;
account-owned reads recheck endpoints and source retirement before projecting
non-forked text. Local bytes/key derivation/initialization policy are owned solely
by [DR-0028](../../docs/survival-program/decisions/DR-0028-did2-application-event-handoff.md).
Explicit local contact acceptance is now retained in account-owned protected
custody and materialized only from the actual committed DPE2 plus retained Hello
and current endpoint closure. The local authored position is reserved atomically;
exact replay is idempotent and a same-position conflict remains latched.
Local/peer acceptance views recheck actual send/receive custody, not just SQL
metadata. Formats and retry policy are solely owned by
[DR-0029](../../docs/survival-program/decisions/DR-0029-did2-contact-accept-custody.md).
Retained acceptance is not Active, dispatch/delivery or ACK authority.
Ordinary text commands now originate only from the account owner, using a
protected pending/stable journal and exact SQL mirror. It generates the logical
ID and sequence once, recovers the exact pending draft, and rejects missing
stable rows, counter rollback/advance or changed recipient/content. Responder
text requires actual retained acceptance and its existing counter. Raw text
and other uncomposed event kinds cannot enter account send merely because the
codec accepts them. Local format, capacity, reset and retry policy are owned by
[DR-0030](../../docs/survival-program/decisions/DR-0030-did2-owned-direct-text-outbox.md).
This is local queued-text custody, not transport acceptance or delivery.
Protected semantic rollback checkpoints, typed-event counter extension, MAUI composition and physical
contacts/files/images/groups evidence remain open.
Source custody now separates key-free metadata from the deletable initial TRS, and
the account-owned retirement journal covers source keys and sealed preclaim
copies. Exact completed retry precedes preclaim restore; retired intents keep
key-free tombstones. Activation accepts only the closed stable retirement
receipt, never parsed control metadata. The local source generations require
explicit QA reset, not migration; exact formats remain solely in DR-0027.
The narrow DID2 fixture checks bidirectional DPE2 text, skipped-key delivery
and replay against real SQLCipher with an in-memory protected adapter and
account-owned source retirement/activation, including crash recovery and
key-free exact retry. This validates isolated crypto/storage/source mechanics,
not shipping MSG/platform composition, active contact reachability, group membership,
blob transport or physical delivery. Ordinary crypto custody does not force
every event into the initial direct conversation; semantic/group authority must
validate that separately before materialization or ACK.

The attachment candidate now uses Protocol's frozen section-16 chunk cipher,
not the retired `/file`/DEEPATT2 production path. Shared owns exact-length stream
preparation, fresh object scope and independently disposable manifest custody;
the prepared ciphertext is immutable across retries/copies. The actual account
owner now adopts it into its SQLCipher application store using a protected
pending/stable asset journal. Recovery retains exact manifest/chunks without
the picker URI or plaintext; changed-input retry and registered SQL loss or
ciphertext substitution reject without reencrypting the adopted object.
Local bytes/reset/lifecycle policy is solely owned by
[DR-0031](../../docs/survival-program/decisions/DR-0031-did2-local-attachment-custody.md).
This custody grants no blob route, upload receipt or runtime activation. Masked
transport padding/resume, typed offer/cancel and MAUI images remain BLOB-01 gates.
The old HTTP reader/author/options/factory and its positive attachment tests
have now been removed. `IAttachmentFileTransport` retains only the UI file-I/O
boundary with explicit unavailable behavior; it cannot activate the blob path.

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

The internal `DeepIdV2MailboxOnionTransport` now derives a fresh DID2 network
context through the actual account-owned source for each scoped MAU2 attempt.
It reuses the identity-neutral mailbox codecs and path selector, binds the
request to its credential route before refresh, and derives TLS facts only
after selecting the exact three-hop path. Account-owned guards and entropy
are mandatory; foreign custody, unscoped calls and route substitution reject
before dispatch. The composition contract is owned by
[DR-0032](../../docs/survival-program/decisions/DR-0032-did2-mailbox-selected-entry.md).
No DID1 proof/source adapter or static ingress is introduced. This internal
carrier has no shipping caller yet: durable DID2 route adoption/publication,
protected random reachability-scoped holder, XMG1/XMC1 grants, adapter receipt
and semantic ACK remain independent prerequisites. Codec/path/SQL tests do
not establish socket, masked carrier or Windows/Android delivery.

Protocol's direct current-DID2 route verifier and three-phase genesis author
follow [DR-0033](../../docs/survival-program/decisions/DR-0033-did2-current-mailbox-route.md).
The narrow Shared fixture uses an actual SQLCipher account, nonce-bound current
proofs, retained owned device and real threshold signatures. This verifies the
Protocol boundary, not a durable route owner, publication, mailbox issuer,
transport callback or a shipping client feature. Shared must retain exact
metadata/route custody and recheck its protected account/network floors before
any publication or message dispatch; parsed records cannot substitute for it.

The internal `EnsureOwnContactRouteAsync` now composes that Protocol author
under actual held account/directory/network custody following
[DR-0034](../../docs/survival-program/decisions/DR-0034-did2-owned-route-custody.md).
The protected route journal is initialized atomically with a new account
instance; old instances missing it need explicit QA reset, not repair/migration.
Account/application table shapes remain unchanged; their current storage
generations are governed by DR-0060/DR-0066. Proposal,
threshold and completion are separately adopted with CAS and exact readback;
immutable configuration, delegation, scalar/key ID and coordination nonce are
retained for retry. Advertisement and threshold are independently verified
before callbacks/adoption. Secret-bearing temporary copies are zeroed.
The threshold source is internal and bounded to a 30-second wait, not a
shipping Registry endpoint. Route custody does not mint publication, holder,
grant, contact acceptance, semantic ACK, blob/group or device delivery evidence.

The old caller-owned DID1 mailbox acquisition client is removed under
[DR-0035](../../docs/survival-program/decisions/DR-0035-did2-mailbox-grant-request.md).
`VerifiedCurrentMailboxGrant`/replica models retain only neutral credential
bindings; they do not mint an issued grant. Protocol authors XMG1 directly from
current DID2 route/time and a captured holder key. Shipping requires a new
account-owned holder/request journal, exact retry before transport, live
publication, the DR52 verifier and durable XMC1
installation. The old identity/V1-storage holder owner is removed too; its
narrow signer has only an internal DID2 route/capability-bound factory, with
no public seed/storage/create/delete surface and no shipping custody producer.
It rejects wrong role capability/locator/PMT/PMS for XMG1 and wrong
network/holder/role/placement/epoch for MCP2; these scope checks do not authenticate
an issuer or topology and cannot replace the account owner.
Do not trust an arbitrary nonzero membership commitment as authenticated topology.

The internal `ReadOwnPrivateContactMailboxRouteAsync` drafts private reply
metadata only from the actual phase-7 own publication under the account lease
and final protected readback. It exposes no resolver-read, owner-retrieve,
metadata-scalar or holder capability. Its normative boundary is
[DR-0062](../../docs/survival-program/decisions/DR-0062-did2-private-contact-mailbox-route.md).
Independent current-peer verification is not authenticated event origin or
dispatch. [DR-0063](../../docs/survival-program/decisions/DR-0063-did2-contact-reply-route-embedding.md)
replaces Hello/Accept with mandatory private-route embedding and version2-only
variable acceptance custody. Ordinary owned Store reads only actual retained
authenticated Hello (responder) or peer Accept with native receive-custody
readback (initiator), then independently verifies its current peer route.
Permanent resolution remains initial bootstrap only; missing peer acceptance
retains the pending send without a resolver fallback. Connected reverse
Store/Retrieve/ACK, lifecycle renewal, shipping commands and physical device
verification remain activation gates. Old isolated QA state requires reset.

[DR-0064](../../docs/survival-program/decisions/DR-0064-did2-owned-initial-contact-draft.md)
connects the initial author to mandatory protected draft custody. The account
owns Init/Hello and the private package, checks the unchanged worst-case bucket
before rendezvous/claim mutation, and returns the exact persisted winner on
retry. Claim preparation refuses a missing draft. The connected internal
`CompleteOwnInitialContactAsync` uses only the source's proof client/clock and
actual retained claim; completed/retired sender sources are read back before
any new claim attempt. No raw-event UI contract or claim retry regeneration is
introduced. The root is initialized atomically with the instance key; explicit
isolated QA reset is required for older accounts. Public shipping composition,
complete graph/API review and physical device activation remain gated.

The internal `ReadOwnAttachmentPlaintextAsync` performs the existing actual-owner
DR31 SQL/protected readback before reconstructing a local adopted file. It uses
the frozen chunk cipher, validates complete geometry and the protected plaintext
digest, and returns independently disposable content only after all chunks pass.
No partially verified prefix reaches a file sink or renderer. It changes no
schema, wire or public transport contract. This is a local asset operation, not
an incoming-offer download permission, BLOB route, remote receipt or device result.
Masked remote storage/resume and shipping picker/preview composition remain open.

Attachments, push, call signaling, profile carrier verification, notification
planning, and platform-service interfaces remain separate from mailbox privacy
routing. The former Session group transport was removed. Group state, routes,
messages, replies and reactions now fan out as authenticated E2EE copies to
members' personal mailbox selectors through the same delivery policy. This
current path has no owner-sequenced predecessor-bound epoch or fork latch and
is not release evidence. The target keeps pairwise fanout but submits up to
100 members/500 active devices as one bounded durable logical batch with
device revoke/rekey semantics. No Direct-P2P group transport is implemented.
