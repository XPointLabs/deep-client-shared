# Owned connected group candidate

Decision/limits: [DR-0144](../../../docs/survival-program/decisions/DR-0144-multi-account-group-batches.md), extending [DR-0143](../../../docs/survival-program/decisions/DR-0143-owned-connected-group-candidate.md).
Wire/roles/current-directory predicates belong to
[CONTACT-AND-GROUP](../../../docs/architecture/CONTACT-AND-GROUP-PROTOCOL-V1.md#13-deepsmallgroupv1),
not this repository. Generic group DMC2 authoring stays disabled.

## Local custody

Account creation atomically registers `deep.store.v2.groups`; ordinary account
reopen authenticates it with the other mandatory roots. Missing, foreign,
corrupt or unsupported state rejects without regeneration/import/migration.
Application SQL schema17 only increases the ordinary event payload bound.
The common ordinary journal9 owns all sender sequences; there is no separate
group transport counter. Old profiles require explicit reset; the new CLI
candidate uses isolated profiles and preserves earlier text/file evidence.

Protected group generation2 is a closed binary record, not JSON. Its102-byte
header is version:u8/reserved-zero3, network16/account32/database-instance32,
revision:u64le and five counts:u16le (groups/outgoing/messages/native-selectors/
fragments). Variable byte strings have an i32le nonnegative bounded length.
Groups sort strictly by group ID; retained outgoing work preserves capture
order. Unsupported/truncated/trailing/oversized data rejects before mutation.
Limits are32MiB,32 groups,512 retained outgoing events,4096 messages,8192 native
selectors and342 fragments. All custody buffers are cleared on disposal.

Each group retains up to100 exact sequential packages and100 independent
invitation/original lookup/consent tuples keyed by exact pairwise scope, its next
semantic message sequence and a fork latch with the second verified package.
Receiving a lineage for other members does not activate this account. Its own
joining transition must contain the actual protected local invitation/consent.
Existing members verify subsequent additions without manufacturing local consent
for the new account. An idempotent activation retry binds the exact invitation/
acceptance to its actual successor package; an unrelated successor is not success. Package support DID2 is only a query candidate; independent
current directory verification supplies every missing member capability.
While the account lease is held, that fetch uses a closed borrow of the actual
SQL/marker directory backend, never recursively acquiring the account lock or
waiting on the source's gate. The scoped proof reader owns no transports; it
preserves normal proof verification, authenticated floor CAS and final joint
network/directory/time checks. Other concurrent normal fetches still fail closed
on a changed floor. Per-root verified member capabilities may be reused only
within this held operation; Protocol rechecks currentness on every consumption.
Two independently valid competing heads persist a permanent fork latch; no
last-writer-wins replacement or automatic repair exists.

## Send and recovery

The owner requires actual retained contact consent and independently current
endpoint capabilities. It captures the entire actual fanout batch before any
native encryption or dispatch: original random operations/logical IDs, exact
typed DMC2 events, target scopes and reserved common sender sequences. The
target set must exactly equal the current remote membership (plus the accepted
invitee for activation); incomplete/ambiguous sets reject before preparation.
Service-level consent reads finish before endpoint capture: each such read can
independently advance owned network custody. The complete target set then shares
one actual own/network snapshot, with independent current peer proofs. No later
consent mint is interleaved with this capture; held-lease owner checks remain.
One identical DGM1 is independently wrapped for each target, while history counts
one semantic event. Up to4 target workers preserve per-session order. An account-
operation pump serializes the current lock-holding native/transport loans; workers
wait outside authority capture and the bounded file-lock acquisition. This avoids
sibling-target lock timeouts, but does not qualify parallel wire loans or the final
large-fanout performance gate. Multi-device enrollment and the100-account/500-device release load are
not qualified by this candidate.

Before any ordinary preparation, interrupted group adoption resumes under the
same account lease. Protected pending intent -> exact SQL mirror -> stable
ordinary readback -> protected group adoption flag recover using original
bytes/positions. A committed native row is independently verified before a
retained-Store probe; an adopted plaintext command alone is not a native send.
Drain uses the existing native E2EE and replicated ordinary mailbox. Unknown
outcomes keep original work; `flush` never remints operations or expiry.
Original invitation/consent retries remain idempotent after activation.

## Receive, history and ACK

First native admission checks exact network/conversation/authenticated sender,
closed typed kind, actual contact consent and current endpoint/group predicates.
Canonical bounded GCF1 fragments do not grant membership; full reassembly/hash
and owner/current-closure verification precede head adoption. DGM1 requires
activated membership, exact epoch/head, canonical bounded text and expiry.
Message identity/author sequence collisions with changed bytes reject.

Only an actual verified native receive row supplies plaintext to materialization.
The protected native selector binds scope/operation/event hash and is written
atomically with the semantic state. Replays are idempotent. Immediately before
mailbox tombstone ACK, the owner independently reads actual native receive
custody and repeats durable semantic materialization. A caller record, SQL
projection, count or scheduling flag cannot authorize ACK.

The bounded ACK page reuses one actual verified native snapshot/storage per
scope and one actual protected group root only while the same account lease
is held. It still reads each native operation independently, compares the
native floor again, repeats final endpoint freshness and authenticates exact
protected group-root readback before release. No snapshot survives the call or
replaces pre/post-transport fences. This avoids reopening receiver inventories
and decoding the full group root for every fragment within the30-second ACK
budget; neither that deadline nor signed windows are extended.
The page captures its own current network/directory authority before resolving
peer endpoints, then reuses that exact own authority for every peer. A final
fresh own mint must not advance protected network custody after endpoint capture.
Actual peer proofs and all endpoint/network/floor fences remain independently
required; sharing an own snapshot does not waive a changed floor.

Group history is a protected selector, not an alternative native authority:
every read reconciles the native floor/operation. Received text comes from the
authenticated native plaintext; sent text joins protected original batch bytes
to the actual native event hash. Ordinary compaction preserves that independent
group history rather than manufacturing a direct-message SQL projection.

No group retention/GC is inferred from mailbox ACK. Current bounded custody
fails closed when full. GSR1 long-offline control retention, full membership/
device changes, large fanout and complete S11/release acceptance remain open.


## Current GSR1 composition gap

The ordinary-mailbox candidate above does not call GSR1. Protocol's
`GroupControlProductionClient` and `GroupControlPlacementVerifier` currently
expose no functional current producer/verifier. XNode has durable opaque stores,
CAS/replay/retention logic and an explicit production composition method, but
its DID2 `Program.cs` selects the unavailable boundary; configuration flags
alone cannot activate it. The current account owner has no protected GSR1
recipient descriptor/sealing-key custody or qualified GSS1 receipt/fetch path.

The next implementation must close those exact call paths under the normative
GROUP/ONION contracts, including an explicit E2EE descriptor/key carrier and
current opaque placement derivation. It must not reopen retired authority
configuration, use raw package data as current proof, or count mailbox Store as
group-control quorum. Source/core tests of the dormant service are not connected
GSR1 evidence. Full S11 and long-offline qualification remain open.
