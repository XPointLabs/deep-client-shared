# Owned connected group candidate

Decision/limits: [DR-0145](../../../docs/survival-program/decisions/DR-0145-owned-group-control-rendezvous.md), [DR-0146](../../../docs/survival-program/decisions/DR-0146-stable-group-control-placement.md), [DR-0144](../../../docs/survival-program/decisions/DR-0144-multi-account-group-batches.md), extending [DR-0143](../../../docs/survival-program/decisions/DR-0143-owned-connected-group-candidate.md).
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

Protected group generation3 is a closed binary record, not JSON. Its102-byte
header is version:u8/reserved-zero3, network16/account32/database-instance32,
revision:u64le and five counts:u16le (groups/outgoing/messages/native-selectors/
fragments). Variable byte strings have an i32le nonnegative bounded length.
Groups sort strictly by group ID; retained outgoing work preserves capture
order. Unsupported/truncated/trailing/oversized data rejects before mutation.
Limits are4MiB,32 groups,512 retained outgoing events,4096 messages,8192 native
selectors and342 fragments. All custody buffers are cleared on disposal.
The exact group slot has this same bound in both secure-storage adapters and
all atomic operations/cold readers; ordinary slots retain their1MiB bound.
The entire inventory remains8MiB/1024 entries. Limits are joint, not a promise
that every maximum count fits simultaneously. This corrects a codec/adapter
capacity mismatch without new generations, migration or deleting prior groups;
larger-history partitioning and retirement remain separate S11 qualification.

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


## Current GSR1 composition candidate

DR-0145 adds per-recipient protected descriptors/independent sealing scalars,
original GSW1 bytes, verified GSS1 evidence and fetch cursor/hash to generation3.
Generation2 rejects without a reader or migration; old isolated profiles remain
evidence. The common ordinary journal and SQL schema do not change. Key-bearing
kind30 is admitted/materialized only from actual authenticated native pairwise
custody, with intended recipient, current owner signature and retained invitation
or membership checks. Receiving it is not group membership.

The owner captures all required recipient streams including its own. Original
sealed chunks and write requests precede any callback; a completed write needs
both independently verified selected-replica receipts. Lost/expired writes are
not reencrypted or reminted. Current NETCODEC placement and strict ONION/H2 are
required for dispatch. Historical original receipt verification grants no old
view dispatch permission. New successor commits use control store/fetch, not a
short mailbox substitute. With an installed control stream, an unknown new
ordinary-mailbox package cannot bypass it.

Fetch authenticates/decrypts the exact sequence/predecessor and full GCP closure.
Package/fragment adoption and cursor share one protected-root CAS; an interrupted
page can replay exact chunks without skipping them. Missing, expired, forked or
unavailable control is explicit failure, never empty successful synchronization.
Application fanout is blocked by incomplete required control publication.

Performance: retained group Stores share one actually opened native scope/lease,
while still re-verifying every original native event and receipt. Group history
opens each scope once per held read. Multi-scope DPE2 ACK materialization batches
joint authority-floor reads only for reference-identical own capabilities inside
one phase; each peer, current owned directory, scope, clock and actual native row
is independently checked. Every pre/post-callback phase reads floors anew.
An ACK keeps its actual native SQL owners open until its existing held lease
ends, rather than reopening keys and SQL at every callback. No verified floor,
row or admission result is cached: each phase reconciles native custody and
rechecks current semantic, protected-root and endpoint fences independently.
DPAPI authentication, transport deadlines and currentness checks are unchanged.
Store, like ACK, does not duplicate the interceptor's full pre-callback fence
immediately before adapter bookkeeping. The real interceptor still performs
both full callback fences; every retained/cached outcome crosses the owner's
full final fence. Request bytes, native custody and deadlines are unchanged.

The three-member functional cycle passed through the retained-state recovery
recorded in the [CLI GSR checkpoint](../../../deep-cli/docs/testing/cli-gsr-groups-2026-10-18.md).
That result is not a first-attempt latency qualification.
Long-offline/400-day retention, descriptor rotation/handover, multi-device changes,
large fanout, crash/fault matrix and full source/package/device/release acceptance
remain separate gates; this implementation description is not their PASS.

Uncaptured messaging pairs reacquire the entire own/peer pair once when two
independently verified DTT1 proofs straddle a legitimate signed view/head update.
The existing30-second budget is shared by both acquisitions. A supplied captured
owner is never replaced; mismatch still rejects before business effects. Route
verification remains exact. GSR publication reuses verified package/chunk work
only within the actual held pre-dispatch phase, not across callbacks or loans.

## Explicit command public read scope

Group commands share a private child authority source with nested group work.
Ordinary DPE2 receive uses its own explicit child for one mailbox page; the
parent remains independent for Retrieve, Initial, Braid and the fresh ACK
endpoint capture after materialization. A receive scope cannot supply a cached
proof to that parent ACK acquisition.
It uses the parent's actual acquisition gate, protected directory/network owners,
root and clock. Only existing immutable verified own/peer public capabilities are
reused, never a cached currentness result, native row, signing key or plaintext.
Each use still reads actual protected floors and monotonic time, verifies the
exact network history and current mailbox policy, and keeps all existing
pre/post-effect and native-owner fences. Peer lookup is keyed by the exact DID2
and the reference-identical captured own capability; different endpoint views
are not spliced. Group semantics/consent/signatures are independently checked.

No new TTL or authority window is introduced. Natural own-proof expiry can start
a fresh acquisition only at the existing uncaptured acquisition boundary; it
cannot renew an old loan, replace an original request or turn a verification
failure into success. Clock discontinuity, changed/forked custody, cancellation
and unavailable fresh authority still reject. A closed scope releases its public
references and cannot serve another command. Ordinary callers outside this
explicit command scope retain independent acquisitions. Shared storage/wire formats,
replica requirements, TLS and transport deadlines do not change.

The authority source also retains at most one bounded immutable PMT/PMA grammar
frame keyed by all exact public input bytes. Ordinary ACK work may use this
pure parser optimization too; it does not share a group's or ordinary receive
endpoint capability scope. Every use independently verifies the actual projection, root signatures,
trusted interval and native floors. Changed/duplicate/missing inputs still
parse and reject normally, with no fallback to a former accepted policy. No
private state, currentness decision or authority deadline is cached here.
