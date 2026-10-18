# Owned connected group candidate

Decision/limits: [DR-0143](../../../docs/survival-program/decisions/DR-0143-owned-connected-group-candidate.md).
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

Protected group generation1 is a closed binary record, not JSON. Its102-byte
header is version:u8/reserved-zero3, network16/account32/database-instance32,
revision:u64le and five counts:u16le (groups/outgoing/messages/native-selectors/
fragments). Variable byte strings have an i32le nonnegative bounded length.
Groups sort strictly by group ID; retained outgoing work preserves capture
order. Unsupported/truncated/trailing/oversized data rejects before mutation.
Limits are32MiB,32 groups,512 retained outgoing events,4096 messages,8192 native
selectors and342 fragments. All custody buffers are cleared on disposal.

Each group retains exact package lineage, invitation/original lookup evidence,
consent, exact pairwise scope, next authored group-message sequence and a fork
latch with the second verified competing package. The current candidate stores
genesis and the owner activation successor only. Pending invitation/consent is
not membership. Activation must contain the exact local invitation/consent pair.
Two independently valid competing heads persist a permanent fork latch; no
last-writer-wins replacement or automatic repair exists.

## Send and recovery

The owner requires actual retained contact consent and independently current
endpoint capabilities. It captures the entire actual fanout batch before any
native encryption or dispatch: original random operations/logical IDs, exact
typed DMC2 events, target scopes and reserved common sender sequences. The
current candidate has exactly one remote device; it does not qualify the
100-account/500-device release performance profile.

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

Group history is a protected selector, not an alternative native authority:
every read reconciles the native floor/operation. Received text comes from the
authenticated native plaintext; sent text joins protected original batch bytes
to the actual native event hash. Ordinary compaction preserves that independent
group history rather than manufacturing a direct-message SQL projection.

No group retention/GC is inferred from mailbox ACK. Current bounded custody
fails closed when full. GSR1 long-offline control retention, full membership/
device changes, large fanout and complete S11/release acceptance remain open.
