# Owned recipient application-receipt obligations

Status: narrow S01 recipient obligation block accepted on source6e9d2b3,
current full726/0/0 terminal0. [Exact evidence](../testing/s01-application-receipt-obligations-2026-10-06.md#current-coupled-full--accepted-recipient-obligation-block). This is
not S07 receipt sending or physical E2E. Semantic ownership remains solely in
[TRANSPORT-NEUTRAL-MESSAGING §8.4.1 and §8.4.3](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#841-delivery-transitions).

## Current producer and local format

`AuthenticatedDirectDmc2.FromOwnedDid2Commit` binds the recipient device from
the actual committed DID2 session scope. The structural committed-stage helper
also checks the device against its actual SQLCipher store scope. Caller bytes
or a metadata snapshot alone do not authenticate a receive.

`SqliteDeepMailboxStore.MaterializeDirectDmc2Async` now inserts remote
`MessageCreate`/`AttachmentOffer` semantic history/dedup and the corresponding
`direct_application_receipt_obligations` row in one transaction. These are the
direct user-content kinds currently materialized by the DID2 receive owner.
Local authored history, control events and incoming receipts do not enqueue
this work. Other message semantics are not claimed implemented by this slice.

The local `DMB1` application database requires schema **9**; schema8 and all
other generations require explicit reset. No migration, dual reader, new wire
magic, cryptography or protected-journal generation is introduced. The current
ratchet and DSV2 account schemas remain separately owned and unchanged.

Each row contains exact conversation/logical/author-device key, author account,
recipient local device and committed DMC2 hash. The account-generation owner
is the existing singleton. Exact BLOB widths/types and foreign-key RESTRICT
are enforced. Cardinality cannot exceed the bounded semantic inbox. There is
no completion/delete operation in this slice: all rows represent pending work.
A future S07 completion transition must retain its own terminal/replay facts;
simply deleting the row would violate the current reader.

## Recovery and bounded read API

An interruption after event insertion or before commit rolls both effects
back. An interruption after commit retains both; exact receive retry verifies
the same obligation without inserting another. Cancellation before commit
rolls back. Missing/changed obligations reject; readers never reconstruct them
from history or a transport result. Forked content cannot expose receipt work.

The account service `ListOwnMessagingReceiptObligationsAsync` reads under the
registered account lease and actual stable local session/history custody.
The SQL reader returns at most100 immutable key-free logical/hash snapshots
for the matching author/conversation/recipient-device scope. Owner generation,
canonical source DMC2/hash/network and recipient-device binding are checked.
Snapshots are local facts, not endpoint, signing or dispatch authority. The
in-memory parity model follows the same enqueue/dedup/filtering behavior.

Existing ordinary outbox-only compaction hashes the complete application SQL
projection, including this new table; it deletes only selected outbox rows.
Receipt obligations therefore remain independent of outbox payload cleanup.
Native prefix compaction does not delete semantic inbox or these obligations.
Transport Store and tombstone ACK do not complete this work or imply Delivered.

## Acceptance boundary

The persistence fixtures cover exact replay, scope substitution, cold SQLite
reopen, event→obligation insertion gap, before/after commit, cancellation and
unchanged fail-closed rejection of missing/corrupt work. The existing real
owned DID2 send/receive/reopen fixture additionally reads obligations after
bidirectional receives and replay. Fixture protection is not platform custody.

Receipt authoring/encryption/send, policy-driven Read, authenticated sender
receipt application, UI statuses, scheduler activation and full physical
contacts/messages/files/groups remain later-stage work. This source alone
does not close S01, recipient device-state lifecycle or the release.
