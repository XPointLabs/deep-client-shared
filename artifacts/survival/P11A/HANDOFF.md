# P11A handoff

Human owner: Mr. X

Source commit:
`c54869eb22f18facd395eabb1941342e3b217c70`

## Delivered

- transport-neutral logical bundle and multi-attempt contract;
- monotonic Prepared -> Attempted -> Accepted -> Durable -> Delivered state
  machine plus terminal Expired;
- typed recipient-device acknowledgement requirement;
- revision/CAS, source/reason, retry/not-before, expiry and explicit uncertain
  commit outcome;
- aligned in-memory and SQLite repositories;
- physical SQLite v7 -> v8 additive migration;
- dormant `PersistentTransportOutboxEnabled` feature flag;
- restart, parity, corruption, bounds, cancellation, concurrency, migration and
  purge tests.

## Deliberately not delivered

- no runtime registration or dispatcher;
- no transport adapter or racing policy;
- no bridge or mailbox selection;
- no mailbox receipt verifier;
- no UI or billing;
- no Docker, live network, credentials or blockchain work;
- no `RoutedSessionTransport` changes.

## Consumer guidance

P09C/P11B/P12/P13 adapters should create one `TransportOutboxPreparedItem` per
opaque end-to-end bundle, reuse that logical ID and dedup material for every
transport attempt, and create a new `OutboxAttemptId` per physical attempt.
Adapters must never map Accepted to Durable. They may request Delivered only
after a separately verified `RecipientDeviceAcknowledgement`.

After `TransportOutboxCommitOutcomeUnknownException`, read the logical ID and
reconcile revision/state before retrying the identical transition. A Conflict
means the caller must read current state; it is not evidence of transport
failure.

## Residual blockers

- independent architecture and security review are still required;
- production recipient acknowledgement verification belongs to a later slice;
- runtime composition and mobile background scheduling are intentionally
  unwired;
- physical-device and Windows end-to-end testing occur in later program waves.
