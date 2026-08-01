# P11A security evidence

## Privacy properties

- account scope, logical ID, attempt ID and dedup material are fixed-size opaque
  binary values;
- all-zero opaque values fail construction;
- opaque values redact `ToString()`;
- exceptions contain only generic state/outcome descriptions;
- no diagnostic includes account identity, recipient identity, opaque IDs,
  ciphertext, dedup material or acknowledgement bytes;
- APIs and persistence contain no plaintext message field.

## Integrity and replay properties

- one immutable logical ID binds scope, dedup material, ciphertext and lifetime;
- divergent reuse of a logical ID is Conflict;
- divergent reuse of an attempt ID is Conflict;
- every mutation uses revision CAS;
- legal exact duplicates are Idempotent;
- monotonic attempt and logical state rules reject skips and regressions;
- Accepted cannot satisfy Durable;
- Delivered requires acknowledgement whose logical ID and dedup material match
  the stored item;
- multiple attempts remain subordinate to one logical item and quota event.

## Resource controls

- ciphertext: 1 MiB maximum;
- transition/ack evidence: 4 KiB maximum;
- attempts: 16 maximum per logical item;
- list/expiry batch: 256 maximum;
- lifetime: 365 days maximum;
- fixed-size opaque IDs and dedup fields;
- SQLite projects and validates BLOB lengths before allocating or reading them;
- schema intentionally contains no unbounded TEXT column.

## Failure semantics

- cancellation is checked before the durable point;
- failures/cancellation observed after commit become
  `TransportOutboxCommitOutcomeUnknownException`;
- reconciliation is by opaque logical ID, revision and exact immutable
  transition evidence;
- malformed persisted state returns Corrupt before idempotent/conflict/success
  decisions;
- newer physical schemas fail closed.

## Non-claims

This slice does not verify recipient acknowledgements cryptographically, secure
an untrusted local database against a device owner, hide SQLite access patterns,
or make a production transport available. Those are later adapter/runtime and
platform threat-model responsibilities.
