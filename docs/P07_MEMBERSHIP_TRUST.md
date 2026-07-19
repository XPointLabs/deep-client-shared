# P07 membership trust

Status: dormant, local, fixture-driven; not production-authorized.

The service accepts bounded canonical signed-envelope bytes and uses the exact
local `Deep.Protocol` P04 package. An injected P04 verifier is mandatory.
Deterministic signing exists only in tests.

Three installation-scoped tracks are stored independently:

- offline authority delegation/revocation;
- bridge snapshots;
- membership commitments.

Each track has immutable revisions plus a CAS head. The record digest binds the
profile, domain, typed artifact kind, revision, sequences, predecessor and
canonical hashes, envelope, signing-authority context, bounded revoked
delegation set, state, and timestamps. Corrective record schema v2 intentionally
fails closed on pre-v2 dormant records rather than interpreting an incomplete
verification context. SQLite commits record and head in one transaction. A
corrupt current profile/domain blocks without selecting an older record;
corruption in an unrelated opaque profile cannot deny service to the current
profile.

Profiles bind exact genesis, initial delegation, and initial domain anchors.
Substitution after first use fails closed. Root-signed delegation rotation can
advance a healthy or revoked authority chain. Fork evidence is persisted as a
blocking state and is never resolved by source count or arrival order.
Delegation and revocation candidates use one transition reducer, including
same-sequence and concurrent mixed-type equivocation. Restart revalidates
persisted authority and signed content against canonical bytes and their signed
predecessor context; immutable anchors are explicitly typed and checked against
the profile pins.

Every accepted signed content revision preserves the exact canonical delegation
that verified it. Rotation therefore leaves the old content cryptographically
diagnosable but no longer reports it as `Healthy`; a successor signed by the
current delegation may advance the same content LKG. Revocation must target the
active delegation hash. Each authority revision carries a bounded, de-duplicated
set of revoked delegation hashes so restart and later rotation cannot forget a
revocation.

The corrective refresh path never treats replay as recovery. When stored
content was signed by a superseded or revoked delegation, only an exact
sequence successor is considered, and it must verify under the current active
delegation before any accepted/idempotent result is possible. Exact replay
preserves the existing `ProtocolUnsupported` or `Revoked` state.

If a valid revocation would exceed the 64-hash P04 bound, the 65th revocation
is first verified and then committed as a durable terminal `Corrupt` authority
revision. The prior 64 hashes remain intact. Evaluation, restart, replay, and
ordinary delegation rotation remain blocked; recovery requires a separately
approved explicit rebootstrap flow that is intentionally absent from P07.

In-memory repository inputs and read snapshots are defensive copies, matching
SQLite value semantics. Deterministic test-only fault points prove cancellation
before durable commit rolls back, while cancellation after commit is explicitly
an uncertain caller result whose applied state is resolved by a read/restart.
Malformed, null, or out-of-range SQLite trust timestamps return `Corrupt`.

An installation-scoped, CAS-persisted observed-time high-water mark blocks
rollback across operations and restarts. Every public trust operation samples
the injected clock once and carries that instant through verification and
persistence. Rotated authority remains usable after the immutable bootstrap
delegation expires; current authority validity, rather than bootstrap
delegation validity, controls runtime status.

Self-host import accepts a bounded canonical raw signature envelope, not trusted
P04 model objects, and is restricted to the independent
`install:self-hosted:` profile namespace.

Logical local schema migration `3 -> 4` adds installation trust metadata without
deleting account, message, or group state. Account sign-out intentionally
preserves trust profiles. Rollback disables P07 and leaves the tables dormant;
it does not delete them or silently activate legacy bootstrap.

Remaining blockers include an approved production signature profile and
external review, signed live bootstrap/checkpoints, P06/P07B source policy,
SQLCipher release integrity guard, stale/clock policy approval, runtime
composition, and MAUI self-host import UX.
