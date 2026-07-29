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

Authority apply operations revalidate the persisted head and predecessor before
both exact replay and successor processing. Exact replay also evaluates the
current operation time, so an expired delegation cannot return a stale
`Healthy`/idempotent result. A root-signed successor may still advance a
historically valid but currently expired predecessor.

`Evaluate` uses a final revision-and-digest fence across authority, bridge, and
membership heads. If any head changes while the cross-domain decision is being
formed, the operation fails closed instead of returning a mixed-snapshot
`Healthy` result.

All persisted trust timestamps are canonical UTC whole seconds at construction
and validation boundaries. This matches the signed protocol time unit and gives
SQLite and in-memory stores identical digest, replay, and clock-CAS semantics.
Ordinary profiles use `install:*` excluding the reserved
`install:self-hosted:*` subtree; only the explicit self-host import boundary may
write that namespace.

Every public operation takes a deep snapshot of profile, anchor, envelope, pin,
and self-host import bytes before its first verification or persistence await.
Dependency failures are translated to coarse trust statuses; cancellation still
propagates, while verifier or repository exception text never crosses the public
privacy boundary. Operation time is sampled once and canonicalized to the
protocol's UTC whole-second unit.

Authority equivocation at the bootstrap revision follows the same verified fork
reducer as later revisions. A different same-sequence candidate becomes durable
`ForkDetected` evidence only after successful cryptographic verification.
Content exact replay requires the stored signing authority to equal the active
authority. A newly committed content successor is fenced against the exact
authority revision and digest used for verification before `Healthy` is
returned; a concurrent rotation is reevaluated fail closed.

Repository reads validate every immutable revision from revision one through
the advertised head, including its payload digest and predecessor linkage.
SQLite performs that validation from one ordered, cancellable snapshot query,
not one query per revision. Rows are validated as a stream after their BLOB
lengths are checked, retaining only the predecessor and head. Missing-head and
orphan checks use indexed `SELECT 1 ... LIMIT 1`, never history-wide counts.
Both stores enforce fail-closed per-domain budgets of 4096 records and 8 MiB of
persisted trust BLOBs, preventing attacker-controlled unbounded allocation,
CPU, database-gate, latency, and battery work. The SQLite head stores the
transactionally updated cumulative byte count and rejects an over-budget commit
before it makes the profile unreadable. Reaching either dormant budget blocks
the write rather than silently selecting an older LKG. Production activation
requires a separately reviewed authenticated checkpoint/compaction design that
preserves the same deletion and deep-corruption decisions without these dormant
limits.

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

Membership trust tables are part of the single physical v10 local-state
baseline. They are created only with a wholly fresh database and are never
added, altered, or backfilled on open. Any older or structurally incompatible
database requires an explicit local reset. Account sign-out intentionally
preserves trust profiles inside an already attested v10 database. Disabling P07
leaves those baseline tables dormant; it does not delete them or enable a
rollback path.

Remaining blockers include an approved production signature profile and
external review, signed live bootstrap/checkpoints, P06/P07B source policy,
SQLCipher release integrity guard, stale/clock policy approval, runtime
composition, and MAUI self-host import UX.
