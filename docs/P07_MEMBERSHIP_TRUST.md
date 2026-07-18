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
profile, domain, revision, sequences, predecessor and canonical hashes,
envelope, state, and timestamps. SQLite commits record and head in one
transaction. A corrupt current profile/domain blocks without selecting an older
record; corruption in an unrelated opaque profile cannot deny service to the
current profile.

Profiles bind exact genesis, initial delegation, and initial domain anchors.
Substitution after first use fails closed. Root-signed delegation rotation can
advance a healthy or revoked authority chain. Fork evidence is persisted as a
blocking state and is never resolved by source count or arrival order.

Logical local schema migration `3 -> 4` adds installation trust metadata without
deleting account, message, or group state. Account sign-out intentionally
preserves trust profiles. Rollback disables P07 and leaves the tables dormant;
it does not delete them or silently activate legacy bootstrap.

Remaining blockers include an approved production signature profile and
external review, signed live bootstrap/checkpoints, P06/P07B source policy,
SQLCipher release integrity guard, stale/clock policy approval, runtime
composition, and MAUI self-host import UX.
