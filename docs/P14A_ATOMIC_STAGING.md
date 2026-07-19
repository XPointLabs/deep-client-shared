# P14A atomic staged profile boundary

Status: `ATOMIC-STAGING-PERSISTENCE-CANDIDATE / SELF-HOSTED-RUNTIME-NO-GO`.

P14A stores only bounded opaque bytes for a future signed self-hosted profile.
The stored value remains a staged, unverified candidate. This package does not
define or parse a profile format, verify trust, select or activate a profile,
contact a service, or register a runtime dependency.

## Persistence contract

`IAtomicBoundedSettingsRepository` adds a narrow account-generation settings
primitive. Reads inspect the stored UTF-8 length before materializing or parsing
the internal envelope. Mutations use an opaque revision and support atomic
create, compare-and-replace, and compare-and-delete results. Conflicts are
explicit. A provider failure before commit is distinguishable from an
outcome-unknown failure after the commit attempt.

The implementation uses the existing `settings.payload_json` column. Only the
dedicated `account.self-hosted-staging.v1.*` keys contain the internal
version/revision envelope, so generic settings retain their existing JSON
shape. No table, physical schema version, migration, sidecar, or encryption
primitive is added. Unaccepted pre-corrective P14A catalog rows do not have the
revision envelope and fail closed; there is no released compatibility consumer
or automatic rewrite.

SQLite performs the length projection before selecting the value and executes
revision comparison plus replacement in one immediate transaction. The
in-memory store applies the same outcomes under its durable-state lock and
rolls back a failed pre-commit persistence write. Neither implementation calls
the test fault hook while a store or database lock is held.

The SQLite tests instrument execution of the payload-selection statement and
prove that an oversized row returns from the length projection without issuing
that statement. The in-memory tests inject a failure after the live dictionary
has changed but before persistence concludes, then prove create, replace, and
delete restore both the exact live revision/value and the file-backed state
observed by a reopened store. The injected callback is evaluated outside the
store lock and only its captured fault is raised at the rollback point.

## Account lifecycle and concurrency

`AccountGenerationSessionStore` holds one generation-barrier lease across each
complete bounded read or CAS operation. Sign-out stops new leases, cancels and
joins an in-flight staging mutation, and only then invokes the existing account
purge. Since purge removes every settings row, an old-generation mutation
cannot recreate a staged catalog after successful sign-out.

The staging service uses bounded optimistic CAS retries instead of an
instance-local lock. Two service instances therefore reconcile conflicts
without losing already committed candidates. Outcome-unknown saves and deletes
are read back before a public result is selected.

The concurrency proof uses two independent SQLite store instances over one
database and a deterministic read barrier that makes both services observe the
same revision before their save or delete. One mutation wins, the other retries
the CAS, and neither committed candidate nor unrelated deletion is lost.

Cancellation is rethrown only when the caller token or the account-generation
lease token is actually canceled. Those paths construct a fixed cancellation
exception without preserving provider text or an inner exception. An
unsolicited cancellation-shaped failure from candidate memory, cryptographic
providers, repositories, or concrete stores is treated as a dependency
failure before a commit attempt and as outcome-unknown once a commit may have
occurred.

## Bounds and privacy

- 16 candidates per account;
- 64 KiB per candidate;
- 512 KiB of candidate bytes per account;
- exact staging schema version 1;
- 64 UTF-8 bytes and 256 input characters for the optional internal display
  hint;
- 768 KiB maximum bounded JSON payload for the private catalog envelope.

Candidate input length and display-hint character length are checked before
copying or normalization. Public scope and revision handles have no byte export,
public candidate metadata does not expose the display hint, and public hash
codes do not derive from opaque or content material. Candidate bytes leave the
boundary only through the explicit defensive-copy export operation.

## Remaining blockers

P14C must pin the canonical signed profile producer and contract. Only after
that review may P14 add verification/activation, P14B add platform UX, or P14D
add deployment isolation. Billing, wallet, XPNT, networking, logging, telemetry,
dependency-injection registration, and runtime activation remain absent.
