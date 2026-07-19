# P14A1 atomic staged-profile evidence

Acceptance: `ATOMIC-STAGING-PERSISTENCE-GO / SELF-HOSTED-RUNTIME-NO-GO`.

This carrier describes exact accepted source
`b2c3bbbceb6c173e28f9f2360c863052bf811cea`. It contains normalized,
machine-independent evidence only. It contains no raw TRX, absolute path,
machine or user name, timestamp, endpoint, account/candidate identifier,
candidate material, exception-provider text, credential, or secret.

## Source and review chain

- Review base: `0947f77195986672eb479c2e7b340e18c3c62cfa`.
- First tests-only RED: `f790367654df8dda5bb84350952598050553a967`.
- First GREEN: `8b27ffb3844ebe7ef6cab820dba9cbb7faf201db`.
- Corrective tests-only RED: `282c8e239675585432d68ea83db5cd4f19594df1`.
- Accepted GREEN source: `b2c3bbbceb6c173e28f9f2360c863052bf811cea`.
- Architecture/correctness review: GO, P0/P1/P2/P3 = 0/0/0/0.
- Security/privacy review: GO, P0/P1/P2/P3 = 0/0/0/0.

## Accepted boundary

The package adds bounded raw JSON reads and opaque-revision create, replace,
and delete CAS over the existing settings row. SQLite measures the stored BLOB
length before selecting the payload and performs revision comparison and
mutation in one immediate transaction. In-memory operations provide matching
outcomes and restore the exact live and file-backed value/revision when a fault
is injected after dictionary mutation but before persistence concludes.

Two independent SQLite stores are forced by a deterministic test barrier to
return the same revision to two service instances before save and delete
mutations. The losing CAS retries without discarding the winner's committed
change. The account-generation wrapper holds one generation lease over every
complete bounded operation; sign-out cancels and joins that lease before the
existing settings purge, preventing post-purge resurrection.

Caller or generation cancellation is rethrown only when its associated token
is canceled and is reconstructed with fixed text and no inner exception.
Unsolicited cancellation-shaped failures are typed as dependency failures
before a possible commit and as outcome-unknown after commit uncertainty.

## Compatibility and limits

- Existing `settings.payload_json` is reused; no table, schema version, or
  migration is added.
- Only the dedicated staging keys carry the version-1 revision envelope.
- Unaccepted pre-corrective raw staging rows fail closed and are not rewritten.
- Maximum key: 256 characters and 512 UTF-8 bytes.
- Maximum bounded repository value: 768 KiB.
- Maximum candidates per account: 16.
- Maximum candidate: 64 KiB.
- Maximum aggregate candidate bytes per account: 512 KiB.
- Internal display hint: 256 input characters and 64 UTF-8 bytes.

## Verification

The exact relative commands, exit codes, counts, source-diff hash, and Release
assembly hashes are in `test-summary.json`. `evidence.json` records the full
handoff, file set, compatibility, guarantees, reviews, and remaining blockers.
`HASHES.sha256` authenticates these three carrier files. The evidence content
hash is SHA-256 of the exact UTF-8 bytes of `HASHES.sha256`.

APK evidence is not applicable: this is a dormant shared-library persistence
boundary with no runtime registration, UI, application packaging, deployment,
or self-host activation.

## Remaining activation blockers

P14C must pin and approve the canonical signed profile producer and contract.
Only later packages may add verification/activation, platform UX, or deployment
isolation. Networking, transport, billing, wallet, XPNT, logging, telemetry,
feature registration, dependency-injection registration, and production
readiness remain explicitly outside this package.
