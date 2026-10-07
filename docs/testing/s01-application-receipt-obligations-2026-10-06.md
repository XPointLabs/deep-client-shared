# S01 recipient receipt obligation source checkpoint — 2026-10-06

This checkpoint qualifies focused local persistence behavior, not the whole
S01 stage, S07 AppAck sending, device E2E or release. The actual producer,
current local schema/reset boundary and residual scope are owned by the
[Shared mapping](../architecture/owned-application-receipt-obligations.md).

## Observed builds and focused runs

The actual non-test `Deep.Client.Shared.Production.csproj` Release build and
the production solution build complete with zero warnings/errors. Separate
artifact roots are `artifacts/s01-application-receipt-production-build` and
`artifacts/s01-application-receipt-build`.

Initial focused run:48 cases,43 Passed/5 Failed/0 skipped, observed terminal1.
Three older negative fixtures expected rejection after reopen, whereas the
new independent receipt binding already rejects corrupt metadata at reopen.
Their assertions now require the earlier reset-required rejection and unchanged
raw SQL facts. Two new receipt fixtures incorrectly supplied nonzero flags;
the current codec requires zero. Fixture flags were corrected, no codec or
runtime safety check was weakened. A later attempted test build used a wrong
fixture property (`Operation` instead of actual `OperationId`); it ended1
before tests, and the fixture property was corrected.

Preserved initial receipt (Shared-relative):
`artifacts/s01-application-receipt-focused/s01-application-receipt-focused.trx`,
SHA256 `B947B0CE1F11C9DF4048935ECBEC2E8BB176C4C843CB2C5E50E3DC1B56BA6E59`.

Corrected focused run:53/0/0, observed terminal0,
`S01_APPLICATION_RECEIPT_CORRECTED_EXIT=0`, start22:29:38.8076277+05,
finish22:37:44.7515313+05. All53 results have distinct test/execution IDs and
exact Passed definition mappings. Its receipt is
`artifacts/s01-application-receipt-corrected/s01-application-receipt-corrected.trx`,
SHA256 `621CBF6BDFC71C7B628A844CCAE3244C65B94E39AFB5F03929145E83A099637F`.
This includes actual owned DID2 bidirectional receive/reopen/exact replay and
encrypted native ordinary-outbox cleanup preserving independent recipient work.
Three hostile-SQL cases had colliding xUnit-truncated display names, so this
receipt alone is not unique-name qualification for the current full gate.

Short explicit case labels correct that display issue without runtime changes.
The final structural rerun is51/0/0, observed terminal0,
`S01_APPLICATION_RECEIPT_LABELLED_EXIT=0`:51 unique names/test IDs/execution IDs
and exact Passed definition mappings. Receipt:
`artifacts/s01-application-receipt-labelled/s01-application-receipt-labelled.trx`,
SHA256 `07029223CA6AD0769C2506B33F68E4A337B151081CA32C924F3B1AC74FE5EAB6`,
start22:39:59.6050486+05, finish22:40:02.6199848+05.
Actual test-host Shared DLL remained exactly
`87BEBD929F0B9B4C83F8A66DEECF387E522902B82AD6C07F6662B374BEAFA35E`
between the native53 run and labelled51 rerun. The two native cases were not
rerun solely for display labels; the current full must run them again.

The focused filter uses `AuthenticatedDirectDmc2InboxTests`,
`OnlyCommittedScopedStageCanEnterAccountSemanticInbox` and the two native cases
`Did2MessagingOwner_OrdinarySendReceiveReopenGapAndExactReplay` and
`Did2OutboxCompaction_CachedEncryptionRequiresExactRetainedHistoryWithoutNewRatchet`.
The labelled rerun uses only the first two structural filters.

## Current coupled full — accepted recipient obligation block

The first attempted full on source `aaf233b` found the old raw-key fixture
expecting schema8 rather than the current schema9. The already-failed run was
stopped by terminating only its verified test-process tree; observed launcher
marker `S01_APPLICATION_RECEIPT_FULL_TEST_EXIT=-1`, no full acceptance/TRX is
claimed. Its original launcher and725-case frozen manifest remain preserved
under `artifacts/s01-application-receipt-full`.

The raw-key fixture now explicitly requires9 and keeps the existing durable
policy/wrong-key assertions. Its name is generation-neutral; the old
`CurrentRawKeyReopensEncryptedSchemaEightAndPreservesDurablePolicy` maps only
in evidence bookkeeping to `CurrentRawKeyReopensEncryptedSchemaAndPreservesDurablePolicy`.
There is no runtime alias. An additional negative case rejects generation8
without repair/mutation. Final structural/schema rerun:58/0/0 terminal0,
58 unique names/test/execution IDs and exact Passed definition mappings,
marker `S01_APPLICATION_RECEIPT_SCHEMA_EXIT=0`. Receipt
`artifacts/s01-application-receipt-schema/s01-application-receipt-schema.trx`,
SHA256 `3CC8502F4DAD7A7A0AB3A1FAADE1DC834FE28A583AD3F69E3FDCDF223769EC27`,
start22:46:20.6223204+05, finish22:46:24.7846584+05.
This rerun does not inherit current full/native-host acceptance from the earlier
53 run; current full must execute both native cases on its own final host.

One current full production-solution run is required against the committed
source and immutable built host. Expected discovery is726 cases, including
705 unchanged prior names and the explicitly renamed raw-key case, plus the
current receipt/affected-reader cases. The local launcher
`artifacts/s01-application-receipt-full-corrected/run-and-verify.ps1`
checks source HEAD/tree and frozen inputs before/after, then exact unique
result/definition/execution mapping and required prior/current names.
It uses `dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1
--no-build --no-restore --artifacts-path artifacts/s01-application-receipt-build`
with TRX output in `artifacts/s01-application-receipt-full-corrected`.

The run on exact source `6e9d2b3c5d111f596291dcc4ce1d96a1c1f12c4a`
completed726/0/0, observed process terminal0 and both explicit markers
`S01_APPLICATION_RECEIPT_FULL_TEST_EXIT=0` and
`S01_APPLICATION_RECEIPT_FULL_QUALIFIED_EXIT=0`.
All726 unique results, definitions, test IDs and execution IDs map Passed;
all259 current required and706 prior-mapped cases are present, with no
missing/extra names. All171 frozen inputs remained exact. An independent
post-terminal readback confirmed these facts and the source HEAD before edits
to acceptance documentation.

Receipt (Shared-relative):
`artifacts/s01-application-receipt-full-corrected/s01-application-receipt-full-corrected.trx`,
SHA256 `30708DE6560EBCDE227A2D604C2220CFAE930982E0031601A8789DC92886667A`.
Manifest SHA256 `4E7A35CED642E3D9261B6F023FA6259910F375FE2FF5D7ECC26B2C67BF4556D9`.
Start2026-10-06T22:51:01.6637318+05, finish2026-10-07T00:26:56.9848255+05.
This accepts atomic current recipient due-work and the bounded local reader,
not the whole S01 or any S07 sender/read/scheduler activation.

These local ignored artifacts are not public-upload approval. Fixture-backed SQLCipher/protected
custody and signatures are not physical Windows/Android transmission, current
platform custody, real node deployment or application-receipt sending.
