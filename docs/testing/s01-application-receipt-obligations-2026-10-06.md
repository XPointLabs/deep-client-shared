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

## Current full acceptance remains open

One current full production-solution run is required against the committed
source and immutable built host. Expected discovery is725 cases, including all
706 prior accepted cases and the current receipt/affected-reader cases. The
local launcher `artifacts/s01-application-receipt-full/run-and-verify.ps1`
checks source HEAD/tree and frozen inputs before/after, then exact unique
result/definition/execution mapping and required prior/current names.
It uses `dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1
--no-build --no-restore --artifacts-path artifacts/s01-application-receipt-build`
with TRX output in `artifacts/s01-application-receipt-full`.

No current full receipt or acceptance is claimed here. These local ignored
artifacts are not public-upload approval. Fixture-backed SQLCipher/protected
custody and signatures are not physical Windows/Android transmission, current
platform custody, real node deployment or application-receipt sending.
