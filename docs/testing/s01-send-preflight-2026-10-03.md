# S01 — owned send preflight and grant callback custody

Date: 2026-10-03. Baseline Shared:
`cba9f21fd15e33fb48fb3cdb71927cb7b0615053`.

This is a bounded implementation correction under
[DR-0056](../../../docs/survival-program/decisions/DR-0056-did2-owned-mailbox-message-dispatch.md)
and the current authorization contract
[DR-0081](../../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md).
It does not close S01/S04 or activate a mailbox node. The only execution plan is
[S00–S13](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).

## Defect and change

The owner acquired and installed a grant before decoding the send journal and
checking its capacity or the retained route/body. Acquisition is not read-only:
it persists an independent holder/request and can cause remote grant issuance.
The unchanged source reproduced one grant callback for a new operation against
an already full journal, followed by local rejection. That grant could not be
used by this attempt. An existing operation also reached acquisition before
the original route/ciphertext mismatch was detected.

The owner now reads the mandatory account/instance-bound send root under its
held lease before acquisition. Full custody rejects only a new operation;
existing operations retain their exact retry path. An existing operation's
route and committed ciphertext hashes must match before acquisition. Every
owned grant recheck also requires the same protected send root. A changed root
during the callback prevents winner adoption and Store; the exact XMG request
and holder remain pending. This does not convert a remotely issued grant into
a before-forward rejection or erase its reservation.

After preparation, the existing complete original body/grant/lifetime/MAU
hash/counter checks and independent protected read-back remain mandatory.
No slots are evicted, no replay floor is reset, and no new journal version,
schema, wire, public API, compatibility reader or signing authority is added.

## Test boundary

The production tests use two actual DID2/PQ accounts, native messaging crypto,
committed ciphertext, SQLCipher, current signed fixtures and signed mailbox
receipts. Issuer/terminal transports and trusted time are in-process fixtures:
this is neither real remote durability nor socket/device E2E.

The capacity/changed-binding tests intentionally stage canonical local
commitments, not counterfeit verified grants. They prove rejection before
acquisition, an unchanged grant root and unchanged send bytes. A filled journal
is not evidence of 512 delivered messages or sustained compaction.

The callback case changes only a disposable fixture's valid empty send revision
during issuance. It proves pending-not-winner retention and no Store. Restoring
that fixture snapshot is a test-only fault recovery seam, not an account-owner
repair API or production rollback permission. The subsequent exact XMG retry
and existing SQL/Store crash, lost-response, completion and rollback cases
continue to exercise the ordinary owner path.

## S00 fixture correction

The first full run exposed a stale observer in
`SignedEmptyV2FloorSurvivesAccountReopenAndRejectsCorruption`: it supplied the
current random account key to `sqlite3_key` as a password and failed with
SQLite error 26 before any directory-floor assertions. An isolated rerun
reproduced that failure. Under
[DR-0060](../../../docs/survival-program/decisions/DR-0060-did2-account-random-sqlcipher-key.md),
the account database uses SQLCipher raw-key syntax, not password derivation.
The observer now opens the actual database through the existing account
connection factory. All rollback, corruption, missing-root, restoration and
catch-up assertions remain. No production key mode or database changed.

## Verification

Commands run in the Shared repository, using the source production graph:

```powershell
dotnet test tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj --configuration Release -m:1 --filter "FullyQualifiedName~Did2OwnedMailboxSend_RejectsUnavailableOrChangedCustodyBeforeGrantAcquisition|FullyQualifiedName~Did2OwnedMailboxSend_CommittedTextFaultsExactReopenLostReplyAndDurableReceipt|FullyQualifiedName~Did2OwnedMailboxReceive_ActualPublicationRetainedPageSemanticFaultLostAckAndNextEmptyPoll" --logger trx --results-directory artifacts/s01/send-preflight-focused --verbosity quiet
dotnet test tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj --configuration Release -m:1 --filter "FullyQualifiedName~SignedEmptyV2FloorSurvivesAccountReopenAndRejectsCorruption|FullyQualifiedName~SqliteDeepIdV2AccountKeyModeTests|FullyQualifiedName~Did2OwnedMailboxSend_CommittedTextFaultsExactReopenLostReplyAndDurableReceipt" --logger trx --results-directory artifacts/s01/send-preflight-final-focused --verbosity quiet
dotnet build Deep.Client.Shared.Production.slnx --configuration Release -m:1 --no-restore -warnaserror --verbosity minimal
dotnet test Deep.Client.Shared.Production.slnx --configuration Release -m:1 --no-build --no-restore --logger trx --results-directory artifacts/s01/send-preflight-final-full --verbosity quiet
```

The first focused run passed 5/5 (no skips): three preflight rejection cases,
the existing send path and retained-page receive/ACK recovery. It preceded the
additional callback fault and raw-key observer correction. The final focused
run passed 6/6 (no skips): the augmented send case, directory-floor recovery
and four current/retired-key-mode cases. These overlapping runs are not added
together. The final Release build has 0 warnings and 0 errors.

TRX SHA-256 digests (ignored local test artifacts, not shipping evidence):

| Run | Result | SHA-256 |
| --- | --- | --- |
| Original-source preflight reproduction | 1 failure; expected 0 grant callbacks, actual 1 | `3191def775f8b87982ca3570aed9659ff3ab0ea15587b607211699431a9ee11e` |
| First focused | 5 pass / 0 fail / 0 skips | `5deaafc62dfb117659f088944e3b36b8eb7bd5775421c3f4cdd4793bff3a8ada` |
| Isolated stale floor observer | 1 failure; SQLite error 26 | `b549ef1fbaae06f96ec7cca9fd7e4887ff553ca241d03798a8f2018d748000f9` |
| Final focused | 6 pass / 0 fail / 0 skips | `148357732c792ac3ec9f14d78c2d0cf1e7862de0bbb1190a3dcb835fe82621f6` |
| Final full source gate | 545 pass / 0 fail / 0 skips | `f1949cc8c477c8afb3d811547f0022da8c7b924a53e555e49d2902e86901bc79` |

The first full attempt was stopped after the independently reproduced observer
failure, then rebuilt and restarted. It is not a completed full-gate result.
The final full source gate passed all 545 cases, including the three preflight
rejections, the augmented callback/send recovery and directory-floor tests.
This is the Shared production test graph, not the whole release/package gate.

## Remaining integration

Send replay floors still derive from retained prepared entries. The ordinary
command journal also retains its authored sequence history. Neither journal
has sustained retirement/compaction; grant renewal/retirement and retained
route reconciliation remain separate S01/S04 work. Removing successful entries
would lose those floors. A full journal still applies backpressure, not eviction.

Current node/peer admission, issuer renewal, the two-client real transport gate,
scheduler/application receipts and shipping Android/Windows composition remain
open in [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md). No production, device, node
key, operator secret or deployment artifact was changed by this correction.
