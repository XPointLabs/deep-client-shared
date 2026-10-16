# S05 — atomic protected floor reads

The retained Windows22 exact retry cancelled before new Store dispatch while
validating the original Initial recipient. Android38 Retrieve separately
returned OutcomeUnknown. Neither establishes noncommit or a precise latency cause.

The existing `IDeepSecureStorage.ReadOwnedBatchAsync` contract already supplies
one actual atomic inventory snapshot with deterministic disposal, without a
plaintext cache. Network floor validation now reads current projection marker,
exact-history anchor and both future markers together (four reads to one).
Directory floor validation similarly reads current/future markers together
(two reads to one). All missing/scope/exact-history/rollback checks remain.
Each independent validation reacquires a new inventory snapshot; no disk format,
currentness/crypto lease, deadline, key, account or wire changes.

Receipts: `artifacts/s05-network-marker-batch-20261016/`, Windows PowerShell5.1,
SDK10.0.301, focused rather than canonical full qualification.

- `focused-01`:38PASS/0FAIL/0skip/native0, initial network-only batch.
- `focused-02`:47PASS/0FAIL/0skip/native0, final network/directory batch and
  opt-in test counters. No compiler diagnostics. Includes actual encrypted
  native floor reopen, independent reacquisition, missing current marker/anchor,
  future marker/anchor, cancellation after the actual batch callback, unchanged
  protected bytes after rejection, directory rollback and storage batch contracts.

Test counters are disabled outside the new bounded case; normal fixtures do not
retain a growing read log. An atomic batch's single platform decryption is
independently covered by the existing Journaled storage tests.

Matching Windows23/APK39 include this source and retain the QA accounts; both
build native0 with no compiler diagnostics. APK39 dry137/update138 and Settings139
confirm retained Android account/recovery. Windows's saved retry rejected its
expired XUR; normal owned stop succeeded before separately explicit new work.
The fresh request returned OutcomeUnknown at18:50:31Z, with inner cancellation
in the actual batch read during directory-floor validation. It entered the Store
path, but neither network forwarding nor storage is independently confirmed.
Android Refresh141 -> independent Inspect142 still ends in messaging error;
closed caller metadata identifies Retrieve OutcomeUnknown. No reset or new
signed-resource deadline was used to evade either refusal.

This proves reduced read calls, NOT a latency benchmark or resolved transport.
Actual Store/Retrieve/ACK, narrow remaining work/timeout diagnosis, canonical
full/package and physical business acceptance remain required. Exact receipts
and hashes belong to the [device checkpoint](../../../deep-client-maui/docs/DID2-HTTPS-DEVICE-2026-09-28.md).
