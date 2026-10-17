# S05 — logical assignment grant custody

Scope: local dev source correction under accepted
[DR-0122](../../../docs/survival-program/decisions/DR-0122-logical-mailbox-assignment-carriage.md),
not new wire, journal generation, authority, production activation or physical acceptance.
The implementation mapping belongs to [owned custody](../architecture/owned-mailbox-grant-custody.md).

## Diagnosis

Windows build20 failed Initial Deposit acquisition before confirmed Store.
Matching Shared module SHA256
`eb4e8696c0c15003f935ddbfb50fe8516486d83e2c935eed3efdcd5eb602f613`
and portable PDB SHA256
`c4ce936936895048dc0ce789100dd702b8747de69d41689e8f5ae7b765cf03d2`
have matching CodeView identity. `OriginalCeiling` IL758 maps to line624,
the no-possible-interval throw, NOT the compound binding throw at line616.
The earlier checkpoint diagnosis was imprecise; original receipts remain unchanged.

The Shared ceiling wrongly included the original PMT snapshot's expiry. Protocol
issuance/result verification already uses the five signed logical-resource
intervals. Current issuer policy must bind independently verified CURRENT
projection, while the exact original assignment stays immutable. These joins
are now used consistently by acquisition, SQL installation and Store dispatch.
Historical reply/epoch evidence authenticates both distinct exact policy/projection
pairs; it cannot authorize new dispatch. No time, holder, floor, revocation,
SQL/native guard or exact retry check is disabled.

The sole current journal reader recomputes the corrected ceiling. An old record
with a different stored ceiling rejects; no compatibility reader, rewrite,
migration or automatic reset is introduced. Retained devices must be tested
without replacing their accounts or pending intents.

## Native source receipts

Prefix: `artifacts/s05-deposit-logical-ceiling-20261016/`.
Windows PowerShell5.1 / SDK10.0.301; these are focused, not canonical full gates.

| Run | Result | Interpretation |
| --- | --- | --- |
| red-01 | native1, no TRX | Missing test namespace import; fixed. |
| red-02 | 2PASS/1FAIL/native1 | Fixture selected old policy, corrected to actual successor. |
| red-03 | 2PASS/1FAIL/native1 | Pending incorrectly joined current issuer to original projection. |
| focused-04 | 3PASS/0FAIL/native0 | Five logical intervals, original selection, cold journal/result verification. |
| owned-05 | 2PASS/1FAIL/native1 | Harness omitted actual owned dispatch loan; now matches production call. |
| owned-06 | 2PASS/1FAIL/native1 | Actual SQL installation still joined policy to old projection. |
| affected-07 | 41PASS/0FAIL/0skip/native0 | Actual owned grant loss/reopen/exact retry/SQL install, custody, epoch exclusion, namespace negatives and renewal. |
| store-08 | interrupted/native1, partial31PASS/0FAIL | Deliberately stopped the owned test host to defer duplicate broad Store coverage until final qualification. Original aborted TRX/log/terminal remain; NOT PASS. |

All final cases retain real signed histories, native SQLCipher and protected
owners; the issuer callback is in-process fixture transport, not physical nodes.
Wrong current projection, changed epoch, route expiry, missing/corrupt historical
metadata and unsupported roles reject. The fixture correction passes the same
owned dispatch loan as production; it does not synthesize authority.

Matching Windows22/APK38 were built and opened on the retained accounts; no
compiler diagnostics, reset or new identity. The original Windows retry now
rejects its expired rendezvous, independently of the repaired grant ceiling.
The normal owned stop succeeded. A separately explicit new contact command
passed grant custody and reached Store dispatch, then returned OutcomeUnknown
with inner cancellation. Its exact retry later cancelled while validating
the original recipient, before a new dispatch. Neither outcome proves noncommit.
See [device observations](../../../deep-client-maui/docs/DID2-HTTPS-DEVICE-2026-09-28.md).

Remaining: canonical Shared qualification, actual Store/receive/consent and
two-client text, plus bounded-work/performance diagnosis. The
separate Android original draft-metadata mismatch remains unresolved. Empty
mailbox reads do not close contacts/messages/attachments/groups acceptance.

## 2026-10-17: pending Initial across ordinary carriage renewal

Windows30 exact retry after the matching local TTL correction stopped before
dispatch in `RetainInitialStoreEvidenceUnderLeaseAsync:168` (30900ms,
3 Protect/1191 Unprotect,8662ms protection). Native terminal diagnostics contained
no new failure in that observation. Independent UI remained terminal with the
same retry choice; this is not delivery or proof of noncommit for earlier work.

The source compared newly captured current XNV1/XND1 bytes with immutable
original Store evidence. Routine carriage renewal can legitimately change these
bytes while preserving the exact assignment and node receipt identities. The
new native encrypted fixture reproduces the same guard before ingress and after
a lost reply: `artifacts/s05-pending-initial-view-20261017/red-01`,0PASS/2FAIL,
native1/0skip. Original failure receipts remain unchanged.

The correction preserves the original commitment and all original SQL records.
Account/logical/policy/recipient/route bindings still match exactly; both original
and current signed replica facts are independently verified through the actual
retained lineage, and the selected node IDs and receipt keys must match. The
original peer proof is independently verified at original creation. Completion
still requires the original MAU/quorum and signed original-view/grant intervals;
no current document replaces a historical record. This applies existing
[DR-0106](../../../docs/survival-program/decisions/DR-0106-retained-store-public-evidence.md)
and [DR-0122](../../../docs/survival-program/decisions/DR-0122-logical-mailbox-assignment-carriage.md),
not a new wire, journal, schema, expiry, authority or compatibility path.

Focused source verification:23PASS/0FAIL/0skip/native0, no compiler diagnostics,
Windows PowerShell5.1/SDK10.0.301, receipt
`artifacts/s05-pending-initial-view-20261017/focused-02`. Both new encrypted
cold-retry scenarios pass and compare the complete original SQL evidence digest
before/after delivery. Existing original evidence/key/view substitution, missing
evidence, lost completion, attempt rebinding, assignment and successor cases
remain enforced. Matching client builds/device retry remain pending. Full/package
qualification and physical business acceptance are open.

## Committed Initial on the next carriage view

Windows31/APK47 exercised the matching correction above without account reset.
Windows reached Store transport again (OutcomeUnknown113584ms), and Android's
incoming path reached Initial claim promotion but rejected it. The physical
closed trace does not expose the exact rejection field. The new owned scenario
independently reproduces the exact-current-placement guard after ordinary view
renewal: `artifacts/s05-committed-initial-carriage-20261017/red-01`,0PASS/1FAIL,
native1. Existing allocated request/result bytes must not be rewritten.

[DR-0136](../../../docs/survival-program/decisions/DR-0136-committed-claim-original-carriage.md)
corrects only committed-recipient verification. Current admitted identities,
both original signatures, exact original placement and continuous unchanged
current epoch/cohort remain mandatory; initiator admission stays current-only.
The first affected batch `focused-02` passed8/failed1/native1: the cycle passed
Initial promotion, then the fixture omitted its original PMA when producing
the reverse Store. That missing-policy guard was preserved. The ordinary-view
fixture now distributes the real signed original/current policy history;
deliberately hostile policy/issuer candidates remain isolated, not hidden by a
valid predecessor.

`focused-03`:6PASS/native0/0skip. Final fixture cleanup `focused-04`:2PASS/native0,
0skip/no compiler diagnostics: complete native encrypted two-account
receive/ContactAccept/reply cycle after renewal plus the existing policy-source
negative. The intended issuer-rotation filter in04 did not match its actual
method name; no rotation coverage is claimed there. Separate `issuer-05` passed2
cases/native0/0skip/no compiler diagnostics for initial and ordinary original
Store outcomes across issuer rotation/current-policy substitution. Protocol's
`crypto-02` passed14, including its actual monolithic claim-cryptography witness.
Matching corrected clients and physical business acceptance remain pending. No replay freshness,
authority lifetime, timeout, schema or account reset was changed.
