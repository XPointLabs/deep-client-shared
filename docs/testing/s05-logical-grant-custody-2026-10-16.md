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
