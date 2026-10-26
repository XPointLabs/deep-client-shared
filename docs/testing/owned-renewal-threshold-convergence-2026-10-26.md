# Owned renewal threshold convergence — unqualified candidate

The scheduling contract is [DR-0078, 2026-10-26 bounded admission](../../../docs/survival-program/decisions/DR-0078-did2-owned-publication-renewal.md#2026-10-26--bounded-admission-of-an-exact-future-start-threshold).
Protocol alone produces the authenticated `DeepIdV2RouteNotBeforeException`.
Shared repeats full verification of one owned response under the original
30-second monotonic acquisition budget, including dispatch and fetch, with
at most three attempts and two cancellable waits. Actual owner/source,
same-boot time, resolver capability and exact protected proposal are rejoined
after waiting and before guarded adoption. No TRS loan is created by this path.

`DeepIdV2ContactPathAuthoritySourceTests.ThresholdConvergence.cs` contains genuine
signed full-entry cases for future scheduling, invalid later XRC/XSS
signatures, mixed expiry, start beyond the upper bound, final-reading
convergence and unchanged strict author completion. The XRC signature case has
the unresolved coverage gap recorded below. Owned renewal cases cover
one exact fetch/signing/adoption, finite attempts, cancellation, proposal/source
loss, proof expiry, boot change, the actual original fetch deadline and a late
clock callback that ignores cancellation. In-process signed fixture evidence
is not connected Registry, retained-profile or latency qualification.

## Recorded focused runs

Both runs used Windows PowerShell 5.1 and the existing root TestGate helpers.
Their original logs, input manifests, native results and terminal receipts are
preserved under `artifacts/owned-renewal-threshold-convergence-20261026-01` and
`artifacts/owned-renewal-threshold-convergence-20261026-02`.

- **Focused01:** Release build native exit **1**, zero warnings and two CS0103
  errors for the missing test namespace import of
  `DeepIdV2ContactAuthorizationCodec`. Source inputs were unchanged during the
  build. Tests were not launched; the terminal's `InputsUnchanged=false` is
  not a test-phase unchanged-input qualification. `FocusedAccepted=false` and
  `FullAccepted=false`.
- **Focused02:** Release build native exit **0**, zero warnings/errors;
  tests native exit **1**, **18 PASS / 1 FAIL / 0 SKIP** out of the declared
  19 cases. Source inputs were unchanged during the build, and all **2,208**
  captured code/binary/normative inputs were unchanged during tests.
  `FocusedAccepted=false` and `FullAccepted=false`.

The sole Focused02 failure is
`Did2ThresholdConvergence_FullSignedRetainedEntryKeepsEveryAuthorityCheck(mode: 1)`.
The actual rejection is `ContactFormatException / ClosureReferenceMismatch`
before the intended invalid-XRC witness-signature check. This case therefore
does not establish that specific signature-rejection witness. The original
assertion and failure remain preserved; no passing replacement is claimed.

The other six signed-entry cases, all nine owned renewal cases and the three
selected existing renewal/recovery regressions passed in Focused02. This is
partial focused evidence, not accepted qualification.

Status: **unqualified candidate preserved for review**. No full gate, connected
activation, retained-profile recovery, live publication or latency acceptance
is established by this checkpoint. No product/test changes or native rerun
followed the read-only safe-checkpoint instruction.
