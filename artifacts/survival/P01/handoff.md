# P01 handoff

Owner: Mr. X

Feature gate: `DEEP_SURVIVAL_METADATA_GATE`

Artifact root: `artifacts/survival/P01`

## For independent reviewer

1. Verify production source and current wire fixtures are unchanged.
2. Run the default focused lane and confirm every characterization case passes with zero skips.
3. Set `DEEP_SURVIVAL_METADATA_GATE=1`, run only `BetaMetadataGate`, and confirm one non-skipped failure for each unresolved Beta blocker.
4. Compare the observer/collusion matrix to the byte-level and serialized request evidence.
5. Reject any attempt to mark a finding resolved using design prose alone; require producer tests and reviewed implementation evidence.
6. Review P03 against `producer-contract-for-P03.md` without treating any listed reference as a selected primitive.

## Expected current result

- Default suite: green.
- Strict metadata gate: red.
- Beta privacy decision: NO-GO.
- Production readiness: false.
