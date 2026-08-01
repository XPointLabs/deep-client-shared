# P14A2 sanitized evidence carrier

Accepted source commit:

`e0d6cba25dc05734f5eba0f1690bb07efdaf2e0f`

Accepted source tree:

`7e83f454219a02ce47e220838897ddb71551e526`

Decisions:

- `DORMANT-CLIENT-VERIFIER-GO`
- `STAGED-BYTES-ONLY-GO`
- `PRODUCTION-VERIFIER-NO-GO`
- `PRODUCTION-TIME-POLICY-NO-GO`
- `ACTIVATION-RUNTIME-DI-NETWORK-UI-BILLING-NO-GO`

Human decision owner: Mr. X.

Two independently labelled final reviews examined the exact accepted source and
returned `GO` with `P0/P1/P2/P3 = 0/0/0/0`. The complete RED, GREEN, build
closure and corrective chain is retained in `evidence.json`.

The inherited strict metadata privacy gate still has eight unresolved release
blockers outside P14A2. A nonblocking inherited SQLite `ClearAllPools` P3 test
flake is also recorded with its initial failure and successful isolated and full
reruns. It is not classified as a P14A2 regression.

This directory is evidence-only. It contains no source, test, vendor, script or
binary copies. It contains no absolute paths, timestamps, durations, host or user
names, endpoints, network identifiers, candidate or account identifiers,
credentials, seeds, keys, signature or carrier bytes, raw exceptions, provider
data or sensitive test sentinels.

Hash closure is intentionally absent in the RED evidence commit. The GREEN
evidence commit adds `SHA256SUMS` and `CONTENT_SHA256`, and records the RED commit
identity in `evidence.json`. The final evidence commit is reported externally to
avoid a self-referential commit identity inside the carrier.
