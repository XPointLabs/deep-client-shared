# P11A verification evidence

Source commit under test:
`c54869eb22f18facd395eabb1941342e3b217c70`

Exact base:
`13e39cf9ff4b0cf3b1c60084aa5af977db68f280`

Status:
`contract/storage-go-runtime-unwired`

## Gates

| Gate | Result | Count | SHA-256 |
| --- | --- | ---: | --- |
| Locked offline restore | pass | 2 projects | `ddf68db3d8d2f9572a71c51f3f3fdb8d71553978fea549cde378875132e4b7b4` |
| Focused P11A/purge/flag/schema tests | pass | 30/30 | `10d235765f3c9af7fffdff6fa731e613ea6941bd3324ab99f505bdd9dbf711a2` |
| Full Debug solution tests | pass | 476/476 | `73266b552d89a9b3a2ce0b1704ed72d0685f8ae52bf1bbccc75a3de4bb57014f` |
| Full Release solution tests | pass | 476/476 | `2037c48a48ad5e4910241da511eed01c0907fa6ea777d5d863bf1af94366bdad` |
| Focused coverage run | pass | 21/21 | `cf8939e50131699485b4a9277113e810111f1834cec407a54a356ecd9a3a926a` |
| Coverage Cobertura | produced | 3,559,055 bytes | `47f6f3077f05306c06a92260870a1ff000b5fb795afa8c084a1611f1d3f6b42a` |
| Debug build | pass | 0 warnings / 0 errors | `33befd1a94073ecef6c5d3a181cb1ef862cb9ee0fecc2cade82d41f11f28b629` |
| Release build | pass | 0 warnings / 0 errors | `c690c8407f8d0f9c46d81490682ada79f16163bd236626a53bf2fb9fa8113bed` |
| `dotnet format --verify-no-changes --severity warn` | pass | no changes | n/a |
| `git diff --check` | pass | no findings | n/a |

The locked restore used invalid loopback HTTP/HTTPS proxies, locked mode and
`--ignore-failed-sources`; it completed entirely from the local package cache.

## Focused coverage observations

- SQLite P11A repository line rate: 93.03%; branch rate: 78.2%.
- In-memory P11A repository line rate: 82.83%; branch rate: 79.31%.
- Shared outbox state machine line rate: 86.34%; branch rate: 68.99%.

Coverage is supporting evidence, not a runtime-readiness claim.

## Required behavior demonstrated

- restart after Prepared, Attempted, Accepted, Durable and Delivered;
- exact mutation retry is idempotent after restart and after outcome-unknown;
- Accepted remains distinct from Durable;
- Delivered requires matching recipient-device acknowledgement evidence;
- multiple adapter attempts share one logical item and one revision chain;
- an explicit concurrency barrier proves simultaneous durable success produces
  one Applied result, one CAS Conflict and one logical Durable state;
- retry/list/attempt/evidence/payload/lifetime limits are bounded;
- Expired is terminal and batch expiry is bounded;
- cancellation before commit leaves no row;
- post-commit failure reports explicit outcome-unknown and reconciliation works;
- populated physical v7 migrates to v8 without losing its existing row;
- physical schema newer than v8 fails closed;
- oversized item and attempt BLOBs return Corrupt before materialization;
- in-memory and SQLite run the same contract scenarios;
- scope purge is isolated and account purge removes remaining outbox state;
- mutable input and output buffers are defensively copied;
- both default feature profiles leave P11A dormant.

## Final corrective acceptance evidence

Exact accepted source:
`343f770800ad6247a5a0ae63a418b229c9388cde`.

Two independent exact-source reviews returned `GO` with no P0, P1 or P2.
Focused TransportOutbox tests passed 101/101 in Debug and Release; the full
solution passed 556/556 in Debug and Release. Both builds completed with zero
warnings and errors. Locked offline restore, formatting and diff checks passed.

The committed sanitized test files contain the exact source SHA, command,
original local TRX hash, counters and sorted test-name/outcome/occurrence rows.
The occurrence ordinal distinguishes theory cases whose display names collide. They omit
user, host, absolute path, timestamp and execution identifiers.

Acceptance is limited to the dormant transport-neutral storage contract.
Runtime wiring, recipient acknowledgement verification, live delivery,
physical-device E2E and production readiness are not claimed.
