# DR-0175 native overflow provider proof — 2026-10-26

[Accepted design](../../../docs/survival-program/decisions/DR-0175-active-native-state-and-archive-validation.md)
and [runtime implementation map](../architecture/semantic-operation-storage-owner-proposal.md).
Runtime archive verification is **not activated**. Independent Node review found
no blockers; root accepted this bounded provider proof for local commit.

The new [eight-case native test](../../tests/Deep.Client.Shared.Production.Tests/SqlCipherNativeOverflowIntegrityTests.cs)
uses the project's real SQLCipher opener and disposable synthetic data. It
classifies the actual one-row table leaf and complete overflow chain using the
same provider's in-memory `sqlite3_serialize`, validates the reconstructed BLOB,
then changes one proven overflow-page ciphertext byte. No decrypted image is
written; managed/native image buffers are zeroed. Each fixture proves65 overflow
pages, page-size4096 and reserved80. Metadata remains readable after damage.

| Preserved run | Native/result | Captured inputs | Meaning |
| --- | --- | --- | --- |
| [01 terminal](../../artifacts/dr0175-native-overflow-20261026-01/terminal.json) | 1;0PASS/8FAIL/0skip | unchanged | Actual provider has no `dbstat`; target-classification prerequisite failed. No scan coverage claimed. |
| [02 terminal](../../artifacts/dr0175-native-overflow-20261026-02/terminal.json) | 1;0PASS/8FAIL/0skip | unchanged | Serializer classification succeeded; fixture final hash read conflicted with native file sharing. Only hash-reader sharing was corrected. |
| [03 terminal](../../artifacts/dr0175-native-overflow-20261026-03/terminal.json) | 0;8PASS/0FAIL/0skip | unchanged | Four clean controls and four raw-corruption cases pass on fresh, reused, fully primed and callback-mutated handles. |

Run03 used Windows PowerShell Desktop5.1.26100.9457, SDK10.0.301 and the root
TestGate native/input/TRX helpers. Release build exited0 with zero warnings/errors.
The complete cipher scan itself rejects corruption on the required original
handle; no cache clearing or fresh handle substitutes for it. A separate fresh
archive BLOB read also rejects as a target witness. Encrypted file hashes/lengths
stay unchanged through checks. TRX diagnostics contain closed booleans/counts
only. `FocusedAccepted=true`, `FullAccepted=false`; all native processes exited.

Remaining work is the connected DR-0175 runtime slice: bounded existing-owner
prefix maintenance, pending-plan recovery before cold audit, complete metadata
proof with captured selected tuples, all selected payload consumers, retained
full exclusions and fresh callback guards. Full source qualification, scaling
and delivery latency remain unqualified. No live profile/key reads or resets
were used, and no one-second claim follows from this provider proof.
