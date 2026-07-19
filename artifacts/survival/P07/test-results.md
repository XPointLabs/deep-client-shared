# P07 test results

- Locked local restore: exit 0, two projects.
- Dependency gate: PASS.
- Full Release: 453 passed, 0 failed, 0 skipped.
- Focused `MembershipTrust`: 143 passed, 0 failed, 0 skipped.
- Privacy/source gate: 3 passed, 0 failed, 0 skipped.
- Schema/flags: 6 passed, 0 failed, 0 skipped.
- Full TRX SHA-256: `d70ceb57aa3d52fd42335c8f4ab66f93c0ceb33320fbe2fc448d90acde2f0e2a`.
- Focused TRX SHA-256: `7f48daa99d3b0e9ff5c063c3166e01c8bd2be5a6da0e72fcd8c0fc1b85eebba9`.
- Schema/flags TRX SHA-256: `b32a796c08b09836946d1126778d6ba2c68333686e56bc8869c02ac94a4ccbf3`.

The commands above were run from exact source commit
`ff32845d3939e671a43a0d2d4cb73abfb0479847`. The dependency gate also
verified the P04 source/review/final ancestry and all three exact global-cache
package archives without depending on sibling repository HEAD or cleanliness.

TRX files were not committed because they contain machine-local paths. No
external, device, Docker, or network E2E lane was run or claimed.

Residual P3 coverage gaps: the revision-one bootstrap fork restart assertion is
dedicated to the in-memory store rather than SQLite, and the inspected
post-commit fences do not yet have separate deterministic barriers for rotation
after content CAS but before the authority fence or for a competing content-head
change before the content fence. These are not claimed as completed coverage.

Exact commands and exit codes:

| Command | Exit |
| --- | ---: |
| `& .\eng\scripts\Invoke-P07DependencyGate.ps1` (before restore) | 0 |
| `dotnet restore .\Deep.Client.Shared.slnx --locked-mode` | 0 |
| `& .\eng\scripts\Invoke-P07DependencyGate.ps1` (after restore) | 0 |
| `dotnet test .\tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj --configuration Release --no-restore --filter "FullyQualifiedName~MembershipTrust" --logger "trx;LogFileName=p07-corrective11-focused.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |
| `dotnet test .\Deep.Client.Shared.slnx --configuration Release --no-restore --logger "trx;LogFileName=p07-corrective11-full.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |
| `& .\eng\scripts\Invoke-P07TrustGate.ps1` | 0 |
| `dotnet test .\tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj --configuration Release --no-restore --filter "FullyQualifiedName~FeatureFlagsTests\|FullyQualifiedName~LogicalSchemaThreeToFour" --logger "trx;LogFileName=p07-corrective11-schema-flags.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |

The Windows checkout initially materialized one pre-existing push fixture with
CRLF because global `core.autocrlf=true`. Its worktree SHA-256 was
`76bda247901e6f0c651db790b6ac8335e0735ec1be666dad9cb3b2b1278a6013`.
Mr. X authorized exact working-tree-only LF normalization from the unchanged
Git blob; the resulting SHA-256 is
`4bca6bffffa751d124a322a51af878476522faa9ded8a56bd2c89f93ac1e576a`.
The blob remained `76005cbb4fdbcdd8cd0b9eef8482af2386067741` and the fixture has no Git diff.
