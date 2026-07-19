# P07 test results

- Locked local restore: exit 0, two projects.
- Dependency gate: PASS.
- Full Release: 376 passed, 0 failed, 0 skipped.
- Focused `MembershipTrust`: 66 passed, 0 failed, 0 skipped.
- Privacy/source gate: 3 passed, 0 failed, 0 skipped.
- Schema/flags: 6 passed, 0 failed, 0 skipped.
- Full TRX SHA-256: `a655627db8a0fb77d34f2ff0831483bd13aad8ba2b27591f047d40034f83a2de`.
- Focused TRX SHA-256: `6dcbdd70e96aaa3ce7abcbfd9552e1ae4a2ae838f756e1498eab6eab69325b95`.
- Schema/flags TRX SHA-256: `a73095adf4f7a809257c7a3f13a44901815c723d2604c883fc9d61f28b3497bf`.

The commands above were run from exact source commit
`e665972e655160c7359b18d8dfeb432efec524a6`. The dependency gate also
verified the P04 source/review/final ancestry and all three exact global-cache
package archives without depending on sibling repository HEAD or cleanliness.

TRX files were not committed because they contain machine-local paths. No
external, device, Docker, or network E2E lane was run or claimed.

Exact commands and exit codes:

| Command | Exit |
| --- | ---: |
| `& .\eng\scripts\Invoke-P07DependencyGate.ps1` (before restore) | 0 |
| `dotnet restore .\Deep.Client.Shared.slnx --locked-mode` | 0 |
| `& .\eng\scripts\Invoke-P07DependencyGate.ps1` (after restore) | 0 |
| `dotnet test .\tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj --configuration Release --no-restore --filter "FullyQualifiedName~MembershipTrust" --logger "trx;LogFileName=p07-corrective3-focused.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |
| `dotnet test .\Deep.Client.Shared.slnx --configuration Release --no-restore --logger "trx;LogFileName=p07-corrective3-full.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |
| `& .\eng\scripts\Invoke-P07TrustGate.ps1` | 0 |
| `dotnet test .\tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj --configuration Release --no-restore --filter "FullyQualifiedName~FeatureFlagsTests\|FullyQualifiedName~LogicalSchemaThreeToFour" --logger "trx;LogFileName=p07-corrective3-schema-flags.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |

The Windows checkout initially materialized one pre-existing push fixture with
CRLF because global `core.autocrlf=true`. Its worktree SHA-256 was
`76bda247901e6f0c651db790b6ac8335e0735ec1be666dad9cb3b2b1278a6013`.
Mr. X authorized exact working-tree-only LF normalization from the unchanged
Git blob; the resulting SHA-256 is
`4bca6bffffa751d124a322a51af878476522faa9ded8a56bd2c89f93ac1e576a`.
The blob remained `76005cbb4fdbcdd8cd0b9eef8482af2386067741` and the fixture has no Git diff.
