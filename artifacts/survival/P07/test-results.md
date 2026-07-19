# P07 test results

- Locked local restore: exit 0, two projects.
- Dependency gate: PASS.
- Full Release: 414 passed, 0 failed, 0 skipped.
- Focused `MembershipTrust`: 104 passed, 0 failed, 0 skipped.
- Privacy/source gate: 3 passed, 0 failed, 0 skipped.
- Schema/flags: 6 passed, 0 failed, 0 skipped.
- Full TRX SHA-256: `2fd7144d65f9bd66cfbead6106facbe151a6b1de102857adaf19dfaccc551098`.
- Focused TRX SHA-256: `6970692a359b2381039c01bb0cb5e18663b9d69cfd62d8188c9d6fb40759453e`.
- Schema/flags TRX SHA-256: `4faf3d0f36419572acb9990ec32473c90356a4295d2fe1ea0ac6463a46625d25`.

The commands above were run from exact source commit
`4cd90d1f952a64dc000d7f1997f648eea11c26bd`. The dependency gate also
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
| `dotnet test .\tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj --configuration Release --no-restore --filter "FullyQualifiedName~MembershipTrust" --logger "trx;LogFileName=p07-corrective6-focused.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |
| `dotnet test .\Deep.Client.Shared.slnx --configuration Release --no-restore --logger "trx;LogFileName=p07-corrective6-full.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |
| `& .\eng\scripts\Invoke-P07TrustGate.ps1` | 0 |
| `dotnet test .\tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj --configuration Release --no-restore --filter "FullyQualifiedName~FeatureFlagsTests\|FullyQualifiedName~LogicalSchemaThreeToFour" --logger "trx;LogFileName=p07-corrective6-schema-flags.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |

The Windows checkout initially materialized one pre-existing push fixture with
CRLF because global `core.autocrlf=true`. Its worktree SHA-256 was
`76bda247901e6f0c651db790b6ac8335e0735ec1be666dad9cb3b2b1278a6013`.
Mr. X authorized exact working-tree-only LF normalization from the unchanged
Git blob; the resulting SHA-256 is
`4bca6bffffa751d124a322a51af878476522faa9ded8a56bd2c89f93ac1e576a`.
The blob remained `76005cbb4fdbcdd8cd0b9eef8482af2386067741` and the fixture has no Git diff.
