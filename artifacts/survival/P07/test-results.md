# P07 test results

- Locked local restore: exit 0, two projects.
- Dependency gate: PASS.
- Full Release: 438 passed, 0 failed, 0 skipped.
- Focused `MembershipTrust`: 128 passed, 0 failed, 0 skipped.
- Privacy/source gate: 3 passed, 0 failed, 0 skipped.
- Schema/flags: 6 passed, 0 failed, 0 skipped.
- Full TRX SHA-256: `0227223db7073cdf804cd4f92824ddb01d45b224908b2ef391d7c95d60bee678`.
- Focused TRX SHA-256: `a3d19f3a6b44e50c7f2400c537f54465d522358fc2f2b4d22f361b1a7f823a6f`.
- Schema/flags TRX SHA-256: `70b52bce6a3aace2622a6490a1bd50db5d4bcc79c714390c3283f1763914bfc1`.

The commands above were run from exact source commit
`e6319e980eaf9cb1b8059ab8a3f91119482297b4`. The dependency gate also
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
| `dotnet test .\tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj --configuration Release --no-restore --filter "FullyQualifiedName~MembershipTrust" --logger "trx;LogFileName=p07-corrective7-focused.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |
| `dotnet test .\Deep.Client.Shared.slnx --configuration Release --no-restore --logger "trx;LogFileName=p07-corrective7-full.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |
| `& .\eng\scripts\Invoke-P07TrustGate.ps1` | 0 |
| `dotnet test .\tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj --configuration Release --no-restore --filter "FullyQualifiedName~FeatureFlagsTests\|FullyQualifiedName~LogicalSchemaThreeToFour" --logger "trx;LogFileName=p07-corrective7-schema-flags.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |

The Windows checkout initially materialized one pre-existing push fixture with
CRLF because global `core.autocrlf=true`. Its worktree SHA-256 was
`76bda247901e6f0c651db790b6ac8335e0735ec1be666dad9cb3b2b1278a6013`.
Mr. X authorized exact working-tree-only LF normalization from the unchanged
Git blob; the resulting SHA-256 is
`4bca6bffffa751d124a322a51af878476522faa9ded8a56bd2c89f93ac1e576a`.
The blob remained `76005cbb4fdbcdd8cd0b9eef8482af2386067741` and the fixture has no Git diff.
