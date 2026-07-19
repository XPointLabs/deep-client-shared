# P07 test results

- Locked local restore: exit 0, two projects.
- Dependency gate: PASS.
- Full Release: 443 passed, 0 failed, 0 skipped.
- Focused `MembershipTrust`: 133 passed, 0 failed, 0 skipped.
- Privacy/source gate: 3 passed, 0 failed, 0 skipped.
- Schema/flags: 6 passed, 0 failed, 0 skipped.
- Full TRX SHA-256: `2ed7c11d491032154f54d5b6078116b26168e561b8f4684c280f2fa47315316b`.
- Focused TRX SHA-256: `0d8704175e5aeb05f19e1483ad590df9cbcaeb4023dfd1262fab28736875f0ae`.
- Schema/flags TRX SHA-256: `f1ccdceb4701738f472aa97677e34d04f2816a1319551030dba52bbf6cad9f15`.

The commands above were run from exact source commit
`0709e11d257358f6786cffe62ee7cd5994c8e626`. The dependency gate also
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
| `dotnet test .\tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj --configuration Release --no-restore --filter "FullyQualifiedName~MembershipTrust" --logger "trx;LogFileName=p07-corrective8-focused.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |
| `dotnet test .\Deep.Client.Shared.slnx --configuration Release --no-restore --logger "trx;LogFileName=p07-corrective8-full.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |
| `& .\eng\scripts\Invoke-P07TrustGate.ps1` | 0 |
| `dotnet test .\tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj --configuration Release --no-restore --filter "FullyQualifiedName~FeatureFlagsTests\|FullyQualifiedName~LogicalSchemaThreeToFour" --logger "trx;LogFileName=p07-corrective8-schema-flags.trx" --results-directory .\artifacts\survival\P07\trx` | 0 |

The Windows checkout initially materialized one pre-existing push fixture with
CRLF because global `core.autocrlf=true`. Its worktree SHA-256 was
`76bda247901e6f0c651db790b6ac8335e0735ec1be666dad9cb3b2b1278a6013`.
Mr. X authorized exact working-tree-only LF normalization from the unchanged
Git blob; the resulting SHA-256 is
`4bca6bffffa751d124a322a51af878476522faa9ded8a56bd2c89f93ac1e576a`.
The blob remained `76005cbb4fdbcdd8cd0b9eef8482af2386067741` and the fixture has no Git diff.
