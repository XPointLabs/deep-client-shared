# P07 test results

- Locked local restore: exit 0, two projects.
- Dependency gate: PASS.
- Full Release: 349 passed, 0 failed, 0 skipped.
- Focused `MembershipTrust`: 39 passed, 0 failed, 0 skipped.
- Privacy/source gate: 3 passed, 0 failed, 0 skipped.
- Full TRX SHA-256: `a0ad24ba2eee2fcce5f74b0aa303d5ad84659a250bf8159461f4292777c7fec2`.
- Focused TRX SHA-256: `58ec63008e332c2c95171136589063d39735d913cd41c9e483a3cb5f3f60c0be`.

TRX files were not committed because they contain machine-local paths. No
external, device, Docker, or network E2E lane was run or claimed.

The Windows checkout initially materialized one pre-existing push fixture with
CRLF because global `core.autocrlf=true`. Its worktree SHA-256 was
`76bda247901e6f0c651db790b6ac8335e0735ec1be666dad9cb3b2b1278a6013`.
Mr. X authorized exact working-tree-only LF normalization from the unchanged
Git blob; the resulting SHA-256 is
`4bca6bffffa751d124a322a51af878476522faa9ded8a56bd2c89f93ac1e576a`.
The blob remained `76005cbb4fdbcdd8cd0b9eef8482af2386067741` and the fixture has no Git diff.
