# S01/S03 matching client Store writer — 2026-10-04

Owner: Mr. X. Local candidate evidence, not remote delivery or Release activation.
Input Shared: `cdb6101d5783877fd7c527cd2481423bf67a13ed`, plus this commit.
Single semantic owner: [DR-0086](../../../docs/survival-program/decisions/DR-0086-current-mailbox-store-order.md).
Execution owner: [implementation plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).

`MailboxPrivacyPathProvider` keeps Store's exit at the first replica of the
exact scoped credential for both primary and fallback attempts. Retrieve and
ACK retain selection of either replica. There is no writer fallback, forwarding
adapter, new wire or change to the guard retention algorithm.

The owned grant installer takes PMS2 tag 6 in its authenticated order, resolves
each corresponding descriptor key, installs the credential and checks its exact
SQL read-back. The pair constructor and SQL resolver retain first/second order;
they do not lexicographically sort node IDs. The pair itself is not authority.

Two structural path cases deliberately reverse replica ID order. They verify
Store keeps the same writer across attempts while Retrieve/ACK may change exit;
the signed network is genuine, but those synthetic grants prove only bounded
path selection, not grant issuance or remote mutation.

Owned send/retry tests additionally exercise both path selections after actual
signed grant installation, SQL custody, native ratchet and protected send intent.
Their in-process replica result remains a fixture, not a socket or physical
recipient. A test-only guard preference makes an incorrect fallback exit
observable through the selected entry; no shipping guard policy is changed.
SQL reopen coverage compares both replica IDs and their respective keys.

Initial focused gate: **7 pass / 0 fail / 0 skip** in
`artifacts/s03-writer/focused`. Both final Release builds have zero warnings and
errors. Final full production gate: **547 pass / 0 fail / 0 skip**, including
all **8 writer/path/send/SQL-reopen cases**, in 34m30s. Final TRX:
`artifacts/s03-writer/final/shared-writer.trx`, SHA-256
`529193f433295900d51c8c21530e5f62d09b270a03a373defdeadfdbddeeabcf`.

```powershell
dotnet test Deep.Client.Shared.Production.slnx --configuration Release -m:1 --no-build --logger "trx;LogFileName=shared-writer.trx" --results-directory artifacts/s03-writer/final
```

Matching [native writer checkpoint](../../../xnode/docs/testing/s03-mailbox-writer-2026-10-04.md)
records admission, correctly signed non-writer peer rejection, actual TLS/H2
ingress and two-store quorum. Program/DI, startup/retained history/retirement,
object horizon, current issuer/package matrix, scheduler/AppAck and actual
Windows/Android Release delivery remain open. No production/account/key reset
or release publication was performed.
