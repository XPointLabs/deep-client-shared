# S07 authenticated local history — 2026-10-04

This implements the read-only sub-boundary identified by item5 of the
[audit](../../../docs/architecture/ARCHITECTURE-AUDIT-2026-10-03.md).
It does not close S07 or advance past the dependencies in the
[execution plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).

## Source and behavior

The source batch is the Shared/MAUI commit containing this checkpoint and its
linked implementation; root NEXT-SPRINT records the exact committed matrix.
Protocol remains `8989ad6a787cdc8194106a5130fcfa832608e252`.
Shared parent is `c5ed60757c5a563cf76f6afc60a3fdd62c52644f`; MAUI parent is
`11f1c8fb8a0d70178fa62ad78e69e93da1bb400a`.
No wire, suite, protected format, package pin or diagnostic Release guard changes.

Local ListConversations/ListMessages remove the network-source parameter,
without old-signature overloads. Existing protected identity, exact initialized
catalog, peer bootstrap, source retirement and active SQL/floor verification
remain mandatory. Local acceptance projection checks actual receive custody or
the explicit acceptance command/send winner, and exact conversation/Hello
binding. It grants no new network acceptance, send, receive or ACK authority.
Readers cannot initialize a session or recreate missing protected state.

MAUI diagnostic local reads bypass bootstrap HTTP. Network command readiness is
separate from local reading; network loss preserves already authenticated
projection/draft while closing network commands. A changed account or an
integrity rejection clears projections. Refresh reads local state before any
optional online synchronization. Offline queueing is not implemented here.

The initial Clean full run93/1 exposes a reconnect race. A deterministic
synchronous-cancellation test reproduces the exact failure:3 attempts instead of
2. Invalidation now publishes state/wake before cancellation; a superseded
reentrant notification cannot overwrite the newer state. The final full Clean
suite includes the unchanged exact-count assertion and passes95/0/0.
This reproduces that scheduling bug; it does not diagnose unrelated XNode ACK
setup timeouts or prove network availability.

## Terminal local evidence

Shared focused3/0/0 completes exit0,8m33s, rebuilding all test source without a
compile whitelist. The actual two-account native mailbox cycle adds cold local
history after proof TTL with the proof service rejecting requests: both accepted
states and the single sent/received text project with zero additional proof
requests. Foreign handles and cancelled reads reject; missing protected peer
bootstrap rejects both listing paths and is not repaired. Restoring the exact
test-owned record restores reading. Fresh send still fails before grant/terminal
callbacks when proofs are unavailable. Fixture restoration is test-only, not a
product recovery fallback. Signed in-process issuer/time/transport fixtures are
not socket or device evidence.

MAUI full Clean95/0/0 and smoke119/0/0 complete exit0; builds use warnings as
errors. The normal Windows ARM64 Debug build completes with zero warnings/errors.
It does not compile the opt-in HTTPS adapter or qualify a shipping artifact.
The unfiltered Shared production solution completes exit0 on source
`42aee0d8358d552f43bee256e0fb52cc1ab45e3b`: **564 passed /0 failed /0 skipped**,
33m21s. All production test source rebuilds under warnings-as-errors. The prior
564-pass matrix predates this batch; only the new receipt qualifies local history.

| Receipt (repository-relative) | SHA-256 |
| --- | --- |
| Shared `artifacts/s07-local-history/focused-final/nikit_SURFACE-LT_2026-10-04_20_36_22_net10.0.trx` | `b300b13fbe27cd46a4eefa09282e7e5d048483857e68ff82d3a47910fbf40eac` |
| Shared full `artifacts/s07-local-history/full-final/nikit_SURFACE-LT_2026-10-04_20_43_56_net10.0.trx` | `c2f1264389f4f4c85da733a5e8f836c68f4013322d2acd816a217f6acfb04d25` |
| MAUI initial full `artifacts/s07-local-history/ui-full/nikit_SURFACE-LT_2026-10-04_20_35_02_net10.0.trx` | `b70c3359b15411d4ac72bd9c7a3e268fcd2047ce483c4800d4cb730f61d9b281` |
| MAUI regression before fix `artifacts/s07-local-history/reentrant-before/nikit_SURFACE-LT_2026-10-04_20_39_50_net10.0.trx` | `d5de2d3fa80379e19de37c80c43cd8203ab3e1a4fe71133d26aef25757d03ff0` |
| MAUI final full `artifacts/s07-local-history/ui-final-full/nikit_SURFACE-LT_2026-10-04_20_40_49_net10.0.trx` | `22c59fa65bb1e5e7ec99d8a4692ab72099b1ec6c52099a3c99c2f714f9620687` |
| MAUI smoke `artifacts/s07-local-history/smoke-final/nikit_SURFACE-LT_2026-10-04_20_42_21_net10.0.trx` | `c924d83a0002d3befa4867b41f10e51f93a5061e6d9d3a44c8ac297ae3721201` |

## Not qualified

Scheduler, offline logical queueing, AppAck/Read, sustained renewal/retirement,
Release network composition and installed Windows/Android artifacts remain open.
No production service, device, account or operator secret changed in this batch.
Physical contacts/messages/attachments/groups remain0/4; do not infer release
readiness from local tests. Normative availability belongs to
[TRANSPORT-NEUTRAL-MESSAGING](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md).
