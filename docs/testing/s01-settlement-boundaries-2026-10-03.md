# S01 — settlement contract and working-set boundaries

Date: 2026-10-03. Baselines: Shared
`a6dd5997fa97500138d1dbea1c4ee815ad4411c1`; Protocol
`149d689c86a73c2bbc47f028948c96f553680d32`.

The accepted semantic contract is
[DR-0084](../../../docs/survival-program/decisions/DR-0084-owned-delivery-settlement-and-retirement.md).
Its sole transition-table owner is
[TRANSPORT-NEUTRAL-MESSAGING §8.4](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#84-owned-attempt-settlement-renewal-and-retirement).
No transition table or retention number is repeated here. This checkpoint does
not close S01/S04, provision an authority or activate a production endpoint.

## Actual executable boundary

- Shared `Did2OwnedMailboxSend_FullWorkingJournalStillReconcilesExactUnknownAttempt`:
  actual DID2/PQ accounts, committed native-ratchet ciphertext, SQLCipher and
  signed grant/receipts through the ordinary account owner. After a lost Store
  reply, the actual prepared attempt is retained while canonical local filler
  occupies all 512 send slots. The next reopened owner reconciles the exact
  MAU without another grant callback. The full protected root is byte-identical,
  no slot is evicted and the ordinary pending command is completed.
- Filler is deliberately staged local commitment metadata, not 511 real
  acquisitions or remote deliveries. Issuer/terminal/time are in-process signed
  fixtures. This tests the capacity/retry boundary, **not** compaction, renewal,
  a sustained-message soak or socket/device E2E.
- Protocol `CompletedLiveGrantCannotForgetReplayFloorWhenWorkingPayloadIsRetired`:
  actual MCG3/MCP3 signatures exercise the canonical verifier and replay journal.
  Retained completion returns cached replay and rejects a lower counter. Omitting
  the journal deliberately shows the same still-admissible signed request can
  reserve again. This is evidence against deleting the live replay floor, not
  permission to initialize a missing native journal.
- Protocol `ReplayFloorNamespaceIsNotHolderOrAttemptIdentity` exercises the
  actual scope derivation: counter/request/attempt changes stay in the same
  namespace; issuer/serial/epoch/generation/operation changes do not. Modified
  claims are structural inputs, not authenticated host authority. Cached outcome
  bytes and the no-revocation fixture are not a real durable Store receipt or
  native current-admission evidence.

## Source mismatch retained as an activation fence

The current codec maximum is still seven days, XNode's default matches it, and
the owned sender caps original object expiry at grant expiry. Those sources do
not implement the normative mailbox object horizon. DR-0084 separates these
lifetimes but this change does not raise any runtime TTL. Codec, logical retry
deadline, node storage, replay retention and retained-route Retrieve/ACK must
be closed together; an expired grant/route is not historic read authority.

## Commands and gates

```powershell
# Shared
dotnet test tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj --configuration Release -m:1 --no-restore --filter FullyQualifiedName~Did2OwnedMailboxSend_FullWorkingJournalStillReconcilesExactUnknownAttempt --logger trx --results-directory artifacts/s01/settlement-capacity-focused --verbosity quiet
dotnet build Deep.Client.Shared.Production.slnx --configuration Release -m:1 --no-restore -warnaserror --verbosity quiet
dotnet test Deep.Client.Shared.Production.slnx --configuration Release -m:1 --no-build --no-restore --logger trx --results-directory artifacts/s01/settlement-capacity-full --verbosity quiet
# Protocol
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj --configuration Release -m:1 --no-restore --filter "FullyQualifiedName~AuthenticatedMailboxCapabilityContractTests|FullyQualifiedName~DeepProtocolRegistryTests|FullyQualifiedName~XPointRegistryMachineParityTests" --logger trx --results-directory artifacts/s01/settlement-contract-focused --verbosity quiet
dotnet build Deep.Protocol.slnx --configuration Release --no-restore -m:1 -warnaserror --verbosity quiet
dotnet test Deep.Protocol.slnx --configuration Release -m:1 --no-build --no-restore --logger trx --results-directory artifacts/s01/settlement-contract-full --verbosity quiet
./eng/Repin-DeepProtocolRegistrySources.ps1 -Apply
./eng/Repin-DeepProtocolRegistryAnchors.ps1
./eng/Generate-DeepProtocolRegistry.ps1
./eng/Test-DeepProtocolRegistry.ps1
./eng/Test-ProductionProtocolGraph.ps1 -Configuration Release
```

Focused Shared passed 1/1; focused Protocol passed 26/26, no skips. Both Release
source builds completed with 0 warnings and 0 errors. Final Shared full passed
546/546, no failures or skips, in 35m33s. Protocol full completed:
2067 pass / 1 fail / 12 skips (2080 total),
including 131 MembershipRoutes and 105 ProfileCarrier passes. The remaining
package witness inspects actual freshly built packages/assemblies and rejects
retained `MCG2`; it is not a new failing transition or a stale documentation
hash. The separate source graph gate rejects `MAU2` as noted below. Neither
gate is declared green.
The 12 skipped cases remain unqualified: 11 reviewed native ML-KEM/Braid provider
cases and one retained node-history capture requiring its operator input.
No skip was deleted, converted to pass or worked around with a fixture authority.
TRX SHA-256 (ignored local artifacts, not shipping evidence):

| Run | SHA-256 |
| --- | --- |
| Shared focused | `b65a0ae6e3b2bcf47eccd6a5686ef6f939d1fb214ec3cbf3fb771e76015a893f` |
| Shared full source gate | `697c7eee59bc9b2a496d0922a0f6b9a9282b3d9a2090c0ddcfe59c7b6ff9ee5f` |
| Protocol focused | `7ef466d4127513d1f519e9b4bc6e07f5b2eb3085d92c9819351412a2dd80e2e8` |
| Protocol full — MembershipRoutes | `64c8bc2321cf1a237748e3a13356dc94b41c754aca1971d2eaf77083ec5407ad` |
| Protocol full — ProfileCarrier | `bf66496f456bad816938ac95b41583f98ed3b5eb3dd8c44ce3feac180f97f8e8` |
| Protocol full — main tests | `5799ebcb7b4e5353ecd0559aedf1d1046efc3d0fffb2aa979365a980110fc9ca` |

Reviewed repin changes only the transport-owner document hash and derived
registry digest, without changing existing wire values/bytes or approved DNP1
blobs. The dry anchor check validated 175 anchors with zero updates; strict
registry passes. The production graph gate still fails on the retained MAU2
token in `ProductionMailboxAuthorityCodec`, not on this contract repin.

## Remaining and operational boundary

Independent local floors/compaction plans, grant renewal/retirement, bounded
terminal/dedup retention, retained-route lifecycle and connected admission still
require implementation and their crash/soak gates. Application-receipt/native
node/peer contracts and the full integration-first stage gates remain open in
[NEXT-SPRINT](../../../docs/NEXT-SPRINT.md). No production, device, secret, node
key, genesis or deployment state changed; no release was published.
