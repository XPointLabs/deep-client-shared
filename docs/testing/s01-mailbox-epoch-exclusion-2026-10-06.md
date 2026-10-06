# S01 held mailbox epoch-exclusion prerequisite — 2026-10-06

Status: accepted local source slice; full Shared583/0/0 terminal0, cleanup inactive.
Branch: `release-candidate/prod-20260909`.
Shared input: `ce31023e6629c29d00702a7dc6e09ae683479a87` plus this exact patch.
Protocol input: `31a36fdbea6484331cc4ed989e6a449375f9482d` plus the mechanical
TRANSPORT-NEUTRAL source-hash repin. Product root input: `119a526` plus DR-0097.

## Scope and non-claims

[Local API](../architecture/owned-mailbox-grant-custody.md#held-epoch-exclusion-prerequisite),
[semantic owner](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#842-grant-and-route-transitions),
[DR-0097](../../../docs/survival-program/decisions/DR-0097-owned-mailbox-epoch-exclusion.md).
The actual owner retains an account file lease and exact original acquisition
custody; complete signed current policy and account-owned DNH2/anchor are
rechecked before the internal capability is released or consumed. No new wire,
crypto/API allocation, local reader, generation or persistent marker exists.
This is a namespace-exclusion prerequisite, not dependency closure, a durable
compaction plan, deletion permission, non-issuance or non-delivery evidence.
Whole S01, renewal/compaction, object horizon and retained-route read/ACK remain open.

Fixtures use the actual SQLCipher account/history backend with test protected
storage, independently signed Ed/PQ directory evidence and genuine threshold
PMT2 signatures. Their shorter original route expiry is genuinely authored;
it is not an unsigned time/ceiling override. The separate signed epoch fixture
is not production storage-handover implementation or deployment evidence.
New epoch producer/consumer positives exercise actual own Retrieve acquisitions;
the retained grant-custody cases separately exercise Deposit/Retrieve. This does
not qualify every future compaction consumer/direction or the whole S01 lifecycle.
No OS SecureStorage, production socket/node, device, reset, Release or main claim.

## Frozen compiled inputs

Paths are Shared-relative unless prefixed `../deep-protocol`. All are raw SHA256.

| Input | SHA256 |
| --- | --- |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.cs` | `DC06354FBE078D29A2188744E8CA6869BE08ED02C0875C67EAEE1C48C1190086` |
| `src/Deep.Client.Shared/Services/DeepIdV2AccountService.MailboxGrant.cs` | `201F1FE4A635A2240CB8FA1FCE7C4DA9077AFC954EFBF7DDFABFF2A569240BF3` |
| `tests/Deep.Client.Shared.Production.Tests/DeepIdV2ContactPathAuthoritySourceTests.EpochExclusion.cs` | `15B83D55B518155098CAB0BAE67D19A7AB1ADE1F0C9CBABCD7B6ACE25F4D90AA` |
| `tests/Deep.Client.Shared.Production.Tests/DeepIdV2ContactPathAuthoritySourceTests.OwnedRoutes.cs` | `CCB84EB458CB6EE575F7732D9BFEAC4481D2997C2170783C6144FA7524A2E3B1` |
| `tests/Deep.Client.Shared.Production.Tests/DeepIdV2ContactPathAuthoritySourceTests.cs` | `03AB5E73152844C7F6CCF9E2E43435166C6EA5923F9CD709765E7C89DC817853` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Client.Shared.Production.Tests.dll` | `C8C16F1B8D1E37B97C81A1F371B06EE787810FC05B06B4FCC69382C2CE98CE4D` |
| `src/Deep.Client.Shared/bin-production-test/Release/net10.0/Deep.Client.Shared.dll` | `66BDE4F6CFAB3EEB8B73DCBC6D4C43B5A74F5D942C2301CCE399129E834E426D` |
| `../deep-protocol/src/Deep.Protocol/bin/Release/net10.0/Deep.Protocol.dll` | `619B8D2A866EFF0D3F0F04ADCCC70FAB37FC89BBDB6289656101BA7DD928E1FC` |
| `../deep-protocol/registry/deep-protocol-v1.registry.json` | `22E94830946E05C025F1CF3E44F587293679CA37E845CC79D9156541DDDE00A6` |

The nine inputs matched again after Protocol/actual Shared Production builds,
at the full Shared launch and after its terminal exit. No code/DLL rebuild
occurred during that gate. Actual non-test Production DLL SHA256 is
`C3647465FFE34B0EB34F3A118BD145C09664BF943B68CB35AE6FE88875AF5B90`;
it also remained unchanged after the gate.

## Terminal focused results

```powershell
dotnet test tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj -c Release -m:1 --filter 'FullyQualifiedName~Did2EpochExclusion|FullyQualifiedName~Did2GrantCustody' --logger 'trx;LogFileName=s01-epoch-exclusion-custody.trx' --results-directory artifacts/s01-epoch-exclusion-custody
```

**25/0/0 terminal0**, 1m28s. All eight new epoch cases independently map to
Passed in this receipt; known/unresolved, ceiling lower-bound boundary,
same-epoch renewal rejection, cold reopen, missing grant root/anchor,
clock rollback, expired proof, cancellation and disposed capability are covered.
Original grant bytes and issuance count stay unchanged except the explicitly
injected test corruption; the API itself does not delete, reissue or compact.

TRX `artifacts/s01-epoch-exclusion-custody/s01-epoch-exclusion-custody.trx`;
SHA256 `A7A95AFAB7B0E71E4FC520D6B83A0DA9771E87A6DC22A8DE94591426F75CDA3F`.
Start `2026-10-06T07:44:11.6569267+05:00`; finish `07:45:41.2722023+05:00`.
Earlier development-only fixture failures (tag scan offset, request-window
assumption and proof TTL) are not acceptance receipts; none were waived.

## Other terminal gates

Actual Shared Production and Protocol Release solution builds: **0 warnings,
0 errors, terminal0**. Protocol full solution **2018/1/7 terminal1**:
MembershipRoutes14/0/0, ProfileCarrier105/0/0, main1899/1/7. The sole failure is
the unchanged `PackageExactThreeSessionFree_InspectsActualPackageZipsAssembliesResourcesAndPublicApi`
MAU2 actual-package/assembly blocker; source graph also rejects MAU2, terminal1.
Assertions/allowlists remain intact; S08 shipping closure is not waived.

Separate Protocol receipts avoid the earlier shared-filename overwrite:

| TRX under `../deep-protocol/artifacts/s01-epoch-exclusion-protocol/` | SHA256 |
| --- | --- |
| `s01-epoch-exclusion-protocol_net10.0_20261006074708.trx` | `7E84F250A1C7B2D233F5BA495CD4158D924AE04B000ED016D5A91D71E66281BA` |
| `s01-epoch-exclusion-protocol_net10.0_20261006074713.trx` | `B8ABBF883C7BEF3B94910C5C5C2B1658FF3C61196FCB54220A5CB47E7A243923` |
| `s01-epoch-exclusion-protocol_net10.0_20261006074829.trx` | `42C8963B2F863CE74C3FB3057655B99812904566DC66CEC2926E44A85C4F8FC3` |

Strict registry/check passes; one semantic document source hash repinned,175
anchors validated with zero changes, approved DNP1 inputs unchanged.
Ownership fragments: mapped219/packageMissing0 terminal0 — static mapping,
not execution/qualification of219 package vectors. Root docs174 and governance
22/0/0 terminal0. Selected thirteen changed source/doc/generated files secret
scan0; final acceptance documentation is scanned again before commit.

## Required full gate — accepted exact source

```powershell
dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1 --logger 'trx;LogFileName=s01-epoch-exclusion-full.trx' --logger 'console;verbosity=normal' --results-directory artifacts/s01-epoch-exclusion-full
```

**583/0/0 terminal0**. TRX
`artifacts/s01-epoch-exclusion-full/s01-epoch-exclusion-full.trx`;
SHA256 `D40DF86047B6CA8E99A0F04322F133C41D6D8EB73365AA9014D95768B1A7A123`.
Start `2026-10-06T07:48:28.3444361+05:00`;
finish `2026-10-06T08:28:12.5410364+05:00` (39m44s).
Every one of the25 focused exact test names occurs once as Passed in the full
receipt, including all eight new cases. All seven `Did2OwnedMailboxSend` cases
and both `Did2OwnedMailboxReceive_ActualPublicationRetainedPageSemanticFaultLostAckAndNextEmptyPoll`
cases (`selectedSuccessor=false/true`) also occur as Passed:34 selected cases
total, not merely an aggregate inference. All nine frozen inputs and the
actual non-test Production DLL matched after terminal completion.

This accepts the bounded local prerequisite only. S01 dependency/compaction
plan and accepted-object/retained-route closure remain open; no cleanup or
next independent stage follows merely from this source gate.
No deployment, install/reset, release publication or main merge occurred.
