# S01 native replay-fence guard — working checkpoint

Date: 2026-10-06. Owner: Mr. X. This is a focused source checkpoint, not full
S01 acceptance, a runtime retirement activation or physical release evidence.
The only active NEXT-SPRINT block remains the dependency-closed retirement
fence. Semantic owner: [TRANSPORT-NEUTRAL-MESSAGING §8.4.2–8.4.4](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#842-grant-and-route-transitions).
Local API mapping: [owned mailbox grant custody](../architecture/owned-mailbox-grant-custody.md#native-replay-fence-guard-readback).

## Current held dependency-capture checkpoint

The same S01 block now captures and rechecks eight actual dependency roots under
the held epoch exclusion. The [mapping](../architecture/owned-mailbox-grant-custody.md#held-retirement-dependency-capture)
lists the observed obligations and missing closure. This snapshot is not a
serialized 'settled' flag, eligibility proof or retirement plan. It has no SQL,
staging, deletion or signing entry. Known outcomes/retained Retrieve paths remain
pinned rather than inferred complete from empty work. A complete retirement
owner/recovery profile and full current Shared gate remain required; this
checkpoint does not close S01 or inherit the older687-case acceptance.

```powershell
dotnet build Deep.Client.Shared.Production.slnx -c Release -m:1 --no-restore --artifacts-path artifacts/s01-native-fence-build
dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1 --no-build --no-restore --artifacts-path artifacts/s01-native-fence-build --filter 'FullyQualifiedName~Did2EpochExclusion_|FullyQualifiedName~Did2ReplayFence_|FullyQualifiedName~Did2RetirementDependencies_|FullyQualifiedName~DurableHistory_|FullyQualifiedName~AccountNetworkFloor_RejectsSqlRollbackCorruptionDeletionAndRepin|FullyQualifiedName~NetworkMarkerCommittedBeforeSqlCrash_RejectsEmptyFloorAndReopen' --logger 'trx;LogFileName=s01-retirement-dependencies-corrected.trx' --logger 'console;verbosity=minimal' --results-directory artifacts/s01-retirement-dependencies-corrected
```

Build: terminal0, zero warnings/errors. Focused regression: **25/0/0**, observed
terminal0 with `S01_RETIREMENT_DEPENDENCIES_CORRECTED_TERMINAL_EXIT=0`. Start
`2026-10-06T19:38:46.3678362+05:00`, finish
`2026-10-06T19:41:44.6549507+05:00`. Receipt:
`artifacts/s01-retirement-dependencies-corrected/s01-retirement-dependencies-corrected.trx`,
SHA256 `5EBC9E75930838404F2AC4287B3CAD5CD266BD9AB57D473122D78F00F5909495`.
This includes the previous23-case selection, updated to consume the held
snapshot, and two changed/missing-root cases. Caller mutation of exported
metadata cannot alter internal commitments; cancellation/disposal and existing
original-root/anchor/clock/proof faults still reject.

Changed source/test inputs at this run:

| Shared-relative file | SHA256 |
| --- | --- |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.cs` | `CAE769CC2B41F173BC126CE0B7102DD7660C85997E5EE92C9A86BB61299C93C2` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDeepIdV2AccountOwner.MailboxRetirement.cs` | `440FB423A3DEAA3501612163AA19BAB9DF7716478179E1ADB41CD3B546EBB4F1` |
| `tests/Deep.Client.Shared.Production.Tests/DeepIdV2ContactPathAuthoritySourceTests.EpochExclusion.cs` | `07926975483751973CC0F5FCE4CD30819A49F226BEA5C60130032879703ACA90` |

Current host `Deep.Client.Shared.Production.Tests.dll` SHA256
`BB226B5E3E844B846BC2484CA766E0877A5A4923C0285AE5DB29216690D83424`;
current host `Deep.Client.Shared.dll` SHA256
`5C8F809D8C3529EB0806740CA99B05AC186FA57D048F999C407542C03B976A32`.
Host directory is the build directory listed below; those older host hashes
identify the earlier run, not these rebuilt binaries.

Preserved failure: the first dependency regression completed25 total,24 passed,
1 failed, terminal1. Receipt
`artifacts/s01-retirement-dependencies/s01-retirement-dependencies.trx`, SHA256
`8AAEF1A067EC236713CF9A1498414DF4CCF07373761EFC4719C12CB0251985BC`.
The changed-root fixture used insert-only WriteBatch for an existing secure
slot; it failed before the intended rejection assertion. Injection/restoration
now uses exact CAS, preserving both storage semantics and the rejection assertion.
Only the deliberate test fault is restored; this is not runtime repair evidence.
An earlier build found two CS0103 errors from a nonexistent fixture account
field; the fixture now uses its actual already-decoded grant-root account/instance.
No failing product assertion was removed or weakened.

## Implemented boundary

- Capture an unchanged NativeFence plan guard from the existing committed DNH2
  floor while holding and rechecking the real epoch-exclusion capability.
- Cold read the same facts from the actual account SQL registration, complete
  native floor rows, protected network marker and independent history anchor.
  No fresh directory proof or network callback is required for this local read.
- Reject missing/split history, marker/anchor mismatch, SQL rollback, fork latch
  and noncanonical scalar types without initialization or repair. Fractional
  SQLite REAL revisions reject rather than being truncated by GetInt64.

No new persistent root, journal generation, wire, public authority API or legacy
reader was added. No grant/send/read/counter state is deleted. Neither the
returned digest nor a decoded plan authorizes retirement. Dependency-closed
selection, the closed retirement owner/recovery profile, receipt obligations
and accepted-object/retained-route closure remain unfinished. Current object
retention and unavailable historic Retrieve/ACK are not waived.

## Build and focused regression

Commands run from the Shared repository:

```powershell
dotnet build Deep.Client.Shared.Production.slnx -c Release -m:1 --no-restore --artifacts-path artifacts/s01-native-fence-build
dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1 --no-build --no-restore --artifacts-path artifacts/s01-native-fence-build --filter 'FullyQualifiedName~Did2EpochExclusion_|FullyQualifiedName~Did2ReplayFence_|FullyQualifiedName~DurableHistory_|FullyQualifiedName~AccountNetworkFloor_RejectsSqlRollbackCorruptionDeletionAndRepin|FullyQualifiedName~NetworkMarkerCommittedBeforeSqlCrash_RejectsEmptyFloorAndReopen' --logger 'trx;LogFileName=s01-native-fence-regression.trx' --logger 'console;verbosity=minimal' --results-directory artifacts/s01-native-fence-regression
```

Build: terminal0, zero warnings/errors. Focused regression: **23 passed,
0 failed, 0 skipped**, terminal0 with observed shell marker
`S01_NATIVE_FENCE_REGRESSION_TERMINAL_EXIT=0`. TRX contains23 unique names/results
and23 definitions. Start `2026-10-06T19:16:40.6374519+05:00`, finish
`2026-10-06T19:18:59.6050458+05:00`.

Receipt: `artifacts/s01-native-fence-regression/s01-native-fence-regression.trx`.
SHA256: `3C26566F4C069E00401A9FF9C8503401AD0535797C931C132EDCB42F8B3D951B`.
The23 cases comprise11 epoch-exclusion/fence cases and12 existing history,
anchor, rollback and marker-crash cases. This is not the required full Shared
gate. The previously accepted687-case outbox receipt qualifies its older
source only; it is not inherited by these changed sources. Run the full gate
on the completed retirement-owner batch before accepting it.

Changed runtime/test inputs, SHA256 at this run:

| Shared-relative file | SHA256 |
| --- | --- |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.cs` | `A3DEC1CBFECBF59D30158E55711CC448AADDD67FC6831426CF6A12F0D44724D9` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/SqliteDeepIdV2AccountGeneration.NetworkLkg.cs` | `B5723BAEC75CBD7A492902A065DF9AC044974374E231DE21A0B6D25EC2E90B5D` |
| `src/Deep.Client.Shared/Services/DeepIdV2AccountService.MailboxGrant.cs` | `1E3F075002D660EA878FEB9327287891872F3E5628CBC1B4ECFC42857FF2AC5B` |
| `tests/Deep.Client.Shared.Production.Tests/DeepIdV2ContactPathAuthoritySourceTests.EpochExclusion.cs` | `E1755E30B5EB12ECD7323B1122F0A1C13D51A7A9BBBEC7FCF5EA39AD9F743C78` |

Test-host files under `artifacts/s01-native-fence-build/bin/Deep.Client.Shared.Production.Tests/release/`:

| File | SHA256 |
| --- | --- |
| `Deep.Client.Shared.Production.Tests.dll` | `FBA73D2A95CAAFB185F85741D04A3424ED6F14879665FADDAB65F3ECEE7CFA17` |
| `Deep.Client.Shared.dll` | `3117E7C116997468767A27E992C8DC28632440DD80CA1A0BB1C0D68855621F72` |
| `Deep.Protocol.dll` | `A0BDB51EA6C7814920C4AE8EA4247C5810AFCB4961F2E6E84D70C2E172B46C55` |

These identify the bounded focused run, not a complete frozen release manifest
or upload approval. Test artifacts remain local and ignored.

## Preserved failures and harness correction

The first invocation with a fresh artifacts directory and --no-restore produced
no TRX and executed no tests; its exit0 is not test evidence. A restored build
then found CS7036 in the new fixture: the actual own-proof verification call
lacked its cancellation argument. Supplying `default` fixed that compile error.

The first actual focused receipt had11 total,10 passed,1 failed, terminal1:
`artifacts/s01-native-fence-focused/s01-native-fence-focused.trx`, SHA256
`56E4E41101778024FC73B737D571D6333DF79809C7230B1A14D48EEB44BB1C25`.
The changed-anchor fault fixture tried a separate cold owner read while its
epoch-exclusion capability still held the account lease. It correctly received
a lease timeout instead of reaching the anchor check. The assertion was moved
after capability disposal; no lease rule or exception assertion was weakened.

The corrected narrow receipt records11/0/0:
`artifacts/s01-native-fence-corrected/s01-native-fence-corrected.trx`, SHA256
`6D4B0909D04D588E5F98811A52096795C635F8FE0375BF29A1F8732B24283869`.
Its original shell terminal was not retained in the handoff, so it is not used
as terminal qualification. The subsequent23-case regression above has an
observed terminal0 and includes the unchanged corrected11-case selection.
