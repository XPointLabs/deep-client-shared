# S01 closed unused deposit retirement — accepted source checkpoint

Date: 2026-10-06. Owner: Mr. X. The whole S01 remains open.
Semantic owner: [TRANSPORT-NEUTRAL-MESSAGING §8.4.2–8.4.4](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#842-grant-and-route-transitions).
Exact local API/recovery mapping: [owned mailbox grant custody](../architecture/owned-mailbox-grant-custody.md#closed-unused-deposit-retirement-profile--working-implementation).

## Status and qualification boundary

The actual held producer, exact staging, protected-only commit boundary, grant
CAS/readback, pre-commit abandon and startup recovery are implemented for one
closed unused Deposit acquisition with no remaining dependencies. The existing
native floor is unchanged; its guard now commits the complete local account/device
binding as well as revision, floor and history. There is no new wire, journal
generation, scheduler, public authority or legacy reader.

Build, focused regression and the current coupled full gate pass. This accepts
only the closed unused Deposit profile on the frozen source below, not the whole
S01. The prior687-case outbox receipt remains evidence for its own frozen source;
the current706-case receipt qualifies this changed source. Known outcomes,
Retrieve/ACK paths, linked acquisitions and
unclosed receipt/object work remain pinned. Their S01 closure and S04 autonomous
lifecycle are not activated by the unused-acquisition profile.

## Build and corrected focused regression

Commands run from Shared:

```powershell
dotnet build Deep.Client.Shared.Production.slnx -c Release -m:1 --no-restore --artifacts-path artifacts/s01-native-fence-build
dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1 --no-build --no-restore --artifacts-path artifacts/s01-native-fence-build --filter 'FullyQualifiedName~Did2ClosedDepositRetirement_|FullyQualifiedName~Did2EpochExclusion_|FullyQualifiedName~Did2ReplayFence_|FullyQualifiedName~Did2RetirementDependencies_|FullyQualifiedName~DurableHistory_|FullyQualifiedName~AccountNetworkFloor_RejectsSqlRollbackCorruptionDeletionAndRepin|FullyQualifiedName~NetworkMarkerCommittedBeforeSqlCrash_RejectsEmptyFloorAndReopen' --logger 'trx;LogFileName=s01-retirement-profile-corrected.trx' --logger 'console;verbosity=minimal' --results-directory artifacts/s01-retirement-profile-corrected
```

Build: terminal0, zero warnings/errors. Corrected focused: **39 passed, 0 failed,
0 skipped**, observed terminal0 and shell marker
`S01_RETIREMENT_PROFILE_CORRECTED_TERMINAL_EXIT=0`. Start `2026-10-06T20:20:55.5162082+05:00`;
finish `2026-10-06T20:26:27.9530657+05:00`. All39 expected names/results/definitions and unique
test/execution IDs map exactly, without missing/extra cases.

Receipt: `artifacts/s01-retirement-profile-corrected/s01-retirement-profile-corrected.trx`.
SHA256: `DC2A5B959FA909CF9A284100584FF6459D8DEDD83891AF4CA2EDFD5EDE6F14E2`.

The14 profile cases cover five persisted handovers, explicit pre-commit abandon,
both cancellation boundaries, changed canonical name/device binding, missing
native floor, changed/missing send guard and missing successor staging. They
reopen the encrypted protected journal, use a new owner and real SQLCipher
connection, and assert unchanged unrelated roots/no transport callback during
recovery. Failed readback asserts no SQL or protected-state repair. The fixture
protector is not Windows/Android platform custody; this is not device/network E2E.
The other25 cases exercise existing exclusion/dependency/history/rollback
boundaries, including direct refusal to stage retirement of known/unresolved
Retrieve custody.

## Preserved failures

Earlier in-memory profile regression:31/0/0, terminal0,
`artifacts/s01-retirement-profile/s01-retirement-profile.trx`, SHA256
`20B1C7B8AAC6D835604BE9CE3D5B27ED0D7D6B0F7D7AEF43CD77DFDCEF5C76C3`.
It is superseded by the corrected encrypted-journal selection above.

First encrypted-journal regression:36 passed/3 failed/0 skipped of39, terminal1,
`artifacts/s01-retirement-profile-cold/s01-retirement-profile-cold.trx`, SHA256
`F953674F70B9293653AD00C3FE1D717DF6B93AF72D8E5B1A94389BFCE91CF227`.
The three altered binding/guard cases reached the intended existing
ObserveReadback rejection but expected CryptographicException rather than its
exact InvalidDataException contract. The expected type was corrected; rejection
and unchanged-state assertions remain mandatory. No runtime check was weakened.
An earlier test build failed CS0117 by referencing the storage wrapper's
nonexistent Slot; the fixture now uses the actual Did2CompactionPlan.Slot.

## Current coupled full — accepted unused Deposit profile

Source: Shared `25204bfa68a200f3ce8b2e4b53a4b05e11226d51`.
The already-built zero-warning Release host was tested with the complete,
unfiltered Shared production suite:

```powershell
dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1 --no-build --no-restore --artifacts-path artifacts/s01-native-fence-build --logger 'trx;LogFileName=s01-retirement-profile-full.trx' --logger 'console;verbosity=minimal' --results-directory artifacts/s01-retirement-profile-full
```

Full: **706 passed, 0 failed, 0 skipped**, observed process terminal0. The shell
printed `S01_RETIREMENT_PROFILE_FULL_TEST_EXIT=0`, then the completed qualifier
printed `S01_RETIREMENT_PROFILE_FULL_QUALIFIED_EXIT=0` and exited0. Start
`2026-10-06T20:29:30.4079990+05:00`; finish
`2026-10-06T22:01:32.7784427+05:00`.

All706 discovery names/results/definitions and unique test/execution IDs map
exactly. All200 current required and all687 prior cases are Passed, without
missing/extra names, duplicate mappings or skips. All62 frozen inputs matched
before the process and after terminal; source HEAD was still the commit above.
These inputs include changed runtime/tests, test/non-test assemblies and native
host dependencies. A separate readback reconfirmed counters, mappings and hashes.

Receipt: `artifacts/s01-retirement-profile-full/s01-retirement-profile-full.trx`.
SHA256: `B3184583AF4062BB220A5AE5BF37D1DAB8BAFC09F1367A6956C8B582ECD33987`.
Manifest: `artifacts/s01-retirement-profile-full/expected-qualification.json`.
SHA256: `5C9400C06D95AD97EF253D4EF0098A7886EADEFC544EEBB2C1D6A97A1F8B70F7`.

This closes this local owner/recovery profile, not known grant/send/read floor
retirement, application receipt completion, accepted-object/retained-route
closure, sustained cleanup, Release composition or physical device E2E.
Artifacts remain ignored/local; their metadata is not upload approval.
