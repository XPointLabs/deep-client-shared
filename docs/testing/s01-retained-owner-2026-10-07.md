# S01 retained owner join — unfinished source batch

The sole architecture/serialization owner is
[owned mailbox custody](../architecture/owned-mailbox-grant-custody.md).
This follows DR-0104, without new wire, a new journal generation or a legacy
reader. The original current-only Deposit/initial-contact admission is unchanged.

Release solution build finished with0 warnings/errors before the focused run.
The first test-only build failed with three fixture accessibility/type errors;
the next failed with one nonexistent namespace. Both were corrected using the
actual fixture-owned current-host reader and existing Protocol evidence type.
No production verification assertion was removed.

Command:

```powershell
dotnet test tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj -c Release --no-build --no-restore -m:1 --filter 'FullyQualifiedName~Did2RetainedRead|FullyQualifiedName~Did2GrantCustody|FullyQualifiedName~Did2PrivateReplyRoute|FullyQualifiedName~Did2OwnedMailboxReceive' --logger 'trx;LogFileName=retained-owner-focused.trx' --results-directory artifacts/s01-retained-owner/focused --verbosity quiet
```

Original focused terminal1:26 passed /3 failed /0 skipped,29 executions,
8m28s. All nine new retained-owner cases executed; six passed. The three failures
are preserved in `artifacts/s01-retained-owner/focused/retained-owner-focused.trx`,
SHA256 `D91F5E9E525A37D5B2F7DB9868A016F7379B4BEC53C7FCA9CA6B8AE1F24737D3`.
Two elapsed-route cases moved the nominal fixture center only one second past
admission end: the signed lower interval remained before it. Their actual
grant-NotBefore assertion correctly failed. The time-loss case guessed31s proof
expiry and did not actually expire its captured proof, so its expected rejection
correctly failed. The source now moves beyond signed uncertainty and derives
the hostile proof deadline from the actual verified proof, preserving rejection
and no-winner-adoption assertions. Those corrections have NOT been rerun; they
are not accepted evidence or an implementation fix claim.

The fixture uses real PQ accounts, encrypted protected local custody and native
SQLCipher account/holder state. Its two receipt signers and issuer are in process;
they are not independent native-server custody, private Registry HTTPS/SQL or
device evidence. No installation/dispatch/ACK authority is returned by this
candidate acquisition API. Coupled SQL installation, owned read/ACK, native
original-selection/object/tombstone/replay tests and the mandatory full gate
remain required. The preceding paragraph describes the original source
increment only.

The next coupled source replaces the actual own Retrieve acquisition/result,
SQL credential loan, protected page read and ACK continuations with the closed
retained verification path. The intermediate candidate API was removed. Deposit
is explicitly current-only. Actual PQ/SQL/receive tests now use the retained
two-receipt issuer boundary, while original late-adoption/recovery failpoints
and semantic-before-ACK checks remain enforced. Compilation exposed one closed
Protocol-property access and two test-only guessed APIs; these were corrected
using the existing public bound and actual fresh proof owner, not new authority
factories. Release test-source build succeeded with0 warnings/errors.
The combined29-case run completed terminal0:29 passed/0 failed/0 skipped,
17m10s. The receipt is
`artifacts/s01-retained-owner/coupled-01/retained-owner-coupled.trx`, SHA256
`A6425BBC6379A90F9AD8AD87FDFD7E35AC9067D0A7379DC2F19BCCAA3E2112D1`.
It contains29 unique test/execution IDs, including all9 retained cases and both
actual owned receive/recovery cases. The expired-route cases now independently
read back the exact installed credential from SQLCipher; the source's current-only
private publication reader still rejects the expired admission. Source/receipt
secret scan19 selected files passed. This is local PQ/SQL/in-process issuer
qualification only; it does not replace the mandatory full, native or device gate.

That29-case receipt predates the matching object-retention increment. The sender
now prepares the product object horizon independently of short Deposit-grant
expiry and preserves an existing pending body's expiry on exact retry. Actual
owned Store fixture assertions check the encoded MAU3/MEO1 lifetime and grant
separation; its Release test-source build completed terminal0,0 warnings/errors,
but it has not yet been tested. No payload lifetime is
extended during recovery, and no journal capacity/generation is increased.

The object-horizon owned-cycle run in `object-horizon-01` completed terminal1:
5 Passed/4 Failed/0 Skipped,9 executions,17m56s. Its receipt
`retained-object-owned-cycle.trx` has SHA256
`BA825CF5E2B670CD10866C8B0D42A586B5B3688B017AF9AA74076093CAFB7339`.
Three failures exposed the still
seven-day SQL coordinator-statement bound during actual Store receipt commit,
and a fixture regression: the shared successor producer wrongly required
Retrieve even for current-only Deposit. The source now aligns the existing
inbox/statement bound with the codec product horizon, adds actual SQLCipher
receipt cold-reopen/max+1 rejection coverage, and restores a separately verified
current-only Deposit fixture branch. Retained Retrieve still uses its closed
host producer/verification; no current Retrieve fallback or authority adapter
is restored. These additional fixes postdate that failed binary; rebuild and
one combined repeat are required. Original failure/uncertainty assertions stay
unchanged, with receipts preserved.

The corrected Release test-source build completed terminal0,0 warnings/errors.
The repeat in `object-horizon-02` keeps every original owned Send/Receive case
and adds the actual SQLCipher coordinator-horizon cold-reopen/max+1 test. It is
still active; no full, original-native-failure, shipping or device claim follows
from this repeat. No affected test is removed and the original9-case failed
receipt remains unchanged.

The new SQLCipher horizon/cold-reopen/max+1 case passed, and the original
`Did2OwnedMailboxSend_CommittedTextFaultsExactReopenLostReplyAndDurableReceipt`
now passed in3m29s. The corrected ten-case run has not yet reached terminal;
these partial observations do not qualify all Send/Receive or the full gate.
Changed-source/original-receipt secret scan24 selected files passed and ordinary
`git diff --check` is clean.

The corrected run completed terminal0:10 Passed/0 Failed/0 Skipped in26m40s.
Receipt: `artifacts/s01-retained-owner/object-horizon-02/retained-object-owned-cycle-corrected.trx`,
SHA256 `3C1AE1B621F2F9467CE42B0A5602DA8DDF33662F03BADF87FBADAE5ADCD99430`.
It includes every original9-case owned Send/Receive execution plus the new
SQLCipher horizon test. Both recipient variants passed actual protected owner/
PQ/SQL materialization, lost ACK and subsequent empty poll; their issuer and
terminal remain in-process fixtures, not native HTTPS or physical devices.
The complete original5/4 failed receipt remains intact. Required full source,
native, package and device closure is not substituted by this focused pass.
Root neutral contact consistency and30 governance guard tests also passed;
these are input/contract checks, not crypto execution or activation.

The mandatory Shared production solution full run was launched without rebuild
or a filter after capturing source, normative architecture/specification files
and the executed test-output dependencies. The immutable prelaunch manifest is
`artifacts/s01-retained-owner/full-01/inputs.json`, captured at
`2026-10-07T18:02:34.9042440Z`, SHA256
`C9A9DFE9468527C996EDF72DB88FC1A10BF32456A9F847F7871534E7E078AB3C`.
It is still running; there is no terminal/full qualification claim yet.
The capture excludes decision documents and its own script. Their supplemental
hashes were observed after the run began, not represented as prelaunch captures:
capture script `D268367974EA7EF3E684E49F7F803648C4D0D0FC4BD3E725E678473A2F38480F`;
DR-0104 `3FB1D819F0175A46376EF0759A20103F439CDCEA7E3F4900F9349E9C9FF9BC7B`.
Post-terminal verification must preserve the captured input set and map every
prior full/focused execution to its actual full result and definition; aggregate
counts alone are insufficient. No source/normative edits or other heavy test
runs are scheduled concurrently with this full gate.

Live full-run observations (not terminal qualification): four
`Did2EpochExclusion_ConsumerRejectsChangedRootAnchorClockOrExpiredProof` cases
and both `Did2RetirementDependencies_ChangedOrMissingRootRejectsWithoutGrantMutation`
cases failed at the fixture's `PossibleGrantExpiry == 1200` assertion, with
actual1500. The fixture shortened only the publication/route to1200 while its
signed original PMA2 remained valid to1500. Retained Retrieve intentionally has
a separate possible-issuance ceiling; changing that assertion to1500 alone
would also push the later exclusion check past this fixture's current successor
authority expiry. The pending correction is a genuinely shorter signed initial
authority window for these epoch-exclusion fixtures, preserving the later
current successor and all overlap, epoch, protected-root, dependency, cancellation
and cold-reopen assertions. No fix has been applied while the full is running.
The original full inputs and eventual failing receipt must remain intact.

The post-terminal result verifier is prepared in
`artifacts/s01-retained-owner/full-01/verify-results.ps1`. Its expected union is
736 distinct case-sensitive names from the prior726-case full, the29-case coupled
receipt and the10-case corrected owned cycle; it checks actual definitions and
execution IDs. `-AllowFailed` is only a failed-run observation mode, never a
passing qualification. The input-capture script's post-terminal unchanged check
is also required. No second full run has been launched.

The capture's Shared/Protocol/normative inputs remain unchanged while independent
Node test source is being completed for the same S01 transition: original-object
read/ACK across a genuinely signed PMT selection-epoch advance. This revises the
earlier blanket scheduling note; no Node build or test is run concurrently, and
Node source is not an input of this Shared production-solution test graph.

The original full has now completed terminal1:726 Passed/10 Failed/0 Skipped,
736 executions,92m24s. Receipt SHA256
`F2827C7CD637E7E6E6A54E7A2DD25B0D3A6DCD4A9F4494E95B33765823860688`.
The observation-only verifier completed terminal0:all736 exact prior/focused/full
names, definitions and execution IDs mapped;1571 captured inputs unchanged.
Every failure has the same1200/1500 fixture assertion before the consumer:
four root/anchor/clock/proof cases, two retirement-dependency cases, two actual
closed/cold-reopen cases and two ordinary-renewal/non-exclusion cases. No other
failure or skip is observed. This is a preserved FAIL, not full qualification.

The test source now requests a genuinely signed short initial network/PMA window
for exactly these ten cases; the signed directory window remains unchanged and
the successor remains live after the original ceiling. The1200 assertion and
all later negative, uncertainty, mutation, cancellation and cold-reopen checks
remain unchanged. The new original-PMA assertion independently checks the
fixture's intended premise. Rebuild, one focused repeat of all ten affected
cases and the later mandatory full are still required; no corrected pass is
claimed yet. The original input manifest/receipt have not been overwritten.

The corrected Shared Release build completed terminal0,0 warnings/errors.
The single affected-case repeat in `epoch-fixture-02` completed terminal0:
10 Passed/0 Failed/0 Skipped in1m56s. Receipt
`retained-epoch-fixture-corrected.trx`, SHA256
`83992375151CF908E8249960C2444B34D5021DC3F4401882ACBEA323BD224F7D`.
An independent read-only mapping checks exactly the original full's ten failed
names, unique results/test/execution IDs and matching definitions, all Passed.
No affected assertion or case was removed. This corrects the signed fixture's
premise, not production authority behavior. The original full remains FAIL;
mandatory current-source full qualification is still required. Its old capture
is now historical after the corrected test source/rebuild, not an unchanged
manifest for the new binary.

After the linked Registry integration-test project also built terminal0 with
0 warnings/errors, the actual Shared production solution was rebuilt in Release,
terminal0,0 warnings/errors. No other test process was running. The corrected
mandatory full was then launched without a filter/rebuild in a fresh `full-02`
directory; it is currently active, not a terminal or passing qualification.
Its prelaunch capture at `2026-10-07T19:59:31.2646684Z` includes1794 source,
build/lock inputs, executed dependencies, normative specs/decisions, both
qualification scripts and original/reference receipts. Manifest SHA256:
`BF91B9291A07708EAA674A1863352A73383CDE79D55CAF9CA03264034F55D096`.
Unlike the original capture, the decisions and scripts are captured before
launch, not supplemental after-start hashes. Capture script SHA256:
`DA96729554083D7F1587A9DDA6B825F127C05DA29CAA2D2A49D5F867125B69DF`;
verifier SHA256:
`8B565A14C4D60F82A2F8D15E6537FA075F7DCDEE59467E40F0F482266B28B915`.
Both scripts passed PowerShell parsing; the exact prior/focused/full name union
is736, including every original failed execution. The pending post-terminal
verifier requires exact unique result/definition/execution mappings and no
changed captured input. No input source/normative edits or other heavy gates
are scheduled while this run remains active. The earlier full-01 FAIL is intact.

The selected current public source/docs and corrected/original epoch receipts
passed a57-file secret scan. A preceding default-root artifacts scan still
failed closed on two pre-existing raw Android PNGs (four findings); neither was
deleted or waived. The selected-scope pass is not a qualification of those raw
artifacts or the complete release upload. `git diff --check` is clean; no commit,
push, production deployment, release publication or physical E2E occurs here.

At `2026-10-08T02:56:36Z`, the full-02 tool handle was missing; independent OS
inspection found neither its dotnet process nor a final TRX. Windows boot time
was `2026-10-07T20:31:59.9124880Z`, after the run started. This run is interrupted,
not terminal0 or qualification. Its original capture is preserved; VerifyOnly
again matched all1794 inputs unchanged, and the selected SDK remains10.0.301.

The same full command/binaries were relaunched in fresh full-03 without rebuild
or filter by a hidden standalone local runner. Its scripts passed parsing and
selected source secret scan. It records the actual native test exit separately
from the post-terminal exact-mapping/input verification; null exits cannot pass.
No successful outcome is inferred from a missing tool handle or aggregate count.
The runner started at `2026-10-08T03:02:17.2801246Z`; prelaunch capture at
`2026-10-08T03:02:18.6271579Z` contains1795 inputs, including the runner itself.
Manifest SHA256 `0E54E1DE83AA477305807AD75AD5ECA64468FC682CFF0EB7EAC7107C3135AB50`.
Actual runner and dotnet/testhost processes were observed live. Expected cases
remain736, including the original full's ten failures and corrected focused
cases. Current terminal/qualification remains pending. A host reboot still
interrupts tests; absent terminal evidence must remain unqualified.

The Shared CI input defect identified by the earlier Windows723/3 result is
addressed in the workflow source: checkout the frozen ContactAccept vector at
the sibling root docs path before checking out Shared and Protocol. The exact
root snapshot is `9f6d123f95583763d3fe99c266fd4ab83ae37cc5`, already pinned by
Protocol integration CI. Its contact vector Git blob matches the current root
HEAD (`1b68f4ba4363aada3d1f46ca6fcd70933b30ebfa`); no fixture or assertion is
replaced. Workflow files are not inputs of the active local full-03 test run.
This is a CI source correction, not an executed GitHub pass; the Linux native
provider failures and current full/source qualification remain open.

The bounded Actions job/step graph check passed for the pinned root checkout,
sibling paths/order and unchanged unfiltered Windows test command; removing
that checkout correctly fails the check. The actual frozen fixture has one
ContactAccept vector and a consistent embedded route length. This is not a
complete Actions YAML/runner execution qualification. VerifyOnly after the CI
and checkpoint edits again matched all1795 active full-03 inputs unchanged.

## Current full source qualification — 2026-10-08

The standalone full-03 runner ended at `2026-10-08T04:49:31.3001931Z`.
Actual test exit0 and separate qualification exit0 are recorded in its terminal;
the test receipt has736 Passed/0 Failed/0 Skipped. Every exact original/focused
case, definition and execution-entry mapping passed, including all ten failures
from full-01. All1795 captured inputs remained unchanged. The original failed
full-01 and interrupted full-02 are preserved and have not been relabelled.

Receipt `full-03/retained-owner-full-corrected.trx` SHA256:
`807F675EC5FAFC67A6C52030BF430FCD8D9C607D8E49980FB43F83BE06788FC0`.
Manifest SHA256 remains
`0E54E1DE83AA477305807AD75AD5ECA64468FC682CFF0EB7EAC7107C3135AB50`.
The same readonly verifier again completed terminal0 before Node full-03,
checking current inputs, not merely accepting the earlier stored terminal.

This qualifies the current Shared production-solution source/test boundary.
It does not qualify the whole retained-object batch, native package graph,
Registry, shipping composition, GitHub CI execution or physical delivery.
Node current full and mandatory isolated external/no-mock/multi-node gates
remain required before this connected S01 batch is accepted.
