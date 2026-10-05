# S01 — grant acquisition ownership boundary

Owner: Mr. X. Source inspected: Shared
`b238fb4f9bc750185e4fc431b1bf4ae6f33c2b1f`, Protocol
`ed7153e12cc0749e875a047705566bf0a99338b9`.
Baseline status: source-derived contract inventory, **not runtime renewal**.
The implementation section below supersedes this baseline's local-layout status.
Sole transition requirements remain
[TRANSPORT-NEUTRAL-MESSAGING §8.4](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#84-owned-attempt-settlement-renewal-and-retirement).
Execution/status remain the single [plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md)
and [queue](../../../docs/NEXT-SPRINT.md).

## Verified baseline implementation

- `ProtectedDid2MailboxGrantJournal` has one scope-keyed pending/winner entry.
  Its scope is the exact route hash, locator and Deposit/Retrieve direction;
  it is not an acquisition identity. The bounded working set is128 entries.
- `AcquireMailboxGrantUnderLeaseAsync` preserves the exact pending request,
  verifies the response, CAS/read-backs the winner and revalidates before use.
  An existing winner is immutable; there is no renewal branch or independently
  retained successor acquisition under the same scope.
- Dispatch acquires the current winner before comparing a prepared send's
  retained bindings. Retrieve also chooses the scope winner. ACK explicitly
  compares that winner's grant hash with its protected original page cycle.
  Merely replacing the scope entry would therefore break exact pending work;
  changing only the dictionary key would leave these callers inconsistent.
- `ProtectedDid2MailboxSendJournal` already has independent bounded replay
  floors, scope enrollment and counter advancement. It must not be rewritten
  as a row-count-derived floor while adding lifecycle state.

## One bounded producer/consumer contract to close next

The first local-format/API slice must distinguish **scope**, **acquisition** and
**selected winner**, without changing XMG1/XMC2/MCG3 or network authority:

| Boundary | Required local ownership and caller consequence |
| --- | --- |
| Acquisition identity | Bind one immutable exact owned XMG and its seed/response; independent acquisitions in one scope cannot overwrite each other |
| Pending versus selected winner | Keep a successor candidate separate from the current winner; switch selection only after verified successor protected read-back |
| Retained lookup | Store/read/ACK work selects its original acquisition/grant binding, not whichever winner is now current; it cannot mint or substitute a grant |
| Interrupted adoption | Existing request and received winner remain recoverable; a cold reader does not infer selection from timestamps, sort order or row count |
| Bounds and missing state | Preserve working-set backpressure and mandatory roots; do not evict unknown work, raise128/512, regenerate a holder or lazily repair missing custody |

Affected Shared consumers are `ProtectedDeepIdV2AccountOwner.MailboxGrant`,
`.MailboxDispatch`, `.MailboxRetrieve`, `.MailboxAck`, `.MailboxCredentials`
and `SqliteDeepIdV2AccountGeneration`. The current grant-custody, dispatch and
receive production tests own exact callback/CAS/SQL interruption and cold-reopen
coverage; layout changes must preserve those assertions rather than merely
make a new isolated codec test green.

Freeze the exact closed layout and API with hostile/round-trip/adoption fixtures
before changing the sole current reader and these consumers together. A necessary
local generation change rejects earlier state; there is no compatibility reader
or migration. Codec parsing establishes custody shape, not current issuer/time,
grant admission or permission to retire. This inventory allocates no generation,
magic, generic verified factory, cleanup proof or new library.

## Boundaries deliberately not claimed complete

This acquisition-layout slice does not implement issuer renewal, expired/unknown
settlement, logical successor attempts, compaction/retirement or historical
Retrieve/ACK. Those remain S01/S04/S05 work under their existing sole owners.
The already accepted DR-0086 Store-settlement verification API is not a grant
renewal or a historical-read authorization and must not be reinvented as one.
Object retention remains the linked codec/client/node/retained-route fence;
the current short-grant-bound send lifetime is not the normative retention
guarantee. No lifetime increase or expired-authority bypass is authorized here.
No runtime code, package, production resource or device state changed in this
inventory; no new test run or E2E pass is claimed.

## Acquisition layout / connected consumers — 2026-10-05

The sole local reader and producer now implement the closed
[acquisition/pointer layout](../architecture/owned-mailbox-grant-custody.md).
Acquisitions are keyed by the existing exact-XMG hash, not scope. A separate
selection retains current and pending pointers with immutable predecessor
linkage. Received winner and selection adoption have separate protected
CAS/read-back transitions. Previous local state rejects, even if empty; explicit
account reset is required, not migration.

Dispatch selects the prepared attempt's exact original grant before any
acquisition. Active Retrieve and ACK similarly select their pinned cycle grant;
new work uses the selected winner. Missing original custody rejects. Current
route/issuer/time/holder checks, SQL installation and independent replay floors
are unchanged; an expired retained grant is not authorized by this lookup.

Tests cover received-winner→selection interruption and cold adoption without
reissuance; two actual signed acquisitions in one scope; pending/current and
retained-original round-trip; hostile pointers/predecessors/orphans and previous
generation rejection. The connected Store fixture selects a signed successor
while original unknown work remains pinned. Retrieve/page/ACK fixtures retain
the original grant through successor selection, semantic faults and lost ACK.
Successor selection here is controlled signed fixture setup, not a production
renewal branch, compaction, socket test or physical delivery evidence.

### Final source acceptance — 2026-10-06

The required command completed terminal0:

```powershell
dotnet test Deep.Client.Shared.Production.slnx --configuration Release -m:1 `
  --logger "trx;LogFileName=s01-acquisition-full.trx" `
  --results-directory artifacts/s01-acquisition-final
```

Result: **567 passed, 0 failed, 0 skipped**, 46m50s; build emitted no warnings.
The TRX independently contains567 results, all Passed. All12 selected custody,
original-Store and both `selectedSuccessor` receive cases map to Passed, including
`selectedSuccessor: True`; this is not merely the old no-successor receive case.
The full-working-set Store fixture retains its exact original request after
selection changes; both receive variants retain semantic/lost-ACK assertions.

Receipt: `artifacts/s01-acquisition-final/s01-acquisition-full.trx`, SHA256
`228fd216e81052dcfa0177124b0a65cd1fdd8567677e685abd2e2081336c2736`.
Compiled input: Shared4cf9349 plus the exact source patch in this change,
Protocol `ed7153e12cc0749e875a047705566bf0a99338b9`. No runtime/test-source edit or
concurrent rebuild occurred during this final run. All nine changed source/test
files and both compiled assemblies matched their pre-run hashes after terminal0.
Test assembly SHA256:
`4120f869d54ba4c7159a45e78397942bf2f19a44c51cf0d9c1d3648b7c4a2eda`;
Shared test-composition assembly SHA256:
`8da9e89bee83e1b26f341b51b7cb03b39dd7fe4d4ccba3bcb33d5a5f179f1b75`.
This is a source/test-internals composition, not a signed shipping artifact.

The earlier focused17/0/0 run exercised an intermediate patch. An early full
attempt was cancelled after review found the new receive fixture counted all
account scopes instead of its exact Retrieve scope. It was corrected before this
final run; neither intermediate run substitutes for the final receipt above.

The acquisition/pointer/original-lookup slice is accepted locally. No production
deployment, device reset/install or physical E2E occurred. The Protocol native
shipping-graph blocker remains unchanged. This slice alone does not close S01.
Expired-acquisition settlement, issuer
renewal, floor/entry retirement, object horizon, historical read/ACK and the
remaining stage contracts still block later activation.

### Original issuance ceiling and closed-unresolved custody — 2026-10-06 accepted slice

This is a subsequent source change, not a reinterpretation of the generation3
receipt above. Input is Sharedb82c584 plus the current exact source/test patch;
Protocol remainsed7153e. The sole local layout/API owner is
[owned grant custody](../architecture/owned-mailbox-grant-custody.md).

The single current reader is local generation4; prior state rejects even empty.
It captures exact independently verified original PMA2/route evidence before
issuance, recomputes their conservative ceiling, and retains it with the exact
holder/request and immutable winner. Bounded length prefixes reject before
record copying. Count limits remain128 acquisitions and512 working sends.
The retained tail now preserves closed-unresolved acquisitions independently of
current/pending, without permitting current-pointer rollback to an older winner.

The internal account maintenance entry accepts its actual own source and
cancellation, not caller time/outcome/route or a cleanup permission. Independent
current own proof/network custody and the actual account lease allow closure
even when the original request cannot be restored. A protected CAS/read-back and
final root/authority recheck close only pending acquisitions whose request expiry
is reached by authenticated **lower** time. It preserves original evidence and
uncertainty; no issuer callback, SQL cleanup, grant/key/floor eviction or automatic
replacement request occurs. It is not an autonomous renewal/drain scheduler.

Intermediate focused custody11/0/0 exercised uncertainty and both crash points.
The subsequent custody + full-working-set original-Store run completed12/0/0,
terminal0 in1m40s, with zero build warnings. Its filter did not select the two
owned receive cases; those still require the final full gate. Receipt SHA256:
`ce31c60c2fe77d672c7b78ac25cffcaece10c7f09ce6dc743b59afc1fd6b5f2c`.

An initial full run was deliberately stopped after review found the normal
successful closure-return branch missing in the new fixture; it is not final
acceptance or a product FAIL. The final fixture now separates normal success
from after-commit interruption, while keeping before-commit interruption,
straddling-time rejection, cold reopen, unchanged holder/request/evidence and
no-reissue assertions in both variants. Earlier two focused failures arose from
the fixture using nominal signed time instead of its conservative lower bound;
the actual product check was not weakened. Final focused custody completed
**12/0/0 terminal0**,27s, including both normal and after-commit fault variants;
receipt SHA256
`44b35aa12dced576b8ef59e1192e396733910f7146d25dfbd9a8b2a12c599deb`.
The final required full production command completed terminal0, without filters:

```powershell
dotnet test Deep.Client.Shared.Production.slnx --configuration Release -m:1 `
  --logger "trx;LogFileName=s01-acquisition-expiry-full.trx" `
  --results-directory artifacts/s01-acquisition-expiry-complete `
  --logger "console;verbosity=minimal"
```

Result: **570 passed, 0 failed, 0 skipped**,43m24s. The TRX reports570 total,
executed and passed, with0 failed/not-executed; all570 individual results are
Passed. All15 selected cases independently map to Passed: nine hostile headers,
the two-account acquisition fixture, both expired-unknown closure variants,
full-working-set original-Store reconciliation, and both owned receive cases
(`selectedSuccessor: False/True`). The last pair retains semantic-fault and
lost-ACK assertions; this is not the intermediate filter's absent receive coverage.

Receipt: `artifacts/s01-acquisition-expiry-complete/s01-acquisition-expiry-full.trx`,
SHA256 `fa9bf5a915fa7c4f3d61c2832dcfc873291cafa938b4c21ddb0bafb3e5bc5434`.
TRX start/finish: `2026-10-06T00:51:38.7284384+05:00` /
`2026-10-06T01:35:03.5880503+05:00`. The final command emitted no build warnings.
All five changed source/test files and both compiled assemblies matched their
pre-run hashes after terminal0; no runtime/test-source changes or concurrent
rebuild occurred during the run. Exact compiled inputs:

| Input relative to Shared | SHA256 |
| --- | --- |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDid2MailboxGrantJournal.cs` | `b1c58b643f65efec09e3fa5bff4a3e9d6fd6c387e5eb8fcc0c9d54891ee4c66a` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/ProtectedDeepIdV2AccountOwner.MailboxGrant.cs` | `9a963c5003b5470443689e572d8071f8e626f658647f75853c0d5e77b9918da8` |
| `src/Deep.Client.Shared/Persistence/DeviceV2/Did2MailboxInstallationTestHooks.cs` | `17cd776671b948ea48d2e062f4b6f284c6409a62b7297c9c80d38c28d0dd8276` |
| `src/Deep.Client.Shared/Services/DeepIdV2AccountService.MailboxGrant.cs` | `a3a08d308fc313e054889c00a2dd83fa241363e274ace62c8b73de973681048d` |
| `tests/Deep.Client.Shared.Production.Tests/DeepIdV2ContactPathAuthoritySourceTests.GrantCustody.cs` | `172738c6d88ff340e89c114deeb27f0f9ca4b5aa25a4af33fb2d29f6d4be7b78` |
| `tests/Deep.Client.Shared.Production.Tests/bin/Release/net10.0/Deep.Client.Shared.Production.Tests.dll` | `8f5d2dc5bd630047778ba992056a5a1c5fb255419665b504e5418df7d338aeee` |
| `src/Deep.Client.Shared/bin-production-test/Release/net10.0/Deep.Client.Shared.dll` | `5864b0dde79b9688aca25e53d87b9ddd6a370b172908a070295564546aec01d0` |

After this receipt, the actual `Deep.Client.Shared.Production.csproj` Release
build completed terminal0 with **0 warnings, 0 errors**. The full test receipt
still qualifies its source/test-internals composition, not a signed shipping
artifact. The original-ceiling/closed-unresolved slice is accepted locally;
ordinary push does not qualify deployment or physical delivery.

This still does not close S01. Authenticated late-result adoption, irreversible
namespace retirement/compaction, object horizon/retained-route and matched
shipping/physical activation remain unqualified. No deployment/device reset,
new network wire, public verification API, GitHub Release or main merge occurred.
