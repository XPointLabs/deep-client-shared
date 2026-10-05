# S01 — grant acquisition ownership boundary

Owner: Mr. X. Source inspected: Shared
`b238fb4f9bc750185e4fc431b1bf4ae6f33c2b1f`, Protocol
`ed7153e12cc0749e875a047705566bf0a99338b9`.
Status: source-derived contract inventory, **not a frozen new grammar or runtime
renewal**. Sole transition requirements remain
[TRANSPORT-NEUTRAL-MESSAGING §8.4](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#84-owned-attempt-settlement-renewal-and-retirement).
Execution/status remain the single [plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md)
and [queue](../../../docs/NEXT-SPRINT.md).

## Verified existing implementation

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
