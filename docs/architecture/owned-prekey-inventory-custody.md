# Owned prekey inventory custody

Normative owner: [CONTACT-RESOLVER section3.3](../../../docs/architecture/CONTACT-RESOLVER-V1.md).
Local allocation: [DR-0130](../../../docs/survival-program/decisions/DR-0130-owned-prekey-inventory-custody.md),
following the [DR-0129 service boundary](../../../docs/survival-program/decisions/DR-0129-owned-prekey-service-succession.md).
This maps the internal account/receiver custody implementation, not activated
automatic renewal or device acceptance. Protected records are never current
publication, claim/Initial or dispatch authority.

## Implemented component

`ProtectedPreKeyInventoryChain.Entry.Create` checks exact authored public/private
member correspondence and the conservative per-slot budget before transferring
any offering capability to the existing persistence protector. It owns and clears
its private record buffer. `Decode` accepts only the allocated bounded shape,
exact hash/scope, XPS1/XPI1 join, member count and canonical sealed values.
Parsing does not prove signatures/currentness or explain a missing secret.

`StageAsync` uses the existing atomic CAS-and-insert backend to advance the
original inventory pointer and install exactly one record. A competing candidate
cannot leave an orphan. An exact retry observes root and record in one actual
snapshot; it cannot replace changed state or resurrect consumed private values.
Only the owned offering-sealing factory marks an in-process authored candidate;
decoded records cannot advance the pointer. This provenance bit is not persisted
and adds no record version or currentness authority. Reopened pending data is
resumed from custody, never reinterpreted as a new authoring capability.
`ReadAsync` follows exact hash-named records to the independently supplied SQL
initial anchor, detects missing/cyclic/disconnected state, validates scope and
rechecks the pointer after traversal. It returns owned disposable data, not a
freshness cache. Original SQL schema/inventory/receiver history are unchanged.

The sole original tip-slot constant is shared with the initial SQL owner. The
actual account owner now opens the exact chain before validating the one global
receiver ledger. Its internal successor stage takes the account file lease,
uses the original SQL-key-derived DPK2 protector and validates signed service/
epoch lineage. Every ancestor must have its exact protected commit pair; only
the latest publication may remain pending. A pending candidate cannot be
replaced by another inventory. The DR-0131 source candidate now calls this path
through the one owned maintenance/publication command; qualification and
runtime/device activation are separate from that source connection.

Receiver preview selects one exact DPK2 from the initial SQL inventory or its
explicit protected successor chain, never the next available generation. The
receiver commits SQL first, destroys exhausted successor secrets with exact CAS,
then stabilizes its original protected checkpoint. All four interruption points
recover idempotently, including a lost response after secret destruction. The
same original SQL ledger, replay fences and retirement checks cover both kinds
of custody. No successor key is copied into SQL.

Last-resort counters belong to the service generation across inventory epochs.
Distinct sessions cannot reuse one counter on different keys. Secret destruction
waits until all counters admissible for that signed member have arrived; seeing
the highest counter alone does not erase a key needed by a lower-counter Hello
still in flight. This can remove the original SQL last-resort secret when the
final missing counter arrives on a successor key. Staging another inventory with
an already exhausted service counter rejects before sealing or pointer mutation.
Expiry alone destroys no key. Source/compaction readback now pins the complete
exact successor chain and its per-publication pairs in addition to the unchanged
initial encrypted SQL and receiver checkpoint. Initial-only readback bytes stay
unchanged. Missing pairs or changed custody pin cleanup.

## Evidence — 2026-10-16

Receipts are under `artifacts/s05-prekey-custody-20261016/`, Windows
PowerShell5.1/SDK10.0.301:

- `focused-01`:2 passed/native0, initial native authoring/storage component.
- `focused-02`:2 failed/native1. The expanded test injection attempted an
  ordinary add-only write over an existing protected slot; the actual backend
  correctly refused. The test now uses exact CAS. This is a fixture error, not
  a production storage-policy defect or permission to relax add-only writes.
- `regression-03`:63 passed,0 failed/skipped,native0. Includes real concurrent
  CAS, lost response, encrypted cold reopen, missing/cyclic chain, changed root,
  secret authentication failure, unchanged original SQL/pair and existing initial
  publication, storage and receiver checkpoint cases.
- `final-04`:2 passed/native0 after adding independent layout concatenation,
  cancellation during traversal, additional hostile bounds and disposal checks.
- `final-05`:9 passed,0 failed/skipped,native0 on the final source and reviewed
  normative source-hash repin. Adds seven missing/malformed pointer cases;
  zero current hash rejects as a custody error before any record lookup.
- `final-06`:9 passed,0 failed/skipped,native0 after enforcing in-process
  authored-candidate provenance. Even a structurally valid decoded record with
  every sealed secret present cannot stage a new successor. Compilation reports
  no errors and one xUnit2031 test-style warning. This bit is never persisted
  as authority; this receipt is not zero-warning build evidence.

The Protocol repin changes only CONTACT-RESOLVER's reviewed source hash and its
generated/resolved registry digest. All178 normative anchors remain unchanged;
the strict generator and registry gate pass. There is no wire allocation or
public API change. These focused receipts do not replace canonical full and
package qualification of the eventual connected lifecycle.

The original two native custody rows use a real account/device/ML-KEM author and full
current inventory verification before sealing. Encrypted mode uses actual
journaled disk protection with a fixture-owned protector. The DPK2 sealing key
is fixture-owned; they do not prove actual account/SQL-key integration.
All private-record equality assertions use fixed messages, not byte dumps.

Additional native receipts under `artifacts/s05-prekey-owner-20261016/`:

- `focused-01`: compile failure CS0136, no TRX; two shadowed locals were renamed.
- `focused-02`:2 passed/native0, actual SQL-key owner and lease, memory/encrypted
  cold reopen, per-publication pairs, lost CAS response, damaged sealed key and
  unchanged account/initial pair. Compaction readback pins a pending publication.
- `receiver-03`: compile failure CS0051, no TRX; the test's public theory argument
  now carries an integer, without widening the private failpoint API.
- `receiver-04`:4 passed/native0, actual two-account one-time Initial/Hello and
  pending/SQL/secret-delete/stable crash recovery. Exact replay consumes once;
  original33 SQL secrets remain and SQL rollback cannot resurrect custody.
- `regression-05`:87 passed/1 failed/native1. Earlier pair reads introduced by
  chain-open moved a fixture's clock callback before fresh proof acquisition.
  The callback now waits for that fresh proof; production clock guards were not
  relaxed and the original red receipt is retained.
- `regression-06`:89 passed/native0, no failures/skips or compiler errors,
  including current initial publication, original receiver/storage and successor
  source/component cases. This and owner02/receiver04/epoch09 retain one
  xUnit2031 test-style warning, not zero-warning build evidence.
- `compaction-07`:27 passed/native0, no failures/skips, existing actual encrypted
  compaction and namespace retirement cases.
- `epoch-08`: compile failure CS0103, no TRX; missing namespace import corrected.
- `epoch-09`:6 passed/native0, no failures/skips. Includes native same-service
  epoch succession, counter2 before old pending counter1, encrypted cold reopen,
  destruction of both initial/successor LR secrets only after complete counters,
  and rejection of a signed counter1 claim on a different epoch key. Four
  successor crash rows and the original LR-limit case also pass.
- `regression-10`:97 passed/native0, no failures/skips. Covers the final runtime
  counter/destruction changes with the owned-inventory, prekey, receiver,
  compaction and selected namespace-retirement filters. The native same-service
  case also verifies that an exhausted service cannot advance its inventory tip.
  The original test-style warning remains in this immutable receipt.
- `final-11`:2 passed/native0, no failures/skips or compiler warnings/errors.
  Rebuild plus the exact memory/encrypted concurrent-CAS test rows after replacing
  `Assert.Single(Where(...))` with its predicate overload. No runtime source
  changed after regression10; the final pass is not another unfiltered/full gate.

These tests use actual native key/session cryptography and encrypted account
storage, but replicas are independently signed in-process fixtures, not deployed
TLS/ONION nodes or physical devices. They do not qualify shipping activation.

## Connected work still mandatory

### DR-0131 source evidence — 2026-10-16

Receipts: `artifacts/s05-prekey-maintenance-20261016/`, native
WindowsPowerShell5.1/SDK10.0.301. Original red receipts stay unchanged.

- `source-01`: compile-only CS0103, no TRX; missing XPointNetwork import fixed.
- `source-02`:10 passed/2 failed/native1. New restore-negative fixtures expected
  the wrong exception classes for invalid signature/foreign DMD1; they now require
  the exact existing Protocol exceptions, without changing production guards.
- `source-03`: compile-only CS0103, no TRX; missing ContactV1 test import fixed.
- `source-04`:24 passed/2 failed/native1. Forced service renewal exposed an
  unchanged reachability expiry; the owner now requires old expiry+1 within
  actual current authority before signing a new proposal. The hardened service
  author also correctly refused invalid negative-test inputs: tests now assert
  its refusal and independently sign hostile fixture-only support to retain real
  consumer-policy/expiry rejection coverage. Those fixture signatures are
  independently verified before use; no generic signer was added to production.
- `source-05`:25 passed/1 failed/native1. The contact fixture's short signed XNA
  could not authorize a reachability successor. The final cases distinguish
  refusal without mutation under that original short root from an independently
  created genuinely signed long-root fixture. No old authority is extended.
- `source-06`:26 passed/1 failed/native1. Includes both epoch/service expiry,
  actual encrypted reopen, lost stage response, unchanged DID/initial pair,
  network-free exact pending retry, foreign/signature/generation/window/disposal
  guards and existing publication/clock/cancellation/LR cases. The remaining
  long-root test found that its fixture issuer reused XRA's resource expiry for
  a threshold lease beyond that lease's one-day bound. The fixture now follows
  the actual Registry issuer's existing minimum of resource, current issue+day,
  authority and DCA expiry. Production threshold limits were not changed.
- `renewal-08`:9 passed/native0,0 failures/skips/compiler warnings/errors.
  Both long-root successful changed-service publication and short-root refusal
  pass, as do existing owned renewal/crash/restart cases and the independent
  owner/issuer service test. New service cannot mutate route custody without
  its exact prekey pair; completed contact retry preserves locator, owner
  Retrieve capability and exact result without another publication.

The MAUI consumer's `clean-07` receipt in its corresponding artifacts directory
passed230 unfiltered Clean-project cases/native0,0 failures/skips. Its source
calls the one new publisher and removes the obsolete separate PreKeyStaging
diagnostic phase. This is not a Windows/Android build, installation or E2E claim.
Protocol `protocol-09` passed4 targeted cases and retained one xUnit2031 warning
in an existing acquisition-hint test. After its predicate-overload correction,
`protocol-10` passed35 codec, lineage, actual authoring/persistence and acquisition
cases/native0,0 failures/skips/compiler warnings/errors. Full/package and actual
Windows QA compilation remain separate pending qualification.

### Remaining lifecycle closure

The [DR-0131 author/command](../../../docs/survival-program/decisions/DR-0131-owned-prekey-maintenance-author.md)
is now a source candidate. It restores exact signed same-service support, selects
ordinary epoch/service succession under the actual lease, retains exact pending
candidates and uses the existing held-lease authority reader without recursively
acquiring the file lease. The public publisher performs preparation and dispatch
with the same fresh authority. Changed XPS support forces permanent-contact
renewal even before ordinary route expiry, but only after its exact authenticated
prekey commit pair. The canonical Protocol transition predicate is shared with
the independent issuer; no duplicated Shared service-lineage predicate remains.

Qualification must still cover that connected path and failure boundaries.
In particular, immediate service/contact succession is not proof of catch-up
after multiple completed inventory service generations while contact promotion
was unavailable. The contact boundary still requires its exact immediate signed
service predecessor; do not skip it, fabricate missing support or abandon an
old pending publication. Resolve this catch-up case and expired unresolved
publication recovery before claiming the full S05 lifecycle.

Canonical full/package gates, matched services/clients and retained-account physical
Windows/Android E2E remain open. Do not install this partial component as a
workaround for the expired initial inventory, reset accounts or extend signed
intervals. Current release status belongs to [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
