# Owned prekey inventory custody

Normative owner: [CONTACT-RESOLVER section3.3](../../../docs/architecture/CONTACT-RESOLVER-V1.md).
Local allocation: [DR-0130](../../../docs/survival-program/decisions/DR-0130-owned-prekey-inventory-custody.md),
following the [DR-0129 service boundary](../../../docs/survival-program/decisions/DR-0129-owned-prekey-service-succession.md).
This is an internal custody implementation checkpoint, not activated renewal,
publication, claim/Initial authority or device acceptance.

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

The sole original tip-slot constant is shared with the initial SQL owner. No
shipping owner calls the new staging path yet. In particular, the existing
initial-only reader has NOT been changed into a compatibility fallback.

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
  zero warnings/errors. This bit is never persisted as authority.

The Protocol repin changes only CONTACT-RESOLVER's reviewed source hash and its
generated/resolved registry digest. All178 normative anchors remain unchanged;
the strict generator and registry gate pass. There is no wire allocation or
public API change. These focused receipts do not replace canonical full and
package qualification of the eventual connected lifecycle.

The two native custody rows use a real account/device/ML-KEM author and full
current inventory verification before sealing. Encrypted mode uses actual
journaled disk protection with a fixture-owned protector. The DPK2 sealing key
is fixture-owned: production account/SQL key-owner integration is still required.
All private-record equality assertions use fixed messages, not byte dumps.

## Connected work still mandatory

Connect the actual account lease, existing SQL-key-derived persistence protector,
initial anchor and full signed epoch/service lineage before ordinary staging.
Resume the exact pending operation, authenticate both selected replica receipts,
and adopt contact support only after that pair. Keep one global receiver ledger:
restore by exact DPK2 across inventories, remove only the consumed secret after
SQL commit and before checkpoint stabilization, and reconcile that deletion on
every pending reopen. Validate every absence against authenticated history.

Extend source/compaction readback to include the exact protected chain and per-
publication commit custody. Native crash/CAS/reopen/old-pending tests, canonical
full/package gates, matched services/clients and retained-account physical
Windows/Android E2E remain open. Do not install this partial component as a
workaround for the expired initial inventory, reset accounts or extend signed
intervals. Current release status belongs to [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
