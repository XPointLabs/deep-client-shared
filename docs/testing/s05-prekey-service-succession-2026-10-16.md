# S05 — native contact service-succession boundary

Date: 2026-10-16. Normative semantics belong only to
[DR-0129](../../../docs/survival-program/decisions/DR-0129-owned-prekey-service-succession.md)
and its CONTACT-RESOLVER owner. No Shared persistence format/API changes are
implemented by this source slice.

`Did2PreKeyServiceSuccession_NativeOwnerAndIssuerKeepIdentityAndLocator` uses the
real protected account and native authoring authority, device/witness/node
signatures, two object/service successors and independent target5
PublicationCurrent verification. It preserves identity, bundle ID, locator and
Retrieve capability, verifies exact object restore and publication lineage, and
rejects signed policy/no-expiry advancement and a damaged later-generation
genesis signature. Replica responses are in-process; this is not deployed
transport, inventory custody or physical evidence.

Receipts under `artifacts/s05-prekey-service-succession-20261016/`:

- `red-01`: native exit1, 1 failed case at the original genesis-only guard.
- `green-02`: native exit0, 1 passed case, before the target5 assertion.
- `shared-regression-04`: native exit0, 12 passed, no failures/skips; includes
  target5 submission plus existing unchanged-service successors/owned renewal.
- `shared-final-07`: native exit0, the same 12 passed with no failures/skips;
  the native successor case additionally rejects cancelled owned object
  authoring, callback expiry on both owner/issuer threshold paths and reversed
  time, retaining exact predecessor/capability bindings.
- `expired-service-09`: native exit1/1 failed. A valid shorter-lived service
  exposed the existing publication author's request expiry exceeding the signed
  object's effective expiry; the canonical wire constructor correctly rejected.
- `expired-service-10`: native exit0/1 passed after capping request expiry at
  the actual object expiry. The native case now asserts that cap and the actual
  expired predecessor service before succession. A signed no-advance negative
  retains its historical issue time so it is canonical, not an invalid fixture
  interval rejected before reaching the object author.
- `shared-final-12`: native exit0/12 passed, no failures/skips, on the final
  short-service/capped-publication source. Includes both service successors,
  existing unchanged-service publication and owned-renewal cases.

These ran under Windows PowerShell5.1/SDK10.0.301. Full source,
multi-generation protected inventory/pending custody, old Initial/replay state,
crash/restart and same-account Windows/Android acceptance remain unfinished.
