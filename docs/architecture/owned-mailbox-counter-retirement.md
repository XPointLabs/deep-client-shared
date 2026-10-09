# Owned idle mailbox counter retirement

Owner: Mr. X, delegated architecture authority. Current private S01 API/layout
under [DR-0105](../../../docs/survival-program/decisions/DR-0105-idle-mailbox-counter-retirement.md).
Semantics remain solely in
[TRANSPORT-NEUTRAL-MESSAGING §8.4](../../../docs/architecture/TRANSPORT-NEUTRAL-MESSAGING.md#84-owned-attempt-settlement-renewal-and-retirement).
This is not an acquisition/object-path retirement, runtime scheduler or device
qualification. It adds no wire, generation, public verifier or compatibility reader.

## Held selection and exact dependencies

`MailboxEpochExclusion.RetireIdleMailboxCounterFloorAsync(ct)` has no caller
settlement flag, SQL selector, successor or supplied preparation. Its existing
held producer must already exclude the original epoch irreversibly and pass the
original possible-issuance ceiling. The producer rechecks actual DNH2/anchor,
current signed authority/time, original grant root and account lease before
selection and immediately before atomic plan/part publication.

Only an adopted phase2/5 exact winner is eligible. Pending, closed-unknown and
received-unadopted acquisitions reject. Missing custody is never reconstructed.

| Counter root | Exact index and pinning work | Unchanged custody |
| --- | --- | --- |
| Send | MCG3 digest plus existing Protocol Store replay namespace; any matching protected send entry pins the floor, regardless of pending/prepared/SQL outcome | All send entries and other floors |
| Read | Exact MCG3 digest; any active captured Retrieve/ACK cycle using it pins the floor | Other counters, all traversals, any unrelated active cycle |

The index is derived from actual canonical protected roots, not SQL absence,
cached Durable flags, an empty poll or caller assertions. It is specific to the
counter disposition. Removing the floor does not discard unresolved objects,
receipt obligations, initial-contact evidence, holders or retained routes:
those dependencies stay protected and are not reclassified as settled. An idle
read floor may therefore retire while its last retained route stays pinned.
An empty poll alone, without independently checked exclusion, grants no permission.

The general retirement dependency capture uses two distinct opaque namespaces:
grant acquisition uses `Scope(originalRouteHash, locator, domain)`, whereas a
Retrieve cycle/traversal uses the actual `ClientMailboxScope.Derive` from the
original route hash (the installed issuer context), original mailbox and original
selection epoch. Never look up a traversal by the acquisition scope or by a new
current epoch. This structural index identifies a preserved dependency; it does
not verify receipt completion, grant deletion permission or path migration.
After idle read-floor removal, a retained traversal and the last Retrieve/ACK
path remain indexed and pinned even though the selected counter is absent.

## Stored profile and cold recovery

Use the existing ProtectedOnly plan, one ReplayScope row selecting the exact
original acquisition and its exact entry commitment. Its SQL selector is the
existing acquisition scope. SQL before/after are zero because no SQL table or
row is mutated. The first eight roots retain their mapping: Ordinary, Send,
Grant, Read, SessionCatalog, Attachment, AccountRegistration, NativeFence.
The counter profile additionally requires the unique unchanged MailboxStoreState
guard. It binds the actual registered application database's complete logical
schema/rows and every catalogued native database, authenticated history/tip,
protected floor and peer binding. Reads open existing files only. Changed/missing
original publication journal or protected resolver-capability custody also pins
selection/recovery; these remain unchanged under the same guard. Missing or
changed contact intents, initial-key/preclaim custody and protected device-source
marker/checkpoint or complete existing device SQL also pin recovery. Responder
checkpoint, prekey install/inventory/commit markers and the entire existing
encrypted prekey file are also guarded; their readback is specified solely in
the [source custody owner](owned-authored-counter-custody.md#completed-initial--contactaccept-send-working-entries).
Device
reads use the exact registered SQLCipher key profile and schema, without source
repair, creation or key retirement. Uninitialized custody,
pending/latched native work or disagreement rejects,
without creation, promotion or reconciliation. The live producer captures and
rechecks this guard before staging; stored recovery derives it again from actual
local state. A copied digest never grants deletion permission.
Exactly one counter root changes; Grant and all other roots remain byte-exact guards.
The successor removes only the selected floor and increments that root revision.
No namespace tombstone set or new unbounded storage is introduced.

The shared protected-retirement dispatcher distinguishes the unused closed
Deposit acquisition profile (Grant changed, eight roots) from these counter
profiles (Send or Read changed, nine roots). An eight-root counter plan is rejected:
there is no compatibility reader or inferred missing SQL guard.
The separate [used Deposit source candidate](owned-mailbox-grant-custody.md#used-deposit-holder-retirement--s01-source-candidate)
changes Grant with nine roots and preserves independent object/read custody;
it is not this counter disposition or activation permission.
The [superseded Retrieve source candidate](owned-mailbox-grant-custody.md#superseded-retrieve-holder-retirement--s01-source-candidate)
also changes only Grant, after an independently installed and completed replacement
read on the same original path; it preserves the traversal and last-path custody.
Before
commit-marker recording and before CAS adoption it rederives
the exact counter successor from actual unchanged grant custody and the exact
predecessor. Wrong row/scope/domain, non-prefix or third root state, missing
parts, changed guard, SQL binding/floor/anchor rollback or missing registration
rejects. No new proof, signing, issuer or transport callback is needed to finish
an already protected plan; the native exclusion guard must remain exact.

The existing protected commit marker precedes counter-root CAS/readback. After
adoption, matching remaining parts may be disposed and the plan cleared only
after all nine readbacks agree. SQL-only changes also pin the stored plan and
counter before mutation; neither an empty SQL result nor unchanged protected
roots can substitute for the complete readback. Phase1 may be abandoned through
`AbandonUncommittedMailboxRetirementAsync(ct)` only with exact unchanged
predecessors/guards. Phase2 cannot be abandoned, even before adoption.
Cancellation leaves the stored plan owning recovery.

## Remaining boundary

This counter-only profile does not remove known send commitments, acquisitions
or traversal slots. The separate [ordinary outbox profile](owned-authored-counter-custody.md#owned-ordinary-outbox-only-api)
removes selected authenticated completed ordinary send commitments while
preserving their counter, original SQL request/quorum and coordinator ledger.
Only afterward can the held exclusion independently select an idle counter.
The separate [completed contact-send profile](owned-authored-counter-custody.md#completed-initial--contactaccept-send-working-entries)
selects original initial/ContactAccept Store closure and preserves these same
counter floors. Source qualification is pending. Acquisition/traversal slots
still need their separate dependency-closed terminal dispositions, preserved
receipt/object linkage and retained-path closure. No128/512 capacity increases,
automatic eviction, grant renewal or UI/runtime activation follows. Prior grants
cannot become current from a missing floor; dispatch still verifies current
host/issuer/revocation/holder/route before reserving a new request.

Source qualification and exact run receipts belong to
[the checkpoint](../testing/s01-idle-mailbox-floors-2026-10-09.md), not this contract.
