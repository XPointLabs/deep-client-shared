# S05 — fresh owned inventory batches

## Segmented custody read candidate

After Windows29's new Add cancelled at120047ms (1717 Unprotect/69458ms
protection), the selected segmented readers now use fresh bounded inventories:
idle compaction checks all16 successor slots together; compaction successor
read-back preserves its independent before/after exact-plan checks; messaging
pending read captures the exact floor plus all18 possible parts together.
The complete missing/extra/length/hash/scope checks remain. No part deletion,
CAS, native reconciliation, signed deadline or public format changes. Each call
reopens the actual aggregate; no snapshot/plaintext survives across calls.
Other specialized compaction finishing paths are unchanged, not claimed batched.

Affected80 passed/native0/0skip, Windows PowerShell5.1 SDK10.0.301 with no
compiler diagnostics, receipt
`artifacts/s05-segmented-custody-batch-20261017/focused-01`. New encrypted pending8
and actual idle-owner4 cases cover independent reads, first/last orphan slots,
missing/foreign floor, missing/truncated/tampered/extra parts, cancellation and
unchanged custody bytes. The pending fixture observes exactly one Unprotect
per read, twice independently; it is not device latency evidence. Existing
checkpoint, staged compaction, native encrypted cold handovers, Initial retry,
scoped contact start and device-source cases also pass. This is affected source,
not canonical full/package or physical acceptance. Matching builds/retest remain.

Matching Windows24/APK40 include the closed business observer, not this
correction. Windows's exact retained contact retry reached its120s foreground
budget: ContactStartTotal120031ms,3 Protect/1738 Unprotect calls,78880ms of
protection work. Cancellation surfaced while opening application audit custody
before retaining Initial Store evidence. The intent remains available to retry;
neither delivery nor noncommit is established. Android's separate mailbox
refresh returned OutcomeUnknown: MailboxSyncTotal40780ms,2 Protect/304 Unprotect,
26971ms protection work. These are actual command totals, not background
VerificationTotal or a controlled cross-build benchmark.

The source correction reduces repeated protected inventory work without a new
cache, generation, wire/API, account reset or authority/deadline extension:

- Application open reads the key registration, application registration,
  Initial/Accept roots, compaction plan and ordinary journal in one actual
  atomic inventory instead of six independent decryptions. Both normal and
  recovery opens still validate every required registration, account/instance,
  control custody, complete stopped audit and active-compaction distinction.
- The held endpoint-pair recheck reads directory and network rows through one
  freshly authenticated SQLCipher connection/transaction, then validates their
  related protected markers through one atomic inventory. The SQL key remains
  independently reacquired for each invocation. Only actual backends with the
  same storage object, path, full account/device/instance binding and actual
  held account lease can participate. No arbitrary supplied head becomes
  current authority. Existing genesis-gap/current/future directory checks,
  network projection/history anchors, rollback/fork checks, exact history and
  both proof/clock checks remain. The ordinary separate store readers remain
  in use for their independent operations; there is no fallback in this path.

Every owned inventory is disposed before return. Independent invocations
reacquire their connection/key and marker snapshot. Native SQL integrity,
schema/identity and durability checks are not removed. The two reductions
belong to one protected-read performance slice; neither proves device latency
or delivery until matching retained-account retests succeed.

Receipts: `artifacts/s05-owned-read-batch-20261017/`, Windows PowerShell5.1,
SDK10.0.301. `focused-01`:18PASS/0FAIL/0skip/native0 for application-only source.
`focused-02`:39PASS/0FAIL/0skip/native0 for the final combined source, no
compiler diagnostics. Includes both application open paths, all six missing
roots, foreign application registration, cancellation after the actual batch,
independent paired-floor rechecks, missing/corrupt/future markers and anchors,
foreign actual account backend/held lease, unchanged protected/SQL bytes after
refusal, the prior network batch cases, directory reopen/rollback and owned
stopped-control audit binding. `business-03`:3PASS/0FAIL/0skip/native0, no
compiler diagnostics: actual owned first claim→Store→cold exact retry and
lost-reply pinned custody for both Initial and Accept. These are source
fixtures, not physical network delivery. Canonical full,
package and physical acceptance remain open. No production state was changed.

Matching Windows25/APK41 (MAUI `fa927e2`, Shared `7d64fe7`, Protocol `2bb61d0`)
built native0 without compiler diagnostics and retained both QA accounts;
Android Settings151 confirmed account/recovery after dry149/update150.
Windows's retained retry rejected expired XUR (35272ms,498 Unprotect), then
the normal owned stop succeeded (39932ms,907 Unprotect), not a remote recall.
A separately explicit new request returned Store OutcomeUnknown after116234ms
(32 Protect/2058 Unprotect,70861ms protection); closed peer metadata reports504.
This is not a same-workload performance comparison or verified storage.
The new intent remains available to retry; the old uncertainty is not erased.
Android Refresh153→Inspect154 returned protected-state failure, not delivery:
MailboxSyncTotal47635ms,4 Protect/256 Unprotect,23281ms protection.
Matching DLL/PDB maps the refusal to the original retained-result time guard
and the first newly received response verification, not a missing local marker.
Which ordered predicate failed remains unknown; do not weaken it or reset.

## Device-source and retirement opening

Windows28's retained retry measured120050ms with1809 Unprotect calls and75840ms
protection work. Cancellation reached device-source custody opening; this is a
new measured hot path, not proof that every earlier transport refusal is fixed.
See [the matching device observation](../../../deep-client-maui/docs/S05-BUSINESS-WORK-2026-10-17.md#original-contact-retry-expiry-entry-source-candidate).

The next source candidate uses the same actual atomic inventory interface:

- Device-state open reads its SQL registration and install marker together.
  Actual account SQL validation, derived key, file-family/marker checks, initial
  provisioning distinction and initial-session reconciliation are unchanged.
- Each independent retirement read obtains the actual SQL registration,
  retirement journal and optional Initial/catalog owners in one fresh group.
  Registration scope and journal decoding remain mandatory. Only an actual
  role3 entry requires decoding the optional owners; an empty journal does not
  gain new cancellation-absence authority or new root requirements.
- Cancellation staging/completion read the draft/catalog owner pair atomically.
  Every exact stopped-owner binding and matching native floor/history read is
  retained through the same existing cancellation owner. No captured root,
  marker, bool or exception substitutes for native custody.

Each invocation reacquires the full relevant group, checks cancellation and
disposes/zeroes its owned bytes. No verification cache, retained plaintext,
wire/API/schema generation, key/nonce renewal or authority/deadline extension.
The affected source union passed53/0FAIL/0skip/native0 under
`artifacts/s05-device-source-batch-20261017/focused-01`, Windows PowerShell5.1 /
SDK10.0.301, no compiler diagnostics. Fourteen new cases check independent
groups, missing/foreign roots, cancellation after acquisition, unchanged protected
and SQL state on refusal, optional owners for an empty journal, and actual
cancelled owner loss after encrypted cold reopen. Existing native import,
expiry, key-deletion interruption and scoped claim/Store cases remain in the union.
Matching Windows/Android performance/business acceptance and canonical full/package
qualification are separate remaining gates; no device speedup is claimed yet.
