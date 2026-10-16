# S05 — fresh owned inventory batches

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
