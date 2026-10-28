# Paused P1 archive runtime — incomplete, unbuilt

Paused at the owner's request on 2026-10-28. This is a preservation checkpoint,
not an accepted implementation or a deployment candidate. Do not activate it on
the retained CLI profiles until the integration and required qualification finish.

Branch: `wip/p1-archive-runtime-20261028`. Base: `764652a`; minimal qualified
RouteRecovery dispatch fix cherry-picked as `fb8a839` (original `e4dbf4f`).
The original Shared checkout remains on `wip/dr0176-closed-operations-20261027`.
No build or test was run on the changes preserved by this WIP commit.

The normative owner is DR-0177 in the superproject. The adjacent
`WIP-FULL-AUDIT-20261028.md` is a review outline, not a replacement specification.
The superproject `docs/architecture/HANDOFF-2026-10-28-PAUSED.md` records the
retained environment, exact evidence and a separate route catch-up blocker.

## Work in progress

- Catalog V2 (92-byte header, 440-byte entries), explicit enrollment marker and
  1120-byte enrollment progress; ordinary admission requires every session indexed.
- Schema 6 immutable archive nodes/reducers/mirror; root18 is 608 bytes while
  immutable history root10 stays 304 bytes. All dependent closed profiles need
  the actual root18 guard, including Store/ACK/outbox/retirement/recovery.
- `OwnedStorage` becomes an async physical-connection factory using
  `WithSqlAsync`, without a retained connection/key/journal. Ordinary reads use
  selected authenticated references; explicit cold/full audit owns lifetime scans.
- Replay digest2 binds archive608, moving basis188, actual floor188 and every
  suffix transition/header. Enrollment-only handling of original state is explicit.
- Paired authored-source verification, semantic replay/reducer, enrollment,
  prefix compaction and consumer conversion are unfinished and may not compile.
- New tests cover draft catalog/enrollment, selected SQL reads, authored source,
  projections, retention, route endpoints and capacity. None of these tests has
  a passing receipt for this worktree.

## Ownership at interruption

`sol_storage_owner` owned the runtime except the following ceded files.
`sol_archive_builder` owned `Did2CompactionPlan`, `ProtectedDid2CompactionPlan`,
`Did2MessagingSqlJournal.Compaction`, new `.ArchiveDelta`, owner `.Compaction`,
`.OutboxCompaction`, `.OutboxCompactionRecovery`, and coordinated root18 guards.
It could add copied typed observation metadata to `Did2MessagingArchiveBuilder`
while preserving the other owner's pure `Read` method. `sol_xps_tests` owned
isolated tests. Both runtime agents were interrupted; do not assume a final
integration pass occurred.

Proposed seam, not yet confirmed as consistently implemented:
`CaptureArchivePrefixEffects(stable, prefixRows, qualifiedAuthored)` returns
`ArchivePrefixEffects(Successor608, Before32, After32, Rows, TreeNodes, Reducer,
ProofNodes)`. The owner supplies `CaptureArchivePrefixEffectsAsync` and
`ApplyArchivePrefixAsync`. Check signatures and all call sites before compiling.

## Decisions to preserve during integration

1. No callbacks or asynchronous provider edges while a SQL connection/key loan
   remains open. After the last actual protected admission, perform the fresh
   application selected read, close/dispose it, then the fresh native read.
   Do not use the ordinary application constructor's full scans for this seam,
   and do not add a public general-purpose validation bypass.
2. Authored guard field700 is SHA256 of the actual DirectText protected root.
   Source fingerprint field668 includes the domain, account32, scope32, the
   three ordinal-sorted literal protected slot names (LPu16 UTF8), typed absence
   or blob framing and the existing complete canonical schema/table/row/cell
   stream. Roots: DirectTextJournal, ContactAcceptJournal, GroupJournal.
   Parse the atomic batch as owned private bytes and dispose group-key copies
   before application-key acquisition. Rejoin the same roots after SQL callbacks.
   Exact framing and legitimate absent-root semantics still need normative review.
3. TEST-ONLY `AfterProof` uses a one-shot invalidation boundary: close physical
   SQL/key state, invoke the action, re-admit and re-open once. No retained
   `.Sql` compatibility property, production retry engine, or callback loan.
4. Bounded prefix work selects at most32 rows. The changed profile is root18;
   root10 is an immutable guard. Closed profile entries are sorted, including
   5/6/8/10/11/18. SQL-after/protected-before recovery precedes ordinary mirror
   admission. Only the selected journal prefix is removed; original events,
   payloads, Store/ACK evidence and keys remain retained.
5. Full audit must prove exact membership, minima, eligibility and both coverage
   directions, not merely equal counts. See the preserved full-audit outline.
   Keep the independent literal-tree reference tests.

## Known unfinished verification

- Two-session partial enrollment, all cutpoints, registration barrier,
  state1/missing-root rejection, staged missing/collision/source-rowid negatives.
- Receiver initial Hello basis2/count0 and outgoing-source exact counter/payload
  provenance; root/source disagreement must reject before effects.
- Consumer APIs and old assertions still need integration. Old DR-0175
  history304 advancement assertions become archive608 assertions only where
  DR-0177 actually changed the contract. Selected-read corruption timing and
  explicit full-audit detection are distinct claims; do not weaken either.
- Cost-case replacement requires an exact retired-case binding to DR-0177:
  `Did2ActiveNativeCostTests.Did2ActiveArchive_StructuralNativeVerifierCostKeepsCompleteMapAndCipherScan`
  to `Did2ActiveNativeCostTests.Did2IndexedArchive_StructuralSelectedLookupKeepsProofAndRowidBoundsWithoutHistoryScan`
  for100/1000/10000 rows, backed by actual passing receipts.
- One recorded recovery plus24 ordinary route transitions does not cover the
  current seven-completed-publication gap. That requires a separate accepted
  historical-prefix/current-promotion contract before code changes.

No proof-page format, families7/8 or receive outcome3 has been accepted or
implemented by this checkpoint. Current semantic replay promotes ordinary14
with adjacent-generation rules; it must not silently treat historical evidence
as current authority.
