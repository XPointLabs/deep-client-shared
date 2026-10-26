# Native/storage lower bound after DR-0175 — 2026-10-26

Investigation only. No new index, state generation, storage layout or relaxed
integrity timing is authorized by this note. The
[matched measurements](../testing/dr0175-active-native-correctness-and-cost-2026-10-26.md)
reject performance acceptance for the connected DR-0175 candidate.

## Work that remains on the actual path

A normal fresh direct Dpe2 transition has at least16 active verification sites
in the current source, before optional route/source/control/recovery branches:

| Source phase | Active whole-state passes |
| --- | ---: |
| Registered and owned openers' custody reconciliation | 2 |
| Caller reconciliation and original-operation lookup | 2 |
| Transition state/context | 1 |
| Authority predecessor reconciliation | 1 |
| Commit reconciliation, capacity, append predecessor and postcommit check | 4 |
| Authority committed-row read | 1 |
| Caller committed reconciliation/readback | 2 |
| Direct application handoff reconciliation/selected row | 2 |
| Final post-callback selected-row release fence | 1 |

This is a call-graph count, not a measured per-command total. Each active pass
authenticates all actual cipher pages, the complete672-byte metadata map and
current TRS/working suffix. Actual table scans forbid secondary-index covered
columns; ordering may require a lifetime-sized SQLite sort. Full route, initial,
Braid, producer/recovery and unmapped projection consumers add their retained
checks. A32-row compaction mutation bound does not bound its full SQL projection
and archived-payload producer reads.

WithP cipher pages andN archived records, preserving immediate detection of
raw corruption in any unrelated page requires reading/authenticating that page
at the required boundary: at leastOmega(P). The current flat protected history
digest requires a complete ordered map pass: Omega(N). Neither root caching nor
path hashes resolve mutable provider policy, in-place ABA or stale pager pages.
The measured10,000-row existing-handle primitive is already about1.9s; reducing
payload-verification count alone cannot establish a bounded one-second command.

## Protected storage is independently still aggregate work

[JournaledDeepSecureStorage](../../src/Deep.Client.Shared/Persistence/JournaledDeepSecureStorage.cs)
performs recovery/path checks, `File.ReadAllBytes`, full `Unprotect` and full
`Decode` for every single/batch read. Slot selection avoids copying unrelated
value buffers; it still validates every slot, bound, ordering and trailing byte.
The source limits are1,024entries,8MiB plaintext and16MiB protected input. These
are caps, **not measured retained-profile sizes**. The retained59 receipt does
not record aggregate length/entry count; no live profile/key read was authorized.

The saved sanitized [retained59 receipt](../../../deep-cli/artifacts/cli-contact-maintenance-20261023/delivery-59/receipt.json)
records these three sender fanout operations:

| Actual source work | Observations |
| --- | --- |
| StorageLoad/full aggregate Unprotect count | 1,993 /2,222 /2,450 |
| StorageLoad total ms | 6,322 /7,676 /6,841 |
| Application opens | 58 /60 /64 |
| Native reconciliation / verification counts | 163/303;171/319;189/355 |
| Native verification total ms | 3,802 /3,894 /3,968 |

Timings nest; they are not additive CPU budgets. The same receipt's protector
totals include both Protect and Unprotect and cannot be subtracted as a pure
decode cost. A native O(logN) index alone does not remove repeated O(aggregate
bytes +entries) protected-root reads or application opens/integrity scans.

## Requirements for a materially bounded alternative

An independently protected active root would have to bind current floor/TRS,
pending/cleanup custody, initialized source/consent facts and the exact lifetime
operation membership/absence commitments. Selected records need authenticated
operation/direction/ordinal/metadata, event/envelope commitments and archive
location proofs; negative SQL lookups are insufficient. The existing flat SHA
history digest cannot produce bounded membership/nonmembership proofs by itself.
A different producer/root structure and explicit enrollment from the validated
old root are required; an index is untrusted until that independent binding.

Archive content must grant no new permission without a selected proof. Unknown
Store/ACK/retry bytes and receipt obligations remain pinned. Route ordering/fault
and Braid progress need independently committed bounded reducers or retained full
reads; arbitrary content class and peer epoch cannot be guessed from ordinal.
Initial Hello/Init remain bounded full records. Current provider/key/time/revoke,
file-family and actual protected roots must still be re-admitted after callbacks.

Keeping immediate unused-archive raw-corruption detection forces the whole-file
lower bound. Physically separating bounded active state from archives can avoid
reading unused archive bytes only with an **additional explicit detection-timing
change**: unused raw archive corruption is detected on selected access/audit.
That is broader than DR-0175's accepted same-shape semantic substitution change;
it is not an equivalent guarantee and requires normative acceptance. Selected
bytes, active state, replay/rollback and current permissions must remain checked.
Bounded path proofs also defer discovery of corruption in unselected archive
metadata/index records. That additional timing difference must be named; a
current protected root authenticates selected proofs, not every unread byte.

Protected storage also needs either a bounded actual anchor representation or
coalesced reads/writes inside a real closed operation phase, followed by fresh
admission after external callbacks. Do not retain successful plaintext reads or
private loans across arbitrary callbacks; actual protector policy still runs.
Watcher assumptions, process caches, pooling and an unauthenticated touched-row
index do not supply that ownership proof. Measure bytes and phase multiplicity
through closed runtime counters before another connected latency round.
