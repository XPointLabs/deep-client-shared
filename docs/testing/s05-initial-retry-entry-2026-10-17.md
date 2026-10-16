# S05: original Initial retry expiry at the business entry

Scope: Shared source candidate, not device or release acceptance.
Semantic owner: [DR-0135](../../../docs/survival-program/decisions/DR-0135-owned-initial-retry-expiry-entry.md)
and its linked contact contract. No new wire/schema/journal generation.

`StartContactAsync` first returns any independently authenticated original
durable Store. An existing unresolved intent then enters the existing account
expiry owner before current peer resolution. The protected root, own proof,
trusted lower bound, actual native/source custody and stop read-back decide
the result; neither the UI projection nor a failed resolve authorizes it.
Unexpired retries retain all exact metadata and dependency checks.

The conditional native adapter reads the actual committed result: the common
stop helper can recover a durable Store instead of stopping work, so its bool
alone cannot become the informative expiry result. A retained Store is reread
before peer resolution. Prior user cancellation keeps its original reason.

MAUI consumes the payload-free informative exception only to clear the exact
in-memory retry choice. It does not reset the account, claim non-delivery or
automatically create/send another intent. New work requires a separate Add,
which rereads protected operations. Unknown failures preserve the retry choice.

## Bounded checks

Receipts are under `artifacts/s05-initial-retry-entry-20261017/` in this repo.
`focused-01`: native1,22 passed/5 failed/0 skipped. All five failures are the
existing scoped-claim fixture's exact network-fetch count: the new early own
proof adds one fetch before the shared resolve/claim scope. The late-reply case
also fails that same assertion before entering its wait. The assertion is
updated from two to three, not removed; the reply/Store/cancellation checks stay.
The seven initial-entry cases passed in that run. It predates the additional
native-import cases and explicit native outcome read-back correction.

`focused-02`: native0,29 passed/0 failed/0 skipped, no compiler diagnostics.
This affected union includes all nine entry cases, the six existing pre-session
lower-bound cases, six existing native retry-expiry cases and eight existing
scoped-claim cases. The two new imported-unknown cases preserve the actual native
floor, sender projection and exact prepared send bytes through stop/cold reopen.
The earlier failed receipt is retained. Both runs used Windows PowerShell5.1
and SDK10.0.301; neither is the canonical unfiltered repository full gate.
Unfiltered MAUI Clean273 passed/native0/0 skipped before the last Shared-only
read-back correction; this is UI source evidence, not native expiry authority.

Remaining: canonical full/package/API qualification,
matching Windows/Android updates preserving both accounts and recovery, actual
owned expiry followed by a separate explicit new request, recipient acceptance
and bidirectional text. The observed old metadata mismatch has no established
differing field; this change must not be described as an unexpired retry fix.
Physical contacts/messages/attachments/groups remain0/4; S05 is unaccepted.
