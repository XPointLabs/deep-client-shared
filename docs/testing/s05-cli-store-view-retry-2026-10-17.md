# CLI exact Store across ordinary view renewal

The real retained CLI pair completed Initial Store, incoming request/ACK,
ContactAccept Store and peer acceptance. The first text's retry then failed in
`SqliteDeepMailboxStore.RequireSamePublicEvidence`; no text delivery is claimed
by that failed run27. Original operation, native event and ciphertext remain.

Text/ContactAccept rebuilt current XNV1/descriptor evidence for an already
prepared attempt. A normal view renewal changed those bytes. Initial already
retained its original evidence; the ordinary path must do the same.

The held owner now authenticates the existing evidence MAC and exact prepared
attempt/native request, compares immutable transport/policy/route fields, and
independently verifies both original and current replica evidence against the
current complete network authority. Node IDs and receipt keys must be identical.
It returns the exact original evidence, not a rewritten record or new MAC.
Missing evidence for attempted work still rejects; only a Prepared SQL request
with no attempts can receive its first original evidence. Current dispatch
route/grant/floor checks remain independently mandatory.

Local public-evidence/CAS preparation now precedes the fresh signer-free
dispatch scope, matching DR-0056. Both local preparation and dispatch remain
bounded30s separately. The conservative preparation upper bound ages across
preparation; no clock rewind, extended signing loan, renewed original request
or larger signed lifetime. No schema/wire/API generation change or reset.

`artifacts/cli-store-view-retry-20261017/focused-01` retained4FAIL/native1.
After the correction, focused02 passed4/native0/0skip. These four real
encrypted/PQ/ratchet owner cases cover Text and ContactAccept, interrupted
before ingress and lost response, operational view renewal, cold reopen,
byte-stable original MAU/evidence, unchanged native floor and cached durable
replay without another issuer call. Their in-process signed terminal fixture
is not socket/CLI/device acceptance. Focused03 passed16/native0/0skip:
conservative installation-clock boundaries, slow-preparation non-rewind and
both Initial/ContactAccept loss-of-evidence-after-ingress refusals. Real CLI
text and final full/package qualification remain separate.

## Committed acceptance retry after rendezvous expiry

Retained CLI run29 stopped before text: preparing a repeated ContactAccept
used live-rendezvous validation even though its exact native send and semantic
acceptance were already committed. Payload compaction was incorrectly the
only switch to historical verification.

Preparation now reconciles the actual native floor and exact operation. A
committed send uses the existing retained-event reader, which joins the
protected explicit winner, original Hello, native event hash and exact
semantic projection, then independently verifies historical endpoint facts.
An unsent draft still requires live rendezvous authority; a first late receive
cannot convert an expired acceptance into history. No lifetime extension,
reauthoring, schema or protocol change.

Focused04 reproduced the committed-retry defect (1FAIL/native1). Focused05
passed3/native0/0skip, including both first-late-admission refusals;
its native terminal and TRX are the evidence, not this description. CLI text
delivery remains unconfirmed until the physical continuation passes.
