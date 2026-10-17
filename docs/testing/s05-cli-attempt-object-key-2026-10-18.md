# Attempt-scoped mailbox object keys

The real retained CLI pair materialized both directions exactly once and
passed duplicate polls in run32, but both Store results remained unknown.
The receipt correctly records `passed=false`, native1,24 steps and5 failed
attempts. Runtime fingerprint:
`10baa0a7b756bdff03aa390a4b101a19070ba8b96744154e2c13096c5e40d907`.
This is actual transport/history evidence, not full CLI or device acceptance.

[DR-0140](../../../docs/survival-program/decisions/DR-0140-attempt-scoped-mailbox-object-key.md)
owns the producer correction. New transport attempts previously changed
operation/cursor context but reused H(ciphertext), colliding with native
custody of a possibly committed predecessor. New keys now include the actual
mailbox operation under the existing domain. No node refusal is disabled.

Captured canonical SQL requests are not recomputed: protected body/MAU hashes
select their exact digest, with the native envelope and original grant checks
unchanged. Closure uses the same canonical original when SQL exists; missing
prepared SQL still rejects. A pending descriptor without SQL uses the single
current derivation. Retained receipt verification binds the body's exact
object key, independently of the protected native ciphertext hash.

`artifacts/cli-store-view-retry-20261017/focused-06` preserves the intermediate
compile failure (native1), not a test PASS. Focused07 passed4/native0/0skip:
three cold successor fault boundaries and a new lost-committed-reply case
with identical E2EE bytes, distinct transport keys, original uncertainty,
unchanged native floor and exact cached receipt replay. Focused08 passed12/
native0/0skip: closure before/after SQL/prepared CAS, late receipts for Initial,
ContactAccept and text, ordinary-view exact replay and loss-of-evidence refusals.
These use real PQ/SQLCipher owners with in-process signed transport fixtures;
they do not replace real XNode/TLS or the next CLI continuation.

Already captured colliding work remains immutable. Its owner can close it only
when authenticated lower time excludes the old admission, then author a
proper successor; no account reset, fake clock, new semantic message or
in-place request rewrite is used to manufacture success. Full/package and
matched physical qualification remain open.
