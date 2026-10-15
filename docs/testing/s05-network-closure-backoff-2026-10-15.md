# S05 — bounded network-distribution contention recovery

Date: 2026-10-15. Source candidate, not new full or device qualification.

Network closure distribution can reject concurrent public reads with429. The
adapter retries this exact identity-neutral query up to eight times with bounded
exponential jitter, honoring delta Retry-After inside one original configured
request timeout. Response buffers are disposed before waiting. It neither caches
no-store responses nor reuses a proof/placement capability.503 remains a typed
unavailable response; malformed media, scope, framing and other failures do not
retry into success. Caller cancellation remains cancellation and the internal
deadline still reports a timeout.

The16-byte network scope is captured before callbacks; the protected floor is
still never uploaded. Existing downstream signed-history, independent nonce-proof,
time, account and durable-floor verification is unchanged.

`artifacts/s05-contact-diagnostic-20261015/focused-02/closure-retry.trx`:
**27/0/0/native0**, Release under Windows PowerShell5.1; zero compiler diagnostics.
Includes transport limits/media, retry exhaustion, original total budget,
Retry-After, cancellation, caller-buffer mutation and existing signed publication
successors. The latter also assert the closed PMT-reference rejection diagnostic.
Focused01 passed26 before the final eight-attempt/timeout case; it is not the final
receipt. No new Shared full is claimed.

[Actual connected evidence](../../../deep-devops/docs/S05-CONTACT-TRANSPORT-2026-10-15.md)
includes prekey publication followed by a real contact commit and an authenticated
empty mailbox read. Earlier incomplete owners are preserved; neither a new test
owner nor raw distribution retry proves their reconciliation or physical E2E.
