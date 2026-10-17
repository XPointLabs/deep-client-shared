# CLI pending Deposit acquisition (2026-10-17)

The two real CLI profiles published successfully, but contact request retries
first received503 BeforeForward and then failed in Protocol's unchanged
`DeepIdV2MailboxGrantRequestAuthor.RequireWindow`. No message delivery is claimed.

An Initial draft/session can already exist while grant acquisition failed and
no Store attempt was captured. Draft-only maintenance skipped this retry; the
new-work grant selector consequently kept selecting its expired pending XMG2.

The existing owner now closes expired pending acquisitions for this exact
Deposit scope before selecting a new-work grant. It uses authenticated lower
time, protected CAS/read-back and the existing retained predecessor chain under
DR-0126 / root `TRANSPORT-NEUTRAL-MESSAGING` §8.4.2. Original request, holder,
policy, route and uncertainty remain. No reset, wire/schema change, re-signing
of old work or lifetime extension. A captured Store bypasses this acquisition
and keeps its original grant/ciphertext/counter.

`artifacts/cli-grant-admission-20261017/focused-01` retained the new regression's
original1FAIL/native1. The same regression passed1/native0/0skip in focused02.
It cold-reopens the real encrypted owner, preserves the old exact request/key/
route/policy, adopts an independently authorized holder and repeats its winner
without calling the old issuer again. Focused03 passed9/native0/0skip, including
the five pre-existing independent Deposit handover/fault cases, both expired
unknown closure cases, and a full working send journal's exact unknown replay.
Real CLI contact/text acceptance and full qualification remain unfinished.
