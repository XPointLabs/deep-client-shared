# Security review

Decision: **NO-GO for Beta metadata privacy**. Content encryption and onion routing do not resolve the eight P01 metadata blockers.

## Confirmed findings

- DPE1 bytes reveal clear sender and recipient Session IDs in authenticated header fields.
- Storage store exposes raw recipient as `pubkey`; managed payload repeats sender and recipient.
- Repeating the same logical message produces the same client idempotency key.
- Storage retrieval authenticates with raw account public-key material.
- Push subscription exposes raw account, signing public key and provider token.
- No opaque deposit capability, opaque retrieval capability or rotating push handle producer contract exists.

## Safety properties of this package

- Tests use deterministic synthetic recovery phrases already present in the test suite and synthetic identifiers/tokens only.
- Failure messages contain finding IDs, not keys, provider tokens or recovery phrases.
- No production log defaults were changed.
- No claim is made that P01 implements sealed sender, traffic-flow confidentiality, padding or cover traffic.
- The strict gate is executed only through a fixed-filter wrapper that validates exact TRX test IDs,
  findings, per-result outcomes, aggregate passed/failed/skipped/infra counters,
  `ResultSummary.outcome` and process exit.
- Omitted strict environment, caller filter attempts, zero-match, missing/duplicate results,
  expectation-count mismatch and false-green outcomes are harness errors (`exit 2`).

## Review boundary

This is an implementation self-assessment, not approval. Independent privacy/architecture review is required before changing finding status or accepting a P03 construction.

## P03 runtime iteration (2026-07-22)

The direct and routed personal-mailbox transports now have a fail-closed development vertical
slice over the existing P03A/P03B contracts. Captured deposit/retrieve and onion storage requests
carry canonical DPB1/MCP1 material, opaque placement/capability values and fresh attempt-local
identifiers. They do not carry raw sender, recipient, account signing key, or a stable logical
idempotency key. The E2EE round trip proves duplicate logical sends still deliver once.

This mitigates the first six findings in the development slice, but does not resolve them for Beta:
`deep-protocol` deliberately ships no production P03A crypto adapter or P03B capability producer,
and the shared runtime deliberately does not invent either. `ReleaseDefaults` now requires an
opaque metadata transport and fails closed without explicit reviewed dependencies. Legacy storage
is available only by explicit `SessionStorageMetadataMode.LegacyCompatibility` selection for a
Debug/survival lane and is rejected by release defaults.

The exact strict P01 red set remains eight: six mitigated-but-unresolved production findings
(`META-DPE1-CLEAR-SENDER`, `META-DPE1-CLEAR-RECIPIENT`, `META-STORAGE-RAW-TARGET`,
`META-STORAGE-STABLE-IDEMPOTENCY`, `META-OPAQUE-DEPOSIT-CAPABILITY`, and
`META-OPAQUE-RETRIEVE-CAPABILITY`) pending the reviewed producer/crypto/replay implementation and
independent review, plus two untouched push findings (`META-PUSH-RAW-ACCOUNT` and
`META-PUSH-ROTATING-HANDLE`).
