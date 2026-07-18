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

## Review boundary

This is an implementation self-assessment, not approval. Independent privacy/architecture review is required before changing finding status or accepting a P03 construction.
