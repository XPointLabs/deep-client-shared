# P14A2B1 dormant activation-trust package rebind

Status: `P14A2B1-SOURCE-REVIEW-PENDING / STAGED-BYTES-ONLY /
CLIENT-RUNTIME-REGISTRATION-NO-GO / PROFILE-ACTIVATION-NO-GO`.

This iteration replaces the former `Deep.Protocol.ProfileCarrier`
`0.1.0-p14.faa598f` package with the byte-exact accepted P14E2 package
`0.2.0-p14.69a712a`. The accepted raw package is 29,399 bytes with SHA-256
`fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498`.
Its producer source is commit
`69a712a894b024a09859096025c2bb8fe68a642e`, and its separately accepted
evidence carrier is commit `071b5b300bcba3796d621720fb8f21cfdd5eb882`.

Both production and test lock graphs bind the exact package version, NuGet
content hash and its three exact dependencies: `Deep.Protocol
[0.3.0-p04.b887fa0]`, `Sodium.Core [1.4.1]`, and `libsodium [1.0.22]`. The
offline closure contains no copy of the former carrier package.

The inherited verifier implementation and its ownership, cancellation,
bounded-memory, exception and privacy behavior are unchanged. Compatibility
tests execute the accepted verify-only Sodium Ed25519 adapter against an
immutable P04 Genesis-tagged known-answer vector and negative controls. They
do not generate keys or signatures.

The new adapter is not constructed by product code. There is no DI
registration, runtime selection, profile import or activation, network or UI
entry point, feature flag, signing capability, key or seed input, storage,
billing, wallet, entitlement, MAUI, Windows or Android product change in this
iteration. Native execution and client composition belong to P14A2B2.

Two independent exact-source reviews and a later separate sanitized evidence
carrier remain required before P14A2B1 acceptance. Production signer approval
and external cryptographic profile review remain explicit blockers.
