# P14A2 dormant staged-profile verifier

Status: `DORMANT-CLIENT-VERIFIER-GO / STAGED-BYTES-ONLY / ACTIVATION-RUNTIME-DI-NETWORK-UI-BILLING-NO-GO`.

The manually constructed verification service exports exactly one defensive
snapshot from the accepted P14A1 staging boundary and verifies it in memory
through the exact accepted `Deep.Protocol.ProfileCarrier` package. Verification
time, clock skew and protocol are explicit inputs. No clock or production
verifier policy is selected here.

Null account scope, candidate ID, or parameter objects follow the existing staging
API contract and throw `ArgumentNullException`; valid objects with unsupported
verification values return the fixed `InvalidRequest` status.

The result contains only a fixed status and bounded fingerprint, protocol and
component-count metadata. It never exposes or persists carrier bytes, candidate
or account handles, signatures, signer or network identifiers, contacts or
endpoints. The temporary exported byte copy is zeroed after the operation.

Verification does not write, delete, relabel, select, activate, connect, import
or translate a profile. A successful result describes only the exported
snapshot: a concurrent delete or account purge can complete while the bounded
in-memory verification finishes. Future activation must export and re-verify
the exact bytes again inside an approved generation-barrier/CAS transaction.

There is deliberately no runtime registration, dependency injection, feature
flag, network, UI, logging, analytics, billing, wallet, entitlement or
subscription integration. Production signature-verifier and time-policy
approval, atomic full-profile activation and independent security review remain
mandatory blockers.
