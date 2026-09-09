# ContactV1 resolve-operation journal

Normative wire, placement, retry and privacy semantics are owned by
[`../../docs/architecture/CONTACT-RESOLVER-V1.md`](../../docs/architecture/CONTACT-RESOLVER-V1.md).
This file records only the `deep-client-shared` persistence/API mapping.

`SqliteContactStateStore` schema generation 4 and `InMemoryContactStateStore`
implement the same account-scoped resolve-operation state machine. Before the
first transport dispatch, the store commits the immutable canonical XIQ1 bytes,
request/operation identity, relationship identity and imported-address identity.
Every ambiguous retry and process-restart resume sends the stored XIQ1 bytes;
the request is never reconstructed from current time or current network state.
Each coordinator transition performs exactly one transport attempt, then persists
its classification before a scheduler or caller may request the next attempt.

The durable states are prepared, retry-pending, awaiting-refreshed-context,
terminal, relationship-linked and fail-closed. Valid XIS1 bytes plus their closed
UI/retry classification are retained. A successful resolver verification creates
the relationship and its verified-peer recovery package atomically with the same
operation ID before the resolve journal is marked relationship-linked. The package
contains only bounded exact bytes and hashes: canonical address, XIQ1/XIS1, DCR1,
DCB1, DMD1, the ordered DPD1 device set and the six-record route closure. Its
versioned package hash also binds the local store scope, network, local/remote
accounts, relationship and conversation. A crash in that interval therefore
converges through the existing relationship operation journal on the next exact
replay without exposing a partially linked package.

`IContactStateStore.ReadVerifiedPeerPackageAsync` returns defensive copies of
those bytes as `ContactVerifiedPeerPackageEvidence`. This type is deliberately
not a Protocol capability and has no public constructor. After restart, identity,
directory, route or messaging authority must be minted again by the trusted
ContactV1 verifier from the exact transcript and current path authority. Stored
CLR capability objects and caller-authored trust flags are not supported.
`ContactResolverTrustedVerifier.ReverifyAsync` is the public recovery boundary:
it reconstructs the exact address/XIQ1/XIS1 transcript, reacquires current path
authority, reruns Contact bundle, directory, placement, route and claim-receipt
verification, and checks that the rebuilt package hash is byte-identical before
returning `ContactResolverReverifiedPeerAuthority`. DPK2/DPH2 orchestration must
consume that fresh authority object, never the persisted evidence directly.

The journal is bounded to 10,000 operations per account and 16 operations per
logical relationship. Operation-ID/body drift, relationship/address rebinding,
uncorrelated XIS1 and invalid persisted transitions fail closed.

`VerifiedContactResolverPlacementContext` has no public constructor or public
minting method. Its internal authority boundary is intentionally left without a
production implementation until CONTACT-CODEC supplies the protocol-owned,
non-forgeable verified XNV/PMT service-placement capability. This prevents MAUI,
configuration, Registry responses or callers from authoring raw view/placement
hashes. Resume of an already durable exact operation does not require that
capability; replacement after a definitive StaleView does, and always creates a
new operation ID.
