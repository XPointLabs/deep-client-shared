# S00 account-owned one-time contact custody — 2026-10-04

Connected local source candidate under DR82/91; not shipping, installed client,
platform secure-store qualification or physical E2E. The root RC pins the exact
source matrix. Base Protocol `de091f1c87088636f5548fc21e219d28ef0732e6`, Shared
`59eba8b7ddfd9090a99df51021c72e02b5da394c`; only these two child sources change.
Node remains `16a2c4c474daa55f33a7dd55140f9769fd5f86bb`, Registry remains
`1f20f973a57378b78b536a84711a85a39a6341e6`. No vendor/lock/native asset, public
wire, threshold envelope, topology, production identity or deployment changes.

## Connected scope

The exact local-format/API target is
[DR-0091](../../../docs/survival-program/decisions/DR-0091-did2-owned-one-time-custody.md).
Typed internal service methods now use the existing account lease, protected
single journal and publication machinery. Retained genesis requires authenticated
issuance and current authority. Own exact DIA1/ciphertext before callbacks;
independent CAS read-back precedes further work. On resume authenticate exact
AEAD and current route/identity, not a regenerated key or nonce. Reusable paths
reject kind2, including renewal. Missing/incompatible current state fails closed,
without compatibility reader or automatic reset. Internal object copies are
disposable; no public shipping invitation/QR export method is added.

The five owner scenarios exercise interruption/reopen through phases1–7,
directory-head advancement after adoption, corrupt threshold response,
lost replica response, foreign commit receipt, exact cached commit without
callbacks, AEAD/key tampering, mixed/unknown kind, retired local version,
hostile framing/reserved bytes, changed profile and reusable cross-feed.
Independent intents have distinct locators. Capacity rejects the third pending
intent before threshold invocation and leaves protected bytes unchanged.
Read-back faults at proposal and secret adoption return no object; retry adopts
the original protected secret. Pre-cancellation invokes no new threshold.
Secret assertions never emit invitation/key bytes into TRX.

Coordination and replica replies in these Shared tests are in-process fixtures
with real witness/node signatures; they are not deployed Registry/PostgreSQL or
opaque-node storage evidence. The separate Node selection exercises current
one-time and connected contact implementations, including the existing TLS/H2
lane; it does not create a Shared→deployed Registry→Node device scenario.

## Commands and results

```powershell
dotnet build Deep.Client.Shared.Production.slnx -c Release -m:1 --no-restore -warnaserror
dotnet test tests/Deep.Client.Shared.Production.Tests/Deep.Client.Shared.Production.Tests.csproj -c Release -m:1 --no-build --no-restore --filter "FullyQualifiedName~Did2OwnedOneTime" --logger trx --results-directory artifacts/s00-one-time-custody/final-five
dotnet test Deep.Client.Shared.Production.slnx -c Release -m:1 --no-build --no-restore --logger trx --results-directory artifacts/s00-one-time-custody/full
# Protocol repository
dotnet restore Deep.Protocol.slnx
dotnet build Deep.Protocol.slnx --no-restore -warnaserror
dotnet test Deep.Protocol.slnx --no-build --no-restore --logger trx --results-directory artifacts/s00-one-time-custody/full
./eng/Test-ProductionProtocolGraph.ps1 -Configuration Debug
./eng/Test-Dnp1EvidenceOwnership.ps1
# Node repository: current source dependency, unchanged Node code
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -p:DeepProtocolSourceCutover=true --no-restore --filter "FullyQualifiedName~Did2ContactServiceCompositionTests|FullyQualifiedName~OneTime" --logger trx --results-directory artifacts/s00-one-time-custody/downstream-focused
```

Final Shared source warnings-as-errors build terminal0, zero warnings/errors.
Final owned selection **5/5**, terminal0/no skips; downstream Node **94/94**,
terminal0/no skips. Full Shared is **pending**, not the old547 result.
Full Protocol terminal1: **2080 pass /1 fail /12 skips**, including the new
closed API surface test. The sole failure remains the actual package witness
rejecting retired MCG2 assembly bytes; source production graph still rejects
MAU2 in the retired PMA1 consumer. Neither gate is excluded or weakened.
Protocol restore/build terminal0 and zero-warning build. Evidence ownership
classifies exact314/package219/final95 but maps0, so it is not package-complete.
The twelve Protocol skips are unchanged explicit separate-evidence lanes:
six native wrapper cases require their dedicated Windows harness, five managed
Braid cases lack the reviewed native candidate, and one authenticated predecessor
capture case lacks explicit operator inputs. They are not passed tests or
production crypto/device evidence; this contact slice does not provision those
inputs or enable native assets.
Root documentation174, CONTACT/crypto/ONION consistency and governance
ClassificationOnly pass, without package or final release claims.
Final scoped scan passes27 selected source/docs/TRX files; strict UTF-8 checks
pass8 changed Markdown files and263 existing local Markdown paths. These counts
cover documentation and secret hygiene, not release qualification.

Earlier focused attempts found only test expectation/build harness issues:
wrong namespace and span crossing an await in the new test; exact format versus
crypto exception types for hostile stored framing; an existing reusable fixture
flipped the newly empty LP trailer instead of the retained issuance signature.
The fixture now flips the actual signature, preserving its original invariant.
One overlapping attempted test build hit the running test DLL's Windows file
lock; it failed terminal1, not a product gate. Final source was rebuilt only after
that original handle completed; both builds and final selection above are clean.

Sanitized ignored evidence SHA256:

- Shared5 `artifacts/s00-one-time-custody/final-five/nikit_SURFACE-LT_2026-10-04_14_11_32_net10.0.trx`:
  `f329c8e4cdb4aa613d3d4fbb708a3d649810ca7e9ce7c2685e9ab8e0e29e151d`.
- Protocol routes131 `../deep-protocol/artifacts/s00-one-time-custody/full/nikit_SURFACE-LT_2026-10-04_14_11_22_net10.0.trx`:
  `47b08d0a2f537af613f63acc63749e3ea67cc8f63f89fb0401685905558c65b0`.
- Protocol carrier105 `../deep-protocol/artifacts/s00-one-time-custody/full/nikit_SURFACE-LT_2026-10-04_14_11_22_net10.0[1].trx`:
  `f3bd396e5f6459f00afa118fc11a103f7ad39581e0ff13cf130b5a3b32181d50`.
- Protocol core1844/1/12 `../deep-protocol/artifacts/s00-one-time-custody/full/nikit_SURFACE-LT_2026-10-04_14_11_22_net10.0[2].trx`:
  `082df1f4d00f1bcbad5caa7d973802b8d133dfe73550ea04dc2e6ef0b4fc9070`.
- Node94 `../xnode/artifacts/s00-one-time-custody/downstream-focused/nikit_SURFACE-LT_2026-10-04_14_15_40_net10.0.trx`:
  `adc0c3d6b11452710c1938f624863512d67029836d9b68d22edd34c8ea89e3ec`.

## Open work

Follow only root NEXT-SPRINT/IMPLEMENTATION-PLAN. Public account-owned invitation
operation/export and installed reset/provision/package closure remain gated;
incomplete short request/XPA reconciliation remains S01/S04, not remint or longer
old signatures. Current whole-host startup/health/DI, retained-route lifecycle,
shipping client messaging composition and physical contacts/messages/files/groups
remain required. This local checkpoint closes neither full B8 nor the release.
