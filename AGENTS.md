# Deep Client Shared agent rules

The workspace rules in `../AGENTS.md` apply. This file contains only shared-runtime deltas.

## Owns

- Portable accounts, conversations, contacts, groups, messages, attachments and calls.
- Service orchestration, durable outbox/inbox, synchronization and notification planning.
- SQLCipher persistence, current schema and in-memory stores used by tests.
- Transport, media, push, background-task and platform-service interfaces.

MAUI views/platform implementations belong in `deep-client-maui`; wire formats and crypto
primitives belong in `deep-protocol`; deployed service behavior belongs in service repos.

## Repository rules

- Keep this assembly MAUI-free and deterministic; public async APIs accept cancellation tokens.
- Persistence is a pre-production clean break: support only the current schema and explicit reset.
  Do not add migrations, dual readers or JSON snapshot import paths.
- SQLite and in-memory repositories must remain behaviorally aligned.
- Durable send/ACK state must be monotonic, idempotent and recover correctly after restart/crash.
- Public HTTPS uses platform trust. UAT may add an explicit local CA; never add permissive TLS
  callbacks or leaf-SPKI pins for CA-managed endpoints.
- Transport, signatures, E2EE and integrity checks fail closed and remain independently enforced.
- Document changed public contracts, schema generation or required configuration.

## Verify

```powershell
dotnet test Deep.Client.Shared.Production.slnx --configuration Release -m:1
```

The old `Deep.Client.Shared.slnx` test project is a pre-cutover Session corpus;
it is not the clean production gate. Do not restore removed runtime types to
make those tests compile. Move relevant coverage into
`tests/Deep.Client.Shared.Production.Tests` before deleting the old corpus.

Add focused persistence, service and transport tests to the production test
project for the corresponding change.

The production test framework runs at most two independent methods of
`DeepIdV2ContactPathAuthoritySourceTests` concurrently. Each owns its account,
SQL files, protected storage and fault-hook context; theory rows stay in the
standard xUnit method runner. Other classes keep ordinary xUnit collection
isolation. To reproduce a serial run, append `-- xUnit.MaxParallelThreads=1`
to the same test command. Never overlap this gate with another heavy gate.

`eng/Test-ProductionTestResults.ps1` validates a captured native exit and exact
TRX result/definition/execution mappings against the predeclared prior-full
plus new-focused case union. It works in Windows PowerShell 5.1 and PowerShell 7.
Run `eng/Test-ProductionTestResultsContracts.ps1` when changing that verifier.
Mapping validation does not replace immutable input checks or a terminal exit.
