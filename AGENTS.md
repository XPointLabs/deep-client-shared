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
dotnet test Deep.Client.Shared.slnx
```

Add focused persistence tests under `tests/Deep.Client.Shared.Tests/Persistence` and service or
transport tests under `tests/Deep.Client.Shared.Tests/Services` for the corresponding change.
