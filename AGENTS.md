# Agent Specification - Deep Client Shared

Last updated: 2026-06-10.

## Mission

`deep-client-shared` is the portable runtime for Deep clients. It owns domain models, service orchestration, local persistence, transport interfaces, feature flags, and platform service boundaries used by MAUI and future clients.

The repo must preserve Session-compatible client semantics while allowing Deep to evolve cleanly. UI code does not belong here.

## Source Of Truth

- Workspace entry point: `../prompts/00_Agent_Entry_Point.md`.
- Architecture doc: `docs/ARCHITECTURE.md`.
- Porting rules: `docs/SESSION_PORTING.md`.
- MAUI consumer contract: `../deep-client-maui/AGENTS.md`.
- Protocol contract: `../deep-protocol/AGENTS.md`.

When source and docs disagree, update tests and docs in the same change that fixes behavior.

## Ownership Boundaries

Owned here:

- `Domain`: accounts, identifiers, conversations, contacts, groups, messages, attachments.
- `Services`: account lifecycle, message send/receive, sync, notification planning, avatar/profile, push subscription, call signaling orchestration.
- `Persistence`: repository contracts, in-memory store, SQLite store, and the current local-state schema.
- `Platform`: interfaces for permissions, media, background tasks, share extension bridges, push, notification scheduling, and calls.
- `Features`: release/debug feature flags and invariants.

Not owned here:

- XAML, app shell, platform-specific file pickers, app lifecycle, and visual layout.
- Wire codec/protobuf/crypto implementation details, except through consumed interfaces.
- External service deployment or compatibility fixtures.

## Runtime Rules

- Domain behavior must be deterministic, testable, and free of MAUI dependencies.
- Release runtime must not depend on `StubSessionBackend`; stubs are test/dev-only.
- Public APIs should accept cancellation tokens and avoid hiding transport/persistence failures.
- Before production launch, persistence changes are clean breaks: keep only the
  current schema, reject older/incompatible state with an explicit wipe/reset
  requirement, and do not add dual-read or automatic migration unless Mr. X
  explicitly requests it.
- Legacy JSON/in-memory snapshots are not a supported runtime import format.
- Feature flags must fail closed for release: if a release feature needs real infrastructure, missing configuration should be visible.
- Do not log recovery phrases, private keys, Session IDs paired with sensitive payloads, attachment contents, or push tokens.

## New Deep Solution Rules

New behavior belongs here when it is portable across clients or forms part of the domain/runtime contract. Prefer small service boundaries over MAUI-specific shortcuts. Every new service should have:

- domain model or DTO contract,
- repository or transport abstraction if state/networked,
- in-memory or fake implementation for tests,
- production implementation or explicit release guard,
- focused unit tests for success, retry/idempotency, and failure semantics.

## Session Parity Rules

Before porting Session behavior, identify whether it is:

- protocol/wire: belongs in `deep-protocol`,
- runtime/domain: belongs here,
- UX/platform: belongs in `deep-client-maui`,
- backend service contract: belongs in service/devops/e2e repos.

Shared runtime parity must be proven with tests that do not require MAUI.

## Required Verification

```powershell
dotnet test Deep.Client.Shared.slnx
```

For persistence changes, add targeted tests under `tests/Deep.Client.Shared.Tests/Persistence`.
For transport changes, add tests under `tests/Deep.Client.Shared.Tests/Services`.

## Acceptance Gates

A change is complete only when:

- all touched domain/service behavior is covered by tests,
- SQLite and in-memory stores remain behaviorally aligned,
- release feature flags preserve `TransportRequired => !StubTransportAllowed`,
- public contracts are documented in README or architecture docs if they change,
- consumers in `deep-client-maui` can keep using the API without platform leakage.

## Stop-The-Line Conditions

Stop and fix or document a blocker if:

- a release path can silently use stub transport,
- a compatibility fallback or stale-schema path can silently weaken current
  privacy, durability, or fail-closed behavior,
- Session compatibility is guessed without upstream reference or tests,
- sensitive identity/push/attachment material can leak through logs,
- a service API becomes MAUI-specific.

## Agent Workflow

1. Read this file and `docs/SESSION_PORTING.md`.
2. Locate the matching tests before editing runtime code.
3. Add failing tests for changed behavior.
4. Implement in domain/services/persistence with minimal public-surface churn.
5. Run `dotnet test Deep.Client.Shared.slnx`.
6. Update docs when contracts, environment expectations, or supported parity change.
