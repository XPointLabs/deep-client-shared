# P11A preflight

- Human owner: Mr. X
- Repository: `deep-client-shared`
- Worktree: `C:\W\deep-survival\wave03\deep-client-shared-p11a`
- Branch: `survival/w03-p11a-outbox`
- Exact accepted base: `13e39cf9ff4b0cf3b1c60084aa5af977db68f280`
- Started: 2026-07-19

## Required inputs read in full

- `AGENTS.md`
- `docs/SESSION_PORTING.md`
- `docs/ARCHITECTURE.md`
- `C:\Work\DeepSession\docs\resilient-network-program\agent-prompts\P11A-persistent-outbox.md`

## Scope controls

This slice owns only the portable outbox contract, its in-memory and SQLite
repositories, the SQLite v7-to-v8 physical migration, tests, and evidence.
It does not wire a runtime transport, choose a bridge, implement mailbox
receipt verification, touch `RoutedSessionTransport`, add UI or billing, run
Docker, use keys, access a live network, or push Git state.

## Initial status

`preflight-complete; implementation-not-started`
