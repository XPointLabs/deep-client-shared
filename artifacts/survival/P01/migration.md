# Migration assessment

P01 performs no schema, persistence or wire migration.

Future P03 migration constraints:

- version opaque capabilities explicitly;
- support bounded legacy reads only under an explicit migration profile;
- do not silently fall back from strict opaque mode to raw Session-ID addressing;
- rotate push handles with a finite overlap window and durable unregister retry;
- preserve logout/account-switch deletion semantics;
- provide rollback that disables new writes without deleting legacy or new-format state;
- expose telemetry only as aggregate counters without raw identifiers or capabilities.

Mr. X must approve any legacy compatibility window and the point at which strict metadata gates become release-blocking in CI.
