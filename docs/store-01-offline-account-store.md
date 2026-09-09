# STORE-01 offline account store

`DeepAccountService`, `IDeepAccountStore` and `IDeepSecureStorage` are the target
offline account boundary. They have no transport, DNS, Registry, certificate or
bootstrap service dependency.

## Current generation

- Store generation: `1` (`SqliteDeepAccountStore`, application ID `DST1`).
- Exact `sqlite_schema` SHA-256 evidence:
  `2213e0a3666600653a13e2a4f5928d5097efb1feb5e9905b33d28fd754f35703`.
- Account generation: `1`.
- Recovery is exactly one verified `DeepRecoveryV1` 24-word phrase.

Account creation is mandatory two-phase. `PrepareCreate(displayName)` performs
only local computation and returns a sealed, single-use, disposable draft; it
does not read or mutate the store or secure storage. The draft reveals its exact
canonical phrase once through a scoped `ReadOnlySpan<byte>` UTF-8 callback.
`CommitPreparedAsync` accepts only `DeepOwnedRecoveryPhraseUtf8`, requires that
exact constant-time confirmation, consumes the draft on its single commit attempt
and never returns the phrase. Wrong/missing confirmation, disposal, or a crash/drop
before commit causes zero mutation. The unsafe one-shot `CreateAsync` does not exist.
Consequently a crash after commit cannot lose a phrase that was never shown: the
user necessarily saw and confirmed it before any mutation.

Restore accepts an owned mutable UTF-8 input and does not return it. The public
portable API neither accepts nor returns a crown-jewel managed `string`; every
owned byte buffer is wiped on disposal. Neither path persists the phrase or exposes
a routine getter. Create commits `ActiveLocal`; restore
commits the same permanent account identity with a newly generated local device
intent in `RestorePendingActivation`.

The protocol-owned `UseCanonicalUtf8` and `VerifyCanonicalUtf8` seams keep this
boundary string-free end to end. STORE neither reflects protocol internals nor
duplicates BIP-39/identity derivation, and every temporary canonical UTF-8 buffer
is wiped by its owning layer after the scoped callback returns. Capability
derivation feeds PBKDF2 from that bounded mutable canonical byte buffer; the
verified 256-bit recovery entropy is disposed immediately after derivation and
before mutation-lock acquisition or any database/secure-storage I/O.

The reveal span is valid only for the callback duration. A UI adapter must render
it without clipboard, logs, accessibility snapshots or ordinary text-model
persistence and must clear its own mutable buffers when the view closes. Android
IME/GPU/accessibility internals cannot offer deterministic erasure; release UI must
document that platform limit and use a dedicated non-editable secure reveal view.

## Receipts, immutable identity and mutation authority

Account, initial device, profile, a 32-byte operation/initial-snapshot receipt and
a separate 32-byte permanent immutable identity commitment are inserted in one
database transaction.

- The initial-snapshot receipt binds every initial field, including mutable
  profile, activation, current-device state, timestamps and secure-slot names. It
  is rehashed only while the pending creation journal proves reconciliation is
  unfinished.
- The permanent immutable commitment is rehashed on every store read and compared
  with both the database value and protected `DSM3` generation manifest. It binds
  network/store generation, permanent Deep ID, account ID/generation/signing key,
  and the initial device ID/generation/revocation handle/signing/agreement/prekey
  public keys and creation time.
- Display name, activation and the future current-device pointer are mutable and
  excluded from the permanent commitment. Generation 1 stores one initial device,
  so `current_device_id` currently equals it. A later schema must move the mutable
  pointer into directory state without changing the genesis-device commitment.

Secure storage keeps fixed `deep.store.v1.database-account-manifest` and transient
`deep.store.v1.pending-account` records. Canonical `DSM3` binds the exact initial
receipt, permanent immutable commitment, exact random MSG-01 store-instance ID
and exact seven-slot inventory. Outcome-
unknown paths preserve the journal and keys. A cleanup failure after a proven DB
commit is best-effort: commit remains successful and the pending journal itself is
the durable retry record.

Store mutations require `DeepAccountReconciledMutationCapability`, which has no
public constructor. The service mints it only after exact journal/manifest,
receipt, immutable commitment and secret reconciliation while holding the exact
store mutation lease. It is bound to the expected operation/commitment and store;
raw leases, foreign, stale and disposed capabilities cannot mutate.

## Secure storage and SQLCipher lifecycle

`OwnedGenesisDeviceSecrets` generates the device signing/agreement secrets, random
device ID and random revocation handle. Creation obtains a separately owned
`ExportOwnedPersistenceCopy`, copies its four exact values into distinct mutable
buffers, writes them to four dedicated protected slots and wipes every buffer after
the atomic write/commit attempt. Prekey, push and MSG-01 store-instance values are
separate independent 32-byte CSPRNG outputs in three additional slots. The exact
store-instance value is manifest-bound and forms the MSG-01 scope together with the
exact account ID and current STORE generation. The SQLCipher key and database instance ID are independent install-scoped
CSPRNG outputs; none is derived from the phrase. Reads return an independently
owned `OwnedDeepSecret`; plaintext is available only inside a callback/copy while
holding its lifetime lock, so `Dispose` cannot race an exposed span. Disposal wipes
its buffer. Platform adapters must journal
batch writes/deletes when their native keystore lacks atomic batches.

`DeepAccountService` is also the only production boundary for routine local
device-key use. Its public surface accepts an exact current public snapshot and
returns only an Ed25519 signature; it does not expose agreement/prekey callbacks,
spans or leases. Future E2EE composition inside this assembly can use internal
generic scoped callbacks. Their byref-like scope cannot cross an async boundary,
and its owned plaintext is wiped on success, cancellation and exception. Every operation holds the account mutation
gate through reconciliation and callback completion, rechecks the exact public
DeviceId, signing/agreement/prekey keys and generation slots, and rejects missing
or mismatched protected values before invoking caller code. These operations do
not define DPK2/DPH2/DTR2 wire bytes and have no SessionId path.

Account slot names are deterministic within one database generation: their scope
is SHA-256 domain-separated from the random database instance ID. The values remain
independent random secrets. Slot derivation and store disposal are serialized by
the same lifetime gate, so callers observe either the exact generation scope or a
consistent `ObjectDisposedException`, never a partially zeroed instance ID.
`IDeepSecureStorage.PurgeStoreV1NamespaceAsync` is the
narrow destruction primitive: atomically and idempotently removes only keys with
the exact `deep.store.v1.` prefix without decoding any value. Full destroy therefore
works even when generation, manifest and pending records are independently missing
or corrupt. Bootstrap also detects orphan deterministic slots when the encrypted
database is absent.

`SqliteDeepAccountStoreBootstrap.OpenAsync` is the only public SQLite construction
path. Its 72-byte protected generation record contains `dbInstanceId32` and key32;
encrypted `store_identity` must contain the same instance ID. The binary key goes
directly to `sqlite3_key` and is never converted to a managed string. Bootstrap
requires SQLCipher 4 and successful `cipher_integrity_check`. Final databases open
as `ReadWrite`; only sibling `<state>.creating` uses `ReadWriteCreate` before an
atomic rename. There are no migrations or legacy readers.

Every open store holds a lifetime shared generation lease. Destruction obtains the
exclusive lease and writes an out-of-namespace reset marker whose presence alone
is authoritative and whose payload is never decoded. It then purges STORE-V1,
deletes DB/WAL/SHM and `.creating`/WAL/SHM, and deletes the marker last. Missing or
corrupt generation, legacy `DST3`, manifest and pending values cannot block cleanup;
the operation is restart-safe and idempotent. Account-only reset preserves the
encrypted empty database and install-scoped key.

Hostile values, impossible timestamps, storage-class errors, schema drift and
SQLite corruption discovered during reads or after a reconciled mutation starts
are normalized to `LocalStateResetRequiredException`.

Display names must be well-formed UTF-16, canonical NFC, 1..128 UTF-16 code units
and at most 256 exact UTF-8 bytes. Control, format/bidi, line/paragraph-separator
and surrogate categories reject before a receipt or mutation is created. SQLite
duplicates both the code-unit and UTF-8 byte bounds as clean-break constraints.

The schema reserves independent protected-LKG, outbox, inbox and security-event
roots for later packages.

## ID-01 composition

STORE-01 stores permanent DID1 separately from network-scoped `DeepAccountId32`.
New and restored devices use protocol-owned `LocalDeviceIdentityIntent`, which
binds generation 1, independent random `DeviceId32`, random revocation handle and
role-typed signing/agreement keys. The prekey is independently role-typed and the
creation commitments bind its exact public value to the initial device; STORE keeps
that public value as non-authoritative bytes and never invokes a protocol raw factory.

SQLite never reconstructs a device intent from public columns and STORE never calls
raw identity factories. On each startup/reconciliation the service reads the four
protected identity slots into four distinct owned arrays, transfers them to
`OwnedPersistedDeviceIdentitySecrets.TakeOwnership`, consumes that object through
`OwnedGenesisDeviceSecrets.RestoreFromPersistedOwnedSecrets`, and finally calls
`CreateLocalIntent(accountIdentity)`. The encrypted public columns are then only
exact-match evidence for that restored non-authoritative intent. The prekey and push
slots are independently verified. Every temporary array and owned wrapper is wiped
on success and failure.

This is only a local device intent. It is not DPD1, not DXR1, not directory activation
and grants no remote authority. STORE cannot fabricate either artifact or convert an
intent into authority. Exact DPD1/DXR1 authoring remains the separate ID-01
blocker. On every local identity load, Ed25519 and both X25519 public keys are
rederived from owned secure values and compared in constant time.

## Deferred composition and external evidence

`JournaledDeepSecureStorage` now provides the portable binary aggregate used by
platform composition. It serializes a bounded, strictly ordered `DSS1` map,
protects the complete mutable buffer through `IDeepSecretProtector`, and commits
one same-directory replacement while holding both an in-process gate and a
cross-process file lease. A `.pending` file is never promoted after restart and
an old backup is never a recovery source, because either action could resurrect
deleted key material. The focused portable suite covers authenticated tamper
rejection, duplicate-write atomicity, namespace-scoped purge and concurrent
independent store instances.

The MAUI platform layer contains Android Keystore AES-256-GCM and Windows
CurrentUser DPAPI protectors. They do not convert protected values to managed
strings. This is implementation evidence only: release composition has not yet
wired this adapter into onboarding, and Android process-kill/Windows child-process
crash evidence remains mandatory before the platform gate can close.

The existing Session account/runtime consumers remain pre-cutover and are not used
by STORE-01. They are removed later with E2EE/MSG/DEVICE composition.

The shared package does not claim child-process or Android-keystore evidence.
Release composition must add child-process lifetime/mutation-lock tests on every
supported desktop OS and physical-Android crash injection for the real secure-
storage adapter's atomic journal, owned reads and zeroization. Same-process and
in-memory tests are not substitutes for those artifacts.
