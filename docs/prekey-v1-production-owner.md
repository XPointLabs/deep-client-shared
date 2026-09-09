# PreKeyV1 production owner

`ProductionPreKeyV1InventoryOwner` is the account/device-wide owner for DPK2
publication and responder claim material. It is internal to the shared runtime;
no public API accepts private keys, crypto providers, delegates, `SessionId`, or
caller-supplied trust flags.

## Authoring and publication

1. `ProductionPreKeyV1InventoryOwner.CreateAsync` asks `DeepAccountService` to
   restore the current device secrets and create Protocol's
   `Dpk2AuthoringAuthority` for one `VerifiedDeviceRelative`.
2. `EnsureInventoryAsync` creates 32..4096 one-time DPK2 offerings and exactly
   one last-resort offering (reuse limit 1..64) under one current unforked DMD1,
   service generation, inventory epoch, and validity interval.
3. Offerings are sorted by one-time pre-key ID. Protocol computes the XPI1
   Merkle root, the current device signs the exact XPI1 signing projection, and
   Protocol emits canonical XPI1 and XPP1.
4. `AuthoredDpk2Offering.TakeSecretCapability()` is consumed exactly once by
   the first-party SQLCipher owner. Signed X25519, optional one-time X25519, and
   ML-KEM private material are inserted in the same transaction as exact XPI1
   and XPP1. The caller receives only defensive copies of the durable exact
   publication request.

An ambiguous crash after commit is recovered by `ReadPublicationAsync(epoch)`;
the exact stored XPP1 is resent. A crash before commit leaves neither publication
nor private material. Epoch rollback, conflicting replay, predecessor mismatch,
or service-generation rollback permanently latches the store closed.

## Claim binding

`ContactInitialSessionCoordinator` accepts only Protocol-verified XPC1 and DPH2
capabilities. The XPC1-derived exact DPK2 hash and pre-key IDs select one durable
row. The store callback supplies the matching signed X25519, optional one-time
X25519, and ML-KEM secrets. `DeepAccountService` contributes the current device
agreement secret through a short-lived internal lease; Protocol then creates the
exact TRS1. All callback buffers and leases are zeroized.

## Schema and activation

PreKeyV1 is clean-break SQLCipher schema generation 3. Generation 2 databases
must be deleted and recreated; there is no migration or dual reader. DPD1 uses
the canonical application reference (`DPD1`, version 1, exact hash).

The default owner remains `DormantPreKeyV1InventoryOwner`. Production activation
must explicitly provide a verified current device/DMD1 and an approved native
ML-KEM asset. Missing or unapproved ML-KEM remains fail-closed.

## Exact remaining caller wiring

The MAUI account runtime already owns `SqlitePreKeyV1SecretOwner`; no second or
per-conversation pre-key database is required. The remaining composition is:

1. Change MAUI's `DeepDirectMessagingStorageOwner.CreateDpd1Reference` caller
   input to the canonical 38-byte application reference (`DPD1`, big-endian
   version 1, exact DPD1 hash). Its current `ArtifactType.Dpd1` prefix is the
   retired clean-break representation and will be rejected by schema generation
   3. This owner task intentionally does not edit MAUI.
2. After account unlock and current DMD1 verification, pass that same
   `DeepLocalIdentitySnapshot` and its `VerifiedDeviceRelative` to
   `ProductionPreKeyV1InventoryOwner.CreateAsync(preKeyOwner, accountService,
   localIdentity, verifiedDevice)`. If verified DMD1 or the approved ML-KEM
   asset is absent, retain `DormantPreKeyV1InventoryOwner.Instance` and do not
   publish.
3. Build one `PreKeyV1InventoryAuthoringContext` from the same current
   `Dmd1LineageState`, plus service capability/generation, XPS1 and current DRS1
   references, next inventory epoch, current durable XPI1 predecessor hash,
   publication operation ID, placement hash, validity window, inventory count,
   and last-resort reuse limit. Call `EnsureInventoryAsync` once and send only
   `result.Publication.ExactPublicationRequest` (the exact durable XPP1).
4. Route that XPP1 through the privacy-routed Contact publication endpoint.
   Persist and verify XIC1 before advancing scheduling state; on ambiguous send,
   call `ReadPublicationAsync(epoch)` and resend those exact bytes.
5. Schedule bounded replenishment before expiry or one-time depletion. The
   scheduler must derive the next epoch and predecessor from
   `ReadLatestPublicationAsync`, never from volatile UI state.
6. Initiator path: verify the selected published DPK2 with
   `MessagingWireVerification.VerifyDpk2`; authorize and open one
   `LocalDeviceX25519AgreementLease` for `Dph2InitiatorDh1`; call
   `ManagedInitiatorInitialSessionFactory.PrepareClaim`; encode/send XPK1 using
   its operation ID and sender commitment; verify XPC1 with
   `Xpc1PreKeyClaimReceiptVerifier.VerifyAsync`; call preparation `Complete`;
   then create `InitiatorInitialSessionVerifiedScope.FromReverifiedPeer` and
   pass the opaque result to `ManagedInitiatorInitialSessionSqliteAdapter.CommitAsync`.
   The production adapter that restores/authorizes the agreement authority and
   drives these calls is not wired yet.
7. Responder path: verify DPH2 with `MessagingWireVerification.VerifyDph2`, then
   pass Protocol-verified `VerifiedXpc1PreKeyClaimReceipt` and
   `VerifiedDph2Initiation` with the matching verified contact evidence into
   `ContactInitialSessionCoordinator.CommitAsync`. No production caller invokes
   this coordinator yet.
