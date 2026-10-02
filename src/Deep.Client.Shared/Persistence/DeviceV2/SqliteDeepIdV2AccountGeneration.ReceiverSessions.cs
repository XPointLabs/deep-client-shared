using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal static async Task VerifyReceiverMessagingSourceUnderLeaseAsync(IDeepSecureStorage storage,
        string statePath, VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, bool requireRetired, CancellationToken ct)
    {
        var opened = await OpenPreKeyStoreAsync(storage, statePath, current, allowInitialize: false, ct).ConfigureAwait(false);
        await using var store = opened.Store;
        try { await store.VerifyMessagingSourceUnderLeaseAsync(scope, requireRetired, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(opened.ScopeHash); }
    }
    internal static async Task<Did2InitialKeyRetirementReceipt> RetireReceiverUnderLeaseAsync(IDeepSecureStorage storage,
        string statePath, VerifiedDeepIdV2CurrentAccount current, Did2InitialStateTransfer transfer, CancellationToken ct)
    {
        var opened = await OpenPreKeyStoreAsync(storage, statePath, current, allowInitialize: false, ct).ConfigureAwait(false);
        await using var store = opened.Store;
        try { return await store.RetireInitialKeysUnderLeaseAsync(transfer, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(opened.ScopeHash); }
    }

    internal static async ValueTask ReconcilePendingReceiverUnderLeaseAsync(IDeepSecureStorage storage,
        string statePath, VerifiedDeepIdV2CurrentAccount current, CancellationToken ct)
    {
        using var checkpoint = await storage.ReadOwnedAsync(ResponderInitialSessionCheckpoint.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("The protected receiver checkpoint is missing.");
        // EnsureAsync has already authenticated shape/scope. No inventory is
        // needed for empty/stable profile reads; its protected chain is checked
        // on every PKV2 open before inventory/private-key/history release.
        if (checkpoint.Use(static exact => exact[1]) != 2) return;
        var opened = await OpenPreKeyStoreAsync(storage, statePath, current, allowInitialize: false, ct).ConfigureAwait(false);
        await using var store = opened.Store;
        CryptographicOperations.ZeroMemory(opened.ScopeHash);
    }

    internal static async ValueTask<DeepIdV2InitialContactSessionCommit?> FindReceiverUnderLeaseAsync(
        IDeepSecureStorage storage, string statePath, VerifiedDeepIdV2CurrentAccount current, Dph2Record incoming, CancellationToken ct)
    {
        // Check absence without opening SQLCipher twice. The single open below
        // still verifies both protected inventory tip and receiver checkpoint.
        using var installed = await storage.ReadOwnedAsync(PreKeyInstallMarkerSlot, ct).ConfigureAwait(false);
        if (installed is null)
        {
            if (PreKeyFileFamilyExists(PreKeyStatePath(statePath)))
                throw new InvalidDataException("DID2 pre-key state exists without its protected marker.");
            return null;
        }
        var opened = await OpenPreKeyStoreAsync(storage, statePath, current, allowInitialize: false, ct).ConfigureAwait(false);
        await using var store = opened.Store;
        try { return await store.FindExactReceiverSessionAsync(incoming, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(opened.ScopeHash); }
    }

    internal static async ValueTask<DeepIdV2InitialContactSessionCommit> CommitReceiverUnderLeaseAsync(
        IDeepSecureStorage storage, string statePath, VerifiedDeepIdV2CurrentAccount current, VerifiedDph2InitialClaim claim,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, VerifiedDeepIdV2DirectoryFreshness initiator,
        OnionMonotonicReading reading, OnionTrustedTimeAuthority time, int maximumMessagesWithoutPqInjection, CancellationToken ct)
    {
        var opened = await OpenPreKeyStoreAsync(storage, statePath, current, allowInitialize: false, ct).ConfigureAwait(false);
        await using var store = opened.Store;
        try
        {
            var incoming = Dph2Codec.Decode(claim.Initiation.ExactBytes.Span);
            var prior = await store.FindExactReceiverSessionAsync(incoming, ct).ConfigureAwait(false);
            if (prior is not null)
            {
                if (!DeepIdV2InitialContactSessionCommit.Fixed(prior.ExactClaimReplayHashSpan, claim.Claim.ExactReplayHash.Span))
                { prior.Dispose(); throw new CryptographicException("Retained receiver claim replay was substituted."); }
                return prior; // Never restores or reuses a spent prekey.
            }
            var restored = await store.ReadRestoredInitialSecretsAsync(incoming, fresh.Proof, reading, ct).ConfigureAwait(false);
            using var secrets = restored.Secrets;
            using var prepared = await current.Verified.DeviceSecrets.PrepareInitialSessionAsync(claim, fresh.Proof,
                initiator, secrets, time, maximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
            var completed = DeepIdV2InitialContactSessionCommit.Capture(prepared, claim, fresh.Proof.CurrentCheckpoint!.Directory.Record);
            try { await store.CommitReceiverSessionAsync(completed, ct).ConfigureAwait(false); return completed; }
            catch { completed.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(opened.ScopeHash); }
    }
}
