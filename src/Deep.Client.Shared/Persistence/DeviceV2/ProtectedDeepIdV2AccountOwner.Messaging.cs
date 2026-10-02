using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Client.Shared.Persistence.MessagingV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<Did2MessagingSessionScope?> FindIncomingMessagingScopeAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Dpe2Record incoming, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(incoming);
        if (!Did2MessagingSessionScope.Fixed(incoming.NetworkId.Span, networkId))
            throw new CryptographicException("Incoming DPE2 belongs to another network.");
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        var ownDevice = current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate.DeviceId;
        if (!Did2MessagingSessionScope.Fixed(incoming.RecipientDeviceId.Span, ownDevice.Span))
            throw new CryptographicException("Incoming DPE2 belongs to another owned device.");
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            var catalog = new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance);
            using var registered = await catalog.ReadAsync(ct).ConfigureAwait(false);
            var scope = registered.FindIncoming(incoming.NetworkId.Span, incoming.SessionId.Span,
                incoming.SenderDeviceId.Span, incoming.RecipientDeviceId.Span);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return scope;
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    internal async Task<ParsedDid2> ReadMessagingPeerCredentialAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        var catalog = new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance);
        var peer = await catalog.ReadPeerCredentialAsync(scope, ct).ConfigureAwait(false);
        held.RequireActive(); ct.ThrowIfCancellationRequested(); return peer;
    }

    // Returns key-free metadata only. No caller-owned source/TRS, arbitrary
    // callback, SQL path or registration can authorize this transfer.
    internal async Task<Did2MessagingSessionScope> EnsureSenderMessagingAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent,
        ReadOnlyMemory<byte> exactInit, ReadOnlyMemory<byte> exactHello,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(intent.Span);
        if (exactInit.IsEmpty || exactHello.IsEmpty || exactInit.Length > 32768 || exactHello.Length > 32768)
            throw new InvalidDataException("Owned messaging initial events exceed their closed bounds.");
        var ownedIntent = intent.ToArray(); var initial = exactInit.ToArray(); var hello = exactHello.ToArray();
        OwnedInitialMessagingSeed? seed = null;
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
            var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
            using var sourceStore = await SqliteDeepIdV2AccountGeneration.OpenExistingMessagingSenderSourceUnderLeaseAsync(
                storage, sqlStatePath, current, ct).ConfigureAwait(false);
            using var retained = await sourceStore.ReadMessagingSourceByIntentUnderLeaseAsync(ownedIntent, ct).ConfigureAwait(false);
            _ = retained.RequireInitialConversation(initial, hello);
            var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
                storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            var catalog = new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance);
            Did2MessagingSessionScope? scope;
            using (var registered = await catalog.ReadAsync(ct).ConfigureAwait(false))
                scope = registered.FindSource(retained.SessionId.Span, SHA256.HashData(retained.CanonicalSpan));
            if (scope is null)
            {
                seed = await OwnedInitialMessagingSeed.FromSenderAsync(retained, initial, hello, instance, own, peer, source, held, ct).ConfigureAwait(false);
                scope = await catalog.RegisterAsync(seed, ct).ConfigureAwait(false);
            }
            Did2MessagingSourceScope.RequireSender(scope, retained);
            ProtectedDid2MessagingPeerBootstrap.RequireProof(await catalog.ReadPeerCredentialAsync(scope, ct).ConfigureAwait(false), peer);
            OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(
                storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (floor.Ordinal == 0)
            {
                seed ??= await OwnedInitialMessagingSeed.FromSenderAsync(retained, initial, hello, instance, own, peer, source, held, ct).ConfigureAwait(false);
                using var import = OwnedDid2MessagingMutation.Import(seed, floor);
                _ = await opened.Custody.CommitOwnedAsync(import, ct).ConfigureAwait(false);
            }
            seed?.Dispose(); seed = null; retained.Dispose(); sourceStore.Dispose();
            await CompleteMessagingTransferUnderLeaseAsync(current, opened, ct).ConfigureAwait(false);
            await MaterializeInitialMessagingUnderLeaseAsync(current, opened, own, peer, source, held, ct).ConfigureAwait(false);
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            return scope;
        }
        finally
        {
            seed?.Dispose(); CryptographicOperations.ZeroMemory(initial); CryptographicOperations.ZeroMemory(hello);
        }
    }

    internal async Task<Did2MessagingSessionScope> EnsureReceiverMessagingAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> exactDph2,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        if (exactDph2.IsEmpty || exactDph2.Length > 65536)
            throw new InvalidDataException("Owned messaging initiation exceeds its closed bound.");
        var incoming = Dph2Codec.Decode(exactDph2.Span);
        OwnedInitialMessagingSeed? seed = null;
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
            var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
            using var retained = await SqliteDeepIdV2AccountGeneration.FindReceiverUnderLeaseAsync(
                storage, sqlStatePath, current, incoming, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Owned messaging import has no completed receiver source.");
            var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
                storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            var catalog = new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance);
            Did2MessagingSessionScope? scope;
            using (var registered = await catalog.ReadAsync(ct).ConfigureAwait(false))
                scope = registered.FindSource(retained.SessionId.Span, SHA256.HashData(retained.CanonicalSpan));
            if (scope is null)
            {
                seed = await OwnedInitialMessagingSeed.FromReceiverAsync(retained, instance, own, peer, source, held, ct).ConfigureAwait(false);
                scope = await catalog.RegisterAsync(seed, ct).ConfigureAwait(false);
            }
            Did2MessagingSourceScope.RequireReceiver(scope, retained);
            ProtectedDid2MessagingPeerBootstrap.RequireProof(await catalog.ReadPeerCredentialAsync(scope, ct).ConfigureAwait(false), peer);
            OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(
                storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (floor.Ordinal == 0)
            {
                seed ??= await OwnedInitialMessagingSeed.FromReceiverAsync(retained, instance, own, peer, source, held, ct).ConfigureAwait(false);
                using var import = OwnedDid2MessagingMutation.Import(seed, floor);
                _ = await opened.Custody.CommitOwnedAsync(import, ct).ConfigureAwait(false);
            }
            seed?.Dispose(); seed = null; retained.Dispose();
            await CompleteMessagingTransferUnderLeaseAsync(current, opened, ct).ConfigureAwait(false);
            await MaterializeInitialMessagingUnderLeaseAsync(current, opened, own, peer, source, held, ct).ConfigureAwait(false);
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            return scope;
        }
        finally { seed?.Dispose(); }
    }

    private async Task CompleteMessagingTransferUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, CancellationToken ct)
    {
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (floor.Status == 0)
        {
            var transfer = await opened.Custody.VerifyInitialTransferAsync(ct).ConfigureAwait(false);
            Did2InitialKeyRetirementReceipt receipt;
            if (opened.Scope.IsInitiator)
            {
                using var sourceStore = await SqliteDeepIdV2AccountGeneration.OpenExistingMessagingSenderSourceUnderLeaseAsync(
                    storage, sqlStatePath, current, ct).ConfigureAwait(false);
                receipt = await sourceStore.RetireInitialKeysUnderLeaseAsync(transfer, ct).ConfigureAwait(false);
            }
            else receipt = await SqliteDeepIdV2AccountGeneration.RetireReceiverUnderLeaseAsync(
                storage, sqlStatePath, current, transfer, ct).ConfigureAwait(false);
            floor = await opened.Custody.ActivateRetiredAsync(receipt, ct).ConfigureAwait(false);
        }
        if (floor.Status != 1) throw new InvalidOperationException("Owned messaging session cannot be activated from a latched state.");
        // Independently reopen source and verify completed retirement plus the
        // mutable SQL/protected floor before returning only scope metadata.
        using var verified = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(
            storage, sqlStatePath, current, opened.Scope, ct).ConfigureAwait(false);
        var checkedFloor = await verified.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(floor.Exact.Span, checkedFloor.Exact.Span))
            throw new CryptographicException("Owned messaging activation changed during final verification.");
    }

    private async Task MaterializeInitialMessagingUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var batch = await AuthenticatedInitialDmc2Batch.FromOwnedDid2Async(opened, own, peer, source, held, ct).ConfigureAwait(false);
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
            storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        RequireApplicationDisposition(await application.MaterializeInitialDmc2BatchAsync(batch, ct).ConfigureAwait(false));
    }

    private static void RequireApplicationDisposition(DirectDmc2InboxDisposition disposition)
    {
        if (disposition is not (DirectDmc2InboxDisposition.Materialized or DirectDmc2InboxDisposition.ExactReplay))
            throw new CryptographicException("DID2 application event cannot be materialized from forked or exhausted custody.");
    }

    private static async Task<OnionMonotonicReading> RequireMessagingFreshnessAsync(
        VerifiedDeepIdV2CurrentAccount current, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var reading = await source.RecheckEndpointPairUnderLeaseAsync(own, peer, held, ct).ConfigureAwait(false);
        _ = DeepIdV2AccountService.RequireOwnCurrentDirectory(current, own.Proof, reading.BootId.Span, reading.SampleSeconds);
        return reading;
    }

    private static async Task RequireFinalMessagingFreshnessAsync(VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        HeldDeepIdV2AccountLease held, OnionMonotonicReading first, CancellationToken ct)
    {
        var final = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        if (final.SampleSeconds < first.SampleSeconds || !Did2MessagingSessionScope.Fixed(final.BootId.Span, first.BootId.Span))
            throw new CryptographicException("Owned messaging transfer crossed a protected clock discontinuity.");
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, final);
        ct.ThrowIfCancellationRequested(); held.RequireActive();
    }
}
