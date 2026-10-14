using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal static async Task<byte[]> ReadPreclaimCancellationHashUnderLeaseAsync(IDeepSecureStorage storage,
        ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        ReadOnlyMemory<byte> intent, ReadOnlyMemory<byte> draftBinding, bool hasSource, CancellationToken ct)
    {
        using var raw = await storage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        var state = raw.Use(bytes => ProtectedDph2PreClaimJournal.Decode(bytes, network.Span, account.Span, instance.Span));
        var name = Convert.ToHexString(intent.Span);
        if (state.Retired.ContainsKey(name)) throw new CryptographicException("A transferred preclaim cannot become pre-session cancellation.");
        if (state.Claims.TryGetValue(name, out var live)) return SHA256.HashData(live.CanonicalBytes.Span);
        if (state.Cancelled.TryGetValue(name, out var cancelled))
        {
            if (!Fixed(cancelled.DraftBinding, draftBinding.Span)) throw new CryptographicException("Cancelled preclaim changed its draft owner.");
            return cancelled.BlobHash.ToArray();
        }
        if (hasSource) throw new CryptographicException("Completed sender source lost its original preclaim.");
        return new byte[32]; // Actual complete protected snapshot proves no preclaim; not a fabricated blob hash.
    }

    internal static async Task CancelPreclaimUnderLeaseAsync(IDeepSecureStorage storage,
        ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        ProtectedInitialKeyRetirementJournal.Entry expected, CancellationToken ct)
    {
        var journal = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, network, account, ct).ConfigureAwait(false);
        var actual = journal.FindCancellation(expected.Intent);
        if (actual is null || !Fixed(actual.Stable().Exact, expected.Stable().Exact)) throw new CryptographicException("Preclaim deletion lost its independently owned cancellation.");
        using var raw = await storage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        var before = raw.Use(bytes => bytes.ToArray()); byte[] after = [];
        try
        {
            var state = ProtectedDph2PreClaimJournal.Decode(before, network.Span, account.Span, instance.Span);
            journal.RequirePreclaimState(state);
            var name = Convert.ToHexString(actual.Intent);
            if (state.Cancelled.TryGetValue(name, out var cancelled)) return; // Exact binding was checked above, never repair.
            if (actual.Phase == 2) throw new CryptographicException("Completed cancellation cannot erase resurrected preclaim keys.");
            var existed = state.Claims.Remove(name);
            state.Cancelled.Add(name, new(actual.PreclaimHash.ToArray(), actual.ScopeHash.ToArray()));
            after = ProtectedDph2PreClaimJournal.Encode(state with { Revision = checked(state.Revision + (existed ? 1UL : 2UL)) },
                network.Span, account.Span, instance.Span);
            ct.ThrowIfCancellationRequested();
            if (!await storage.CompareExchangeAsync(ProtectedDph2PreClaimJournal.Slot, before, after, ct).ConfigureAwait(false))
                throw new CryptographicException("Preclaim cancellation changed before deletion.");
        }
        finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
    }

    internal static async Task<byte[]> ReadPreclaimRetirementHashUnderLeaseAsync(IDeepSecureStorage storage,
        Did2InitialStateTransfer transfer, ReadOnlyMemory<byte> intent, CancellationToken ct)
    {
        using var owned = await storage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Protected preclaim journal disappeared.");
        var scope = transfer.Scope;
        var state = owned.Use(value => ProtectedDph2PreClaimJournal.Decode(value, scope.Network, scope.LocalAccount, scope.Instance));
        var name = Convert.ToHexString(intent.Span);
        if (state.Claims.TryGetValue(name, out var live)) return SHA256.HashData(live.CanonicalBytes.Span);
        if (state.Retired.TryGetValue(name, out var retired) && Did2InitialStateTransfer.Fixed(retired.SourceBasis, scope.InitialBasis) &&
            Did2InitialStateTransfer.Fixed(retired.MutableScope, scope.Hash)) return retired.BlobHash.ToArray();
        throw new CryptographicException("Source retirement has no exact live or retired preclaim intent.");
    }
    internal static async Task RetirePreclaimUnderLeaseAsync(IDeepSecureStorage storage, Did2InitialStateTransfer transfer,
        ProtectedInitialKeyRetirementJournal.Entry entry, CancellationToken ct)
    {
        var scope = transfer.Scope;
        if (!scope.IsInitiator || entry.Role != 1 || !Did2InitialStateTransfer.Fixed(entry.ScopeHash, scope.Hash))
            throw new CryptographicException("Sender preclaim retirement has a different transfer owner.");
        using var owner = await storage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Protected preclaim journal disappeared.");
        var exact = owner.Use(static value => value.ToArray());
        try
        {
            var state = ProtectedDph2PreClaimJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
            var name = Convert.ToHexString(entry.Intent);
            if (state.Retired.TryGetValue(name, out var retired))
            {
                if (!Did2InitialStateTransfer.Fixed(retired.BlobHash, entry.PreclaimHash) ||
                    !Did2InitialStateTransfer.Fixed(retired.SourceBasis, scope.InitialBasis) ||
                    !Did2InitialStateTransfer.Fixed(retired.MutableScope, scope.Hash))
                    throw new CryptographicException("Preclaim tombstone was substituted.");
                return;
            }
            if (!state.Claims.TryGetValue(name, out var live) ||
                !Did2InitialStateTransfer.Fixed(SHA256.HashData(live.CanonicalBytes.Span), entry.PreclaimHash))
                throw new CryptographicException("Retirement would erase a different preclaim.");
            if (entry.Phase == 2) throw new CryptographicException("A completed retirement resurrected a sealed preclaim; no repair is allowed.");
            state.Claims.Remove(name);
            state.Retired.Add(name, new(entry.PreclaimHash.ToArray(), scope.InitialBasis.ToArray(), scope.Hash.ToArray()));
            var next = ProtectedDph2PreClaimJournal.Encode(state with { Revision = checked(state.Revision + 1) }, scope.Network, scope.LocalAccount, scope.Instance);
            try
            {
                if (!await storage.CompareExchangeAsync(ProtectedDph2PreClaimJournal.Slot, exact, next, ct).ConfigureAwait(false))
                    throw new CryptographicException("Preclaim retirement lost its exact protected predecessor.");
            }
            finally { CryptographicOperations.ZeroMemory(next); }
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    // Caller owns the account lease and its freshly verified local account.
    // The snapshot itself is the protected authority, not a recoverability
    // promise for a later device-DH burn/prepared-secret transaction.
    internal static async ValueTask<InitiatorDph2PreKeyClaim> BeginOrRestorePreClaimUnderLeaseAsync(
        IDeepSecureStorage storage, VerifiedDeepIdV2CurrentAccount current,
        ReadOnlyMemory<byte> logicalIntent, VerifiedDeepIdV2DirectoryFreshness currentProof,
        ReadOnlyMemory<byte> currentBootId, ulong currentMonotonicSample,
        OnionTrustedTimeAuthority trustedTime, int maximumMessagesWithoutPqInjection,
        CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(logicalIntent.Span);
        ct.ThrowIfCancellationRequested();
        var network = current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.NetworkId;
        using var keyOwner = await storage.ReadOwnedAsync(KeySlot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("The DID2 SQL key record is absent.");
        var record = keyOwner.Use(static value => value.ToArray());
        try
        {
            ValidateRecord(record, network.Span, current.AccountId.Span);
            var scope = new InitiatorDph2PreKeyClaimPersistenceScope(record.AsSpan(56, 32), logicalIntent.Span);
            await RequireInitialIntentNotStoppedUnderLeaseAsync(storage, network, current.AccountId,
                scope.DatabaseInstanceId, logicalIntent, ct).ConfigureAwait(false);
            using var protector = new InitiatorDph2PreKeyClaimPersistenceProtector(record.AsSpan(88, 32));
            using var snapshotOwner = await storage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot, ct)
                .ConfigureAwait(false) ?? throw new InvalidDataException("The protected preclaim journal is absent.");
            var exact = snapshotOwner.Use(static value => value.ToArray());
            var state = ProtectedDph2PreClaimJournal.Decode(exact, network.Span, current.AccountId.Span,
                scope.DatabaseInstanceId.Span);
            var name = Convert.ToHexString(logicalIntent.Span);
            if (state.Retired.ContainsKey(name) || state.Cancelled.ContainsKey(name))
                throw new CryptographicException("This preclaim intent is retired; only exact completed custody may be retried.");
            using var authority = DeepIdV2AccountService.OwnAgreementAuthority(current);
            ct.ThrowIfCancellationRequested();
            var directory = DeepIdV2AccountService.RequireOwnCurrentDirectory(current, currentProof,
                currentBootId.Span, currentMonotonicSample);
            if (!state.Claims.TryGetValue(name, out var blob))
            {
                if (state.Count >= ProtectedDph2PreClaimJournal.MaximumIntents)
                    throw new IOException("The protected preclaim journal is full.");
                using var begun = new ManagedInitiatorInitialSessionFactory(maximumMessagesWithoutPqInjection)
                    .BeginClaim(authority, directory, currentProof, currentBootId.Span, currentMonotonicSample);
                blob = protector.SealAndConsume(begun, scope);
                state.Claims.Add(name, blob);
                var next = ProtectedDph2PreClaimJournal.Encode(state with { Revision = checked(state.Revision + 1) },
                    network.Span, current.AccountId.Span, scope.DatabaseInstanceId.Span);
                ct.ThrowIfCancellationRequested();
                if (!await storage.CompareExchangeAsync(ProtectedDph2PreClaimJournal.Slot, exact, next, ct)
                        .ConfigureAwait(false))
                    throw new IOException("The protected preclaim journal changed during account-owned commit.");
            }
            // No newly generated capability can escape before the snapshot
            // commit. Retry/restart restores precisely the winning operation.
            return await protector.RestoreCurrentAsync(blob, scope, authority, directory,
                currentProof, trustedTime, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(record); }
    }
}
