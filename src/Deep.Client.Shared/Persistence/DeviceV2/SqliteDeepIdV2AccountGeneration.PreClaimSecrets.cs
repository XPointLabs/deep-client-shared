using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
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
            using var protector = new InitiatorDph2PreKeyClaimPersistenceProtector(record.AsSpan(88, 32));
            using var snapshotOwner = await storage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot, ct)
                .ConfigureAwait(false) ?? throw new InvalidDataException("The protected preclaim journal is absent.");
            var exact = snapshotOwner.Use(static value => value.ToArray());
            var state = ProtectedDph2PreClaimJournal.Decode(exact, network.Span, current.AccountId.Span,
                scope.DatabaseInstanceId.Span);
            var name = Convert.ToHexString(logicalIntent.Span);
            using var authority = DeepIdV2AccountService.OwnAgreementAuthority(current);
            ct.ThrowIfCancellationRequested();
            var directory = DeepIdV2AccountService.RequireOwnCurrentDirectory(current, currentProof,
                currentBootId.Span, currentMonotonicSample);
            if (!state.Claims.TryGetValue(name, out var blob))
            {
                if (state.Claims.Count >= ProtectedDph2PreClaimJournal.MaximumIntents)
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
