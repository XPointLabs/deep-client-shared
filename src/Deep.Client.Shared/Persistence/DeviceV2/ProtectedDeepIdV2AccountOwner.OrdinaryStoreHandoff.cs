using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Fixed lock files avoid retaining a filename for every retired grant.
    // A collision only queues unrelated work; durable ordering uses full hashes.
    internal static string MailboxGrantFlightStripe(ReadOnlySpan<byte> grantHash)
    {
        if (grantHash.Length != 32) throw new ArgumentException("An exact grant digest is required.", nameof(grantHash));
        return grantHash[0].ToString("X2", System.Globalization.CultureInfo.InvariantCulture);
    }

    private sealed class MailboxGrantFlightBusy(DeepIdV2AccountFileLease grantLease) : Exception
    {
        internal DeepIdV2AccountFileLease GrantLease { get; } = grantLease;
    }

    private static Task RequireMailboxGrantOrderUnderLeaseAsync(ProtectedDid2MailboxSendJournal.State sends,
        MailboxCredentialLoan loan, Did2MessagingSessionScope scope, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, byte[] operation, byte[] grantHash, CancellationToken ct)
    {
        var target = sends.Current(scope.Hash, operation);
        var prior = sends.Entries.Values.Where(candidate => FixedRoute(candidate.GrantHash, grantHash) &&
            !(FixedRoute(candidate.ScopeHash, scope.Hash) && FixedRoute(candidate.Operation, operation)) &&
            (target?.Prepared != true || candidate.Prepared && candidate.Counter < target.Counter)).ToArray();
        // Existing exact retries never wait behind higher/unprepared work.
        // New work requires independent settled evidence for every lower request.
        return prior.Length == 0 ? Task.CompletedTask : loan.Store.RequirePriorMailboxStoreOutcomesAsync(
            scope, own, loan.Selector.AccountScope, loan.Grant, loan.Route, prior, loan.Authority.NowUnixSeconds, ct);
    }

    private static byte[] StoreWaitEvidenceFence(Did2StorePublicEvidence evidence)
    {
        var records = evidence.CopyRecords();
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var bytes in records) hash.AppendData(SHA256.HashData(bytes));
            return hash.GetHashAndReset();
        }
        finally { foreach (var bytes in records) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static async Task<byte[]> ReadStoreWaitOutboxFenceAsync(SqliteDeepMailboxStore application,
        MailboxCredentialLoan loan, ReadOnlyMemory<byte> operation, byte[] exactMau, CancellationToken ct)
    {
        var read = await application.ReadTransportOutboxAsync(loan.Selector.AccountScope,
            OutboxLogicalId.FromBytes(operation.Span), ct).ConfigureAwait(false);
        if (read is not { Result: TransportOutboxReadResult.Found, Item: not null } ||
            read.Item.State != TransportOutboxState.Attempted || !FixedRoute(read.Item.CiphertextBundle, exactMau))
            throw new CryptographicException("Store wait lost its exact original in-flight SQL attempt.");
        var item = read.Item;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(item.AccountScope.Value); hash.AppendData(item.LogicalId.Value); hash.AppendData(item.DedupMaterial.Value);
        hash.AppendData(SHA256.HashData(item.CiphertextBundle));
        void Scalar(ulong value) { Span<byte> bytes = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); hash.AppendData(bytes); }
        Scalar(item.Revision); Scalar((ulong)item.State); Scalar((ulong)item.Source); Scalar((ulong)item.Reason);
        Scalar(checked((ulong)item.CreatedAt.UtcTicks)); Scalar(checked((ulong)item.ExpiresAt.UtcTicks));
        Scalar(checked((ulong)item.NotBefore.UtcTicks)); Scalar(checked((ulong)item.TransitionedAt.UtcTicks));
        Scalar((ulong)item.Attempts.Count);
        foreach (var attempt in item.Attempts.OrderBy(attempt => Convert.ToHexString(attempt.AttemptId.Value), StringComparer.Ordinal))
        {
            hash.AppendData(attempt.AttemptId.Value); Scalar((ulong)attempt.State); Scalar((ulong)attempt.Source); Scalar((ulong)attempt.Reason);
            Scalar(checked((ulong)attempt.OccurredAt.UtcTicks)); hash.AppendData(SHA256.HashData(attempt.Evidence));
        }
        hash.AppendData(SHA256.HashData(item.AcknowledgementEvidence));
        return hash.GetHashAndReset();
    }

    private async Task<bool> IsOrdinaryStoreHandoffUnderLeaseAsync(Did2MessagingSessionScope scope,
        byte[] operation, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
            throw new CryptographicException("Store classification lost protected acceptance custody.");
        using var accepts = root.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        var accept = accepts.FindScope(scope);
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        return accept is null || !FixedRoute(accept.Operation, operation);
    }

    private async Task<(byte[] Send, byte[] Grants, OriginalDepositAcquisition Acquisition)> ReadMailboxStoreRejoinRootsUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        Did2MessagingSessionScope scope, byte[] operation, ProtectedDid2MailboxSendJournal.State original,
        byte[] grantHash, string grantName, byte[] retainedGrantHash, ulong minimumGrantRevision, byte[] instance, CancellationToken ct)
    {
        held.RequireOwner(lease);
        byte[] send = [], grants = [];
        OriginalDepositAcquisition? acquisition = null;
        try
        {
            using (var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Store rejoin lost protected send custody."))
                send = root.Use(bytes => bytes.ToArray());
            using var actual = ProtectedDid2MailboxSendJournal.Decode(send, networkId, current.AccountId.Span, instance);
            if (!FixedRoute(actual.ChainCommitment(scope.Hash, operation), original.ChainCommitment(scope.Hash, operation)) ||
                actual.MinimumCounter(grantHash) != original.MinimumCounter(grantHash) || actual.Revision < original.Revision)
                throw new CryptographicException("Store rejoin changed its exact original attempt or replay floor.");
            using (var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Store rejoin lost protected grant custody."))
                grants = root.Use(bytes => bytes.ToArray());
            using var selected = ProtectedDid2MailboxGrantJournal.Decode(grants, networkId, current.AccountId.Span, instance);
            acquisition = await ReadOriginalDepositAcquisitionUnderLeaseAsync(held, current.AccountId,
                instance, grants, grantHash, ct, grantName).ConfigureAwait(false);
            if (selected.Revision < minimumGrantRevision ||
                !FixedRoute(SHA256.HashData(acquisition.Entry), retainedGrantHash))
                throw new CryptographicException("Store rejoin changed its exact retained grant.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return (send, grants, acquisition);
        }
        catch { acquisition?.Dispose(); CryptographicOperations.ZeroMemory(send); CryptographicOperations.ZeroMemory(grants); throw; }
    }
}
