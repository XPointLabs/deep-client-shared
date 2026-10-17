using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Only the actual prepared/native owner produces provenance. A SQL reader
    // never signs, repairs or fills a missing commitment. This MAC supplies no
    // route, currentness, Store outcome or deletion authority.
    private async Task<Did2StorePublicEvidence> BindStoreEvidenceUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> expectedAttempt,
        ReadOnlyMemory<byte> initialIntent, Did2StorePublicEvidence evidence,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, CancellationToken ct)
    {
        var attempt = await RequireCurrentStoreEvidenceAttemptUnderLeaseAsync(current, held, opened,
            scope, operation, initialIntent, evidence, ct).ConfigureAwait(false);
        byte[] commitment = [];
        try
        {
            if (!FixedRoute(attempt, expectedAttempt.Span))
                throw new CryptographicException("Store evidence cannot select another prepared attempt.");
            if (initialIntent.IsEmpty)
            {
                using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                    storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
                var retained = await application.ReadStorePublicEvidenceIfPresentAsync(scope, operation, attempt, ct).ConfigureAwait(false);
                if (retained is not null)
                {
                    await RequireStoreEvidenceCommitmentUnderLeaseAsync(held, scope, operation, attempt, retained, ct).ConfigureAwait(false);
                    var expected = evidence.CopyRecords(); var original = retained.CopyRecords();
                    try
                    {
                        if (retained.IsInitial || new[] { 0, 1, 2, 6, 7 }.Any(index => !FixedRoute(expected[index], original[index])))
                            throw new CryptographicException("Store retry differs from its first original public evidence.");
                    }
                    finally { foreach (var bytes in expected.Concat(original)) CryptographicOperations.ZeroMemory(bytes); }
                    var route = ContactRouteClosureCodec.Decode(retained.OriginalRoute.Span);
                    var oldKeys = MailboxStoreReplicaEvidenceVerifier.Verify(own.Network, own.Authority, route, retained.Replicas);
                    var newKeys = MailboxStoreReplicaEvidenceVerifier.Verify(own.Network, own.Authority, route, evidence.Replicas);
                    if (!FixedRoute(oldKeys.FirstNodeId.Span, newKeys.FirstNodeId.Span) ||
                        !FixedRoute(oldKeys.FirstReceiptPublicKey.Span, newKeys.FirstReceiptPublicKey.Span) ||
                        !FixedRoute(oldKeys.SecondNodeId.Span, newKeys.SecondNodeId.Span) ||
                        !FixedRoute(oldKeys.SecondReceiptPublicKey.Span, newKeys.SecondReceiptPublicKey.Span))
                        throw new CryptographicException("Store retry changed its authenticated original receipt keys.");
                    // Keep exact original view/descriptors/MAC. This historical
                    // evidence is not new dispatch authority; all current route,
                    // grant/floor checks remain on the actual transport boundary.
                    ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return retained;
                }
                var outbox = await application.ReadTransportOutboxAsync(OutboxAccountScope.FromBytes(evidence.AccountScope.Span),
                    OutboxLogicalId.FromBytes(evidence.Logical.Span), ct).ConfigureAwait(false);
                if (outbox is not { Result: TransportOutboxReadResult.Found, Item.State: TransportOutboxState.Prepared } || outbox.Item.Attempts.Count != 0)
                    throw new CryptographicException("Attempted Store lost its original public evidence; no reconstruction is allowed.");
            }
            commitment = await ComputeStoreEvidenceCommitmentUnderLeaseAsync(held, scope, operation,
                attempt, evidence, ct).ConfigureAwait(false);
            return evidence.WithCommitment(commitment);
        }
        finally { CryptographicOperations.ZeroMemory(attempt); CryptographicOperations.ZeroMemory(commitment); }
    }

    private async Task RequireStoreEvidenceCommitmentUnderLeaseAsync(HeldDeepIdV2AccountLease held,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> attempt,
        Did2StorePublicEvidence evidence, CancellationToken ct)
    {
        var expected = await ComputeStoreEvidenceCommitmentUnderLeaseAsync(held, scope, operation,
            attempt, evidence, ct).ConfigureAwait(false);
        var actual = evidence.EvidenceCommitment.ToArray();
        try
        {
            if (!FixedRoute(expected, actual))
                throw new CryptographicException("Original Store evidence lost its registered attempt commitment.");
        }
        finally { CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(actual); }
    }

    private async Task<byte[]> ComputeStoreEvidenceCommitmentUnderLeaseAsync(HeldDeepIdV2AccountLease held,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> attempt,
        Did2StorePublicEvidence evidence, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        ProtectedDph2PreClaimJournal.RequireIntent(attempt.Span);
        // All record lengths were bounded by the immutable shape/SQL reader
        // before accessing the existing protected application registration.
        var records = evidence.CopyRecords(); byte[] key = [], transcript = [];
        try
        {
            using var registration = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(
                storage, scope.Network.ToArray(), scope.LocalAccount.ToArray(), ct).ConfigureAwait(false);
            key = registration.Use(bytes =>
            {
                if (!FixedRoute(bytes.Slice(56, 32), scope.Instance))
                    throw new CryptographicException("Store evidence belongs to another registered instance.");
                var domain = "Deep/STORE-V2/original-store-evidence-key"u8;
                transcript = new byte[domain.Length + 1 + 80];
                domain.CopyTo(transcript); bytes.Slice(8, 80).CopyTo(transcript.AsSpan(domain.Length + 1));
                return HMACSHA256.HashData(bytes.Slice(88, 32), transcript);
            });
            using var mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
            mac.AppendData("Deep/STORE-V2/original-store-evidence"u8); mac.AppendData([0]);
            mac.AppendData(scope.Exact); mac.AppendData(operation.Span); mac.AppendData(attempt.Span); mac.AppendData([9]);
            var length = new byte[4];
            try
            {
                for (var index = 0; index < 9; index++)
                {
                    BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)records[index].Length));
                    mac.AppendData(length); mac.AppendData(records[index]);
                }
                held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
                return mac.GetHashAndReset();
            }
            finally { CryptographicOperations.ZeroMemory(length); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(transcript);
            foreach (var record in records) CryptographicOperations.ZeroMemory(record);
        }
    }
}
