#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;
using Sodium;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    // A bounded readback of already recorded evidence. No insertion/pruning,
    // capacity reservation or reconstructed coordinator statement is permitted.
    internal Task RequireRetainedCoordinatorStatementAsync(MailboxAuthenticatedGrant grant,
        VerifiedMailboxDurableQuorumV3 verified, ulong expiry, CancellationToken ct) =>
        WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction(); ValidateTransportOutboxSchema(connection, tx);
            RequireRetainedCoordinatorStatement(connection, tx, grant, verified, expiry, ct);
            return Task.FromResult(true);
        }, ct);

    private static void RequireRetainedCoordinatorStatement(SqliteConnection connection, SqliteTransaction tx,
        MailboxAuthenticatedGrant grant, VerifiedMailboxDurableQuorumV3 verified, ulong expiry, CancellationToken ct)
    {
        var receipt = verified.CoordinatorReceipt;
        var key = CoordinatorStatementKey(grant.MembershipCommitment.Span, grant.Epoch,
            receipt.CoordinatorId.Span, receipt.CoordinatorSequence);
        var digest = SHA256.HashData(MailboxReceiptV3Codec.GetQuorumSigningBytes(receipt));
        try
        {
            using var command = connection.CreateCommand(); command.Transaction = tx;
            command.CommandText = "SELECT length(statement_digest),typeof(statement_digest),statement_digest,length(expires_at),typeof(expires_at),expires_at FROM client_mailbox_coordinator_journal WHERE statement_key=$key LIMIT 2;";
            command.Parameters.AddWithValue("$key", key);
            using var reader = command.ExecuteReader();
            if (!reader.Read() || reader.GetInt64(0) != 32 || reader.GetString(1) != "blob" ||
                reader.GetInt64(3) != 8 || reader.GetString(4) != "blob")
                throw new CryptographicException("Retained Store has no exact recorded coordinator statement.");
            var actual = reader.GetFieldValue<byte[]>(2); var deadline = reader.GetFieldValue<byte[]>(5);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(actual, digest) || ReadU64(deadline) != expiry || reader.Read())
                    throw new CryptographicException("Retained Store disagrees with its original coordinator statement.");
            }
            finally { CryptographicOperations.ZeroMemory(actual); CryptographicOperations.ZeroMemory(deadline); }
            ct.ThrowIfCancellationRequested();
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(digest); }
    }

    // One bounded SQL snapshot, independent signatures and existing coordinator
    // evidence. A local Stored marker can never settle a lower replay counter.
    internal Task RequirePriorMailboxStoreOutcomesAsync(Did2MessagingSessionScope ownerScope,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, OutboxAccountScope account, MailboxAuthenticatedGrant grant, ScopedMailboxResolvedRoute route,
        IReadOnlyList<ProtectedDid2MailboxSendJournal.Entry> lower, ulong currentUpper, CancellationToken ct)
    {
        if (lower.Count is < 1 or > ProtectedDid2MailboxSendJournal.MaximumEntries)
            throw new ArgumentException("Grant ordering requires bounded exact lower attempts.", nameof(lower));
        return WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction(); ValidateTransportOutboxSchema(connection, tx);
            var exactGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant);
            var grantHash = SHA256.HashData(exactGrant);
            try
            {
                foreach (var prior in lower)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!prior.Prepared || !CryptographicOperations.FixedTimeEquals(prior.GrantHash, grantHash))
                        throw new IOException("Resume the original pending grant request before new work.");
                    TransportOutboxStoredItem item;
                    try
                    {
                        item = ReadTransportOutboxItem(connection, tx, account.Value, prior.MailboxOperation) ??
                            throw new CryptographicException("Earlier grant work lost its original SQL request.");
                        TransportOutboxStateMachine.Validate(item);
                    }
                    catch (TransportOutboxCorruptException error)
                    { throw new CryptographicException("Earlier grant work has corrupt original SQL custody.", error); }
                    if (item.State is not (TransportOutboxState.Durable or TransportOutboxState.Delivered))
                        throw new IOException("Resume the exact unknown grant request before a later counter.");
                    var exact = item.CiphertextBundle;
                    var evidence = item.Attempts.Single(attempt => attempt.State == TransportOutboxAttemptState.Durable).Evidence;
                    try
                    {
                        var request = MailboxAuthenticatedClientRequestCodec.Decode(exact);
                        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Binding.CanonicalRequest.Span);
                        var signing = MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(request.Presentation);
                        var operation = ProtectedDeepIdV2AccountOwner.MailboxSendOperation(ownerScope.Network, ownerScope.LocalAccount,
                            prior.ScopeHash, prior.Attempt, envelope.Ciphertext.Span);
                        try
                        {
                            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(exact), prior.MauHash) ||
                                request.Binding.Operation != MailboxAuthenticatedOperation.Store ||
                                request.Presentation.ReplayCounter != prior.Counter ||
                                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(request.Binding.CanonicalRequest.Span), prior.BodyHash) ||
                                !CryptographicOperations.FixedTimeEquals(MailboxAuthenticatedCapabilityCodec.EncodeGrant(request.Presentation.Grant), exactGrant) ||
                                !CryptographicOperations.FixedTimeEquals(operation, prior.MailboxOperation) ||
                                !CryptographicOperations.FixedTimeEquals(operation, request.Binding.OperationId.Span) ||
                                !CryptographicOperations.FixedTimeEquals(operation, envelope.OperationId.Span) ||
                                !CryptographicOperations.FixedTimeEquals(item.DedupMaterial, request.Binding.RequestDigest.Span) ||
                                item.ExpiresAt != DateTimeOffset.FromUnixTimeSeconds(checked((long)envelope.ExpiresAtUnixSeconds)) ||
                                envelope.CreatedAtUnixSeconds < grant.NotBeforeUnixSeconds || envelope.CreatedAtUnixSeconds >= grant.ExpiresAtUnixSeconds ||
                                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(envelope.Ciphertext.Span), prior.EnvelopeHash) ||
                                envelope.CreatedAtUnixSeconds != prior.Created || envelope.ExpiresAtUnixSeconds != prior.Expires ||
                                envelope.Epoch != grant.Epoch || !CryptographicOperations.FixedTimeEquals(envelope.MailboxId.Bytes.Span, route.MailboxId.Bytes.Span) ||
                                !CryptographicOperations.FixedTimeEquals(envelope.PlacementId.Bytes.Span, route.PlacementId.Bytes.Span) ||
                                !PublicKeyAuth.VerifyDetached(request.Presentation.HolderSignature.ToArray(), signing, grant.HolderPublicKey.ToArray()))
                                throw new CryptographicException("Earlier grant work changed its signed original request.");
                        }
                        finally { CryptographicOperations.ZeroMemory(signing); CryptographicOperations.ZeroMemory(operation); }
                        var records = ReadStorePublicEvidence(connection, tx, prior.ScopeHash.ToArray(), prior.Operation.ToArray(), prior.Attempt.ToArray()) ??
                            throw new CryptographicException("Earlier grant work lost its original replica evidence.");
                        VerifiedMailboxStoreReplicaEvidence replicas;
                        try
                        {
                            if (!CryptographicOperations.FixedTimeEquals(records[0], account.Value) ||
                                !CryptographicOperations.FixedTimeEquals(records[1], prior.MailboxOperation) ||
                                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(records[7]), prior.RouteHash))
                                throw new CryptographicException("Earlier grant replica evidence changed its original binding.");
                            var originalRoute = ContactRouteClosureCodec.Decode(records[7]);
                            if (!CryptographicOperations.FixedTimeEquals(grant.SelectionInput.Span, originalRoute.Selection.Field(3).Span) ||
                                !CryptographicOperations.FixedTimeEquals(grant.MembershipCommitment.Span, originalRoute.Projection.ArtifactHash.Span))
                                throw new CryptographicException("Earlier grant replica evidence changed its original selector.");
                            replicas = MailboxStoreReplicaEvidenceVerifier.Verify(own.Network, own.Authority, originalRoute,
                                new(records[3], records[4], records[5]));
                        }
                        finally { foreach (var record in records) CryptographicOperations.ZeroMemory(record); }
                        var pinned = new ClientMailboxPinnedRoute(route.PlacementId, route.MembershipCommitment.Span,
                            replicas.FirstNodeId.Span, replicas.FirstReceiptPublicKey.Span,
                            replicas.SecondNodeId.Span, replicas.SecondReceiptPublicKey.Span);
                        var verified = new PinnedClientMailboxReceiptVerifier(new SodiumMailboxPeerReplicationCrypto()).VerifyDurable(evidence, new()
                        {
                            Epoch = envelope.Epoch, OperationId = envelope.OperationId, MailboxId = envelope.MailboxId,
                            Route = pinned, EnvelopeDigest = envelope.DeduplicationDigest, ExpiresAtUnixSeconds = envelope.ExpiresAtUnixSeconds,
                            AllowedDispositions = new HashSet<MailboxReplicaDisposition> { MailboxReplicaDisposition.Stored, MailboxReplicaDisposition.Duplicate }
                        });
                        if (!CryptographicOperations.FixedTimeEquals(verified.CoordinatorReceipt.CoordinatorId.Span, replicas.FirstNodeId.Span))
                            throw new CryptographicException("Earlier grant Store changed its authenticated sole writer.");
                        foreach (var replica in verified.ReplicaReceipts)
                            if (replica.AcceptedAtUnixSeconds < grant.NotBeforeUnixSeconds || replica.AcceptedAtUnixSeconds >= grant.ExpiresAtUnixSeconds ||
                                replica.AcceptedAtUnixSeconds < envelope.CreatedAtUnixSeconds || replica.DurableAtUnixSeconds > currentUpper ||
                                replica.AcceptedAtUnixSeconds < replicas.OriginalViewNotBefore || replica.AcceptedAtUnixSeconds >= replicas.OriginalViewExpiresAt)
                                throw new CryptographicException("Earlier grant Store is outside its authenticated original interval.");
                        RequireRetainedCoordinatorStatement(connection, tx, grant, verified, envelope.ExpiresAtUnixSeconds, ct);
                    }
                    finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(evidence); }
                }
                ct.ThrowIfCancellationRequested(); return Task.FromResult(true);
            }
            finally { CryptographicOperations.ZeroMemory(exactGrant); CryptographicOperations.ZeroMemory(grantHash); }
        }, ct);
    }
}
#endif
