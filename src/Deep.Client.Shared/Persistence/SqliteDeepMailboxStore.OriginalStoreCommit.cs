#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    // Owner-only data commit, not a verification/deletion capability. The held
    // owner independently authenticates the original native/request/grant/pair.
    // Coordinator and both existing state transitions share ONE SQL transaction.
    internal Task CommitOwnedOriginalStoreReplyAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> nativeOperation, ReadOnlyMemory<byte> attemptSelector, Did2StorePublicEvidence publicEvidence,
        TransportOutboxItemSnapshot expected,
        MailboxAuthenticatedGrant grant, VerifiedMailboxDurableQuorumV3 verified, ulong currentUpper,
        Func<CancellationToken, Task> recheck, CancellationToken ct)
    {
        var exact = expected.GetCiphertextBundleCopy();
        var quorum = MailboxReceiptV3Codec.EncodeDurableQuorum(verified.CoordinatorReceipt);
        var statement = SHA256.HashData(MailboxReceiptV3Codec.GetQuorumSigningBytes(verified.CoordinatorReceipt));
        return Commit();
        async Task Commit()
        {
            try
            {
                await WithReplayConnectionAsync(async connection =>
                {
                    using var tx = connection.BeginTransaction(deferred: false);
                    ValidateTransportOutboxSchema(connection, tx);
                    var records = ReadStorePublicEvidence(connection, tx, scope.Hash.ToArray(), nativeOperation.ToArray(),
                        attemptSelector.ToArray()) ?? throw new CryptographicException("Late Store lost original public evidence.");
                    var originalRecords = publicEvidence.CopyRecords();
                    try { RequireSamePublicEvidence(records, originalRecords); }
                    finally { foreach (var bytes in records.Concat(originalRecords)) CryptographicOperations.ZeroMemory(bytes); }
                    var actual = ReadTransportOutboxItem(connection, tx, expected.AccountScope.Value,
                        expected.LogicalId.Value) ?? throw new CryptographicException("Late Store lost its actual request.");
                    if (actual.Revision != expected.Revision || actual.State != expected.State ||
                        !CryptographicOperations.FixedTimeEquals(actual.CiphertextBundle, exact) ||
                        !CryptographicOperations.FixedTimeEquals(actual.DedupMaterial, expected.DedupMaterial.Value))
                        throw new CryptographicException("Late Store SQL changed before commit.");
                    if (actual.State is not (TransportOutboxState.Attempted or TransportOutboxState.Accepted) ||
                        actual.LastTransitionAttemptId is null)
                        throw new CryptographicException("Late Store has no original possibly dispatched SQL attempt.");
                    var now = DateTimeOffset.FromUnixTimeSeconds(checked((long)currentUpper));
                    if (now < actual.TransitionedAt || now >= actual.ExpiresAt)
                        throw new IOException("Late Store is outside its retained working object horizon.");
                    await recheck(ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeSettlementSql);
#endif
                    var coordinator = await RecordCoordinatorInTransactionAsync(connection, tx,
                        ClientMailboxJournalScope.Derive(grant.IssuerPublicKey.Span), grant.MembershipCommitment,
                        grant.Epoch, verified.CoordinatorReceipt.CoordinatorId,
                        verified.CoordinatorReceipt.CoordinatorSequence, statement,
                        checked((ulong)actual.ExpiresAt.ToUnixTimeSeconds()), currentUpper, false, ct).ConfigureAwait(false);
                    if (coordinator is not (ClientMailboxCoordinatorRecordResult.Applied or ClientMailboxCoordinatorRecordResult.Idempotent))
                        throw new CryptographicException("Late Store coordinator is conflicting or at capacity.");
                    var attempt = OutboxAttemptId.FromBytes(actual.LastTransitionAttemptId);
                    if (actual.State == TransportOutboxState.Attempted)
                    {
                        var accepted = TransportOutboxTransition.Accepted(expected.AccountScope, expected.LogicalId,
                            actual.Revision, attempt, OutboxTransitionSource.Recovery, OutboxTransitionReason.CrashReconciled,
                            now, now, quorum);
                        var next = actual.Clone();
                        if (TransportOutboxStateMachine.Apply(next, accepted) != TransportOutboxCommitResult.Applied)
                            throw new CryptographicException("Late Store could not adopt its original accepted evidence.");
                        UpdateTransportOutboxItem(connection, tx, actual, next, accepted); actual = next;
                    }
                    else if (!CryptographicOperations.FixedTimeEquals(actual.Attempts.Single(value =>
                        value.AttemptId.AsSpan().SequenceEqual(attempt.Value)).Evidence, quorum))
                        throw new CryptographicException("Late Store cannot replace existing accepted evidence.");
                    var durable = TransportOutboxTransition.Durable(expected.AccountScope, expected.LogicalId,
                        actual.Revision, attempt, OutboxTransitionSource.Recovery, OutboxTransitionReason.CrashReconciled, now, quorum);
                    var terminal = actual.Clone();
                    if (TransportOutboxStateMachine.Apply(terminal, durable) != TransportOutboxCommitResult.Applied)
                        throw new CryptographicException("Late Store could not adopt its original durable evidence.");
                    UpdateTransportOutboxItem(connection, tx, actual, terminal, durable);
                    await recheck(ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested();
                    tx.Commit();
#if DEEP_TEST_INTERNALS
                    Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterSettlementSql);
#endif
                    return true;
                }, ct).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(quorum); CryptographicOperations.ZeroMemory(statement); }
        }
    }
}
#endif
