using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    private long storeResumes, mailboxResumes, recoveryLeaseWaits;
    /// <summary>Diagnostic count of bounded resumes of original owned Store operations; not delivery authority.</summary>
    public long ExactStoreResumes => Interlocked.Read(ref storeResumes);
    /// <summary>Diagnostic count of bounded resumes of original owned mailbox pages/ACKs; not receipt authority.</summary>
    public long ExactMailboxResumes => Interlocked.Read(ref mailboxResumes);
    /// <summary>Diagnostic count of bounded waits for existing protected retry leases.</summary>
    public long ExactRecoveryLeaseWaits => Interlocked.Read(ref recoveryLeaseWaits);

    internal async Task<ClientMailboxStoreResult> DeliverOwnMessagingWithRecoveryAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, DeepIdV2ContactPathAuthoritySource source, IDid2MailboxGrantTransport grants,
        IDid2OwnedMailboxTransportFactory transport, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var exact = operation.ToArray();
        try
        {
            return await OwnedMailboxRecovery.RunAsync(
                () => DeliverOwnMessagingAsync(scope, exact, source, grants, transport, ct),
                () => source.DiscardUncapturedAuthorityAsync(ct),
                () => Interlocked.Increment(ref storeResumes), () => Interlocked.Increment(ref recoveryLeaseWaits), ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    internal Task<DeepIdV2MailboxSynchronizationResult> SynchronizeOwnMailboxWithRecoveryAsync(
        DeepIdV2ContactPathAuthoritySource source, IDid2MailboxGrantTransport grants,
        IDid2OwnedMailboxTransportFactory transport, CancellationToken ct) =>
        OwnedMailboxRecovery.RunAsync(() => SynchronizeOwnMailboxAsync(source, grants, transport, ct),
            () => source.DiscardUncapturedAuthorityAsync(ct),
            () => Interlocked.Increment(ref mailboxResumes), () => Interlocked.Increment(ref recoveryLeaseWaits), ct);
}
