using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

/// <summary>
/// The native-cloud MAU2 preparation boundary. It never leases credentials
/// independently: every frame is prepared with its durable outbox row in the
/// scoped repository transaction.
/// </summary>
public sealed class MailboxAuthenticatedRequestFactory
{
    private readonly IScopedMailboxCredentialRepository credentials;
    private readonly VerifiedOfficialMailboxAuthority authority;

    internal MailboxAuthenticatedRequestFactory(
        IScopedMailboxCredentialRepository credentials,
        VerifiedOfficialMailboxAuthority authority)
    {
        this.credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        authority.Validate();
    }

    internal bool Uses(IScopedMailboxCredentialRepository repository) =>
        ReferenceEquals(credentials, repository);

    internal ValueTask<IAsyncDisposable>
        AcquireDispatchPolicyAsync(
        CancellationToken cancellationToken = default) =>
        authority.AcquireDispatchPolicyAsync(cancellationToken);

    internal void ReloadCommittedPolicy() =>
        authority.ReloadCommittedPolicy();

    public Task<ScopedMailboxResolvedRoute> ReadRouteAsync(
        MailboxCredentialSelector selector,
        CancellationToken cancellationToken = default) =>
        credentials.ReadScopedMailboxRouteAsync(selector, authority, cancellationToken);

    public Task<ScopedMailboxResolvedRoute> RevalidateDispatchAsync(
        MailboxCredentialSelector selector,
        MailboxAuthenticatedOperation operation,
        CancellationToken cancellationToken = default) =>
        credentials.RevalidateScopedMailboxDispatchAsync(
            selector, operation, authority, cancellationToken);

    public async Task<MailboxAuthenticatedRequestFrame> CreateStoreAsync(
        OutboxAccountScope accountScope,
        MailboxCredentialSelector selector,
        IMailboxOperationSigner signer,
        MailboxEncryptedEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        _ = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        return await PrepareAsync(accountScope, selector, signer,
            MailboxAuthenticatedRequestTranscript.ForStore(envelope),
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<MailboxAuthenticatedRequestFrame> CreateRetrieveAsync(
        OutboxAccountScope accountScope,
        MailboxCredentialSelector selector,
        IMailboxOperationSigner signer,
        ReadOnlyMemory<byte> operationId,
        ulong afterCursor,
        ushort maximumItems,
        ReadOnlyMemory<byte> continuationToken,
        CancellationToken cancellationToken = default)
    {
        var route = await ReadRouteAsync(selector, cancellationToken)
            .ConfigureAwait(false);
        return await CreateRetrieveAsync(
            accountScope,
            selector,
            signer,
            route,
            operationId,
            afterCursor,
            maximumItems,
            continuationToken,
            cancellationToken).ConfigureAwait(false);
    }

    internal async Task<MailboxAuthenticatedRequestFrame> CreateRetrieveAsync(
        OutboxAccountScope accountScope,
        MailboxCredentialSelector selector,
        IMailboxOperationSigner signer,
        ScopedMailboxResolvedRoute route,
        ReadOnlyMemory<byte> operationId,
        ulong afterCursor,
        ushort maximumItems,
        ReadOnlyMemory<byte> continuationToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(route);
        var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            route.Epoch, operationId.Span, route.MailboxId, route.PlacementId,
            afterCursor, maximumItems, continuationToken.Span);
        return await PrepareAsync(accountScope, selector, signer, binding,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<MailboxAuthenticatedRequestFrame> CreateAckAsync(
        OutboxAccountScope accountScope,
        MailboxCredentialSelector selector,
        IMailboxOperationSigner signer,
        ReadOnlyMemory<byte> operationId,
        bool isFinalPage,
        ReadOnlyMemory<byte> continuationToken,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default)
    {
        var route = await ReadRouteAsync(selector, cancellationToken)
            .ConfigureAwait(false);
        var binding = MailboxAuthenticatedRequestTranscript.ForAck(
            route.Epoch, operationId.Span, route.MailboxId, route.PlacementId,
            isFinalPage, continuationToken.Span, acknowledgements);
        return await PrepareAsync(accountScope, selector, signer, binding,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<MailboxAuthenticatedRequestFrame> PrepareAsync(
        OutboxAccountScope accountScope,
        MailboxCredentialSelector selector,
        IMailboxOperationSigner signer,
        MailboxAuthenticatedRequestBinding binding,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(signer);
        if (!selector.AccountScope.Equals(accountScope))
            throw new InvalidOperationException("Mailbox selector belongs to another account scope.");
        var logicalId = LogicalSingleOperationId(selector, binding);
        var prepared = await credentials.PrepareScopedMailboxBatchAsync(
            new ScopedMailboxPrepareBatchRequest(
                accountScope,
                logicalId,
                logicalId,
                [new ScopedMailboxBatchSelector(
                    selector,
                    new Domain.MessageId(Convert.ToHexString(binding.OperationId.Span)),
                    binding.Operation)],
                [new ScopedMailboxBatchTarget(selector, binding)],
                // The authority clock is sampled at each prepare/resume.  A
                // caller clock must not keep an expired grant artificially live.
                TransportOutboxTime.Canonical(authority.TimeProvider.GetUtcNow())),
            signer,
            authority,
            cancellationToken).ConfigureAwait(false);
        return prepared.Frames.Single();
    }

    private static byte[] LogicalSingleOperationId(
        MailboxCredentialSelector selector,
        MailboxAuthenticatedRequestBinding binding)
    {
        using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(
            System.Security.Cryptography.HashAlgorithmName.SHA256);
        hash.AppendData("deep.mailbox.logical-single-operation.v1"u8);
        hash.AppendData([(byte)binding.Operation]);
        hash.AppendData(selector.ScopeId.Span);
        hash.AppendData(binding.OperationId.Span);
        return hash.GetHashAndReset()[..MailboxClientLimits.OperationIdLength];
    }
}

public sealed class MailboxAuthenticatedRequestFrame
{
    private readonly byte[] canonicalMau2;
    internal MailboxAuthenticatedRequestFrame(MailboxAuthenticatedOperation operation, ReadOnlySpan<byte> canonicalMau2)
    { Operation = operation; this.canonicalMau2 = canonicalMau2.ToArray(); }
    public MailboxAuthenticatedOperation Operation { get; }
    public byte[] GetCanonicalMau2Copy() => canonicalMau2.ToArray();
    public override string ToString() => "[strict-mailbox-authenticated-request]";
}
