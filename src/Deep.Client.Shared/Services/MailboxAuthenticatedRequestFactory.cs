using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

/// <summary>Builds the sole current signed canonical MAU2 client carrier.</summary>
public sealed class MailboxAuthenticatedRequestFactory
{
    private readonly IClientMailboxCredentialStateRepository state;
    private readonly IMailboxCapabilityRevocationSource revocations;
    private readonly TimeProvider timeProvider;

    public MailboxAuthenticatedRequestFactory(IClientMailboxCredentialStateRepository state,
        IMailboxCapabilityRevocationSource revocations, TimeProvider? timeProvider = null)
    {
        this.state = state ?? throw new ArgumentNullException(nameof(state));
        this.revocations = revocations ?? throw new ArgumentNullException(nameof(revocations));
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<MailboxAuthenticatedRequestFrame> CreateStoreAsync(
        IMailboxOperationSigner signer, MailboxEncryptedEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        _ = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        var now = Now();
        var lease = await state.LeaseCredentialAsync(
            MailboxCredentialGrantKind.PeerDeposit,
            now,
            new MailboxCredentialLeaseExpectation(
                envelope.Epoch,
                envelope.MailboxId.Bytes.Span,
                envelope.PlacementId.Bytes.Span),
            cancellationToken).ConfigureAwait(false);
        var generation = lease.Generation;
        var epoch = ActiveEpoch(generation, lease.ActiveEpoch, now);
        if (envelope.Epoch != epoch.Epoch || !Equal(envelope.MailboxId.Bytes.Span, generation.PeerMailboxId.Span) ||
            !Equal(envelope.PlacementId.Bytes.Span, epoch.PlacementId.Span))
            throw new InvalidOperationException("Mailbox store does not match the active credential route.");
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        return Sign(signer, binding, lease, epoch, revocations);
    }

    public async Task<MailboxAuthenticatedRequestFrame> CreateRetrieveAsync(
        IMailboxOperationSigner signer, ReadOnlyMemory<byte> operationId, ulong afterCursor,
        ushort maximumItems, ReadOnlyMemory<byte> continuationToken,
        CancellationToken cancellationToken = default)
    {
        ValidateRetrieveInputs(
            operationId.Span,
            maximumItems,
            continuationToken.Span);
        var now = Now();
        var lease = await state.LeaseCredentialAsync(
            MailboxCredentialGrantKind.OwnRetrieve,
            now,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        var generation = lease.Generation;
        var epoch = ActiveEpoch(generation, lease.ActiveEpoch, now);
        var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(epoch.Epoch, operationId.Span,
            new BlindedMailboxId(generation.OwnMailboxId.Span), new BlindedPlacementId(epoch.PlacementId.Span),
            afterCursor, maximumItems, continuationToken.Span);
        return Sign(signer, binding, lease, epoch, revocations);
    }

    public async Task<MailboxAuthenticatedRequestFrame> CreateAckAsync(
        IMailboxOperationSigner signer, ReadOnlyMemory<byte> operationId, bool isFinalPage,
        ReadOnlyMemory<byte> continuationToken, IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(acknowledgements);
        ValidateAckInputs(
            operationId.Span,
            isFinalPage,
            continuationToken.Span,
            acknowledgements);
        var now = Now();
        var lease = await state.LeaseCredentialAsync(
            MailboxCredentialGrantKind.OwnRetrieve,
            now,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        var generation = lease.Generation;
        var epoch = ActiveEpoch(generation, lease.ActiveEpoch, now);
        var binding = MailboxAuthenticatedRequestTranscript.ForAck(epoch.Epoch, operationId.Span,
            new BlindedMailboxId(generation.OwnMailboxId.Span), new BlindedPlacementId(epoch.PlacementId.Span),
            isFinalPage, continuationToken.Span, acknowledgements);
        return Sign(signer, binding, lease, epoch, revocations);
    }

    private static MailboxAuthenticatedRequestFrame Sign(IMailboxOperationSigner signer,
        MailboxAuthenticatedRequestBinding binding,
        MailboxCredentialOperationLease lease,
        MailboxCredentialEpoch epoch,
        IMailboxCapabilityRevocationSource revocations)
    {
        ArgumentNullException.ThrowIfNull(signer);
        var generation = lease.Generation;
        var key = signer.GetEd25519PublicKey();
        try
        {
            if (!Equal(key, generation.HolderPublicKey.Span))
                throw new InvalidOperationException("Mailbox signer does not match the pinned credential holder.");
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(lease.CanonicalGrant.Span);
            var expectedDomain = lease.Kind == MailboxCredentialGrantKind.OwnRetrieve
                ? MailboxCapabilityDomain.Retrieve
                : MailboxCapabilityDomain.Deposit;
            if (lease.ActiveEpoch != epoch.Epoch ||
                grant.Epoch != lease.ActiveEpoch ||
                grant.Generation != lease.ActiveEpoch ||
                grant.Domain != expectedDomain ||
                !Equal(grant.NetworkId.Span, generation.NetworkId.Span) ||
                !Equal(grant.IssuerPublicKey.Span, generation.IssuerPublicKey.Span) ||
                !Equal(grant.HolderPublicKey.Span, generation.HolderPublicKey.Span) ||
                !Equal(grant.PlacementCommitment.Span, epoch.PlacementCommitment.Span) ||
                !Equal(grant.MembershipCommitment.Span, epoch.MembershipCommitment.Span))
                throw new InvalidOperationException("Mailbox credential lease is incoherent.");
            if (revocations.IsRevoked(new MailboxCapabilityRevocationQuery
            {
                IssuerPublicKey = grant.IssuerPublicKey.ToArray(), Serial = grant.Serial.ToArray(),
                Domain = grant.Domain, Generation = grant.Generation, Epoch = grant.Epoch,
                MembershipCommitment = grant.MembershipCommitment.ToArray()
            }))
                throw new InvalidOperationException("Mailbox credential has been revoked.");
            var unsigned = new MailboxAuthenticatedPresentation
            {
                Operation = binding.Operation, OperationId = binding.OperationId.ToArray(),
                ReplayCounter = lease.ReplayCounter, RequestDigest = binding.RequestDigest.ToArray(),
                Grant = grant, HolderSignature = new byte[MailboxAuthenticatedCapabilityLimits.SignatureLength]
            };
            var transcript = MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(unsigned);
            var signature = signer.SignMailboxPresentation(binding.Operation, transcript);
            if (signature.Length != MailboxAuthenticatedCapabilityLimits.SignatureLength ||
                signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !new SodiumMailboxCapabilityCrypto().VerifyHolder(
                    generation.HolderPublicKey.Span, transcript, signature))
                throw new InvalidOperationException("Mailbox signer returned an invalid presentation signature.");
            var presentation = unsigned with { HolderSignature = signature.ToArray() };
            return new MailboxAuthenticatedRequestFrame(binding.Operation,
                MailboxAuthenticatedClientRequestCodec.Encode(new MailboxAuthenticatedClientRequest
                { Binding = binding, Presentation = presentation }));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private ulong Now() => checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());

    private static void ValidateRetrieveInputs(
        ReadOnlySpan<byte> operationId,
        ushort maximumItems,
        ReadOnlySpan<byte> continuationToken)
    {
        ValidateOperationId(operationId);
        if (maximumItems is 0 or > MailboxClientLimits.MaximumPageItems ||
            continuationToken.Length >
                MailboxClientLimits.MaximumContinuationTokenLength)
        {
            throw new ArgumentException(
                "Mailbox retrieve inputs are outside strict bounds.");
        }
    }

    private static void ValidateAckInputs(
        ReadOnlySpan<byte> operationId,
        bool isFinalPage,
        ReadOnlySpan<byte> continuationToken,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements)
    {
        ValidateOperationId(operationId);
        if (acknowledgements.Count is 0 or > MailboxClientLimits.MaximumPageItems ||
            continuationToken.Length >
                MailboxClientLimits.MaximumContinuationTokenLength ||
            isFinalPage != continuationToken.IsEmpty)
        {
            throw new ArgumentException(
                "Mailbox acknowledgement inputs are outside strict bounds.");
        }
        ulong previousCursor = 0;
        foreach (var acknowledgement in acknowledgements)
        {
            if (acknowledgement is null ||
                acknowledgement.Cursor <= previousCursor ||
                acknowledgement.EnvelopeDigest.Length !=
                    MailboxClientLimits.DigestLength ||
                acknowledgement.EnvelopeDigest.Span.IndexOfAnyExcept((byte)0) < 0)
            {
                throw new ArgumentException(
                    "Mailbox acknowledgements are not canonical.",
                    nameof(acknowledgements));
            }
            previousCursor = acknowledgement.Cursor;
        }
    }

    private static void ValidateOperationId(ReadOnlySpan<byte> operationId)
    {
        if (operationId.Length != MailboxClientLimits.OperationIdLength ||
            operationId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "Mailbox operation id is invalid.",
                nameof(operationId));
        }
    }

    private static MailboxCredentialEpoch ActiveEpoch(MailboxCredentialGeneration generation, ulong activeEpoch, ulong now) =>
        activeEpoch == generation.Current.Epoch && now >= generation.Current.NotBeforeUnixSeconds && now <= generation.Current.ExpiresAtUnixSeconds
            ? generation.Current : activeEpoch == generation.Next.Epoch && now >= generation.Next.NotBeforeUnixSeconds && now <= generation.Next.ExpiresAtUnixSeconds
                ? generation.Next : throw new InvalidOperationException("Mailbox credential is not active.");
    private static bool Equal(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
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
