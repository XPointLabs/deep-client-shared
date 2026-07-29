using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

/// <summary>Builds the current strict MAU2 carrier. It intentionally does not synthesize MCP1,
/// MST1, MRT1, MAK1, legacy JSON, or a mixed-version fallback.</summary>
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
        var generation = await state.ReadCredentialGenerationAsync(cancellationToken).ConfigureAwait(false);
        var now = Now(); var epoch = ActiveEpoch(generation,
            await state.ReadActiveCredentialEpochAsync(cancellationToken).ConfigureAwait(false), now);
        if (envelope.Epoch != epoch.Epoch || !Equal(envelope.MailboxId.Bytes.Span, generation.PeerMailboxId.Span) ||
            !Equal(envelope.PlacementId.Bytes.Span, epoch.PlacementId.Span))
            throw new InvalidOperationException("Mailbox store does not match the active credential route.");
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        var lease = await state.AllocateReplayCounterAsync(MailboxCredentialGrantKind.PeerDeposit, now, cancellationToken).ConfigureAwait(false);
        return Sign(signer, generation, binding, lease, revocations);
    }

    public async Task<MailboxAuthenticatedRequestFrame> CreateRetrieveAsync(
        IMailboxOperationSigner signer, ReadOnlyMemory<byte> operationId, ulong afterCursor,
        ushort maximumItems, ReadOnlyMemory<byte> continuationToken,
        CancellationToken cancellationToken = default)
    {
        var generation = await state.ReadCredentialGenerationAsync(cancellationToken).ConfigureAwait(false);
        var now = Now(); var epoch = ActiveEpoch(generation,
            await state.ReadActiveCredentialEpochAsync(cancellationToken).ConfigureAwait(false), now);
        var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(epoch.Epoch, operationId.Span,
            new BlindedMailboxId(generation.OwnMailboxId.Span), new BlindedPlacementId(epoch.PlacementId.Span),
            afterCursor, maximumItems, continuationToken.Span);
        var lease = await state.AllocateReplayCounterAsync(MailboxCredentialGrantKind.OwnRetrieve, now, cancellationToken).ConfigureAwait(false);
        return Sign(signer, generation, binding, lease, revocations);
    }

    public async Task<MailboxAuthenticatedRequestFrame> CreateAckAsync(
        IMailboxOperationSigner signer, ReadOnlyMemory<byte> operationId, bool isFinalPage,
        ReadOnlyMemory<byte> continuationToken, IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(acknowledgements);
        var generation = await state.ReadCredentialGenerationAsync(cancellationToken).ConfigureAwait(false);
        var now = Now(); var epoch = ActiveEpoch(generation,
            await state.ReadActiveCredentialEpochAsync(cancellationToken).ConfigureAwait(false), now);
        var binding = MailboxAuthenticatedRequestTranscript.ForAck(epoch.Epoch, operationId.Span,
            new BlindedMailboxId(generation.OwnMailboxId.Span), new BlindedPlacementId(epoch.PlacementId.Span),
            isFinalPage, continuationToken.Span, acknowledgements);
        var lease = await state.AllocateReplayCounterAsync(MailboxCredentialGrantKind.OwnRetrieve, now, cancellationToken).ConfigureAwait(false);
        return Sign(signer, generation, binding, lease, revocations);
    }

    private static MailboxAuthenticatedRequestFrame Sign(IMailboxOperationSigner signer,
        MailboxCredentialGeneration generation, MailboxAuthenticatedRequestBinding binding,
        MailboxCredentialGrantLease lease, IMailboxCapabilityRevocationSource revocations)
    {
        ArgumentNullException.ThrowIfNull(signer);
        var key = signer.GetEd25519PublicKey();
        try
        {
            if (!Equal(key, generation.HolderPublicKey.Span))
                throw new InvalidOperationException("Mailbox signer does not match the pinned credential holder.");
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(lease.CanonicalGrant.Span);
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
