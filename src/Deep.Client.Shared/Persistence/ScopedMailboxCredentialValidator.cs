using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence;

internal static class ScopedMailboxCredentialValidator
{
    private const int MaximumLogicalIdentifierUtf8Bytes = 512;
    private static readonly System.Text.UTF8Encoding StrictUtf8 = new(false, true);
    internal const int MaximumBatchTargets = 2048;
    internal const long MaximumBatchRequestBytes = 128L * 1024 * 1024;

    internal static MailboxCredentialRole RoleFor(
        MailboxAuthenticatedOperation operation) => operation switch
        {
            MailboxAuthenticatedOperation.Store =>
                MailboxCredentialRole.Deposit,
            MailboxAuthenticatedOperation.Retrieve or
                MailboxAuthenticatedOperation.Ack =>
                MailboxCredentialRole.Retrieve,
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };

    internal static void EnsureRoleAllowed(
        MailboxCredentialSelector selector,
        MailboxCredentialRole role)
    {
        if (selector.Kind == MailboxCredentialScopeKind.Peer &&
            role != MailboxCredentialRole.Deposit)
        {
            throw new InvalidOperationException(
                "Peer mailbox scopes are deposit-only.");
        }
    }

    internal static void ValidateGeneration(
        ScopedMailboxCredentialGeneration value,
        VerifiedOfficialMailboxAuthority authority,
        ISet<string> serials)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(value.Selector);
        ArgumentNullException.ThrowIfNull(value.Current);
        ArgumentNullException.ThrowIfNull(value.Next);
        ArgumentNullException.ThrowIfNull(value.CurrentReplicas);
        ArgumentNullException.ThrowIfNull(value.NextReplicas);
        ArgumentNullException.ThrowIfNull(serials);
        authority.Validate();
        if (!Nonzero(value.Generation.Span, 32) ||
            !Nonzero(value.HolderPublicKey.Span, 32) ||
            !Nonzero(value.MailboxId.Span, 32) ||
            value.Next.Epoch != value.Current.Epoch + 1 ||
            value.Current.NotBeforeUnixSeconds >=
                value.Next.NotBeforeUnixSeconds ||
            value.Next.NotBeforeUnixSeconds >
                value.Current.ExpiresAtUnixSeconds ||
            value.Current.ExpiresAtUnixSeconds >=
                value.Next.ExpiresAtUnixSeconds ||
            authority.NowUnixSeconds > value.Current.ExpiresAtUnixSeconds ||
            !Fixed(
                value.Current.PlacementCommitment.Span,
                MailboxPlacementCommitment.Compute(
                    new BlindedPlacementId(
                        value.Current.PlacementId.Span))) ||
            !Fixed(
                value.Next.PlacementCommitment.Span,
                MailboxPlacementCommitment.Compute(
                    new BlindedPlacementId(
                        value.Next.PlacementId.Span))) ||
            value.Selector.Kind == MailboxCredentialScopeKind.Self &&
                value.Retrieve is null ||
            value.Selector.Kind == MailboxCredentialScopeKind.Peer &&
                (value.Deposit is null || value.Retrieve is not null) ||
            value.Selector.Kind == MailboxCredentialScopeKind.Group &&
                value.Deposit is null)
        {
            throw new InvalidDataException(
                "Scoped mailbox credential generation is invalid.");
        }

        ValidateEpoch(value, value.Current, authority, serials);
        ValidateEpoch(value, value.Next, authority, serials);
    }

    internal static MailboxAuthenticatedGrant ValidateCanonicalGrant(
        ReadOnlySpan<byte> encoded,
        MailboxCredentialRole role,
        ulong epoch,
        ulong notBeforeUnixSeconds,
        ulong expiresAtUnixSeconds,
        ReadOnlySpan<byte> placementCommitment,
        ReadOnlySpan<byte> membershipCommitment,
        ReadOnlySpan<byte> holderPublicKey,
        VerifiedOfficialMailboxAuthority authority,
        bool rejectRevoked)
    {
        MailboxAuthenticatedGrant grant;
        try
        {
            grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(encoded);
        }
        catch (Exception exception) when (
            exception is ArgumentException or
                MailboxAuthenticatedCapabilityException)
        {
            throw new InvalidDataException(
                "Scoped mailbox grant is not canonical.", exception);
        }

        var canonical = MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant);
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuer = authority.ResolveIssuer(grant);
        if (!Fixed(encoded, canonical) ||
            grant.Lifecycle != MailboxCapabilityLifecycle.Active ||
            grant.OverlapUntilUnixSeconds != 0 ||
            grant.Epoch != epoch ||
            grant.Generation < authority.MinimumGeneration ||
            issuer.AllowedLifecycle != grant.Lifecycle ||
            grant.Generation < issuer.MinimumGeneration ||
            grant.Generation > issuer.MaximumGeneration ||
            grant.NotBeforeUnixSeconds < issuer.ValidFromUnixSeconds ||
            grant.ExpiresAtUnixSeconds > issuer.ValidUntilUnixSeconds ||
            grant.NotBeforeUnixSeconds != notBeforeUnixSeconds ||
            grant.ExpiresAtUnixSeconds != expiresAtUnixSeconds ||
            grant.Domain != (role == MailboxCredentialRole.Deposit
                ? MailboxCapabilityDomain.Deposit
                : MailboxCapabilityDomain.Retrieve) ||
            !Fixed(grant.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(grant.HolderPublicKey.Span, holderPublicKey) ||
            !Fixed(grant.PlacementCommitment.Span,
                placementCommitment) ||
            !Fixed(grant.MembershipCommitment.Span,
                membershipCommitment) ||
            !crypto.VerifyIssuer(
                grant.IssuerPublicKey.Span,
                MailboxAuthenticatedCapabilityCodec
                    .GetGrantSigningBytes(grant),
                grant.IssuerSignature.Span))
        {
            throw new InvalidDataException(
                "Scoped mailbox grant is invalid or unauthenticated.");
        }
        if (rejectRevoked && authority.Revocations.IsRevoked(
                RevocationQuery(grant)))
        {
            throw new InvalidOperationException(
                "Scoped mailbox grant is revoked.");
        }
        return grant;
    }

    internal static void ValidateBindingRoute(
        MailboxAuthenticatedRequestBinding binding,
        ulong epoch,
        ReadOnlySpan<byte> mailbox,
        ReadOnlySpan<byte> placement)
    {
        ArgumentNullException.ThrowIfNull(binding);
        (ulong Epoch, ReadOnlyMemory<byte> Mailbox,
            ReadOnlyMemory<byte> Placement) route =
            binding.Operation switch
            {
                MailboxAuthenticatedOperation.Store => StoreRoute(
                    MailboxAuthenticatedRequestTranscript.DecodeStoreBody(
                        binding.CanonicalRequest.Span)),
                MailboxAuthenticatedOperation.Retrieve => RetrieveRoute(
                    MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
                        binding.CanonicalRequest.Span)),
                MailboxAuthenticatedOperation.Ack => AckRoute(
                    MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                        binding.CanonicalRequest.Span)),
                _ => throw new InvalidOperationException(
                    "Mailbox operation is unsupported.")
            };
        if (route.Epoch != epoch ||
            !Fixed(route.Mailbox.Span, mailbox) ||
            !Fixed(route.Placement.Span, placement))
        {
            throw new InvalidOperationException(
                "Mailbox request route was not selected by the scoped resolver.");
        }

        static (ulong, ReadOnlyMemory<byte>, ReadOnlyMemory<byte>) StoreRoute(
            MailboxEncryptedEnvelope value) =>
            (value.Epoch, value.MailboxId.Bytes, value.PlacementId.Bytes);
        static (ulong, ReadOnlyMemory<byte>, ReadOnlyMemory<byte>) RetrieveRoute(
            MailboxAuthenticatedRetrieveBody value) =>
            (value.Epoch, value.MailboxId.Bytes, value.PlacementId.Bytes);
        static (ulong, ReadOnlyMemory<byte>, ReadOnlyMemory<byte>) AckRoute(
            MailboxAuthenticatedAckBody value) =>
            (value.Epoch, value.MailboxId.Bytes, value.PlacementId.Bytes);
    }

    internal static void ValidateBatch(
        ScopedMailboxPrepareBatchRequest request,
        IMailboxOperationSigner signer)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.AccountScope);
        ArgumentNullException.ThrowIfNull(request.Targets);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(request.Selectors);
        if (request.ParentOperationId.Length != 16 ||
            request.ParentOperationId.Span.IndexOfAnyExcept((byte)0) < 0 ||
            request.SemanticOperationId.Length != 16 ||
            request.SemanticOperationId.Span.IndexOfAnyExcept((byte)0) < 0 ||
            request.Targets.Count is < 1 or > MaximumBatchTargets ||
            request.Selectors.Count != request.Targets.Count ||
            request.CreatedAt != TransportOutboxTime.Canonical(
                request.CreatedAt))
        {
            throw new ArgumentException("Scoped mailbox batch is invalid.");
        }
        ValidateResumeBatch(
            new ScopedMailboxResumeBatchRequest(
                request.AccountScope,
                request.ParentOperationId,
                request.SemanticOperationId,
                request.Selectors),
            signer);

        long requestBytes = 0;
        for (var ordinal = 0; ordinal < request.Targets.Count; ordinal++)
        {
            var target = request.Targets[ordinal];
            var selector = request.Selectors[ordinal];
            ArgumentNullException.ThrowIfNull(target);
            ArgumentNullException.ThrowIfNull(target.Selector);
            ArgumentNullException.ThrowIfNull(target.Binding);
            if (!target.Selector.ScopeId.Span.SequenceEqual(selector.Selector.ScopeId.Span) ||
                target.Binding.Operation != selector.Operation)
            {
                throw new InvalidOperationException(
                    "Mailbox target does not match its logical batch selector.");
            }
            if (!target.Selector.AccountScope.Equals(request.AccountScope))
            {
                throw new InvalidOperationException(
                    "Mailbox target belongs to another account scope.");
            }
            requestBytes = checked(
                requestBytes + target.Binding.CanonicalRequest.Length);
            if (requestBytes > MaximumBatchRequestBytes)
            {
                throw new ArgumentException(
                    "Mailbox batch exceeds its canonical request byte bound.");
            }
        }
    }

    internal static byte[] ComputePlanDigest(
        ScopedMailboxPrepareBatchRequest request) =>
        ComputePlanDigest(
            request.AccountScope,
            request.ParentOperationId,
            request.SemanticOperationId,
            request.Selectors);

    internal static void ValidateResumeBatch(
        ScopedMailboxResumeBatchRequest request,
        IMailboxOperationSigner signer)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.AccountScope);
        ArgumentNullException.ThrowIfNull(request.Selectors);
        ArgumentNullException.ThrowIfNull(signer);
        if (request.ParentOperationId.Length != 16 ||
            request.ParentOperationId.Span.IndexOfAnyExcept((byte)0) < 0 ||
            request.SemanticOperationId.Length != 16 ||
            request.SemanticOperationId.Span.IndexOfAnyExcept((byte)0) < 0 ||
            request.Selectors.Count is < 1 or > MaximumBatchTargets)
        {
            throw new ArgumentException("Scoped mailbox resume batch is invalid.");
        }

        byte[]? previousScope = null;
        string? previousWire = null;
        foreach (var selector in request.Selectors)
        {
            ValidateSelector(request.AccountScope, selector);
            var scope = selector.Selector.ScopeId.ToArray();
            var scopeOrder = previousScope is null
                ? -1
                : previousScope.AsSpan().SequenceCompareTo(scope);
            if (previousScope is not null &&
                (scopeOrder > 0 ||
                 scopeOrder == 0 && string.CompareOrdinal(
                     previousWire, selector.WireMessageId.Value) >= 0))
            {
                throw new ArgumentException(
                    "Mailbox logical selectors are not in canonical unique order.");
            }
            previousScope = scope;
            previousWire = selector.WireMessageId.Value;
        }
    }

    internal static byte[] ComputePlanDigest(
        ScopedMailboxResumeBatchRequest request) =>
        ComputePlanDigest(
            request.AccountScope,
            request.ParentOperationId,
            request.SemanticOperationId,
            request.Selectors);

    private static byte[] ComputePlanDigest(
        OutboxAccountScope accountScope,
        ReadOnlyMemory<byte> parentOperationId,
        ReadOnlyMemory<byte> semanticOperationId,
        IReadOnlyList<ScopedMailboxBatchSelector> selectors)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("deep.mailbox.logical-prepared-batch.v3"u8);
        hash.AppendData(accountScope.Value);
        hash.AppendData(parentOperationId.Span);
        hash.AppendData(semanticOperationId.Span);
        foreach (var selector in selectors)
        {
            hash.AppendData([(byte)selector.Operation]);
            hash.AppendData(selector.Selector.ScopeId.Span);
            AppendString(hash, selector.WireMessageId.Value);
        }
        return hash.GetHashAndReset();
    }

    private static void ValidateSelector(
        OutboxAccountScope accountScope,
        ScopedMailboxBatchSelector value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(value.Selector);
        if (!value.Selector.AccountScope.Equals(accountScope) ||
            string.IsNullOrWhiteSpace(value.WireMessageId.Value) ||
            !Enum.IsDefined(value.Operation) ||
            LogicalIdentifierByteCount(value.WireMessageId.Value) >
                MaximumLogicalIdentifierUtf8Bytes)
        {
            throw new InvalidOperationException("Mailbox logical batch selector is invalid.");
        }
    }

    private static void AppendString(IncrementalHash hash, string value)
    {
        var bytes = StrictUtf8.GetBytes(value);
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }

    private static int LogicalIdentifierByteCount(string value)
    {
        try
        {
            return StrictUtf8.GetByteCount(value);
        }
        catch (System.Text.EncoderFallbackException exception)
        {
            throw new ArgumentException(
                "Mailbox logical identifier is not valid UTF-8.", exception);
        }
    }

    internal static MailboxAuthenticatedRequestFrame Sign(
        MailboxAuthenticatedRequestBinding binding,
        IMailboxOperationSigner signer,
        MailboxAuthenticatedGrant grant,
        ulong counter,
        ReadOnlySpan<byte> holderKey)
    {
        var publicKey = signer.GetEd25519PublicKey();
        try
        {
            if (!Fixed(publicKey, holderKey))
            {
                throw new InvalidOperationException(
                    "Mailbox signer does not match scoped credential holder.");
            }
            var unsigned = new MailboxAuthenticatedPresentation
            {
                Operation = binding.Operation,
                OperationId = binding.OperationId.ToArray(),
                ReplayCounter = counter,
                RequestDigest = binding.RequestDigest.ToArray(),
                Grant = grant,
                HolderSignature =
                    new byte[MailboxAuthenticatedCapabilityLimits
                        .SignatureLength]
            };
            var transcript = MailboxAuthenticatedCapabilityCodec
                .GetPresentationSigningBytes(unsigned);
            var signature = signer.SignMailboxPresentation(
                binding.Operation, transcript);
            if (signature.Length !=
                    MailboxAuthenticatedCapabilityLimits.SignatureLength ||
                !new SodiumMailboxCapabilityCrypto().VerifyHolder(
                    holderKey, transcript, signature))
            {
                throw new InvalidOperationException(
                    "Mailbox signer returned an invalid signature.");
            }
            return new MailboxAuthenticatedRequestFrame(
                binding.Operation,
                MailboxAuthenticatedClientRequestCodec.Encode(
                    new MailboxAuthenticatedClientRequest
                    {
                        Binding = binding,
                        Presentation = unsigned with
                        {
                            HolderSignature = signature
                        }
                    }));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    internal static MailboxCapabilityRevocationQuery RevocationQuery(
        MailboxAuthenticatedGrant grant) => new()
        {
            IssuerPublicKey = grant.IssuerPublicKey.ToArray(),
            Serial = grant.Serial.ToArray(),
            Domain = grant.Domain,
            Generation = grant.Generation,
            Epoch = grant.Epoch,
            MembershipCommitment = grant.MembershipCommitment.ToArray()
        };

    internal static bool Fixed(
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void ValidateEpoch(
        ScopedMailboxCredentialGeneration value,
        MailboxCredentialEpoch epoch,
        VerifiedOfficialMailboxAuthority authority,
        ISet<string> serials)
    {
        if (value.Selector.Kind == MailboxCredentialScopeKind.Group &&
            !Fixed(
                epoch.MembershipCommitment.Span,
                value.Selector.GroupMembershipCommitment.Span))
        {
            throw new InvalidDataException(
                "Group credential is not bound to verified membership.");
        }
        ValidateGrant(value.Retrieve, MailboxCredentialRole.Retrieve);
        ValidateGrant(value.Deposit, MailboxCredentialRole.Deposit);

        void ValidateGrant(
            MailboxCredentialGrantSet? set,
            MailboxCredentialRole role)
        {
            if (set is null)
            {
                return;
            }
            var encoded = epoch.Epoch == value.Current.Epoch
                ? set.CurrentGrant
                : set.NextGrant;
            var grant = ValidateCanonicalGrant(
                encoded.Span,
                role,
                epoch.Epoch,
                epoch.NotBeforeUnixSeconds,
                epoch.ExpiresAtUnixSeconds,
                epoch.PlacementCommitment.Span,
                epoch.MembershipCommitment.Span,
                value.HolderPublicKey.Span,
                authority,
                rejectRevoked: false);
            if (authority.Revocations.IsRevoked(RevocationQuery(grant)))
            {
                throw new InvalidDataException(
                    "Scoped mailbox grant is revoked.");
            }
            var serialKey = Convert.ToHexString(grant.IssuerPublicKey.Span) +
                ":" + Convert.ToHexString(grant.Serial.Span);
            if (!serials.Add(serialKey))
            {
                throw new InvalidDataException(
                    "Scoped mailbox grant serial is reused.");
            }
        }
    }

    private static bool Nonzero(ReadOnlySpan<byte> value, int length) =>
        value.Length == length &&
        value.IndexOfAnyExcept((byte)0) >= 0;
}
