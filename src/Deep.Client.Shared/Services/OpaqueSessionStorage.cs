using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.CompatibilityEnvelopes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Client.Shared.Services;

public enum SessionStorageMetadataMode
{
    OpaqueP03 = 1,
    LegacyCompatibility = 2
}

public sealed record OpaqueMailboxDepositMaterial(
    MailboxCapabilityPresentation Capability,
    OpaquePlacementKey PlacementKey,
    ReadOnlyMemory<byte> RecipientKeyMaterial,
    ReadOnlyMemory<byte> SenderAuthenticationSecret);

public sealed record OpaqueMailboxRetrieveMaterial(
    MailboxCapabilityPresentation Capability,
    OpaquePlacementKey PlacementKey);

/// <summary>
/// Production boundary for reviewed P03B capability lifecycle and key material.
/// The shared runtime intentionally provides no derivation implementation.
/// </summary>
public interface IOpaqueMailboxCapabilityProvider
{
    OpaqueMailboxDepositMaterial CreateDeposit(
        OutboundMessageEnvelope envelope,
        ReadOnlyMemory<byte> transportAttemptId,
        uint currentBucket);

    OpaqueMailboxRetrieveMaterial CreateRetrieve(
        SessionIdentityProvider identity,
        ReadOnlyMemory<byte> transportAttemptId,
        uint currentBucket);

    ReadOnlyMemory<byte> GetRecipientKeyMaterial(SessionId recipient);
}

public sealed record OpaqueSessionStorageDependencies(
    IOpaqueMailboxCapabilityProvider Capabilities,
    ICompatibilityEnvelopeCrypto Crypto,
    ICompatibilityEnvelopeReplayGuard ReplayGuard)
{
    internal void Validate()
    {
        ArgumentNullException.ThrowIfNull(Capabilities);
        ArgumentNullException.ThrowIfNull(Crypto);
        ArgumentNullException.ThrowIfNull(ReplayGuard);
    }
}

internal sealed record OpaqueStorageDeposit(
    string Capability,
    string PlacementKey,
    string AttemptId,
    string IdempotencyKey,
    string Data);

internal sealed record OpaqueStorageRetrieve(
    string Capability,
    string PlacementKey,
    string AttemptId);

internal sealed class OpaqueInboxDecodeCache
{
    private const int MaximumEntries = DurableInboxLimits.MaxPendingItemCount;
    private readonly object gate = new();
    private readonly Dictionary<string, InboundMessageEnvelope> entries = new(StringComparer.Ordinal);
    private readonly Queue<string> insertionOrder = new();

    public bool TryDecode(
        DurableInboxWireEntry entry,
        SessionId recipient,
        int ttlMilliseconds,
        OpaqueSessionStorageDependencies dependencies,
        out InboundMessageEnvelope envelope)
    {
        var key = recipient.Value + ":" + entry.ServerHash + ":" + entry.WireDigest;
        lock (gate)
        {
            if (entries.TryGetValue(key, out envelope!))
            {
                return true;
            }

            if (!OpaqueSessionStorageCodec.TryDecode(
                    entry,
                    recipient,
                    ttlMilliseconds,
                    dependencies,
                    out envelope))
            {
                return false;
            }

            entries.Add(key, envelope);
            insertionOrder.Enqueue(key);
            while (entries.Count > MaximumEntries)
            {
                entries.Remove(insertionOrder.Dequeue());
            }

            return true;
        }
    }
}

internal static class OpaqueSessionStorageCodec
{
    private const int Dpe1SenderOffset = 8;
    private const int Dpe1RecipientOffset = 73;
    private const int Dpe1SessionIdLength = 33;
    private const int BucketSeconds = 60 * 60;

    private static readonly OpaqueBundleNegotiatedProfile NegotiatedProfile = new(
        OpaqueBundleWireVersion.V1,
        OpaqueBundleFeatures.V1Required |
        OpaqueBundleFeatures.LegacyDpe1Compatibility |
        OpaqueBundleFeatures.AuthenticatedCompatibilityEnvelope,
        AllowLegacyDpe1: true);

    public static uint CurrentBucket() =>
        checked((uint)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / BucketSeconds));

    public static OpaqueStorageDeposit EncodeDeposit(
        OutboundMessageEnvelope envelope,
        int ttlMilliseconds,
        OpaqueSessionStorageDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        dependencies.Validate();

        var dpe1 = DecodeWireBody(envelope.Body);
        var attemptBytes = RandomNumberGenerator.GetBytes(OpaqueBundleLimits.IdentifierLength);
        var attemptId = new TransportAttemptId(attemptBytes);
        var currentBucket = CurrentBucket();
        var material = CreateDepositMaterial(
            dependencies.Capabilities,
            envelope,
            attemptBytes,
            currentBucket);
        ValidatePresentation(
            material.Capability,
            MailboxCapabilityDomain.Deposit,
            attemptBytes,
            currentBucket,
            ttlMilliseconds);
        ValidateDepositMaterial(material, envelope);

        var encodedCapability = EncodeCapability(material.Capability, "deposit");
        var expiryBucket = material.Capability.ExpiresAtBucket;

        var dedupMaterial = envelope.Id?.Value ?? Convert.ToHexStringLower(SHA256.HashData(dpe1));
        var dedupHash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("deep-p03-dedup-v1\n" + dedupMaterial));
        var dedupBytes = dedupHash.AsSpan(0, OpaqueBundleLimits.IdentifierLength).ToArray();
        if (dedupBytes.AsSpan().SequenceEqual(attemptBytes))
        {
            dedupBytes[^1] ^= 1;
        }

        var headerNonce = RandomNumberGenerator.GetBytes(CompatibilityEnvelopeLimits.NonceContextLength);
        var payloadNonce = RandomNumberGenerator.GetBytes(CompatibilityEnvelopeLimits.NonceContextLength);
        if (headerNonce.AsSpan().SequenceEqual(payloadNonce))
        {
            payloadNonce[^1] ^= 1;
        }

        try
        {
            byte[] encoded;
            try
            {
                encoded = CompatibilityMetadataEnvelopeCodec.Encode(
                    new CompatibilityEnvelopeWriteRequest
                    {
                        Capability = new OpaqueDepositCapability(encodedCapability),
                        TransportAttemptId = attemptId,
                        EndToEndDedupId = new EndToEndDedupId(dedupBytes),
                        ExpiryBucket = expiryBucket,
                        PaddingClass = SelectPaddingClass(dpe1.Length),
                        ReplayMaterial = RandomNumberGenerator.GetBytes(OpaqueBundleLimits.ReplayMaterialLength),
                        HeaderNonceContext = headerNonce,
                        PayloadNonceContext = payloadNonce,
                        RecipientKeyMaterial = material.RecipientKeyMaterial,
                        SenderAuthenticationSecret = material.SenderAuthenticationSecret,
                        LegacyDpe1 = dpe1
                    },
                    NegotiatedProfile,
                    dependencies.Crypto);
            }
            catch (Exception)
            {
                throw new InvalidOperationException(
                    "Opaque mailbox deposit encryption failed at the configured trust boundary.");
            }
            var attempt = Convert.ToBase64String(attemptBytes);
            return new OpaqueStorageDeposit(
                Convert.ToBase64String(encodedCapability),
                Convert.ToBase64String(material.PlacementKey.Bytes.Span),
                attempt,
                attempt,
                Convert.ToBase64String(encoded));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dpe1);
            CryptographicOperations.ZeroMemory(dedupHash);
            CryptographicOperations.ZeroMemory(dedupBytes);
            CryptographicOperations.ZeroMemory(headerNonce);
            CryptographicOperations.ZeroMemory(payloadNonce);
        }
    }

    public static OpaqueStorageRetrieve EncodeRetrieve(
        SessionIdentityProvider identity,
        int ttlMilliseconds,
        OpaqueSessionStorageDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(identity);
        dependencies.Validate();

        var attemptBytes = RandomNumberGenerator.GetBytes(OpaqueBundleLimits.IdentifierLength);
        var currentBucket = CurrentBucket();
        var material = CreateRetrieveMaterial(
            dependencies.Capabilities,
            identity,
            attemptBytes,
            currentBucket);
        ValidatePresentation(
            material.Capability,
            MailboxCapabilityDomain.Retrieve,
            attemptBytes,
            currentBucket,
            ttlMilliseconds);
        ValidateRetrieveMaterial(material, identity.SessionId);
        var encodedCapability = EncodeCapability(material.Capability, "retrieve");
        return new OpaqueStorageRetrieve(
            Convert.ToBase64String(encodedCapability),
            Convert.ToBase64String(material.PlacementKey.Bytes.Span),
            Convert.ToBase64String(attemptBytes));
    }

    public static bool TryDecode(
        DurableInboxWireEntry entry,
        SessionId recipient,
        int ttlMilliseconds,
        OpaqueSessionStorageDependencies dependencies,
        out InboundMessageEnvelope envelope)
    {
        envelope = default!;
        byte[]? encoded = null;
        byte[]? dpe1 = null;
        try
        {
            encoded = Convert.FromBase64String(entry.WirePayload);
            var currentBucket = CurrentBucket();
            var maximumTtlBuckets = checked((uint)Math.Max(
                1,
                (long)Math.Ceiling(ttlMilliseconds / (double)(BucketSeconds * 1000))));
            var opened = CompatibilityMetadataEnvelopeCodec.Decode(
                encoded,
                dependencies.Capabilities.GetRecipientKeyMaterial(recipient),
                new OpaqueBundleDecodePolicy
                {
                    MinimumVersion = OpaqueBundleWireVersion.V1,
                    MaximumVersion = OpaqueBundleWireVersion.V1,
                    SupportedCriticalFeatures = NegotiatedProfile.SupportedCriticalFeatures,
                    MinimumExpiryBucket = currentBucket,
                    MaximumExpiryBucket = checked(currentBucket + maximumTtlBuckets + 1),
                    AllowLegacyDpe1 = true
                },
                dependencies.Crypto,
                dependencies.ReplayGuard);
            dpe1 = opened.LegacyDpe1.ToArray();
            if (dpe1.Length < Dpe1RecipientOffset + Dpe1SessionIdLength)
            {
                return false;
            }

            var senderBytes = dpe1.AsSpan(Dpe1SenderOffset, Dpe1SessionIdLength);
            var recipientBytes = dpe1.AsSpan(Dpe1RecipientOffset, Dpe1SessionIdLength);
            if (!opened.SenderAuthenticationData.Span.SequenceEqual(senderBytes) ||
                !recipientBytes.SequenceEqual(Convert.FromHexString(recipient.Value)))
            {
                return false;
            }

            var sender = SessionId.Parse(Convert.ToHexStringLower(senderBytes));
            var digest = Convert.ToHexStringLower(SHA256.HashData(dpe1));
            envelope = new InboundMessageEnvelope(
                new MessageId("opaque-" + digest),
                sender,
                recipient,
                E2eeClientTransport.WireBodyPrefix + Convert.ToBase64String(dpe1),
                [],
                DateTimeOffset.FromUnixTimeMilliseconds(entry.StorageTimestamp),
                null,
                entry.ServerHash);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (OpaqueBundleException)
        {
            return false;
        }
        catch (CompatibilityEnvelopeException)
        {
            return false;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            if (encoded is not null)
            {
                CryptographicOperations.ZeroMemory(encoded);
            }

            if (dpe1 is not null)
            {
                CryptographicOperations.ZeroMemory(dpe1);
            }
        }
    }

    private static byte[] DecodeWireBody(string body)
    {
        if (string.IsNullOrWhiteSpace(body) ||
            !body.StartsWith(E2eeClientTransport.WireBodyPrefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Opaque P03 storage accepts only authenticated DPE1 wire bodies.");
        }

        var encoded = body[E2eeClientTransport.WireBodyPrefix.Length..]
            .Replace('-', '+')
            .Replace('_', '/');
        encoded = (encoded.Length % 4) switch
        {
            0 => encoded,
            2 => encoded + "==",
            3 => encoded + "=",
            _ => throw new FormatException("The DPE1 wire body has invalid base64url length.")
        };
        return Convert.FromBase64String(encoded);
    }

    private static void ValidatePresentation(
        MailboxCapabilityPresentation presentation,
        MailboxCapabilityDomain expectedDomain,
        ReadOnlySpan<byte> attemptId,
        uint currentBucket,
        int ttlMilliseconds)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        var actualDomain = presentation.DomainValue switch
        {
            RotatingDepositCapability => MailboxCapabilityDomain.Deposit,
            RotatingRetrieveCapability => MailboxCapabilityDomain.Retrieve,
            OpaquePlacementKey => MailboxCapabilityDomain.Placement,
            _ => throw new InvalidOperationException("The mailbox provider returned an unsupported capability domain.")
        };
        var maximumTtlBuckets = MaximumTtlBuckets(ttlMilliseconds);
        if (actualDomain != expectedDomain ||
            presentation.MixedVersion != MailboxMixedVersionMarker.StrictV1 ||
            presentation.Lifecycle != MailboxCapabilityLifecycle.Active)
        {
            throw new InvalidOperationException("The mailbox provider returned a non-strict capability presentation.");
        }

        if (presentation.NotBeforeBucket > currentBucket ||
            presentation.ExpiresAtBucket <= currentBucket ||
            presentation.ExpiresAtBucket > checked(currentBucket + maximumTtlBuckets + 1) ||
            presentation.NotBeforeBucket >= presentation.ExpiresAtBucket)
        {
            throw new InvalidOperationException("The mailbox capability validity window is not currently usable.");
        }

        if (presentation.Generation == 0 ||
            presentation.ReplayCounter == 0 ||
            !presentation.IdempotencyKey.Span.SequenceEqual(attemptId))
        {
            throw new InvalidOperationException("The mailbox capability replay scope is not bound to this transport attempt.");
        }
    }

    private static OpaqueMailboxDepositMaterial CreateDepositMaterial(
        IOpaqueMailboxCapabilityProvider provider,
        OutboundMessageEnvelope envelope,
        ReadOnlyMemory<byte> attemptId,
        uint currentBucket)
    {
        try
        {
            return provider.CreateDeposit(envelope, attemptId, currentBucket)
                ?? throw new InvalidOperationException();
        }
        catch (Exception)
        {
            throw new InvalidOperationException(
                "Opaque mailbox deposit material was rejected at the configured trust boundary.");
        }
    }

    private static OpaqueMailboxRetrieveMaterial CreateRetrieveMaterial(
        IOpaqueMailboxCapabilityProvider provider,
        SessionIdentityProvider identity,
        ReadOnlyMemory<byte> attemptId,
        uint currentBucket)
    {
        try
        {
            return provider.CreateRetrieve(identity, attemptId, currentBucket)
                ?? throw new InvalidOperationException();
        }
        catch (Exception)
        {
            throw new InvalidOperationException(
                "Opaque mailbox retrieve material was rejected at the configured trust boundary.");
        }
    }

    private static byte[] EncodeCapability(
        MailboxCapabilityPresentation presentation,
        string operation)
    {
        try
        {
            return MailboxCapabilityCodec.Encode(presentation);
        }
        catch (Exception)
        {
            throw new InvalidOperationException(
                $"Opaque mailbox {operation} capability was rejected at the configured trust boundary.");
        }
    }

    private static void ValidateDepositMaterial(
        OpaqueMailboxDepositMaterial material,
        OutboundMessageEnvelope envelope)
    {
        if (material.RecipientKeyMaterial.IsEmpty ||
            material.SenderAuthenticationSecret.IsEmpty ||
            material.RecipientKeyMaterial.Length > 512 ||
            material.SenderAuthenticationSecret.Length > 512)
        {
            throw new InvalidOperationException("Opaque mailbox deposit key material is outside strict bounds.");
        }

        var sender = Convert.FromHexString(envelope.Sender.Value);
        var recipient = Convert.FromHexString(envelope.Recipient.Value);
        if (ContainsSequence(material.Capability.DomainValue.Bytes.Span, sender) ||
            ContainsSequence(material.Capability.DomainValue.Bytes.Span, recipient) ||
            ContainsSequence(material.PlacementKey.Bytes.Span, sender) ||
            ContainsSequence(material.PlacementKey.Bytes.Span, recipient))
        {
            throw new InvalidOperationException("Opaque mailbox deposit addressing contains forbidden raw identity material.");
        }
    }

    private static void ValidateRetrieveMaterial(
        OpaqueMailboxRetrieveMaterial material,
        SessionId recipient)
    {
        var rawRecipient = Convert.FromHexString(recipient.Value);
        if (ContainsSequence(material.Capability.DomainValue.Bytes.Span, rawRecipient) ||
            ContainsSequence(material.PlacementKey.Bytes.Span, rawRecipient))
        {
            throw new InvalidOperationException("Opaque mailbox retrieve addressing contains forbidden raw identity material.");
        }
    }

    private static bool ContainsSequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle) =>
        haystack.IndexOf(needle) >= 0;

    private static uint MaximumTtlBuckets(int ttlMilliseconds)
    {
        if (ttlMilliseconds <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ttlMilliseconds));
        }

        return checked((uint)Math.Max(
            1,
            (long)Math.Ceiling(ttlMilliseconds / (double)(BucketSeconds * 1000))));
    }

    private static OpaqueBundlePaddingClass SelectPaddingClass(int dpe1Length) =>
        dpe1Length switch
        {
            <= 96 => OpaqueBundlePaddingClass.Bytes256,
            <= 800 => OpaqueBundlePaddingClass.Bytes1024,
            <= 3800 => OpaqueBundlePaddingClass.Bytes4096,
            _ => OpaqueBundlePaddingClass.Bytes16384
        };
}
