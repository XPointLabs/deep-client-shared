using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Client.Shared.Platform;

namespace Deep.Client.Shared.Services;

public static class PushNotificationCrypto
{
    public const string PackageName = "network.xpoint.deep";
    public const string EnvelopeProtocolVersion = "1";
    public const byte EnvelopeVersion = 1;
    public const int KeySizeBytes = 32;
    public const int NonceSizeBytes = 12;
    public const int TagSizeBytes = 16;
    public const int MaxPlaintextBytes = 2048;
    public const int MaxEnvelopeBytes = 4096;
    public const int MaxMessageDataBytes = 1024;
    public const int MaxMessageHashChars = 128;
    public const long MaxPayloadLifetimeSeconds = 28L * 24 * 60 * 60;
    public const long AllowedFutureClockSkewSeconds = 5L * 60;

    public static byte[] Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        string subscriptionBinding,
        string sessionBinding)
    {
        ValidateKey(key);
        ValidateBinding(subscriptionBinding, sessionBinding);
        if (plaintext.Length == 0 || plaintext.Length > MaxPlaintextBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintext));
        }

        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];
        using var aes = new AesGcm(key, TagSizeBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, CreateAssociatedData(subscriptionBinding, sessionBinding));

        var envelope = new byte[1 + nonce.Length + ciphertext.Length + tag.Length];
        envelope[0] = EnvelopeVersion;
        Buffer.BlockCopy(nonce, 0, envelope, 1, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, envelope, 1 + nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, envelope, 1 + nonce.Length + ciphertext.Length, tag.Length);
        if (envelope.Length > MaxEnvelopeBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintext));
        }

        return envelope;
    }

    public static bool TryDecrypt(
        ReadOnlySpan<byte> envelope,
        ReadOnlySpan<byte> key,
        string subscriptionBinding,
        string sessionBinding,
        out byte[] plaintext)
    {
        plaintext = [];
        try
        {
            ValidateKey(key);
            ValidateBinding(subscriptionBinding, sessionBinding);
            if (envelope.Length < 1 + NonceSizeBytes + TagSizeBytes || envelope.Length > MaxEnvelopeBytes ||
                envelope[0] != EnvelopeVersion)
            {
                return false;
            }

            var ciphertextLength = envelope.Length - 1 - NonceSizeBytes - TagSizeBytes;
            if (ciphertextLength <= 0 || ciphertextLength > MaxPlaintextBytes)
            {
                return false;
            }

            var nonce = envelope.Slice(1, NonceSizeBytes);
            var ciphertext = envelope.Slice(1 + NonceSizeBytes, ciphertextLength);
            var tag = envelope.Slice(1 + NonceSizeBytes + ciphertextLength, TagSizeBytes);
            plaintext = new byte[ciphertextLength];
            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, CreateAssociatedData(subscriptionBinding, sessionBinding));
            return true;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            plaintext = [];
            return false;
        }
        catch (ArgumentException)
        {
            plaintext = [];
            return false;
        }
    }

    public static string ComputeSubscriptionBinding(string sessionId, string service, string token)
    {
        if (string.IsNullOrWhiteSpace(sessionId) || string.IsNullOrWhiteSpace(service) || string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("Push binding inputs are required.");
        }

        var material = $"deep.push/subscription/v1|session={sessionId.Trim().ToLowerInvariant()}|service={service.Trim().ToLowerInvariant()}|token={token.Trim()}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    public static byte[] CreateAssociatedData(string subscriptionBinding, string sessionBinding)
    {
        ValidateBinding(subscriptionBinding, sessionBinding);
        return Encoding.UTF8.GetBytes($"deep.push/envelope/v1|package={PackageName}|protocol={EnvelopeProtocolVersion}|subscription={subscriptionBinding}|session={sessionBinding}");
    }

    public static bool TryDecodePayload(ReadOnlySpan<byte> plaintext, out PushNotificationPayload? payload)
    {
        payload = null;
        if (plaintext.Length == 0 || plaintext.Length > MaxPlaintextBytes)
        {
            return false;
        }

        try
        {
            payload = JsonSerializer.Deserialize<PushNotificationPayload>(plaintext, JsonOptions);
            if (payload is null || string.IsNullOrWhiteSpace(payload.MessageHash) ||
                payload.MessageHash.Length > MaxMessageHashChars || payload.Namespace < 0 ||
                payload.Timestamp <= 0 || payload.Expiration <= payload.Timestamp)
            {
                payload = null;
                return false;
            }

            if (payload.Data is not null)
            {
                if (payload.Data.Length > ((MaxMessageDataBytes + 2) / 3 * 4) + 4)
                {
                    payload = null;
                    return false;
                }

                var data = Convert.FromBase64String(payload.Data);
                if (data.Length > MaxMessageDataBytes)
                {
                    payload = null;
                    return false;
                }
            }

            return true;
        }
        catch (FormatException)
        {
            payload = null;
            return false;
        }
        catch (JsonException)
        {
            payload = null;
            return false;
        }
    }

    public static bool IsPayloadCurrentlyValid(PushNotificationPayload payload, long nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (nowUnixSeconds <= 0 || payload.Timestamp <= 0 || payload.Expiration <= payload.Timestamp)
        {
            return false;
        }

        var lifetime = payload.Expiration - payload.Timestamp;
        return lifetime <= MaxPayloadLifetimeSeconds &&
               payload.Timestamp <= nowUnixSeconds + AllowedFutureClockSkewSeconds &&
               nowUnixSeconds < payload.Expiration;
    }

    public static string ComputeReplayId(
        PushNotificationPayload payload,
        string subscriptionBinding)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (string.IsNullOrWhiteSpace(subscriptionBinding) || subscriptionBinding.Length > 128)
        {
            throw new ArgumentException("Push subscription binding is invalid.", nameof(subscriptionBinding));
        }

        var material = string.Join(
            '|',
            "deep.push/replay/v1",
            subscriptionBinding,
            payload.Namespace.ToString(System.Globalization.CultureInfo.InvariantCulture),
            payload.Timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
            payload.Expiration.ToString(System.Globalization.CultureInfo.InvariantCulture),
            payload.MessageHash);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    private static void ValidateKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySizeBytes)
        {
            throw new ArgumentException("Push encryption key must be 256 bits.", nameof(key));
        }
    }

    private static void ValidateBinding(string subscriptionBinding, string sessionBinding)
    {
        if (string.IsNullOrWhiteSpace(subscriptionBinding) || string.IsNullOrWhiteSpace(sessionBinding) ||
            subscriptionBinding.Length > 128 || sessionBinding.Length > 128)
        {
            throw new ArgumentException("Push envelope bindings are invalid.");
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
}

public sealed record PushNotificationPayload(
    [property: JsonPropertyName("message_hash")] string MessageHash,
    [property: JsonPropertyName("namespace")] int Namespace,
    [property: JsonPropertyName("timestamp")] long Timestamp,
    [property: JsonPropertyName("expiration")] long Expiration,
    [property: JsonPropertyName("data")] string? Data);

public sealed record PushNotificationKeyState(
    string KeyHex,
    string SubscriptionBinding,
    string SessionBinding,
    PushRegistration Registration,
    bool RemoteSubscribed = false);
