using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class PushNotificationCryptoTests
{
    [Fact]
    public void EnvelopeRoundTripsWithExplicitBinding()
    {
        var key = RandomNumberGenerator.GetBytes(PushNotificationCrypto.KeySizeBytes);
        var binding = PushNotificationCrypto.ComputeSubscriptionBinding("05session", "firebase", "device-token");
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(new PushNotificationPayload("hash", 0, 100, 200, Convert.ToBase64String("hello"u8.ToArray())));

        var envelope = PushNotificationCrypto.Encrypt(plaintext, key, binding, "05session");

        Assert.True(PushNotificationCrypto.TryDecrypt(envelope, key, binding, "05session", out var decrypted));
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EnvelopeFailsClosedForTamperWrongKeyPlaintextAndOversize()
    {
        var key = RandomNumberGenerator.GetBytes(PushNotificationCrypto.KeySizeBytes);
        var binding = PushNotificationCrypto.ComputeSubscriptionBinding("05session", "firebase", "device-token");
        var plaintext = Encoding.UTF8.GetBytes("authenticated push");
        var envelope = PushNotificationCrypto.Encrypt(plaintext, key, binding, "05session");

        envelope[^1] ^= 0x01;
        Assert.False(PushNotificationCrypto.TryDecrypt(envelope, key, binding, "05session", out _));
        var validEnvelope = PushNotificationCrypto.Encrypt(plaintext, key, binding, "05session");
        Assert.False(PushNotificationCrypto.TryDecrypt(validEnvelope, RandomNumberGenerator.GetBytes(32), binding, "05session", out _));
        Assert.False(PushNotificationCrypto.TryDecrypt(validEnvelope, key, binding, "05other-session", out _));
        Assert.False(PushNotificationCrypto.TryDecrypt(Encoding.UTF8.GetBytes("plaintext"), key, binding, "05session", out _));
        Assert.Throws<ArgumentOutOfRangeException>(() => PushNotificationCrypto.Encrypt(new byte[PushNotificationCrypto.MaxPlaintextBytes + 1], key, binding, "05session"));
    }

    [Fact]
    public void PayloadSchemaRejectsMalformedAndOversizeData()
    {
        var malformed = Encoding.UTF8.GetBytes("{\"message_hash\":\"hash\",\"namespace\":0}");
        Assert.False(PushNotificationCrypto.TryDecodePayload(malformed, out _));

        var oversized = JsonSerializer.SerializeToUtf8Bytes(new PushNotificationPayload(
            "hash", 0, 100, 200, Convert.ToBase64String(new byte[PushNotificationCrypto.MaxMessageDataBytes + 1])));
        Assert.False(PushNotificationCrypto.TryDecodePayload(oversized, out _));
    }

    [Fact]
    public void PayloadWindowRejectsExpiredFutureAndUnboundedLifetimes()
    {
        const long now = 1_800_000_000;
        var valid = new PushNotificationPayload("hash", 0, now - 10, now + 60, null);
        var future = valid with { Timestamp = now + PushNotificationCrypto.AllowedFutureClockSkewSeconds + 1, Expiration = now + 1_000 };
        var expired = valid with { Expiration = now };
        var unbounded = valid with { Timestamp = now, Expiration = now + PushNotificationCrypto.MaxPayloadLifetimeSeconds + 1 };

        Assert.True(PushNotificationCrypto.IsPayloadCurrentlyValid(valid, now));
        Assert.False(PushNotificationCrypto.IsPayloadCurrentlyValid(future, now));
        Assert.False(PushNotificationCrypto.IsPayloadCurrentlyValid(expired, now));
        Assert.False(PushNotificationCrypto.IsPayloadCurrentlyValid(unbounded, now));
    }

    [Fact]
    public void ReplayIdIsStableAndBoundToSubscriptionAndMessage()
    {
        var payload = new PushNotificationPayload("hash", 0, 100, 200, null);

        var first = PushNotificationCrypto.ComputeReplayId(payload, "subscription-a");
        var repeated = PushNotificationCrypto.ComputeReplayId(payload, "subscription-a");
        var otherMessage = PushNotificationCrypto.ComputeReplayId(payload with { MessageHash = "other" }, "subscription-a");
        var otherSubscription = PushNotificationCrypto.ComputeReplayId(payload, "subscription-b");

        Assert.Equal(first, repeated);
        Assert.NotEqual(first, otherMessage);
        Assert.NotEqual(first, otherSubscription);
        Assert.Equal(64, first.Length);
    }
}
