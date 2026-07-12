using System.Text.Json;
using Sodium;

namespace Deep.Client.Shared.Services;

public static class RelayContactSignatureVerifier
{
    private const string Algorithm = "ed25519";
    private const string PayloadVersion = "deep-relay-contact-v1";
    private static readonly TimeSpan MaximumContactAge = TimeSpan.FromHours(12);
    private static readonly TimeSpan MaximumFutureClockSkew = TimeSpan.FromMinutes(5);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static bool Verify(TransportRouteNode contact, DateTimeOffset now)
    {
        if (!string.Equals(contact.SignatureAlgorithm, Algorithm, StringComparison.OrdinalIgnoreCase)
            || contact.SignedAt == default
            || contact.ExpiresAt <= now
            || contact.ExpiresAt <= contact.SignedAt
            || contact.SignedAt > now.Add(MaximumFutureClockSkew)
            || now - contact.SignedAt >= MaximumContactAge)
        {
            return false;
        }

        try
        {
            var publicKey = DecodeHex(contact.RouterId, 32);
            var signature = DecodeHex(contact.Signature, 64);
            return PublicKeyAuth.VerifyDetached(signature, BuildSigningPayload(contact), publicKey);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            return false;
        }
    }

    private static byte[] BuildSigningPayload(TransportRouteNode contact)
    {
        var payload = new RelayContactSigningPayload(
            PayloadVersion,
            contact.RouterId,
            contact.PublicHost,
            contact.PublicIp,
            contact.PublicPort,
            contact.X25519PublicKey,
            contact.RpcEndpoint,
            contact.SignedAt.ToUnixTimeMilliseconds(),
            contact.ExpiresAt.ToUnixTimeMilliseconds(),
            contact.RouterVersion,
            contact.IsReachable,
            contact.Capabilities
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim())
                .Order(StringComparer.Ordinal)
                .ToArray());
        return JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
    }

    private static byte[] DecodeHex(string value, int expectedBytes)
    {
        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }
        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException($"Expected {expectedBytes}-byte hex value.");
        }
        return Convert.FromHexString(normalized);
    }

    private sealed record RelayContactSigningPayload(
        string Version,
        string RouterId,
        string PublicHost,
        string PublicIp,
        int PublicPort,
        string X25519PublicKey,
        string RpcEndpoint,
        long SignedAtUnixMs,
        long ExpiresAtUnixMs,
        string RouterVersion,
        bool IsReachable,
        IReadOnlyList<string> Capabilities);
}
