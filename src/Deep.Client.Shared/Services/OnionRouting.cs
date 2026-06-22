using System.Text.Json;
using System.Text.Json.Serialization;
using Sodium;

namespace Deep.Client.Shared.Services;

internal static class OnionRouting
{
    public const string EnvelopeVersion = "deep-onion-v1";
    public const string ResponseVersion = "deep-onion-response-v1";
    public const string RelayLayerType = "relay";
    public const string StorageLayerType = "storage";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static OnionBuildResult BuildStorageRequest(
        IReadOnlyList<TransportRouteNode> route,
        string storagePath,
        object body)
    {
        if (route.Count == 0)
        {
            throw new InvalidOperationException("Storage onion route is empty.");
        }

        foreach (var node in route)
        {
            if (string.IsNullOrWhiteSpace(node.X25519PublicKey))
            {
                throw new InvalidOperationException($"Route node {node.RouterId} does not publish an onion key.");
            }
        }

        for (var index = 1; index < route.Count; index++)
        {
            if (string.IsNullOrWhiteSpace(route[index].RpcEndpoint))
            {
                throw new InvalidOperationException($"Route node {route[index].RouterId} does not publish a relay RPC endpoint.");
            }
        }

        var responseKeyPair = PublicKeyBox.GenerateKeyPair();
        var responsePublicKey = Convert.ToBase64String(responseKeyPair.PublicKey);
        OnionEnvelope? envelope = null;

        for (var index = route.Count - 1; index >= 0; index--)
        {
            var node = route[index];
            var nodeKey = DecodeHex32(node.X25519PublicKey, nameof(node.X25519PublicKey));
            object layer = index == route.Count - 1
                ? new OnionLayer(
                    StorageLayerType,
                    null,
                    null,
                    null,
                    storagePath,
                    JsonSerializer.SerializeToElement(body, JsonOptions),
                    responsePublicKey)
                : new OnionLayer(
                    RelayLayerType,
                    route[index + 1].RouterId,
                    route[index + 1].RpcEndpoint,
                    envelope,
                    null,
                    null,
                    null);

            envelope = EncryptForNode(nodeKey, layer);
        }

        return new OnionBuildResult(
            new OnionRequest(envelope ?? throw new InvalidOperationException("Failed to build onion request.")),
            responseKeyPair.PrivateKey);
    }

    public static JsonElement DecryptResponse(OnionResponseEnvelope envelope, byte[] responsePrivateKey)
    {
        if (!string.Equals(envelope.Version, ResponseVersion, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Unsupported onion response version.");
        }

        var ephemeralPublicKey = Convert.FromBase64String(envelope.EphemeralPublicKey);
        var nonce = Convert.FromBase64String(envelope.Nonce);
        var ciphertext = Convert.FromBase64String(envelope.Ciphertext);
        var plaintext = PublicKeyBox.Open(ciphertext, nonce, responsePrivateKey, ephemeralPublicKey);
        using var document = JsonDocument.Parse(plaintext);
        return document.RootElement.Clone();
    }

    private static OnionEnvelope EncryptForNode(byte[] recipientPublicKey, object plaintext)
    {
        using var keyPair = PublicKeyBox.GenerateKeyPair();
        var nonce = PublicKeyBox.GenerateNonce();
        var plaintextBytes = JsonSerializer.SerializeToUtf8Bytes(plaintext, JsonOptions);
        var ciphertext = PublicKeyBox.Create(plaintextBytes, nonce, keyPair.PrivateKey, recipientPublicKey);

        return new OnionEnvelope(
            EnvelopeVersion,
            Convert.ToBase64String(keyPair.PublicKey),
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(ciphertext));
    }

    private static byte[] DecodeHex32(string value, string argumentName)
    {
        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }

        if (normalized.Length != 64 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("Expected 32-byte hex value.", argumentName);
        }

        return Convert.FromHexString(normalized);
    }
}

internal sealed record OnionBuildResult(
    OnionRequest Request,
    byte[] ResponsePrivateKey);

internal sealed record OnionEnvelope(
    string Version,
    string EphemeralPublicKey,
    string Nonce,
    string Ciphertext);

internal sealed record OnionResponseEnvelope(
    string Version,
    string EphemeralPublicKey,
    string Nonce,
    string Ciphertext);

internal sealed record OnionRequest(
    OnionEnvelope Envelope);

internal sealed record OnionLayer(
    string Type,
    string? NextRouterId,
    string? NextRpcEndpoint,
    OnionEnvelope? Inner,
    string? StoragePath,
    JsonElement? Body,
    string? ResponsePublicKey);
