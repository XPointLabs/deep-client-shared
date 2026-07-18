using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Services;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class PushSignatureV2GoldenTests
{
    private const string FixtureSha256 = "4bca6bffffa751d124a322a51af878476522faa9ded8a56bd2c89f93ac1e576a";
    private static readonly string FixturePath =
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "push-signature-v2.golden.json");

    [Fact]
    public void GoldenFixture_PinsCanonicalBytesAndDeterministicEd25519Signatures()
    {
        var bytes = File.ReadAllBytes(FixturePath);
        Assert.Equal(FixtureSha256, Convert.ToHexStringLower(SHA256.HashData(bytes)));

        using var fixture = JsonDocument.Parse(bytes);
        Assert.Equal("deep.push-signature-v2-golden/v1", fixture.RootElement.GetProperty("schema").GetString());
        Assert.Equal(PushSubscriptionCanonicalFormat.SignatureVersion, fixture.RootElement.GetProperty("signature_version").GetInt32());

        var publicKey = Convert.FromHexString(
            fixture.RootElement.GetProperty("key").GetProperty("ed25519_public_key_hex").GetString()!);
        foreach (var goldenCase in fixture.RootElement.GetProperty("cases").EnumerateArray())
        {
            var request = ReadRequest(goldenCase);
            var canonical = CreateCanonical(request);
            var canonicalBytes = Encoding.UTF8.GetBytes(canonical);

            Assert.Equal(goldenCase.GetProperty("canonical").GetString(), canonical);
            Assert.DoesNotContain('\r', canonical);
            Assert.EndsWith("\n", canonical);
            Assert.Equal(goldenCase.GetProperty("canonical_utf8_length").GetInt32(), canonicalBytes.Length);
            Assert.Equal(goldenCase.GetProperty("canonical_hex").GetString(), Convert.ToHexStringLower(canonicalBytes));
            Assert.True(PublicKeyAuth.VerifyDetached(
                Convert.FromBase64String(request.Signature),
                canonicalBytes,
                publicKey));
        }
    }

    [Fact]
    public void GoldenSignatures_RejectTamperOfEveryCanonicalField()
    {
        using var fixture = JsonDocument.Parse(File.ReadAllBytes(FixturePath));
        var publicKey = Convert.FromHexString(
            fixture.RootElement.GetProperty("key").GetProperty("ed25519_public_key_hex").GetString()!);

        foreach (var goldenCase in fixture.RootElement.GetProperty("cases").EnumerateArray())
        {
            var request = ReadRequest(goldenCase);
            var tampered = new List<GoldenRequest>
            {
                request with { Pubkey = request.Pubkey[..^1] + (request.Pubkey[^1] == '0' ? "1" : "0") },
                request with { SigTs = request.SigTs + 1 },
                request with { Service = request.Service + "-tampered" },
                request with { Token = request.Token + "-tampered" }
            };

            if (request.Operation == "subscribe")
            {
                tampered.AddRange(
                [
                    request with { EncKey = (request.EncKey![0] == '0' ? "1" : "0") + request.EncKey[1..] },
                    request with { Data = !request.Data },
                    request with { Namespaces = [.. request.Namespaces, 99] },
                    request with { AppId = request.AppId + "-tampered" },
                    request with { AppVersion = request.AppVersion + "-tampered" }
                ]);
            }

            var signature = Convert.FromBase64String(request.Signature);
            Assert.All(
                tampered,
                candidate => Assert.False(PublicKeyAuth.VerifyDetached(
                    signature,
                    Encoding.UTF8.GetBytes(CreateCanonical(candidate)),
                    publicKey)));
        }
    }

    [Fact]
    public void PushDtos_IgnoreInboundSigVersionAndAlwaysSerializeVersionTwo()
    {
        var subscribeJson = """
            {
              "pubkey":"05abc",
              "session_ed25519":"ed",
              "namespaces":[0],
              "data":true,
              "service":"firebase",
              "sig_ts":1,
              "signature":"sig",
              "service_info":{"token":"token"},
              "enc_key":"key",
              "app_id":"app",
              "app_version":"1",
              "sig_v":99
            }
            """;
        var unsubscribeJson = """
            {
              "pubkey":"05abc",
              "session_ed25519":"ed",
              "service":"firebase",
              "sig_ts":1,
              "signature":"sig",
              "service_info":{"token":"token"},
              "sig_v":1
            }
            """;

        var subscribe = JsonSerializer.Deserialize<PushSubscriptionRequest>(subscribeJson);
        var unsubscribe = JsonSerializer.Deserialize<PushUnsubscribeRequest>(unsubscribeJson);

        Assert.Equal(2, subscribe!.SigVersion);
        Assert.Equal(2, unsubscribe!.SigVersion);
        Assert.Equal(2, JsonDocument.Parse(JsonSerializer.Serialize(subscribe)).RootElement.GetProperty("sig_v").GetInt32());
        Assert.Equal(2, JsonDocument.Parse(JsonSerializer.Serialize(unsubscribe)).RootElement.GetProperty("sig_v").GetInt32());
    }

    private static GoldenRequest ReadRequest(JsonElement goldenCase)
    {
        var operation = goldenCase.GetProperty("operation").GetString()!;
        var request = goldenCase.GetProperty("request");
        var namespaces = operation == "subscribe"
            ? goldenCase.GetProperty("unsorted_namespaces_for_canonicalizer")
                .EnumerateArray()
                .Select(static value => value.GetInt32())
                .ToArray()
            : [];

        return new GoldenRequest(
            operation,
            request.GetProperty("pubkey").GetString()!,
            request.GetProperty("sig_ts").GetInt64(),
            request.GetProperty("service").GetString()!,
            request.GetProperty("service_info").GetProperty("token").GetString()!,
            operation == "subscribe" ? request.GetProperty("enc_key").GetString() : null,
            operation == "subscribe" && request.GetProperty("data").GetBoolean(),
            namespaces,
            operation == "subscribe" ? request.GetProperty("app_id").GetString() : null,
            operation == "subscribe" ? request.GetProperty("app_version").GetString() : null,
            request.GetProperty("signature").GetString()!);
    }

    private static string CreateCanonical(GoldenRequest request) =>
        request.Operation == "subscribe"
            ? PushSubscriptionCanonicalFormat.CreateSubscribe(
                request.Pubkey,
                request.SigTs,
                request.Data,
                request.Namespaces,
                request.Service,
                request.Token,
                request.EncKey!,
                request.AppId!,
                request.AppVersion!)
            : PushSubscriptionCanonicalFormat.CreateUnsubscribe(
                request.Pubkey,
                request.SigTs,
                request.Service,
                request.Token);

    private sealed record GoldenRequest(
        string Operation,
        string Pubkey,
        long SigTs,
        string Service,
        string Token,
        string? EncKey,
        bool Data,
        IReadOnlyList<int> Namespaces,
        string? AppId,
        string? AppVersion,
        string Signature);
}
