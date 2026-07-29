using System.Buffers.Binary;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed partial class MetadataPrivacyCharacterizationTests
{
    private const string AlicePhrase =
        "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed";
    private const string BobPhrase =
        "update vague zinger boxes ornament renting glass gained island nabbing afield calamity nabbing";
    private const string MetadataGate = "DEEP_SURVIVAL_METADATA_GATE";

    private const int SenderSessionIdOffset = 8;
    private const int SenderEd25519Offset = 41;
    private const int RecipientSessionIdOffset = 73;
    private const int NonceOffset = 106;
    private const int WrappedLengthOffset = 118;
    private const int CiphertextLengthOffset = 120;

    [Fact]
    public void Dpe1Header_ContainsClearSenderAndRecipientIdentifiers()
    {
        using var sender = new SessionIdentityProvider(AlicePhrase);
        using var recipient = new SessionIdentityProvider(BobPhrase);
        var marker = Encoding.UTF8.GetBytes("synthetic-p01-content-marker");

        var envelope = sender.CreateEnvelopeCodec()
            .Encrypt(E2eeEnvelopeKind.Message, recipient.SessionId, marker);

        Assert.Equal("DPE1"u8.ToArray(), envelope[..4]);
        Assert.Equal(E2eeEnvelopeCodec.ProtocolVersion, envelope[4]);
        Assert.Equal((byte)E2eeEnvelopeKind.Message, envelope[5]);
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(envelope.AsSpan(6, 2)));
        Assert.Equal(
            Convert.FromHexString(sender.SessionId.Value),
            envelope[SenderSessionIdOffset..SenderEd25519Offset]);
        Assert.Equal(
            Convert.FromHexString(recipient.SessionId.Value),
            envelope[RecipientSessionIdOffset..NonceOffset]);
        Assert.Equal(
            E2eeEnvelopeCodec.WrappedContentEncryptionKeySize,
            BinaryPrimitives.ReadUInt16BigEndian(envelope.AsSpan(WrappedLengthOffset, 2)));
        Assert.Equal(
            checked((uint)marker.Length),
            BinaryPrimitives.ReadUInt32BigEndian(envelope.AsSpan(CiphertextLengthOffset, 4)));
        Assert.False(ContainsSequence(envelope, marker));
    }

    [Fact]
    public async Task StorageStore_ExposesTargetPairAndStableIdempotencyMaterial()
    {
        using var senderIdentity = new SessionIdentityProvider(AlicePhrase);
        using var recipientIdentity = new SessionIdentityProvider(BobPhrase);
        var requests = new List<JsonElement>();
        using var client = new HttpClient(new CaptureHandler(async request =>
        {
            var bytes = await request.Content!.ReadAsByteArrayAsync();
            using var document = JsonDocument.Parse(bytes);
            requests.Add(document.RootElement.Clone());
            return Json(new { hash = "synthetic-storage-hash" });
        }))
        {
            BaseAddress = new Uri("https://storage.test/")
        };
        var transport = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions(
                "https://storage.test",
                Namespace: 0,
                MetadataMode: SessionStorageMetadataMode.LegacyCompatibility));
        var message = new OutboundMessageEnvelope(
            senderIdentity.SessionId,
            recipientIdentity.SessionId,
            "synthetic outer payload",
            [],
            DateTimeOffset.Parse("2026-07-18T00:00:00Z"),
            null,
            new MessageId("synthetic-message-p01"));

        await transport.SendAsync(message);
        await transport.SendAsync(message);

        Assert.Equal(2, requests.Count);
        Assert.All(
            requests,
            request => Assert.Equal(
                recipientIdentity.SessionId.Value,
                request.GetProperty("pubkey").GetString()));
        Assert.Equal(
            requests[0].GetProperty("idempotency_key").GetString(),
            requests[1].GetProperty("idempotency_key").GetString());

        var managedPayload = Convert.FromBase64String(requests[0].GetProperty("data").GetString()!);
        using var payload = JsonDocument.Parse(managedPayload);
        Assert.Equal(senderIdentity.SessionId.Value, payload.RootElement.GetProperty("sender").GetString());
        Assert.Equal(recipientIdentity.SessionId.Value, payload.RootElement.GetProperty("recipient").GetString());
    }

    [Fact]
    public void PushSubscription_ExposesRawAccountAndStableProviderToken()
    {
        using var fixture = LoadSyntheticFixture();
        var sender = fixture.RootElement.GetProperty("identifiers").GetProperty("sender_session_id").GetString()!;
        var token = fixture.RootElement.GetProperty("identifiers").GetProperty("push_token").GetString()!;
        var request = new PushSubscriptionRequest(
            sender,
            new string('3', 64),
            [0, 10],
            true,
            "firebase",
            1_782_000_000,
            Convert.ToBase64String(new byte[64]),
            new PushSubscriptionServiceInfo(token),
            new string('4', 64));

        var json = JsonSerializer.SerializeToUtf8Bytes(request);
        using var document = JsonDocument.Parse(json);

        Assert.Equal(sender, document.RootElement.GetProperty("pubkey").GetString());
        Assert.Equal(
            token,
            document.RootElement.GetProperty("service_info").GetProperty("token").GetString());
        Assert.Equal(2, document.RootElement.GetProperty("sig_v").GetInt32());
    }

    [Fact]
    public void SyntheticIdentifierScanner_DetectsExpectedManagedPayloadAndLogLeaks()
    {
        using var fixture = LoadSyntheticFixture();
        var identifiers = fixture.RootElement.GetProperty("identifiers");
        var sender = identifiers.GetProperty("sender_session_id").GetString()!;
        var recipient = identifiers.GetProperty("recipient_session_id").GetString()!;
        var pushToken = identifiers.GetProperty("push_token").GetString()!;
        var correlationId = identifiers.GetProperty("correlation_id").GetString()!;

        foreach (var item in fixture.RootElement.GetProperty("cases").EnumerateArray())
        {
            var actual = Scan(
                item.GetProperty("text").GetString()!,
                sender,
                recipient,
                pushToken,
                correlationId);
            var expected = item.GetProperty("expected_findings")
                .EnumerateArray()
                .Select(static value => value.GetString()!)
                .Order(StringComparer.Ordinal)
                .ToArray();

            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void MetadataExpectations_HaveUniqueActionableEvidenceAndProducerContracts()
    {
        using var document = LoadFixture("metadata-expectations.v1.json");
        var root = document.RootElement;

        Assert.Equal("deep-metadata-expectations.v1", root.GetProperty("schema").GetString());
        Assert.Equal(MetadataGate, root.GetProperty("feature_gate").GetString());
        var findings = root.GetProperty("findings").EnumerateArray().ToArray();
        Assert.NotEmpty(findings);
        Assert.Equal(
            findings.Length,
            findings.Select(static finding => finding.GetProperty("id").GetString())
                .Distinct(StringComparer.Ordinal)
                .Count());
        Assert.All(findings, static finding =>
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.GetProperty("observer").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(finding.GetProperty("domain").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(finding.GetProperty("status").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(finding.GetProperty("evidence").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(
                finding.GetProperty("required_producer_contract").GetString()));
        });
    }

    public static IEnumerable<object[]> BetaBlockingFindings()
    {
        using var document = LoadFixture("metadata-expectations.v1.json");
        foreach (var finding in document.RootElement.GetProperty("findings").EnumerateArray())
        {
            if (finding.GetProperty("beta_blocking").GetBoolean())
            {
                yield return
                [
                    finding.GetProperty("id").GetString()!,
                    finding.GetProperty("status").GetString()!,
                    finding.GetProperty("evidence").GetString()!
                ];
            }
        }
    }

    [Theory]
    [MemberData(nameof(BetaBlockingFindings))]
    public void BetaMetadataGate_FailsForEachUnresolvedFinding(
        string findingId,
        string status,
        string evidence)
    {
        Assert.False(string.IsNullOrWhiteSpace(findingId));
        Assert.False(string.IsNullOrWhiteSpace(evidence));

        if (!string.Equals(Environment.GetEnvironmentVariable(MetadataGate), "1", StringComparison.Ordinal))
        {
            Assert.Contains(status, new[] { "unresolved", "mitigated", "resolved" });
            return;
        }

        Assert.True(
            string.Equals(status, "resolved", StringComparison.Ordinal),
            $"{findingId}: strict metadata gate requires resolved evidence.");
    }

    private static string[] Scan(
        string text,
        string sender,
        string recipient,
        string pushToken,
        string correlationId)
    {
        var findings = new HashSet<string>(StringComparer.Ordinal);
        if (RawSessionIdRegex().IsMatch(text))
        {
            findings.Add("raw-session-id");
        }

        if (text.Contains(sender, StringComparison.Ordinal) &&
            text.Contains(recipient, StringComparison.Ordinal))
        {
            findings.Add("raw-sender-recipient-pair");
        }

        if (text.Contains(pushToken, StringComparison.Ordinal))
        {
            findings.Add("raw-push-token");
        }

        if (text.Contains(correlationId, StringComparison.Ordinal))
        {
            findings.Add("stable-cross-transport-id");
        }

        return findings.Order(StringComparer.Ordinal).ToArray();
    }

    private static JsonDocument LoadSyntheticFixture() =>
        LoadFixture("metadata-synthetic-fixtures.v1.json");

    private static bool ContainsSequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        for (var index = 0; index <= haystack.Length - needle.Length; index++)
        {
            if (haystack.Slice(index, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }

    private static JsonDocument LoadFixture(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", name);
        return JsonDocument.Parse(File.ReadAllBytes(path));
    }

    private static HttpResponseMessage Json<T>(T payload) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };

    [GeneratedRegex(@"(?<![0-9a-f])(?:05|15|25)[0-9a-f]{64}(?![0-9a-f])", RegexOptions.CultureInvariant)]
    private static partial Regex RawSessionIdRegex();

    private sealed class CaptureHandler(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            handler(request);
    }
}
