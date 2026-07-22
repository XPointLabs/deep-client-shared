using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using Deep.Protocol.DeepExtension.CompatibilityEnvelopes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Tests.Services;

public sealed class OpaqueMetadataTransportTests
{
    private const string AlicePhrase =
        "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade";
    private const string BobPhrase =
        "cactus canyon cedar circle cloud comet coral crystal dawn delta dune ember";

    [Fact]
    public async Task Deposit_RequestContainsOnlyOpaqueCapabilityAndAttemptLocalCorrelation()
    {
        using var sender = new SessionIdentityProvider(AlicePhrase);
        using var recipient = new SessionIdentityProvider(BobPhrase);
        var requests = new List<string>();
        using var client = CreateClient(async request =>
        {
            requests.Add(await request.Content!.ReadAsStringAsync());
            return Json(new { hash = "opaque-store-hash" });
        });
        var transport = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions("http://storage.test"),
            TestOpaqueDependencies.Create());
        var envelope = new OutboundMessageEnvelope(
            sender.SessionId,
            recipient.SessionId,
            E2eeClientTransport.WireBodyPrefix + Convert.ToBase64String("DPE1synthetic-red"u8),
            [],
            DateTimeOffset.Parse("2026-07-22T00:00:00Z"),
            null,
            new MessageId("logical-message-red"));

        await transport.SendAsync(envelope);
        await transport.SendAsync(envelope);

        Assert.Equal(2, requests.Count);
        Assert.All(requests, request =>
        {
            Assert.DoesNotContain(sender.SessionId.Value, request, StringComparison.Ordinal);
            Assert.DoesNotContain(recipient.SessionId.Value, request, StringComparison.Ordinal);
            using var json = JsonDocument.Parse(request);
            Assert.False(json.RootElement.TryGetProperty("pubkey", out _));
            Assert.True(json.RootElement.TryGetProperty("deposit_capability", out _));
            Assert.True(json.RootElement.TryGetProperty("attempt_id", out _));
            Assert.StartsWith(
                "DPB1",
                Encoding.ASCII.GetString(
                    Convert.FromBase64String(json.RootElement.GetProperty("data").GetString()!)),
                StringComparison.Ordinal);
        });
        using var first = JsonDocument.Parse(requests[0]);
        using var second = JsonDocument.Parse(requests[1]);
        Assert.NotEqual(
            first.RootElement.GetProperty("attempt_id").GetString(),
            second.RootElement.GetProperty("attempt_id").GetString());
        Assert.NotEqual(
            first.RootElement.GetProperty("idempotency_key").GetString(),
            second.RootElement.GetProperty("idempotency_key").GetString());
    }

    [Fact]
    public async Task Retrieve_RequestUsesRotatingOpaqueHandleWithoutAccountAuthenticationMaterial()
    {
        using var recipient = new SessionIdentityProvider(BobPhrase);
        var requests = new List<string>();
        using var client = CreateClient(async request =>
        {
            requests.Add(await request.Content!.ReadAsStringAsync());
            return Json(new { messages = Array.Empty<object>() });
        });
        var transport = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions("http://storage.test"),
            TestOpaqueDependencies.Create());

        await transport.RetrieveAuthenticatedAsync(recipient, null, 10);
        await transport.RetrieveAuthenticatedAsync(recipient, null, 10);

        Assert.Equal(2, requests.Count);
        Assert.All(requests, request =>
        {
            Assert.DoesNotContain(recipient.SessionId.Value, request, StringComparison.Ordinal);
            using var json = JsonDocument.Parse(request);
            Assert.False(json.RootElement.TryGetProperty("pubkey", out _));
            Assert.False(json.RootElement.TryGetProperty("pubkey_ed25519", out _));
            Assert.False(json.RootElement.TryGetProperty("signature", out _));
            Assert.True(json.RootElement.TryGetProperty("retrieve_capability", out _));
            Assert.True(json.RootElement.TryGetProperty("attempt_id", out _));
        });
        using var first = JsonDocument.Parse(requests[0]);
        using var second = JsonDocument.Parse(requests[1]);
        Assert.NotEqual(
            first.RootElement.GetProperty("retrieve_capability").GetString(),
            second.RootElement.GetProperty("retrieve_capability").GetString());
        Assert.NotEqual(
            first.RootElement.GetProperty("attempt_id").GetString(),
            second.RootElement.GetProperty("attempt_id").GetString());
    }

    [Fact]
    public async Task OpaqueDepositAndRetrieve_PreserveContentE2eeAndLogicalDeduplication()
    {
        var stored = new List<(string Hash, long Timestamp, string Placement, string Data)>();
        var retrievedCount = 0;
        using var client = CreateClient(async request =>
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            if (request.RequestUri!.AbsolutePath.EndsWith("/store", StringComparison.Ordinal))
            {
                stored.Add((
                    $"opaque-hash-{stored.Count + 1}",
                    DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    body.RootElement.GetProperty("placement_key").GetString()!,
                    body.RootElement.GetProperty("data").GetString()!));
                return Json(new { hash = stored[^1].Hash });
            }

            var placement = body.RootElement.GetProperty("placement_key").GetString();
            retrievedCount = stored.Count(item => item.Placement == placement);
            return Json(new
            {
                messages = stored.Where(item => item.Placement == placement).Select(static item => new
                {
                    hash = item.Hash,
                    timestamp = item.Timestamp,
                    data = item.Data
                })
            });
        });
        var raw = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions("http://storage.test"),
            TestOpaqueDependencies.Create());
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        using var alice = new E2eeClientTransport(
            raw,
            _ => Task.FromResult<string?>(AlicePhrase),
            new SystemClock(),
            new InMemorySessionStore());
        using var bob = new E2eeClientTransport(
            raw,
            _ => Task.FromResult<string?>(BobPhrase),
            new SystemClock(),
            new InMemorySessionStore());
        var logical = new OutboundMessageEnvelope(
            aliceIdentity.SessionId,
            bobIdentity.SessionId,
            "content remains encrypted",
            [],
            DateTimeOffset.UtcNow,
            null,
            new MessageId("opaque-logical-dedup"));

        await alice.SendAsync(logical);
        await alice.SendAsync(logical);
        var diagnosticRaw = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions("http://storage.test"),
            TestOpaqueDependencies.Create());
        var diagnosticBatch = await diagnosticRaw.RetrieveAuthenticatedAsync(bobIdentity, null, 10);
        Assert.Equal(2, diagnosticBatch.Entries.Count);
        Assert.True(diagnosticRaw.TryDecodeInboxEntry(
            diagnosticBatch.Entries[0],
            bobIdentity.SessionId,
            out _));
        var received = await bob.ReceiveAsync(bobIdentity.SessionId);

        Assert.Equal(4, stored.Count);
        Assert.Equal(2, retrievedCount);
        var delivered = Assert.Single(received);
        Assert.Equal(logical.Id, delivered.Id);
        Assert.Equal(logical.Body, delivered.Body);
        Assert.Equal(aliceIdentity.SessionId, delivered.Sender);
        Assert.Equal(bobIdentity.SessionId, delivered.Recipient);
    }

    [Fact]
    public void OpaqueModeWithoutReviewedDependencies_FailsClosed()
    {
        using var client = CreateClient(_ => Task.FromResult(Json(new { })));

        var exception = Assert.Throws<InvalidOperationException>(() =>
            new SessionStorageMessageTransport(
                client,
                new SessionStorageMessageTransportOptions("http://storage.test")));

        Assert.Contains("explicit capability, crypto and replay", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LegacyCompatibility_IsExplicitAndNotMarkedMetadataPrivate()
    {
        using var client = CreateClient(_ => Task.FromResult(Json(new { })));
        var transport = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions(
                "http://storage.test",
                MetadataMode: SessionStorageMetadataMode.LegacyCompatibility));

        Assert.False(transport.UsesOpaqueMetadata);
    }

    [Fact]
    public void ReleaseRuntime_RejectsExplicitLegacyCompatibility()
    {
        using var client = CreateClient(_ => Task.FromResult(Json(new { })));
        var transport = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions(
                "http://storage.test",
                MetadataMode: SessionStorageMetadataMode.LegacyCompatibility));

        var exception = Assert.Throws<InvalidOperationException>(() => new ClientRuntime(
            new InMemorySessionStore(),
            ClientFeatureFlags.ReleaseDefaults,
            new SystemClock(),
            transport));

        Assert.Contains("not opaque P03", exception.Message, StringComparison.Ordinal);
    }

    private static HttpClient CreateClient(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) =>
        new(new CaptureHandler(handler))
        {
            BaseAddress = new Uri("http://storage.test/")
        };

    private static HttpResponseMessage Json<T>(T payload) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };

    private sealed class CaptureHandler(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            handler(request);
    }

    internal static class TestOpaqueDependencies
    {
        public static OpaqueSessionStorageDependencies Create() =>
            new(new TestCapabilities(), new TestCompatibilityCrypto(), new TestReplayGuard());
    }

    private sealed class TestCapabilities : IOpaqueMailboxCapabilityProvider
    {
        private long counter;

        public OpaqueMailboxDepositMaterial CreateDeposit(
            OutboundMessageEnvelope envelope,
            ReadOnlyMemory<byte> transportAttemptId,
            uint currentBucket) =>
            new(
                Presentation(
                    new RotatingDepositCapability(Derive("deposit", envelope.Recipient.Value)),
                    transportAttemptId,
                    currentBucket),
                new OpaquePlacementKey(Derive("placement", envelope.Recipient.Value)),
                Derive("recipient-key", envelope.Recipient.Value),
                Convert.FromHexString(envelope.Sender.Value));

        public OpaqueMailboxRetrieveMaterial CreateRetrieve(
            SessionIdentityProvider identity,
            ReadOnlyMemory<byte> transportAttemptId,
            uint currentBucket)
        {
            var generation = Interlocked.Increment(ref counter);
            return new OpaqueMailboxRetrieveMaterial(
                Presentation(
                    new RotatingRetrieveCapability(
                        Derive("retrieve", $"{identity.SessionId.Value}:{generation}")),
                    transportAttemptId,
                    currentBucket),
                new OpaquePlacementKey(Derive("placement", identity.SessionId.Value)));
        }

        public ReadOnlyMemory<byte> GetRecipientKeyMaterial(SessionId recipient) =>
            Derive("recipient-key", recipient.Value);

        private MailboxCapabilityPresentation Presentation(
            MailboxDomainValue value,
            ReadOnlyMemory<byte> transportAttemptId,
            uint currentBucket) =>
            new()
            {
                DomainValue = value,
                Lifecycle = MailboxCapabilityLifecycle.Active,
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                Generation = 1,
                NotBeforeBucket = currentBucket,
                ExpiresAtBucket = checked(currentBucket + 24),
                OverlapUntilBucket = 0,
                ReplayCounter = checked((ulong)Interlocked.Increment(ref counter)),
                IdempotencyKey = transportAttemptId,
                FreeAdmission = null
            };

        private static byte[] Derive(string domain, string value) =>
            SHA256.HashData(Encoding.UTF8.GetBytes($"deep-test/{domain}/{value}"));
    }

    private sealed class TestCompatibilityCrypto : ICompatibilityEnvelopeCrypto
    {
        private const int SenderLength = 33;
        private const int TagLength = 16;

        public CompatibilityEnvelopeSealedResult Seal(CompatibilityEnvelopeSealRequest request)
        {
            Assert.Equal(SenderLength, request.SenderAuthenticationSecret.Length);
            var plaintext = new byte[SenderLength + request.Plaintext.Length];
            request.SenderAuthenticationSecret.Span.CopyTo(plaintext);
            request.Plaintext.Span.CopyTo(plaintext.AsSpan(SenderLength));
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagLength];
            using var aes = new AesGcm(DeriveKey(request.RecipientKeyMaterial.Span, request.Domain), TagLength);
            aes.Encrypt(
                DeriveNonce(request.NonceContext.Span, request.Domain),
                plaintext,
                ciphertext,
                tag,
                request.AssociatedData.Span);
            CryptographicOperations.ZeroMemory(plaintext);
            var sealedBytes = new byte[ciphertext.Length + tag.Length];
            ciphertext.CopyTo(sealedBytes, 0);
            tag.CopyTo(sealedBytes, ciphertext.Length);
            return new CompatibilityEnvelopeSealedResult(sealedBytes);
        }

        public CompatibilityEnvelopeOpenedResult Open(CompatibilityEnvelopeOpenRequest request)
        {
            if (request.Ciphertext.Length <= TagLength + SenderLength)
            {
                throw new CryptographicException("Test compatibility ciphertext is truncated.");
            }

            var ciphertext = request.Ciphertext.Span[..^TagLength];
            var plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(DeriveKey(request.RecipientKeyMaterial.Span, request.Domain), TagLength);
            aes.Decrypt(
                DeriveNonce(request.NonceContext.Span, request.Domain),
                ciphertext,
                request.Ciphertext.Span[^TagLength..],
                plaintext,
                request.AssociatedData.Span);
            var sender = plaintext.AsSpan(0, SenderLength).ToArray();
            var content = plaintext.AsSpan(SenderLength).ToArray();
            CryptographicOperations.ZeroMemory(plaintext);
            return new CompatibilityEnvelopeOpenedResult(content, sender);
        }

        private static byte[] DeriveKey(ReadOnlySpan<byte> recipient, string domain) =>
            SHA256.HashData([.. recipient, .. Encoding.UTF8.GetBytes(domain)]);

        private static byte[] DeriveNonce(ReadOnlySpan<byte> nonceContext, string domain) =>
            SHA256.HashData([.. nonceContext, .. Encoding.UTF8.GetBytes(domain)])[..12];
    }

    private sealed class TestReplayGuard : ICompatibilityEnvelopeReplayGuard
    {
        private readonly HashSet<string> seen = new(StringComparer.Ordinal);

        public bool TryAccept(CompatibilityEnvelopeReplayScope scope) =>
            seen.Add(
                Convert.ToHexString(scope.Capability.Span) + ":" +
                scope.ExpiryBucket + ":" +
                Convert.ToHexString(scope.ReplayMaterial.Span));
    }
}
