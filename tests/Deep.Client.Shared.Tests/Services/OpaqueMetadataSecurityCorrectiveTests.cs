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

public sealed class OpaqueMetadataSecurityCorrectiveTests
{
    private const string AlicePhrase =
        "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed";
    private const string BobPhrase =
        "update vague zinger boxes ornament renting glass gained island nabbing afield calamity nabbing";
    private const string CharliePhrase =
        "sickness rhino tilt yeti innocent network dogs boat feast ionic subtly zodiac ionic";

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(255)]
    public void UndefinedMetadataMode_IsRejected(int rawMode)
    {
        using var client = Client(_ => Json(new { }));
        var mode = (SessionStorageMetadataMode)rawMode;

        Assert.Throws<ArgumentOutOfRangeException>(() => new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions("https://storage.test", MetadataMode: mode)));
    }

    [Fact]
    public void ArbitraryAuthenticatedTransport_CannotForgeReleaseMetadataProof()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => new ClientRuntime(
            new InMemorySessionStore(),
            ClientFeatureFlags.ReleaseDefaults,
            new SystemClock(),
            new ForgedMetadataTransport()));

        Assert.Contains("not opaque P03", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(false, true)]
    public async Task CapabilityValidityWindow_IsEnforcedForDepositAndRetrieve(
        bool deposit,
        bool futureNotBefore)
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var provider = new MutatingCapabilities(
            new OpaqueMetadataTransportTests.TestCapabilities(),
            presentation => presentation with
            {
                NotBeforeBucket = futureNotBefore
                    ? checked(OpaqueSessionStorageCodec.CurrentBucket() + 1)
                    : checked(OpaqueSessionStorageCodec.CurrentBucket() - 2),
                ExpiresAtBucket = futureNotBefore
                    ? checked(OpaqueSessionStorageCodec.CurrentBucket() + 2)
                    : checked(OpaqueSessionStorageCodec.CurrentBucket() - 1)
            });
        using var client = Client(_ => Json(new { messages = Array.Empty<object>() }));
        var transport = Transport(client, provider);

        var exception = deposit
            ? await Assert.ThrowsAsync<InvalidOperationException>(() => transport.SendAsync(Wire(alice, bob)))
            : await Assert.ThrowsAsync<InvalidOperationException>(() =>
                transport.RetrieveAuthenticatedAsync(bob, null, 10));

        Assert.Contains("validity", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MaliciousProvider_RawCapabilityAndSecretExceptionAreRejectedWithoutLeak()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        using var client = Client(_ => Json(new { }));
        var rawProvider = new MutatingCapabilities(
            new OpaqueMetadataTransportTests.TestCapabilities(),
            presentation => presentation with
            {
                DomainValue = new RotatingDepositCapability(
                    Pad(Convert.FromHexString(bob.SessionId.Value), 64))
            });
        var rawTransport = Transport(client, rawProvider);

        var raw = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            rawTransport.SendAsync(Wire(alice, bob)));
        Assert.DoesNotContain(bob.SessionId.Value, raw.ToString(), StringComparison.Ordinal);

        var throwing = Transport(client, new ThrowingCapabilities(alice.SessionId.Value));
        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            throwing.SendAsync(Wire(alice, bob)));
        Assert.DoesNotContain(alice.SessionId.Value, thrown.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task TamperWrongRecipientAndReplay_FailClosed()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        using var charlie = new SessionIdentityProvider(CharliePhrase);
        string? stored = null;
        using var client = Client(async request =>
        {
            using var document = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            stored = document.RootElement.GetProperty("data").GetString();
            return Json(new { hash = "stored" });
        });
        var transport = Transport(client, new OpaqueMetadataTransportTests.TestCapabilities());
        await transport.SendAsync(Wire(alice, bob));
        var first = DurableInboxWireEntry.CreateBounded("first", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), stored!);

        var tamperedBytes = Convert.FromBase64String(stored!);
        tamperedBytes[^1] ^= 1;
        var tampered = DurableInboxWireEntry.CreateBounded(
            "tampered",
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            Convert.ToBase64String(tamperedBytes));
        Assert.False(transport.TryDecodeInboxEntry(tampered, bob.SessionId, out _));
        Assert.False(transport.TryDecodeInboxEntry(first, charlie.SessionId, out _));
        Assert.True(transport.TryDecodeInboxEntry(first, bob.SessionId, out _));

        var replay = DurableInboxWireEntry.CreateBounded(
            "replayed-at-storage",
            first.StorageTimestamp,
            first.WirePayload);
        Assert.False(transport.TryDecodeInboxEntry(replay, bob.SessionId, out _));
    }

    private static SessionStorageMessageTransport Transport(
        HttpClient client,
        IOpaqueMailboxCapabilityProvider provider) =>
        new(
            client,
            new SessionStorageMessageTransportOptions("https://storage.test"),
            new OpaqueSessionStorageDependencies(
                provider,
                new OpaqueMetadataTransportTests.TestCompatibilityCrypto(),
                new OpaqueMetadataTransportTests.TestReplayGuard()));

    private static OutboundMessageEnvelope Wire(
        SessionIdentityProvider sender,
        SessionIdentityProvider recipient)
    {
        var dpe1 = sender.CreateEnvelopeCodec().Encrypt(
            E2eeEnvelopeKind.Message,
            recipient.SessionId,
            "corrective"u8);
        return new OutboundMessageEnvelope(
            sender.SessionId,
            recipient.SessionId,
            E2eeClientTransport.WireBodyPrefix + Convert.ToBase64String(dpe1),
            [],
            DateTimeOffset.UtcNow,
            null,
            new MessageId("corrective-logical"));
    }

    private static byte[] Pad(byte[] value, int length)
    {
        var padded = new byte[length];
        value.CopyTo(padded, 0);
        return padded;
    }

    private static HttpClient Client(Func<HttpRequestMessage, HttpResponseMessage> handler) =>
        Client(request => Task.FromResult(handler(request)));

    private static HttpClient Client(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) =>
        new(new Handler(handler)) { BaseAddress = new Uri("https://storage.test/") };

    private static HttpResponseMessage Json<T>(T value) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json")
        };

    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => handler(request);
    }

    private sealed class MutatingCapabilities(
        IOpaqueMailboxCapabilityProvider inner,
        Func<MailboxCapabilityPresentation, MailboxCapabilityPresentation> mutate)
        : IOpaqueMailboxCapabilityProvider
    {
        public OpaqueMailboxDepositMaterial CreateDeposit(
            OutboundMessageEnvelope envelope,
            ReadOnlyMemory<byte> transportAttemptId,
            uint currentBucket)
        {
            var material = inner.CreateDeposit(envelope, transportAttemptId, currentBucket);
            return material with { Capability = mutate(material.Capability) };
        }

        public OpaqueMailboxRetrieveMaterial CreateRetrieve(
            SessionIdentityProvider identity,
            ReadOnlyMemory<byte> transportAttemptId,
            uint currentBucket)
        {
            var material = inner.CreateRetrieve(identity, transportAttemptId, currentBucket);
            return material with { Capability = mutate(material.Capability) };
        }

        public ReadOnlyMemory<byte> GetRecipientKeyMaterial(SessionId recipient) =>
            inner.GetRecipientKeyMaterial(recipient);
    }

    private sealed class ThrowingCapabilities(string secret) : IOpaqueMailboxCapabilityProvider
    {
        public OpaqueMailboxDepositMaterial CreateDeposit(
            OutboundMessageEnvelope envelope,
            ReadOnlyMemory<byte> transportAttemptId,
            uint currentBucket) => throw new InvalidOperationException("provider-secret:" + secret);

        public OpaqueMailboxRetrieveMaterial CreateRetrieve(
            SessionIdentityProvider identity,
            ReadOnlyMemory<byte> transportAttemptId,
            uint currentBucket) => throw new InvalidOperationException("provider-secret:" + secret);

        public ReadOnlyMemory<byte> GetRecipientKeyMaterial(SessionId recipient) =>
            throw new InvalidOperationException("provider-secret:" + secret);
    }

    private sealed class ForgedMetadataTransport :
        ISessionMessageTransport,
        IAuthenticatedInboxTransport
    {
        public int InboxNamespace => 0;

        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);

        public Task<AuthenticatedInboxBatch> RetrieveAuthenticatedAsync(
            SessionIdentityProvider identity,
            string? cursor,
            int limit,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new AuthenticatedInboxBatch([], cursor));

        public bool TryDecodeInboxEntry(
            DurableInboxWireEntry entry,
            SessionId recipient,
            out InboundMessageEnvelope envelope)
        {
            envelope = default!;
            return false;
        }
    }
}
