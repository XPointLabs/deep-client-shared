using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Production.Tests;

// Exact codec/route consistency only; constructed grants here are not
// authenticated credentials and these tests claim neither issuance nor delivery.
public sealed class Did2MailboxRouteBindingTests
{
    [Fact]
    public async Task MismatchedRouteRejectsBeforeAuthorityAndGuardMutation()
    {
        var source = new NeverAuthority();
        var guards = new InMemoryProtectedEntryGuardStore();
        var provider = new MailboxPrivacyPathProvider(source, guards,
            PrivacyMailboxRouteSelection.Primary, () => throw new InvalidOperationException("No entropy before route verification."));
        var route = Route();
        var request = Request(OnionOperation.Retrieve, route);
        await Assert.ThrowsAsync<ClientMailboxTransportException>(() => provider.PrepareOnRouteAsync(
            OnionOperation.Retrieve, request, route with { MailboxId = new(B(32, 9)) }, default).AsTask());
        await Assert.ThrowsAsync<ClientMailboxTransportException>(() => provider.PrepareOnRouteAsync(
            OnionOperation.Retrieve, request, route with { PlacementCommitment = new byte[33] }, default).AsTask());
        Assert.Equal(0, source.Calls);
        Assert.Null(await guards.ReadAsync(default));
    }

    private sealed class NeverAuthority : IMailboxPrivacyNetworkAuthoritySource
    {
        internal int Calls { get; private set; }
        public ValueTask<VerifiedOnionNetworkContext> GetCurrentForMailboxAsync(
            ReadOnlyMemory<byte> commitment, CancellationToken ct)
        { Calls++; throw new InvalidOperationException("No network before route verification."); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task RetiredOrCrossFedFramingRejectsBeforeNetworkGuardsAndEntropy(int fault)
    {
        var route = Route();
        var exact = Request(OnionOperation.Retrieve, route);
        switch (fault)
        {
            case 0: "MAU2"u8.CopyTo(exact); break;
            case 1: exact[4] = 2; break;
            case 2: "MCP2"u8.CopyTo(exact.AsSpan(16)); break;
            case 3: exact[16 + 4] = 2; break;
            case 4: "MCG2"u8.CopyTo(exact.AsSpan(16 + 72)); break;
            case 5: exact[16 + 72 + 4] = 2; break;
        }
        var source = new NeverAuthority();
        var guards = new InMemoryProtectedEntryGuardStore();
        var provider = new MailboxPrivacyPathProvider(source, guards,
            PrivacyMailboxRouteSelection.Primary, () => throw new InvalidOperationException("No entropy for retired frames."));
        var failure = await Assert.ThrowsAsync<ClientMailboxTransportException>(() =>
            provider.PrepareOnRouteAsync(OnionOperation.Retrieve, exact, route, default).AsTask());
        Assert.Equal(ClientMailboxTransportFailure.MalformedRequest, failure.Failure);
        Assert.Equal(0, source.Calls);
        Assert.Null(await guards.ReadAsync(default));
    }

    [Theory]
    [InlineData(OnionOperation.Store)]
    [InlineData(OnionOperation.Retrieve)]
    [InlineData(OnionOperation.Acknowledge)]
    public void CanonicalBodyAndGrantMustMatchEveryRouteField(OnionOperation operation)
    {
        var route = Route();
        var exact = Request(operation, route);
        MailboxPrivacyPathProvider.ValidateRouteRequest(operation, exact, route);
        ScopedMailboxResolvedRoute[] changed =
        [
            route with { Epoch = 8 },
            route with { ExpiresAtUnixSeconds = 999 },
            route with { MailboxId = new(B(32, 9)) },
            route with { PlacementId = new(B(32, 10)) },
            route with { PlacementCommitment = B(32, 11) },
            route with { MembershipCommitment = B(32, 12) }
        ];
        foreach (var substitute in changed)
        {
            var error = Assert.Throws<ClientMailboxTransportException>(() =>
                MailboxPrivacyPathProvider.ValidateRouteRequest(operation, exact, substitute));
            Assert.Equal(ClientMailboxTransportFailure.ProtocolViolation, error.Failure);
            Assert.False(error.Retryable);
        }
        Assert.Throws<ClientMailboxTransportException>(() =>
            MailboxPrivacyPathProvider.ValidateRouteRequest(OnionOperation.ContactResolve, exact, route));
        Assert.Throws<ClientMailboxTransportException>(() =>
            MailboxPrivacyPathProvider.ValidateRouteRequest(operation, exact[..^1], route));
        var wrongOperation = operation == OnionOperation.Store ? OnionOperation.Retrieve : OnionOperation.Store;
        Assert.Throws<ClientMailboxTransportException>(() =>
            MailboxPrivacyPathProvider.ValidateRouteRequest(wrongOperation, exact, route));
    }

    private static ScopedMailboxResolvedRoute Route()
    {
        var placement = new BlindedPlacementId(B(32, 2));
        return new(7, 1000, new(B(32, 1)), placement, MailboxPlacementCommitment.Compute(placement),
            B(32, 3), new(B(32, 4), B(32, 5), B(32, 6), B(32, 7)));
    }

    internal static byte[] Request(OnionOperation operation, ScopedMailboxResolvedRoute route,
        ReadOnlyMemory<byte> networkId = default)
    {
        var binding = operation switch
        {
            OnionOperation.Store => MailboxAuthenticatedRequestTranscript.ForStore(new MailboxEncryptedEnvelope
            {
                Epoch = route.Epoch, MailboxId = route.MailboxId, PlacementId = route.PlacementId,
                OperationId = B(16, 20), DeduplicationDigest = B(32, 21),
                CreatedAtUnixSeconds = 100, ExpiresAtUnixSeconds = 1000, Ciphertext = B(64, 22)
            }),
            OnionOperation.Retrieve => MailboxAuthenticatedRequestTranscript.ForRetrieve(route.Epoch,
                B(16, 20), route.MailboxId, route.PlacementId, 0, 1, []),
            OnionOperation.Acknowledge => MailboxAuthenticatedRequestTranscript.ForAck(route.Epoch,
                B(16, 20), route.MailboxId, route.PlacementId, true, [],
                [new() { Cursor = 1, EnvelopeDigest = B(32, 21) }]),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };
        return MailboxAuthenticatedClientRequestCodec.Encode(new()
        {
            Binding = binding,
            Presentation = new()
            {
                Operation = binding.Operation, OperationId = binding.OperationId, ReplayCounter = 1,
                RequestDigest = binding.RequestDigest, HolderSignature = B(64, 23),
                Grant = new()
                {
                    Domain = operation == OnionOperation.Store ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve,
                    Lifecycle = MailboxCapabilityLifecycle.Active,
                    NetworkId = networkId.IsEmpty ? B(16, 24) : networkId, Epoch = route.Epoch,
                    Generation = 1, Serial = B(16, 25), NotBeforeUnixSeconds = 1,
                    ExpiresAtUnixSeconds = route.ExpiresAtUnixSeconds, OverlapUntilUnixSeconds = 0,
                    PlacementCommitment = route.PlacementCommitment, MembershipCommitment = route.MembershipCommitment,
                    SelectionInput = B(32, 29),
                    IssuerPublicKey = B(32, 26), HolderPublicKey = B(32, 27), IssuerSignature = B(64, 28)
                }
            }
        });
    }

    private static byte[] B(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
}
