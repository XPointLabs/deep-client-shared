using System.Net.Http;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Tests.Services;

public sealed class OrderedReplicaMailboxBinaryIngressTests
{
    [Fact]
    public async Task DefiniteNonAcceptingResponse_FailsOverWithExactMau2()
    {
        var request = RetrieveRequest(7);
        var primary = new FakeIngress(new ClientMailboxTransportException(
            ClientMailboxTransportFailure.DependencyUnavailable,
            retryable: true,
            "definite 503"));
        var secondary = new FakeIngress(result: Bytes(9, 0xd1));
        using var ingress = Runtime(primary, secondary, new FakeIngress(), new FakeIngress());

        var result = await ingress.RetrieveAsync(request);

        Assert.Equal(Bytes(9, 0xd1), result.ToArray());
        Assert.Equal(request, Assert.Single(primary.Requests));
        Assert.Equal(request, Assert.Single(secondary.Requests));
    }

    [Fact]
    public async Task AmbiguousPostDispatchTimeout_DoesNotFailOver()
    {
        var primary = new FakeIngress(new ClientMailboxTransportException(
            ClientMailboxTransportFailure.DeadlineExceeded,
            retryable: true,
            "ambiguous timeout",
            new OperationCanceledException()));
        var secondary = new FakeIngress(result: Bytes(9, 0xd1));
        using var ingress = Runtime(primary, secondary, new FakeIngress(), new FakeIngress());

        await Assert.ThrowsAsync<ClientMailboxTransportException>(() =>
            ingress.RetrieveAsync(RetrieveRequest(7)));

        Assert.Empty(secondary.Requests);
    }

    [Fact]
    public async Task AmbiguousConnectionReset_DoesNotFailOver()
    {
        var primary = new FakeIngress(new ClientMailboxTransportException(
            ClientMailboxTransportFailure.NetworkUnavailable,
            retryable: true,
            "connect failed",
            new HttpRequestException(
                HttpRequestError.ConnectionError, "connect failed", null)));
        var secondary = new FakeIngress(result: Bytes(7, 0xe1));
        using var ingress = Runtime(primary, secondary, new FakeIngress(), new FakeIngress());

        await Assert.ThrowsAsync<ClientMailboxTransportException>(() =>
            ingress.RetrieveAsync(RetrieveRequest(7)));

        Assert.Empty(secondary.Requests);
    }

    [Fact]
    public async Task DefinitePreDispatchNameResolutionFailure_FailsOver()
    {
        var primary = new FakeIngress(new ClientMailboxTransportException(
            ClientMailboxTransportFailure.NetworkUnavailable,
            retryable: true,
            "name resolution failed",
            new HttpRequestException(
                HttpRequestError.NameResolutionError,
                "name resolution failed",
                null)));
        var secondary = new FakeIngress(result: Bytes(7, 0xe1));
        using var ingress = Runtime(primary, secondary, new FakeIngress(), new FakeIngress());

        var result = await ingress.RetrieveAsync(RetrieveRequest(7));

        Assert.Equal(Bytes(7, 0xe1), result.ToArray());
        Assert.Single(secondary.Requests);
    }

    [Fact]
    public async Task NextEpoch_UsesOnlyNextOrderedPair()
    {
        var currentPrimary = new FakeIngress(result: Bytes(4, 0xa1));
        var currentSecondary = new FakeIngress(result: Bytes(4, 0xb1));
        var nextPrimary = new FakeIngress(result: Bytes(4, 0xc1));
        var nextSecondary = new FakeIngress(result: Bytes(4, 0xd1));
        using var ingress = Runtime(
            currentPrimary, currentSecondary, nextPrimary, nextSecondary);

        var result = await ingress.RetrieveAsync(RetrieveRequest(8));

        Assert.Equal(Bytes(4, 0xc1), result.ToArray());
        Assert.Empty(currentPrimary.Requests);
        Assert.Empty(currentSecondary.Requests);
        Assert.Single(nextPrimary.Requests);
        Assert.Empty(nextSecondary.Requests);
    }

    private static OrderedReplicaMailboxBinaryIngress Runtime(
        IClientMailboxBinaryIngress currentPrimary,
        IClientMailboxBinaryIngress currentSecondary,
        IClientMailboxBinaryIngress nextPrimary,
        IClientMailboxBinaryIngress nextSecondary) => new(
            7, 8, currentPrimary, currentSecondary, nextPrimary, nextSecondary);

    private static byte[] RetrieveRequest(ulong epoch)
    {
        var operationId = Bytes(16, 0x11);
        var mailbox = new BlindedMailboxId(Bytes(32, 0x21));
        var placement = new BlindedPlacementId(Bytes(32, 0x41));
        var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            epoch, operationId, mailbox, placement, 0, 10, []);
        return MailboxAuthenticatedClientRequestCodec.Encode(
            new MailboxAuthenticatedClientRequest
            {
                Binding = binding,
                Presentation = new MailboxAuthenticatedPresentation
                {
                    Operation = MailboxAuthenticatedOperation.Retrieve,
                    OperationId = operationId,
                    ReplayCounter = 1,
                    RequestDigest = binding.RequestDigest.ToArray(),
                    Grant = new MailboxAuthenticatedGrant
                    {
                        Domain = MailboxCapabilityDomain.Retrieve,
                        Lifecycle = MailboxCapabilityLifecycle.Active,
                        NetworkId = Bytes(16, 0x61),
                        Epoch = epoch,
                        Generation = epoch + 100,
                        Serial = Bytes(16, 0x71),
                        NotBeforeUnixSeconds = 900,
                        ExpiresAtUnixSeconds = 1200,
                        OverlapUntilUnixSeconds = 0,
                        PlacementCommitment = MailboxPlacementCommitment.Compute(placement),
                        MembershipCommitment = Bytes(32, 0x81),
                        IssuerPublicKey = Bytes(32, 0x91),
                        HolderPublicKey = Bytes(32, 0xa1),
                        IssuerSignature = Bytes(64, 0xb1)
                    },
                    HolderSignature = Bytes(64, 0xc1)
                }
            });
    }

    private static byte[] Bytes(int count, byte start) => Enumerable.Range(0, count)
        .Select(index => unchecked((byte)(start + index))).ToArray();

    private sealed class FakeIngress(
        Exception? exception = null,
        byte[]? result = null) : IClientMailboxBinaryIngress
    {
        public List<byte[]> Requests { get; } = [];

        public Task<ReadOnlyMemory<byte>> StoreAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default) =>
            Invoke(canonicalMau2, cancellationToken);

        public Task<ReadOnlyMemory<byte>> RetrieveAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default) =>
            Invoke(canonicalMau2, cancellationToken);

        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken = default) =>
            Invoke(canonicalMau2, cancellationToken);

        private Task<ReadOnlyMemory<byte>> Invoke(
            ReadOnlyMemory<byte> request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request.ToArray());
            return exception is null
                ? Task.FromResult<ReadOnlyMemory<byte>>(result ?? [])
                : Task.FromException<ReadOnlyMemory<byte>>(exception);
        }
    }
}
