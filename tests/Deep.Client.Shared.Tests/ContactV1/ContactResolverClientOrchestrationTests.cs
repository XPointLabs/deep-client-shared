using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.ContactV1;

public sealed class ContactResolverClientOrchestrationTests
{
    internal static readonly byte[] Network = B(16, 0x11);

    [Fact]
    public async Task ConstructsCanonicalXiq1AndKeepsOperationSeparateFromAttempt()
    {
        var fixture = await FixtureAsync();
        ContactResolverTransportRequest? captured = null;
        var transport = new DelegateTransport(request =>
        {
            captured = request;
            return Failure(request, Xis1Status.NotFound);
        });
        var client = Client(fixture.Store, transport, new RejectingVerifier(), attempts: 1);

        var result = await client.ResolveAsync(fixture.Command);

        Assert.Equal(ContactResolverDisposition.NotFound, result.Disposition);
        var xiq = Xiq1Codec.Decode(captured!.ExactXiq1.Span);
        Assert.Equal(fixture.Command.OperationId.ToArray(), xiq.OperationId.ToArray());
        Assert.Equal(xiq.OperationId.ToArray(), xiq.RedemptionOperationId.ToArray());
        Assert.Equal(Network, xiq.NetworkId.ToArray());
        Assert.Equal(Xiq1AntiSpamTokenType.None, xiq.AntiSpamTokenType);
        Assert.Empty(xiq.AntiSpamToken.ToArray());
        Assert.NotEqual(xiq.OperationId.ToArray(), captured.AttemptId.Bytes.ToArray());
    }

    [Fact]
    public async Task OneTimeXiq1UsesOnlyDomainHashedOpaqueLocator()
    {
        var store = new InMemoryContactStateStore(Scope());
        var dia = ContactCodec.Decode("DIA1", Dia1(2_000_000_000));
        var pending = (await new ContactAddressImportService(store, Network)
            .ImportAsync(DeepInvitationTextCodec.EncodeCanonical(dia))).PendingAddress;
        var command = ContactResolverCommand.CreateUnverifiedForTests(pending,
            ContactMutationId32.FromBytes(B(32, 0x35)),
            ContactRelationshipId32.FromBytes(B(32, 0x36)),
            B(32, 0x37), B(32, 0x38), 10, 100);
        ContactResolverTransportRequest? captured = null;
        var client = Client(store, new DelegateTransport(request =>
        {
            captured = request;
            return Failure(request, Xis1Status.NotFound);
        }), new RejectingVerifier(), attempts: 1);

        await client.ResolveAsync(command);

        var request = Xiq1Codec.Decode(captured!.ExactXiq1.Span);
        Assert.Equal(HashDomain("Deep/ContactResolver/V1/one-time-locator", dia.Field(5).Span),
            request.LocatorHash.ToArray());
        Assert.NotEqual(dia.Field(5).ToArray(), request.LocatorHash.ToArray());
        Assert.DoesNotContain(dia.Field(6).ToArray(), captured.ExactXiq1.ToArray());
        Assert.DoesNotContain(dia.CanonicalBytes.ToArray(), captured.ExactXiq1.ToArray());
    }

    [Fact]
    public async Task OutcomeUnknownTransportRetryReusesExactXiqAndChangesAttemptId()
    {
        var fixture = await FixtureAsync();
        var requests = new List<ContactResolverTransportRequest>();
        var transport = new DelegateTransport(request =>
        {
            requests.Add(request);
            if (requests.Count == 1)
                throw new ContactResolverTransportException(
                    ContactResolverTransportFailureKind.OutcomeUnknown, "lost response");
            return Failure(request, Xis1Status.NotFound);
        });
        var client = Client(fixture.Store, transport, new RejectingVerifier(), attempts: 2);

        var result = await client.ResolveAsync(fixture.Command);

        Assert.Equal(2, result.AttemptCount);
        Assert.Equal(2, requests.Count);
        Assert.Equal(requests[0].ExactXiq1.ToArray(), requests[1].ExactXiq1.ToArray());
        Assert.NotEqual(requests[0].AttemptId.Bytes.ToArray(), requests[1].AttemptId.Bytes.ToArray());
    }

    [Fact]
    public async Task TemporaryXis1AutomaticallyRetriesTheSameExactRequestWithinBound()
    {
        var fixture = await FixtureAsync();
        var calls = 0;
        var transport = new DelegateTransport(request =>
            Failure(request, ++calls == 1 ? Xis1Status.TemporarilyUnavailable : Xis1Status.NotFound));
        var client = Client(fixture.Store, transport, new RejectingVerifier(), attempts: 2);

        var result = await client.ResolveAsync(fixture.Command);

        Assert.Equal(ContactResolverDisposition.NotFound, result.Disposition);
        Assert.Equal(2, result.AttemptCount);
        Assert.Equal(transport.Requests[0].ExactXiq1.ToArray(), transport.Requests[1].ExactXiq1.ToArray());
        Assert.NotEqual(transport.Requests[0].AttemptId.Bytes.ToArray(), transport.Requests[1].AttemptId.Bytes.ToArray());
    }

    [Fact]
    public async Task ConcurrentExactRequestIsDispatchedOnce()
    {
        var fixture = await FixtureAsync();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var transport = new AsyncDelegateTransport(async request =>
        {
            Interlocked.Increment(ref calls);
            entered.TrySetResult();
            await release.Task;
            return Failure(request, Xis1Status.NotFound);
        });
        var client = Client(fixture.Store, transport, new RejectingVerifier(), attempts: 1);

        var first = client.ResolveAsync(fixture.Command).AsTask();
        await entered.Task;
        var second = client.ResolveAsync(fixture.Command).AsTask();
        release.SetResult();
        await Task.WhenAll(first, second);

        Assert.Equal(1, calls);
        Assert.Equal(ContactResolverDisposition.NotFound, (await first).Disposition);
        Assert.Equal(ContactResolverDisposition.NotFound, (await second).Disposition);
    }

    [Fact]
    public async Task CancelingOneWaiterDoesNotCancelSharedDispatchAndCompletionIsEvicted()
    {
        var fixture = await FixtureAsync();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new CancellationAwareTransport(async (request, cancellationToken) =>
        {
            Assert.False(cancellationToken.CanBeCanceled);
            entered.TrySetResult();
            await release.Task;
            return Failure(request, Xis1Status.NotFound);
        });
        var client = Client(fixture.Store, transport, new RejectingVerifier(), attempts: 1);
        using var canceledWaiter = new CancellationTokenSource();

        var first = client.ResolveAsync(fixture.Command, canceledWaiter.Token).AsTask();
        await entered.Task;
        var second = client.ResolveAsync(fixture.Command).AsTask();
        canceledWaiter.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        release.SetResult();
        Assert.Equal(ContactResolverDisposition.NotFound, (await second).Disposition);
        Assert.Equal(1, transport.CallCount);

        var replay = await client.ResolveAsync(fixture.Command);
        Assert.Equal(ContactResolverDisposition.NotFound, replay.Disposition);
        Assert.Equal(2, transport.CallCount);
    }

    [Fact]
    public async Task OperationIdCannotBeReusedForDifferentCanonicalBody()
    {
        var fixture = await FixtureAsync();
        var transport = new DelegateTransport(request => Failure(request, Xis1Status.NotFound));
        var client = Client(fixture.Store, transport, new RejectingVerifier(), attempts: 1);
        await client.ResolveAsync(fixture.Command);
        var changed = ContactResolverCommand.CreateUnverifiedForTests(fixture.Pending, fixture.Command.OperationId,
            fixture.Command.RelationshipId, B(32, 0x66), fixture.Command.PlacementHash.Span, 10, 100);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ResolveAsync(changed).AsTask());
        Assert.Single(transport.Requests);
    }

    [Theory]
    [InlineData(Xis1Status.Expired, ContactResolverDisposition.Expired, ContactResolverRetryClassification.Terminal)]
    [InlineData(Xis1Status.AlreadyClaimed, ContactResolverDisposition.AlreadyClaimed, ContactResolverRetryClassification.Terminal)]
    [InlineData(Xis1Status.NotFound, ContactResolverDisposition.NotFound, ContactResolverRetryClassification.Terminal)]
    [InlineData(Xis1Status.TemporarilyUnavailable, ContactResolverDisposition.TemporarilyUnavailable, ContactResolverRetryClassification.RetrySameExactRequest)]
    [InlineData(Xis1Status.RateLimited, ContactResolverDisposition.RateLimited, ContactResolverRetryClassification.RetrySameExactRequest)]
    [InlineData(Xis1Status.OutcomeUnknown, ContactResolverDisposition.OutcomeUnknown, ContactResolverRetryClassification.RetrySameExactRequest)]
    [InlineData(Xis1Status.StaleView, ContactResolverDisposition.StaleView, ContactResolverRetryClassification.RefreshViewAndCreateNewOperation)]
    [InlineData(Xis1Status.Conflict, ContactResolverDisposition.Conflict, ContactResolverRetryClassification.FailClosed)]
    public async Task ClosedXis1StatusesHaveExplicitRetryClassification(
        Xis1Status status,
        ContactResolverDisposition disposition,
        ContactResolverRetryClassification retry)
    {
        var fixture = await FixtureAsync();
        var transport = new DelegateTransport(request => Failure(request, status));
        var verifier = new RejectingVerifier();
        var client = Client(fixture.Store, transport, verifier, attempts: 1);

        var result = await client.ResolveAsync(fixture.Command);

        Assert.Equal(disposition, result.Disposition);
        Assert.Equal(retry, result.Retry);
        Assert.Equal(0, verifier.CallCount);
        Assert.Empty(await fixture.Store.ReadRelationshipsAsync());
        if (status == Xis1Status.StaleView) Assert.Equal(B(32, 0x73), result.RequiredViewHash.ToArray());
    }

    [Fact]
    public async Task MalformedOrUncorrelatedXis1FailsClosedBeforeVerifierAndStore()
    {
        var fixture = await FixtureAsync();
        var verifier = new RejectingVerifier();
        var client = Client(fixture.Store,
            new DelegateTransport(_ => new ContactResolverTransportResponse(B(256, 0x41))),
            verifier, attempts: 1);

        await Assert.ThrowsAsync<CryptographicException>(() => client.ResolveAsync(fixture.Command).AsTask());

        Assert.Equal(0, verifier.CallCount);
        Assert.Empty(await fixture.Store.ReadRelationshipsAsync());
        Assert.Single(await fixture.Store.ReadPendingAddressesAsync());
    }

    [Fact]
    public async Task SuccessfulXis1PersistsOnlyVerifierMintedBundleVerifiedRelationship()
    {
        var fixture = await FixtureAsync();
        var verifier = new TestTrustedVerifier(B(32, 0xB0));
        var transport = new DelegateTransport(Success);
        var client = Client(fixture.Store, transport, verifier, attempts: 1);

        Assert.Empty(await fixture.Store.ReadRelationshipsAsync());
        var result = await client.ResolveAsync(fixture.Command);

        Assert.Equal(ContactResolverDisposition.Verified, result.Disposition);
        Assert.Equal(ContactRelationshipCommitDisposition.Applied, result.Commit!.Disposition);
        Assert.Equal(ContactRelationshipState.BundleVerified, result.Commit.Relationship!.State);
        Assert.Equal(fixture.Command.RelationshipId, result.Commit.Relationship.RelationshipId);
        Assert.Equal(1, verifier.CallCount);
        Assert.Single(await fixture.Store.ReadRelationshipsAsync());
        Assert.Single(await fixture.Store.ReadPendingAddressesAsync());
        var package = await fixture.Store.ReadVerifiedPeerPackageAsync(fixture.Command.RelationshipId);
        Assert.NotNull(package);
        Assert.Equal(result.Commit.Relationship.ConversationId, package.ConversationId);
        Assert.Equal(result.Commit.Relationship.RemoteAccountId, package.RemoteAccountId);
        Assert.Equal(Assert.Single(transport.Requests).ExactXiq1.ToArray(), package.ExactXiq1.ToArray());
        Assert.Equal(result.ExactXis1.ToArray(), package.ExactXis1.ToArray());
    }

    [Fact]
    public async Task SuccessfulLocalCommitReplayIsIdempotentWithStableCommandTimestamp()
    {
        var fixture = await FixtureAsync();
        var client = Client(fixture.Store, new DelegateTransport(Success),
            new TestTrustedVerifier(B(32, 0xB0)), attempts: 1);

        var first = await client.ResolveAsync(fixture.Command);
        await Task.Delay(10);
        var replay = await client.ResolveAsync(fixture.Command);

        Assert.Equal(ContactRelationshipCommitDisposition.Applied, first.Commit!.Disposition);
        Assert.Equal(ContactRelationshipCommitDisposition.Idempotent, replay.Commit!.Disposition);
        Assert.Equal(first.Commit.Relationship!.CreatedAt, replay.Commit.Relationship!.CreatedAt);
        Assert.Single(await fixture.Store.ReadRelationshipsAsync());
    }

    [Fact]
    public async Task VerifierExceptionCannotCreateConversationOrRelationship()
    {
        var fixture = await FixtureAsync();
        var client = Client(fixture.Store, new DelegateTransport(Success), new RejectingVerifier(), attempts: 1);

        await Assert.ThrowsAnyAsync<CryptographicException>(() => client.ResolveAsync(fixture.Command).AsTask());

        Assert.Empty(await fixture.Store.ReadRelationshipsAsync());
        Assert.Single(await fixture.Store.ReadPendingAddressesAsync());
    }

    private static ContactResolverClient Client(
        IContactStateStore store,
        IContactResolverTransport transport,
        IContactResolverTrustedVerifier verifier,
        int attempts) => new(store, transport, verifier,
            new ContactResolverClientOptions(attempts, TimeSpan.Zero, 64));

    private static async Task<TestFixture> FixtureAsync()
    {
        var store = new InMemoryContactStateStore(Scope());
        var did = ApplicationCoreCodec.AuthorDid1(B(32, 0x21), B(16, 0x22));
        var imported = await new ContactAddressImportService(store, Network).ImportAsync(did.Text);
        var command = ContactResolverCommand.CreateUnverifiedForTests(imported.PendingAddress,
            ContactMutationId32.FromBytes(B(32, 0x31)),
            ContactRelationshipId32.FromBytes(B(32, 0x32)),
            B(32, 0x33), B(32, 0x34), 10, 100);
        return new(store, imported.PendingAddress, command);
    }

    internal static ContactResolverTransportResponse Failure(
        ContactResolverTransportRequest request,
        Xis1Status status)
    {
        var payload = status is Xis1Status.StaleView or Xis1Status.Conflict
            ? new ReadOnlyMemory<byte>[] { B(32, 0x73) }
            : Array.Empty<ReadOnlyMemory<byte>>();
        var retry = status is Xis1Status.RateLimited or Xis1Status.OutcomeUnknown ? 7u : 0u;
        var outcome = status == Xis1Status.OutcomeUnknown
            ? ContactServiceMutationOutcome.OutcomeUnknown
            : ContactServiceMutationOutcome.None;
        return new ContactResolverTransportResponse(Xis1Codec.Encode(request.ExactXiq1.Span,
            status, outcome, 50, retry, ContactServicePaddingClass.Bytes256, payload));
    }

    internal static ContactResolverTransportResponse Success(ContactResolverTransportRequest request)
    {
        var cipher = B(40, 0x44);
        var route = RouteClosure();
        var exact = Xis1Codec.Encode(request.ExactXiq1.Span, Xis1Status.Success,
            ContactServiceMutationOutcome.None, 50, 0, ContactServicePaddingClass.Bytes16384,
            new ReadOnlyMemory<byte>[] { U64(0), U64(90), SHA256.HashData(cipher), cipher,
                SHA256.HashData(route), route, ReplicaReceipts() });
        return new ContactResolverTransportResponse(exact);
    }

    private static byte[] ReplicaReceipts()
    {
        var receipts = new byte[193];
        receipts[0] = 2;
        B(32, 0x11).CopyTo(receipts, 1);
        B(64, 0x31).CopyTo(receipts, 33);
        B(32, 0x22).CopyTo(receipts, 97);
        B(64, 0x41).CopyTo(receipts, 129);
        return receipts;
    }

    internal static byte[] RouteClosure()
    {
        var pmt = Author("PMT2", [Network,U64(0),new byte[32],Ref("PMA2",2),Ref("XNV1",3),U64(1),new byte[]{2},U16(2),Rows(136,2,4),U64(1),U64(1),U64(2),new byte[32],Ref("ADH1",5),new byte[]{2},Rows(96,2,6)]);
        var xra = Author("XRA1", [Network,B(32,2),U64(0),new byte[32],ContactCodec.ArtifactReference("PMT2",pmt).CanonicalBytes,B(32,3),U16(1),U32(1),B(32,4),B(32,5),B(32,6),U64(1),U64(2),B(32,7),Ref("DPD1",8),B(64,9)]);
        var ranked = RankedNodes(pmt, xra.Field(6));
        ReadOnlyMemory<byte>[] pmsFields = [Network,ContactCodec.ArtifactReference("PMT2",pmt).CanonicalBytes,xra.Field(6),pmt.Field(6),new byte[]{2},ranked.AsMemory(0,64),new byte[32],U64(1),U64(2),new byte[]{2},Rows(96,2,10)];
        var provisional = Write("PMS2", pmsFields);
        pmsFields[6] = SelectionHash(provisional);
        var pms = Author("PMS2", pmsFields);
        var replicas = ReplicaEntries(pms);
        var xrc = Author("XRC1", [Network,B(32,10),U64(0),new byte[32],ContactCodec.ArtifactReference("XRA1",xra).CanonicalBytes,ContactCodec.ArtifactReference("PMT2",pmt).CanonicalBytes,pms.ArtifactHash,pmt.Field(5),Ref("XNH1",12),B(32,13),xra.Field(10),xra.Field(11),U64(1),new byte[]{2},replicas,U64(1),U64(1),U64(2),pmt.Field(14),new byte[]{2},Rows(96,2,18)]);
        var xss = Author("XSS1", [Network,xrc.Field(2),U64(1),xrc.CoreHash,ContactCodec.ArtifactReference("XRC1",xrc).CanonicalBytes,ContactCodec.ArtifactReference("XRC1",xrc).CanonicalBytes,ContactCodec.ArtifactReference("PMT2",pmt).CanonicalBytes,xrc.Field(8),pms.ArtifactHash,U64(1),U64(2),Ref("ADH1",23),new byte[]{2},Rows(96,2,24)]);
        var xrr = Author("XRR1", [Network,B(32,25),U64(0),new byte[32],ContactCodec.ArtifactReference("XRA1",xra).CanonicalBytes,ContactCodec.ArtifactReference("XRC1",xrc).CanonicalBytes,ContactCodec.ArtifactReference("XSS1",xss).CanonicalBytes,ContactCodec.ArtifactReference("PMT2",pmt).CanonicalBytes,pms.ArtifactHash,B(32,26),B(32,27),new byte[]{1},U32(1),U16(1),U64(1),U64(1),U64(2),xra.Field(15),B(64,29),new byte[2]]);
        var records = new[] { xrr, xra, xrc, xss, pmt, pms };
        var output = new byte[1 + records.Sum(record => 4 + record.CanonicalBytes.Length)];
        output[0] = 6;
        var offset = 1;
        foreach (var record in records)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset), checked((uint)record.CanonicalBytes.Length));
            offset += 4;
            record.CanonicalBytes.Span.CopyTo(output.AsSpan(offset));
            offset += record.CanonicalBytes.Length;
        }
        return output;
    }

    private static ContactRecord Author(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields) =>
        ContactCodec.Decode(magic, Write(magic, fields));

    internal static byte[] Write(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        var output = new byte[12 + fields.Sum(field => 8 + field.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            fields[index].Span.CopyTo(output.AsSpan(offset + 8));
            offset += 8 + fields[index].Length;
        }
        return output;
    }

    private static byte[] SelectionHash(byte[] pms)
    {
        var projection = Project(pms, 6);
        return HashDomain("Deep/XPoint/V1/PMS2/selection", projection);
    }

    private static byte[] Project(byte[] record, int fieldCount)
    {
        var fields = ReadFields(record).Take(fieldCount).ToArray();
        return Write(Encoding.ASCII.GetString(record, 0, 4), fields);
    }

    private static IEnumerable<ReadOnlyMemory<byte>> ReadFields(byte[] record)
    {
        var count = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(8));
        var offset = 12;
        for (var index = 0; index < count; index++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(record.AsSpan(offset + 4)));
            yield return record.AsMemory(offset + 8, length);
            offset += 8 + length;
        }
    }

    private static byte[] RankedNodes(ContactRecord pmt, ReadOnlyMemory<byte> placement)
    {
        var reference = ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes.ToArray();
        return pmt.Field(9).ToArray().Chunk(136).Select(row => row[..32]).Select(node => new
            {
                Node = node,
                Score = SHA256.HashData(Join(Encoding.ASCII.GetBytes("Deep/XPoint/V1/PMS2/rendezvous-sha256/v2"),
                    [0], Network, reference, pmt.Field(6).ToArray(), placement.ToArray(), node)),
            })
            .OrderBy(value => value.Score, ByteArrayComparer.Instance)
            .ThenBy(value => value.Node, ByteArrayComparer.Instance)
            .SelectMany(value => value.Node).ToArray();
    }

    private static byte[] ReplicaEntries(ContactRecord pms)
    {
        var ranked = pms.Field(6).ToArray();
        var output = new byte[ranked.Length * 2];
        for (var index = 0; index < ranked.Length / 32; index++)
        {
            ranked.AsSpan(index * 32, 32).CopyTo(output.AsSpan(index * 64));
            B(32, checked((byte)(0x80 + index))).CopyTo(output, index * 64 + 32);
        }
        return output;
    }

    private static byte[] Rows(int width, int count, byte seed)
    {
        var output = new byte[width * count];
        for (var index = 0; index < count; index++)
        {
            B(32, checked((byte)(seed + index))).CopyTo(output, index * width);
            B(width - 32, checked((byte)(seed + 32 + index))).CopyTo(output, index * width + 32);
        }
        return output;
    }

    private static byte[] Ref(string magic, byte seed)
    {
        var output = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        B(32, seed).CopyTo(output, 6);
        return output;
    }

    internal static byte[] Dia1(ulong expiresAt) => Write("DIA1", new ReadOnlyMemory<byte>[]
    {
        Network, B(32, 0x91), new byte[] { 2 }, U16(1), B(16, 0x92),
        B(32, 0x93), B(32, 0x94), U64(expiresAt), U16(1),
    });

    private static byte[] HashDomain(string domain, ReadOnlySpan<byte> payload)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var input = new byte[label.Length + 5 + payload.Length];
        label.CopyTo(input, 0);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(label.Length + 1), checked((uint)payload.Length));
        payload.CopyTo(input.AsSpan(label.Length + 5));
        return SHA256.HashData(input);
    }

    private static byte[] Join(params byte[][] values) => values.SelectMany(static value => value).ToArray();
    internal static byte[] B(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }

    internal static ContactStoreScope Scope() => ContactStoreScope.ForCurrentAccount(
        DeepAccountIdentityCapability.FromVerifiedInputs(DeepNetworkId16.FromVerifiedBytes(Network), 1,
            AccountEd25519PublicKey32.FromVerifiedBytes(B(32, 0xA1))).AccountId);

    private sealed record TestFixture(
        InMemoryContactStateStore Store,
        PendingContactAddress Pending,
        ContactResolverCommand Command);

    internal sealed class DelegateTransport(Func<ContactResolverTransportRequest, ContactResolverTransportResponse> send)
        : IContactResolverTransport
    {
        public List<ContactResolverTransportRequest> Requests { get; } = [];
        public ValueTask<ContactResolverTransportResponse> SendXiq1Async(
            ContactResolverTransportRequest request, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            return ValueTask.FromResult(send(request));
        }
    }

    private sealed class AsyncDelegateTransport(Func<ContactResolverTransportRequest, Task<ContactResolverTransportResponse>> send)
        : IContactResolverTransport
    {
        public async ValueTask<ContactResolverTransportResponse> SendXiq1Async(
            ContactResolverTransportRequest request, CancellationToken cancellationToken = default) =>
            await send(request);
    }

    private sealed class CancellationAwareTransport(
        Func<ContactResolverTransportRequest, CancellationToken, Task<ContactResolverTransportResponse>> send)
        : IContactResolverTransport
    {
        public int CallCount { get; private set; }

        public async ValueTask<ContactResolverTransportResponse> SendXiq1Async(
            ContactResolverTransportRequest request,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            return await send(request, cancellationToken);
        }
    }

    private sealed class RejectingVerifier : IContactResolverTrustedVerifier
    {
        public int CallCount { get; private set; }
        public ValueTask<ContactResolverTrustedVerificationResult> VerifyAsync(ContactResolverVerificationInput input,
            ContactStoreScope localScope, ContactRelationshipId32 relationshipId,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            throw new CryptographicException("rejected fixture");
        }
    }

    internal sealed class TestTrustedVerifier(byte[] remoteAccount) : IContactResolverTrustedVerifier
    {
        public int CallCount { get; private set; }
        public ValueTask<ContactResolverTrustedVerificationResult> VerifyAsync(ContactResolverVerificationInput input,
            ContactStoreScope localScope, ContactRelationshipId32 relationshipId,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            var hashes = Enum.GetValues<ContactVerifiedArtifactKind>().ToDictionary(kind => kind,
                kind => (ReadOnlyMemory<byte>)B(32, checked((byte)(0x40 + (int)kind))));
            var evidence = ContactTrustedVerifierBoundary.BundleVerified(localScope,
                input.Address, remoteAccount, relationshipId, hashes, B(32, 0x70));
            var device = new ContactVerifiedPeerDeviceEvidence(B(32, 0xD1), B(776, 0xD2));
            var package = new ContactVerifiedPeerPackageEvidence(
                localScope, relationshipId, evidence.ConversationId, evidence.RemoteAccountId,
                input.Address.Kind, input.Address.NetworkId.Span, input.Address.CanonicalBytes.Span,
                input.Request.WireBytes.Span, input.Result.WireBytes.Span,
                B(1, 0xD3), B(1, 0xD4), B(1, 0xD5), [device], B(1, 0xD6));
            return ValueTask.FromResult(new ContactResolverTrustedVerificationResult(evidence, package));
        }
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? x, byte[]? y) => x.AsSpan().SequenceCompareTo(y);
    }
}
