using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2OwnedPublication_CommitsExactTwoReceiptsAndReopensWithoutCallbacks()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckOwnedPublicationBusinessAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckOwnedPublicationBusinessAsync()
        {
            var intent = Bytes(32, 0xc4);
            var config = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd1));
            using var threshold = new OwnedRouteThreshold(this);
            _ = await accounts.EnsureOwnContactObjectAsync(intent, Source(accounts), config, threshold, "DID2 contact QA");
            await CheckOwnedContactPublicationAsync(intent, config, threshold);
        }

        private async Task CheckOwnedContactPublicationAsync(byte[] intent, Did2ContactRouteConfiguration config,
            OwnedRouteThreshold threshold)
        {
            var route = await EnsureRoute(intent, config, threshold, reopen: true);
            var publication = new OwnedPublicationSource(this, route) { CorruptResponse = true };
            var replica = new OwnedPublicationReplica(this, route);
            await RequireRouteRejectionAsync(async () => await EnsureCommit());
            using (var state = await RouteState())
                Assert.Equal((byte)5, state.Entries[Convert.ToHexString(intent)].Phase);
            Assert.Equal(1, publication.Calls); Assert.Equal(0, replica.Calls);
            publication.CorruptResponse = false; replica.LoseResponse = true;
            await Assert.ThrowsAsync<IOException>(() => EnsureCommit());
            using (var state = await RouteState())
                Assert.Equal((byte)6, state.Entries[Convert.ToHexString(intent)].Phase);
            Assert.Equal(2, publication.Calls); Assert.Equal(1, replica.Calls);
            replica.LoseResponse = false; replica.CorruptReceipt = true;
            await Assert.ThrowsAsync<CryptographicException>(() => EnsureCommit());
            using (var state = await RouteState())
                Assert.Equal((byte)6, state.Entries[Convert.ToHexString(intent)].Phase);
            Assert.Equal(2, publication.Calls);
            replica.CorruptReceipt = false;
            var committed = await EnsureCommit();
            Assert.Equal(0ul, committed.Generation);
            Assert.True(publication.StableRequest); Assert.True(replica.StableRequest);
            using (var state = await RouteState())
            {
                var entry = state.Entries[Convert.ToHexString(intent)];
                Assert.Equal((byte)7, entry.Phase);
                Assert.Equal(committed.ExactXpo1.ToArray(), entry.Record(11).ToArray());
            }
            var before = await RouteSnapshot();
            var publications = publication.Calls; var dispatches = replica.Calls;
            var reopened = await EnsureCommit();
            Assert.Equal(committed.ExactXpo1.ToArray(), reopened.ExactXpo1.ToArray());
            Assert.Equal(publications, publication.Calls); Assert.Equal(dispatches, replica.Calls);
            var after = await RouteSnapshot();
            try { Assert.Equal(before, after); }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }

            Task<VerifiedDeepIdV2PublicationCommit> EnsureCommit()
            {
                var account = ReopenAccount();
                return account.EnsureOwnContactPublicationCommitAsync(intent, Source(account), config,
                    threshold, "DID2 contact QA", publication, replica);
            }
        }
    }

    // In-process coordination with real witness/node signatures. Replica result
    // is synthetic here; actual opaque-node durability is covered in XNode.
    private sealed class OwnedPublicationSource(Fixture fixture, VerifiedDeepIdV2ContactRouteClosure route)
        : IDid2ContactPublicationSource
    {
        internal bool CorruptResponse { get; set; }
        internal int Calls { get; private set; }
        internal bool StableRequest { get; private set; } = true;
        private byte[]? exactRequest, winner;
        public async ValueTask<ReadOnlyMemory<byte>> FetchAsync(ContactPublicationAuthorityWireRequest request, Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            Calls++; var exact = ContactPublicationAuthorityWireCodec.EncodeRequest(request);
            StableRequest &= exactRequest is null || exactRequest.AsSpan().SequenceEqual(exact);
            exactRequest ??= exact;
            if (winner is null)
            {
                var authorized = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(route, request,
                    fixture.PublicationWitnesses(), ct);
                winner = ContactPublicationAuthorityWireCodec.EncodeResponse(request,
                    new(request.NetworkId.Span, request.RequestNonce.Span, authorized.ExactXpu1.Span));
            }
            var returned = winner.ToArray();
            if (CorruptResponse) returned[^1] ^= 1;
            return returned;
        }
    }

    private sealed class PublicationWitness(Signer signer) : IXpa1PublicationAuthorizationWitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => signer.WitnessId;
        public ValueTask<ReadOnlyMemory<byte>> SignXpa1Async(ReadOnlyMemory<byte> input, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return ValueTask.FromResult<ReadOnlyMemory<byte>>(signer.SignCommit(input)); }
    }

    private sealed partial class Fixture
    {
        internal IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner> PublicationWitnesses() =>
            witnesses.Select(signer => (IXpa1PublicationAuthorizationWitnessSigner)new PublicationWitness(signer)).ToArray();
        internal byte[] PublicationReceipt(ReadOnlyMemory<byte> id, ReadOnlyMemory<byte> input) =>
            nodes.Single(node => node.SignerId.Span.SequenceEqual(id.Span)).SignCommit(input);
    }

    private sealed class OwnedPublicationReplica(Fixture fixture, VerifiedDeepIdV2ContactRouteClosure route)
        : IDid2ContactReplicaPublicationTransport
    {
        internal bool LoseResponse { get; set; }
        internal bool CorruptReceipt { get; set; }
        internal int Calls { get; private set; }
        internal bool StableRequest { get; private set; } = true;
        private byte[]? exactRequest;
        internal ReadOnlyMemory<byte> ExactPublication => exactRequest?.ToArray() ?? throw new InvalidOperationException("No publication was dispatched.");
        public Task<ReadOnlyMemory<byte>> PublishAsync(ReadOnlyMemory<byte> exactXpu1, Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++;
            StableRequest &= exactRequest is null || exactRequest.AsSpan().SequenceEqual(exactXpu1.Span);
            exactRequest ??= exactXpu1.ToArray();
            if (LoseResponse) throw new IOException("Injected publication response loss.");
            var request = Xpu1Codec.Decode(exactXpu1.Span);
            var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, request.LocatorHash);
            var generation = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(generation, 1);
            var tuple = request.RequestHash.ToArray().Concat(request.ObjectCiphertextHash.ToArray()).Concat(generation).ToArray();
            // Independently encode the frozen neutral receipt transcript; do
            // not expose Protocol internals or a new generic signing API.
            var label = System.Text.Encoding.ASCII.GetBytes("Deep/ContactResolver/V1/publish-commit");
            var input = new byte[label.Length + 7 + tuple.Length];
            label.CopyTo(input, 0);
            BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(label.Length + 1), 0x0201);
            BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(label.Length + 3), checked((uint)tuple.Length));
            tuple.CopyTo(input, label.Length + 7);
            var rows = new byte[193]; rows[0] = 2;
            var ids = placement.RankedReplicaNodeIds.OrderBy(id => Convert.ToHexString(id.Span), StringComparer.Ordinal).ToArray();
            for (var i = 0; i < 2; i++)
            {
                ids[i].Span.CopyTo(rows.AsSpan(1 + i * 96));
                fixture.PublicationReceipt(ids[i], input).CopyTo(rows, 33 + i * 96);
            }
            if (CorruptReceipt) rows[^1] ^= 1;
            var ownGeneration = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(ownGeneration, request.Generation);
            var response = Xpo1Codec.Encode(exactXpu1.Span, Xpo1Status.Committed,
                ContactServiceMutationOutcome.DurablyCommitted, 1_100, 0, ContactServicePaddingClass.Bytes1024,
                [ownGeneration, request.ObjectCiphertextHash, generation, rows]);
            return Task.FromResult<ReadOnlyMemory<byte>>(response);
        }
    }
}
