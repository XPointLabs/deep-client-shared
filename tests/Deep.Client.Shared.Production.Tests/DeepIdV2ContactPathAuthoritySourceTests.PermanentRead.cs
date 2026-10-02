using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2PermanentRead_TwoOwnedAccountsIndependentProofAndNoAcceptance()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckPermanentReadBusinessAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckPermanentReadBusinessAsync()
        {
            var intent = Bytes(32, 0xc5);
            var configuration = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd1));
            using var threshold = new OwnedRouteThreshold(this);
            var published = await accounts.EnsureOwnContactObjectAsync(intent, Source(), configuration, threshold, "DID2 publisher");
            var route = await EnsureRoute(intent, configuration, threshold, reopen: false);
            var coordination = new OwnedPublicationSource(this, route);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnContactPublicationCommitAsync(intent, Source(), configuration,
                threshold, "DID2 publisher", coordination, replicas);
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            var reader = peerAccounts!;
            Assert.False((await reader.GetCurrentAsync())!.PermanentId.ExactDid2Hash.Span.SequenceEqual(address.ExactDid2Hash.Span));
            var source = Source(reader);
            var transport = new SyntheticPermanentRead(this, source, replicas.ExactPublication);
            var before = ProofRequests;
            var resolved = await reader.ResolvePermanentContactAsync(address, source, transport);
            Assert.Equal(published.Closure.CanonicalBytes.ToArray(), resolved.Contact.CanonicalBytes.ToArray());
            Assert.Equal(address.ExactDid2Hash.ToArray(), resolved.Candidate.ExactDid2.RecordHash.ToArray());
            Assert.True(ProofRequests >= before + 4); // own, path, own, independently fetched peer
            Assert.Equal(1, transport.Calls); // no automatic second read
            Assert.False(await reader.HasOwnStagedPreKeyInventoryAsync()); // resolution does not create keys/session/acceptance
            transport.CorruptReceipt = true;
            await Assert.ThrowsAsync<CryptographicException>(() => reader.ResolvePermanentContactAsync(address, source, transport));
            Assert.Equal(2, transport.Calls);
            Assert.False(await reader.HasOwnStagedPreKeyInventoryAsync());
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ResolvePermanentContactAsync(address, source, transport, cancelled.Token));
            Assert.Equal(2, transport.Calls);
        }
    }

    // Only the response adapter is synthetic. Account/device/native PQ,
    // nonce-bound directory proof verification and protected SQLCipher floors
    // are real. Actual two-node opaque stores are covered by XNode, not here;
    // this test makes no socket/TLS/ONION/device or consent claim.
    private sealed class SyntheticPermanentRead(Fixture fixture, DeepIdV2ContactPathAuthoritySource source,
        ReadOnlyMemory<byte> exactPublication) : IExactContactResolveOnionTransport
    {
        internal bool CorruptReceipt { get; set; }
        internal int Calls { get; private set; }
        public async ValueTask<ExactContactResolveOnionResponse> SendExactAsync(ContactResolveCanonicalPathRequest canonical,
            ReadOnlyMemory<byte> requiredExitReplicaId, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested(); Calls++;
            var authority = await source.GetCurrentAsync(canonical, ct);
            var query = Xiq1Codec.Decode(canonical.ExactRequest.Span);
            var publication = Xpu1Codec.Decode(exactPublication.Span);
            Assert.Equal(publication.LocatorHash.ToArray(), query.LocatorHash.ToArray());
            Assert.Equal(authority.Placement.RankedReplicaNodeIds[0].ToArray(), requiredExitReplicaId.ToArray());
            var generation = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(generation, publication.Generation);
            var expiry = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(expiry, publication.EffectiveExpiresAtUnixSeconds);
            var routeHash = SHA256.HashData(publication.ExactRouteClosure.Span);
            var tuple = query.RequestHash.ToArray().Concat(query.LocatorHash.ToArray()).Concat(generation).Concat(expiry)
                .Concat(publication.ObjectCiphertextHash.ToArray()).Concat(routeHash).ToArray();
            Assert.Equal(144, tuple.Length);
            var label = Encoding.ASCII.GetBytes("Deep/ContactResolver/V1/resolve-read");
            var input = new byte[label.Length + 7 + tuple.Length]; label.CopyTo(input, 0);
            BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(label.Length + 1), 0x0201);
            BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(label.Length + 3), checked((uint)tuple.Length));
            tuple.CopyTo(input, label.Length + 7);
            var rows = new byte[193]; rows[0] = 2;
            var ids = authority.Placement.RankedReplicaNodeIds.OrderBy(id => Convert.ToHexString(id.Span), StringComparer.Ordinal).ToArray();
            for (var i = 0; i < 2; i++)
            {
                ids[i].Span.CopyTo(rows.AsSpan(1 + i * 96));
                fixture.PublicationReceipt(ids[i], input).CopyTo(rows, 33 + i * 96);
            }
            if (CorruptReceipt) rows[^1] ^= 1;
            var body = Xis1Codec.Encode(query.CanonicalBytes.Span, Xis1Status.Success, ContactServiceMutationOutcome.None,
                fixture.CurrentProofTime, 0, ContactServicePaddingClass.Bytes16384,
                [generation, expiry, publication.ObjectCiphertextHash, publication.ObjectCiphertext,
                    routeHash, publication.ExactRouteClosure, rows]);
            return new(body, authority);
        }
    }
}
