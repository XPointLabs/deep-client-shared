using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Persistence.PreKeyV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Tests.ContactV1;

public sealed class BoundedPreKeyV1PrivacyTransportTests
{
    [Fact]
    public async Task PublicationDispatchesCompleteSequenceIndependentlyToEachReplicaBeforeVerification()
    {
        var durable = Publication();
        var logical = Xpp1Codec.Decode(durable.ExactXpp1Span);
        var network = CreateNetwork(logical.NetworkId.Span);
        var replicas = new[] { Bytes(32, 0x31), Bytes(32, 0x41) };
        var placement = CreatePlacement(
            network,
            ContactServiceRequestKind.PublishPreKeyInventory,
            ContactServiceClass.PreKeyClaim,
            Bytes(32, 0x51),
            logical.PlacementHash.Span,
            logical.Manifest.ServiceCapability.Span,
            7,
            logical.Manifest.ExpiresAtUnixSeconds,
            replicas);
        var authority = new ContactResolvePathAuthority(network, placement);
        var onion = new RecordingOnionTransport(authority);
        var verifier = new RecordingPublicationVerifier();
        var transport = new PrivacyRoutedPreKeyV1ClientTransport(
            UninitializedJournal(),
            onion,
            RejectingClaimVerifier.Instance,
            new PublicationAuthoritySource(authority),
            verifier);

        await Assert.ThrowsAsync<VerificationReachedException>(async () =>
            await transport.PublishInventoryAsync(durable));

        var bounded = Assert.IsType<BoundedPreKeyInventoryPublication>(verifier.Publication);
        Assert.Equal(2, verifier.CommitReceipts?.Count);
        Assert.Equal(2, onion.ByReplica.Count);
        foreach (var replica in replicas)
        {
            var requests = onion.ByReplica[Convert.ToHexString(replica)];
            Assert.Equal(
                bounded.OrderedRequests.Select(static request => request.CanonicalBytes.ToArray()),
                requests);
        }
    }

    [Fact]
    public async Task RejectedIntermediateReceiptNeverReachesActivationVerifierOrSecondReplica()
    {
        var durable = Publication();
        var logical = Xpp1Codec.Decode(durable.ExactXpp1Span);
        var network = CreateNetwork(logical.NetworkId.Span);
        var replicas = new[] { Bytes(32, 0x32), Bytes(32, 0x42) };
        var placement = CreatePlacement(
            network,
            ContactServiceRequestKind.PublishPreKeyInventory,
            ContactServiceClass.PreKeyClaim,
            Bytes(32, 0x52),
            logical.PlacementHash.Span,
            logical.Manifest.ServiceCapability.Span,
            8,
            logical.Manifest.ExpiresAtUnixSeconds,
            replicas);
        var authority = new ContactResolvePathAuthority(network, placement);
        var onion = new RecordingOnionTransport(authority, rejectFirstChunk: true);
        var verifier = new RecordingPublicationVerifier();
        var transport = new PrivacyRoutedPreKeyV1ClientTransport(
            UninitializedJournal(), onion, RejectingClaimVerifier.Instance,
            new PublicationAuthoritySource(authority), verifier);

        var error = await Assert.ThrowsAsync<PreKeyV1PublicationReplicaRejectedException>(
            async () => await transport.PublishInventoryAsync(durable));

        Assert.Equal(Xpp1BoundedPhase.Chunk, error.Phase);
        Assert.Null(verifier.Publication);
        Assert.Single(onion.ByReplica);
    }

    private static PreKeyV1DurablePublicationOperation Publication()
    {
        var network = Bytes(16, 0x11);
        var account = Bytes(32, 0x12);
        var device = Bytes(32, 0x13);
        var dpdReference = Reference("DPD1", Bytes(32, 0x14));
        var dmdHash = Bytes(32, 0x15);
        var oneTime = Enumerable.Range(0, 32)
            .Select(index => Dpk2(
                network, account, device, dpdReference, dmdHash,
                Dpk2PrekeyKind.OneTime, checked((byte)(0x20 + index))))
            .OrderBy(static exact => Dpk2Codec.Decode(exact).OneTimeX25519PrekeyId.ToArray(), ByteComparer.Instance)
            .ToArray();
        var last = Dpk2(
            network, account, device, dpdReference, dmdHash,
            Dpk2PrekeyKind.LastResort, 0x70);
        var hashes = oneTime
            .Select(static exact => MessagingWireCryptographicInputs.ComputeExactDpk2Hash(
                Dpk2Codec.Decode(exact)))
            .ToArray();
        var root = PreKeyInventoryPublicationVerifier.ComputeMerkleRoot(hashes);
        var lastHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(Dpk2Codec.Decode(last));
        var predecessor = new byte[32];
        var operation = Bytes(32, 0x81);
        var placementHash = Bytes(32, 0x82);
        var fields = new Xpi1UnsignedFields(
            network, Bytes(32, 0x83), device, dpdReference, 19,
            Reference("XPS1", Bytes(32, 0x84)), 1, predecessor,
            32, root, lastHash, dmdHash,
            Reference("DRS1", Bytes(32, 0x85)), 100, 1_000);
        var exactXpi1 = Xpi1Codec.Encode(fields, Bytes(64, 0x86));
        var manifest = Xpi1Codec.Decode(exactXpi1);
        var exactXpp1 = Xpp1Codec.Encode(
            network, operation, placementHash, manifest,
            oneTime.Select(static exact => (ReadOnlyMemory<byte>)exact).ToArray(), last);
        var request = new PreKeyV1PublicationRequest(
            1, 19, operation, predecessor, 17, dmdHash,
            Xpi1Codec.ComputeHash(exactXpi1), exactXpi1, exactXpp1);
        return new PreKeyV1DurablePublicationOperation(request);
    }

    private static byte[] Dpk2(
        byte[] network,
        byte[] account,
        byte[] device,
        byte[] dpdReference,
        byte[] dmdHash,
        Dpk2PrekeyKind kind,
        byte marker)
    {
        var signed = Bytes(32, marker);
        var signedPublic = Deep.Protocol.Identity.DeepIdentityCrypto.DeriveX25519PublicKey(signed);
        var oneTime = kind == Dpk2PrekeyKind.OneTime ? Bytes(32, checked((byte)(marker + 1))) : [];
        var oneTimePublic = oneTime.Length == 0
            ? []
            : Deep.Protocol.Identity.DeepIdentityCrypto.DeriveX25519PublicKey(oneTime);
        var record = new Dpk2Record(
            network, account, device, 11, dpdReference, 17, dmdHash,
            19, 1, Bytes(32, checked((byte)(marker + 2))), 23, 100, 90, 1_000,
            Bytes(32, 0x91), Bytes(32, checked((byte)(marker + 3))), signedPublic,
            Bytes(64, checked((byte)(marker + 4))),
            kind == Dpk2PrekeyKind.OneTime ? Bytes(32, checked((byte)(marker + 5))) : [],
            oneTimePublic, Bytes(32, checked((byte)(marker + 6))),
            Bytes(1184, checked((byte)(marker + 7))), kind,
            kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : (ushort)2,
            Bytes(64, checked((byte)(marker + 8))),
            Bytes(64, checked((byte)(marker + 9))));
        return Dpk2Codec.Encode(record);
    }

    private static SqliteXpk1ClaimJournal UninitializedJournal() =>
        (SqliteXpk1ClaimJournal)RuntimeHelpers.GetUninitializedObject(typeof(SqliteXpk1ClaimJournal));

    private static byte[] Reference(string magic, byte[] hash)
    {
        var value = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        value[5] = 1;
        hash.CopyTo(value, 6);
        return value;
    }

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedOnionNetworkContext CreateNetwork(ReadOnlySpan<byte> networkId);

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedContactServicePlacement CreatePlacement(
        VerifiedOnionNetworkContext network,
        ContactServiceRequestKind requestKind,
        ContactServiceClass serviceClass,
        ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> placementHash,
        ReadOnlySpan<byte> shardKey,
        ulong selectionEpoch,
        ulong validUntilUnixSeconds,
        IEnumerable<byte[]> rankedReplicaNodeIds);

    private sealed class PublicationAuthoritySource(ContactResolvePathAuthority authority) :
        IContactResolvePublicationPathAuthoritySource
    {
        public ValueTask<ContactResolvePathAuthority> GetCurrentForPublicationAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> serviceCapability,
            CancellationToken cancellationToken) => ValueTask.FromResult(authority);
    }

    private sealed class RecordingOnionTransport(
        ContactResolvePathAuthority authority,
        bool rejectFirstChunk = false) : IExactContactResolveOnionTransport
    {
        internal Dictionary<string, List<byte[]>> ByReplica { get; } = [];

        public ValueTask<ExactContactResolveOnionResponse> SendExactAsync(
            ContactResolveCanonicalPathRequest pathRequest,
            ReadOnlyMemory<byte> requiredExitReplicaId,
            CancellationToken cancellationToken = default)
        {
            var request = Xpp1BoundedCodec.Decode(pathRequest.ExactRequest.Span);
            var key = Convert.ToHexString(requiredExitReplicaId.Span);
            if (!ByReplica.TryGetValue(key, out var requests))
                ByReplica[key] = requests = [];
            requests.Add(request.CanonicalBytes.ToArray());
            var reject = rejectFirstChunk && request.Phase == Xpp1BoundedPhase.Chunk;
            var status = reject
                ? Xic1BoundedStatus.TemporarilyUnavailable
                : request.Phase switch
                {
                    Xpp1BoundedPhase.Manifest => Xic1BoundedStatus.ManifestStaged,
                    Xpp1BoundedPhase.Chunk => Xic1BoundedStatus.ChunkStaged,
                    _ => Xic1BoundedStatus.Committed,
                };
            var outcome = reject
                ? Xic1BoundedMutationOutcome.None
                : request.Phase == Xpp1BoundedPhase.Commit
                    ? Xic1BoundedMutationOutcome.DurablyActivated
                    : Xic1BoundedMutationOutcome.DurablyStaged;
            var count = request.Phase switch
            {
                Xpp1BoundedPhase.Manifest => (ushort)0,
                Xpp1BoundedPhase.Chunk => checked((ushort)(request.ChunkIndex + 1)),
                _ => request.ChunkCount,
            };
            var length = request.Phase switch
            {
                Xpp1BoundedPhase.Manifest => 0UL,
                Xpp1BoundedPhase.Chunk => Math.Min(
                    request.InventoryTotalLength,
                    checked((ulong)count * Xpp1BoundedCodec.MaximumChunkPayloadBytes)),
                _ => request.InventoryTotalLength,
            };
            var stateHash = request is Xpp1CommitRequest commit
                ? Xic1BoundedCodec.ComputeActivatedStateHash(commit)
                : Bytes(32, 0xa1);
            var fields = new Xic1BoundedUnsignedFields(
                request, status, outcome, count, length, requiredExitReplicaId.Span,
                200, stateHash);
            var exact = Xic1BoundedCodec.Encode(fields, Bytes(64, 0xb1));
            return ValueTask.FromResult(new ExactContactResolveOnionResponse(exact, authority));
        }
    }

    private sealed class RecordingPublicationVerifier : IPreKeyV1PublicationVerifier
    {
        internal BoundedPreKeyInventoryPublication? Publication { get; private set; }
        internal IReadOnlyList<Xic1BoundedReceipt>? CommitReceipts { get; private set; }

        public ValueTask<VerifiedPreKeyInventoryPublication> VerifyAsync(
            BoundedPreKeyInventoryPublication publication,
            IReadOnlyList<Xic1BoundedReceipt> commitReceipts,
            ContactResolvePathAuthority pathAuthority,
            CancellationToken cancellationToken)
        {
            Publication = publication;
            CommitReceipts = commitReceipts;
            throw new VerificationReachedException();
        }
    }

    private sealed class RejectingClaimVerifier : IPreKeyV1ClaimReceiptVerifier
    {
        internal static RejectingClaimVerifier Instance { get; } = new();
        public ValueTask<VerifiedXpc1PreKeyClaimReceipt> VerifyAsync(
            PreKeyV1DurableClaimOperation operation,
            Xpc1Result result,
            ContactResolvePathAuthority pathAuthority,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<VerifiedXpc1PreKeyClaimReceipt>(new NotSupportedException());
    }

    private sealed class VerificationReachedException : Exception;

    private sealed class ByteComparer : IComparer<byte[]>
    {
        internal static ByteComparer Instance { get; } = new();
        public int Compare(byte[]? left, byte[]? right) =>
            left.AsSpan().SequenceCompareTo(right);
    }
}
