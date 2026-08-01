using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Tests.Services;

public sealed class NativeMailboxRecoveryAcceptanceTests
{
    [Theory]
    [InlineData("cursor")]
    [InlineData("digest")]
    [InlineData("expiry")]
    [InlineData("disposition")]
    public void Store_rejects_wrong_mqr3_binding(string mutation)
    {
        var fixture = new ReceiptFixture();
        var encoded = mutation switch
        {
            "cursor" => fixture.Quorum(cursor: 43),
            "digest" => fixture.Quorum(digest: Bytes(32, 0xf0)),
            "expiry" => fixture.Quorum(expiresAt: 1121),
            "disposition" => fixture.Quorum(
                disposition: MailboxReplicaDisposition.Duplicate),
            _ => throw new ArgumentOutOfRangeException(nameof(mutation))
        };

        Assert.Throws<MailboxReceiptException>(() =>
            new PinnedClientMailboxReceiptVerifier(fixture.Crypto)
                .VerifyDurable(encoded, fixture.Expectation()));
    }

    [Fact]
    public void Store_rejects_equivocated_replica_statements()
    {
        var fixture = new ReceiptFixture();
        var encoded = fixture.Quorum(secondCursor: 44);
        Assert.Throws<MailboxReceiptException>(() =>
            new PinnedClientMailboxReceiptVerifier(fixture.Crypto)
                .VerifyDurable(encoded, fixture.Expectation()));
    }

    [Fact]
    public void Retrieve_summary_is_exact_and_immutable_after_source_mutation()
    {
        var operation = Bytes(16, 0x21);
        var request = Request(operation, afterCursor: 7);
        var token = Bytes(32, 0x31);
        var page = Page(operation, token, 42);
        var canonical = MailboxClientCodec.EncodeRetrievePage(page);
        var encoded = ClientMailboxRetrieveOutcomeSummary.Encode(
            request, page, canonical);

        token[0] ^= 0xff;
        canonical[0] ^= 0xff;
        var decoded = ClientMailboxRetrieveOutcomeSummary.DecodeAndValidate(
            encoded, request);

        Assert.Equal(42UL, decoded.ResultAfterCursor);
        Assert.Equal(Bytes(32, 0x31), decoded.ContinuationToken.ToArray());
        Assert.Equal(1, decoded.ItemCount);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(64)]
    [InlineData(80)]
    [InlineData(90)]
    public void Retrieve_summary_rejects_malformed_or_equivocated_evidence(int offset)
    {
        var operation = Bytes(16, 0x41);
        var request = Request(operation, afterCursor: 9);
        var page = Page(operation, Bytes(16, 0x51), 51);
        var encoded = ClientMailboxRetrieveOutcomeSummary.Encode(
            request, page, MailboxClientCodec.EncodeRetrievePage(page));
        encoded[offset] ^= 0x01;

        Assert.Throws<InvalidDataException>(() =>
            ClientMailboxRetrieveOutcomeSummary.DecodeAndValidate(encoded, request));
    }

    [Fact]
    public void Retrieve_summary_rejects_another_operation_even_when_shape_matches()
    {
        var request = Request(Bytes(16, 0x61), afterCursor: 3);
        var page = new MailboxRetrievePage
        {
            Epoch = 7,
            OperationId = request.OperationId,
            NextCursor = 0,
            HasMore = false,
            ContinuationToken = ReadOnlyMemory<byte>.Empty,
            Items = []
        };
        var encoded = ClientMailboxRetrieveOutcomeSummary.Encode(
            request, page, MailboxClientCodec.EncodeRetrievePage(page));

        Assert.Throws<InvalidDataException>(() =>
            ClientMailboxRetrieveOutcomeSummary.DecodeAndValidate(
                encoded, Request(Bytes(16, 0x62), afterCursor: 3)));
    }

    private static MailboxAuthenticatedRetrieveBody Request(
        byte[] operationId,
        ulong afterCursor) =>
        MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
            MailboxAuthenticatedRequestTranscript.ForRetrieve(
                7,
                operationId,
                new BlindedMailboxId(Bytes(32, 0x71)),
                new BlindedPlacementId(Bytes(32, 0x81)),
                afterCursor,
                100,
                ReadOnlySpan<byte>.Empty).CanonicalRequest.Span);

    private static MailboxRetrievePage Page(
        byte[] operationId,
        byte[] continuationToken,
        ulong cursor) => new()
        {
            Epoch = 7,
            OperationId = operationId,
            NextCursor = cursor,
            HasMore = true,
            ContinuationToken = continuationToken,
            Items =
            [
                new MailboxRetrievedEnvelope
                {
                    Cursor = cursor,
                    Envelope = new MailboxEncryptedEnvelope
                    {
                        Epoch = 7,
                        MailboxId = new BlindedMailboxId(Bytes(32, 0x71)),
                        PlacementId = new BlindedPlacementId(Bytes(32, 0x81)),
                        OperationId = Bytes(16, 0x91),
                        DeduplicationDigest = Bytes(32, 0xa1),
                        CreatedAtUnixSeconds = 1000,
                        ExpiresAtUnixSeconds = 1120,
                        Ciphertext = Bytes(64, 0xb1)
                    }
                }
            ]
        };

    private sealed class ReceiptFixture
    {
        private readonly byte[] firstSeed = Bytes(32, 0x10);
        private readonly byte[] secondSeed = Bytes(32, 0x50);
        private readonly byte[] firstId = Bytes(32, 0x20);
        private readonly byte[] secondId = Bytes(32, 0x60);
        private readonly byte[] membership = Bytes(32, 0x80);
        private readonly BlindedPlacementId placement =
            new(Bytes(32, 0xa0));
        private readonly byte[] operationId = Bytes(16, 0x70);
        private readonly byte[] digest = Bytes(32, 0xe0);

        public ReceiptFixture()
        {
            Crypto = new SodiumMailboxPeerReplicationCrypto();
            Route = new ClientMailboxPinnedRoute(
                placement,
                membership,
                firstId,
                Crypto.GetPublicKey(firstSeed),
                secondId,
                Crypto.GetPublicKey(secondSeed));
        }

        public SodiumMailboxPeerReplicationCrypto Crypto { get; }
        public ClientMailboxPinnedRoute Route { get; }
        public BlindedMailboxId MailboxId { get; } = new(Bytes(32, 0xc0));

        public ClientMailboxReceiptExpectation Expectation() => new()
        {
            Epoch = 7,
            OperationId = operationId,
            MailboxId = MailboxId,
            Route = Route,
            EnvelopeDigest = digest,
            ExpiresAtUnixSeconds = 1120,
            AllowedDispositions = new HashSet<MailboxReplicaDisposition>
            {
                MailboxReplicaDisposition.Stored
            },
            Cursor = 42
        };

        public byte[] Quorum(
            ulong cursor = 42,
            ulong? secondCursor = null,
            MailboxReplicaDisposition disposition =
                MailboxReplicaDisposition.Stored,
            byte[]? digest = null,
            ulong expiresAt = 1120)
        {
            digest ??= this.digest;
            var first = Replica(firstId, firstSeed, cursor, disposition, digest, expiresAt);
            var second = Replica(secondId, secondSeed, secondCursor ?? cursor,
                disposition, digest, expiresAt);
            var unsigned = new MailboxDurableQuorumReceiptV3
            {
                CoordinatorId = firstId,
                CoordinatorSequence = 42,
                FirstReplica = first,
                SecondReplica = second,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            return MailboxReceiptV3Codec.EncodeDurableQuorum(
                Crypto.SignQuorumResponse(unsigned, firstSeed));
        }

        private MailboxReplicaReceiptV2 Replica(
            byte[] replicaId,
            byte[] seed,
            ulong cursor,
            MailboxReplicaDisposition disposition,
            byte[] digest,
            ulong expiresAt) =>
            Crypto.SignReplicaResponse(
                new MailboxReplicaReceiptV2
                {
                    Status = MailboxReceiptStatus.Durable,
                    Disposition = disposition,
                    ReplicaId = replicaId,
                    OperationId = operationId,
                    Epoch = 7,
                    Cursor = cursor,
                    AcceptedAtUnixSeconds = 1050,
                    DurableAtUnixSeconds = 1051,
                    ExpiresAtUnixSeconds = expiresAt,
                    BlindedMailboxId = MailboxId.Bytes,
                    PlacementCommitment = MailboxPlacementCommitment.Compute(placement),
                    MembershipCommitment = membership,
                    EnvelopeDigest = digest,
                    Signature = ReadOnlyMemory<byte>.Empty
                }, seed);
    }

    private static byte[] Bytes(int count, byte start)
    {
        var value = new byte[count];
        for (var index = 0; index < count; index++)
            value[index] = unchecked((byte)(start + index));
        return value;
    }
}
