using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task StoredAttachmentReplayVerifiesOriginalPayloadAndReceiptBeforeAnyNewUpload()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        var assetOperation = Bytes(32, 0xe3);
        using var asset = await fixture.PrepareOwnedAsset(sender, assetOperation, [1, 2, 3], "stored.bin", "application/octet-stream", 4_000_000);
        using var offer = await fixture.CreateOwnedAttachmentOffer(sender, assetOperation);
        using var manifestBytes = asset.OwnManifest(); using var manifest = manifestBytes.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
        Assert.Null(await fixture.ReadRetainedAttachmentStore(sender, offer.OperationId, manifest));
        using var sent = await fixture.SendOwnedMessage(sender, offer.OperationId, ApplicationCoreCodec.DecodeDmc2(offer.ExactDmc2.Span));
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, offer.OperationId.ToArray(), sent.ExactEnvelope.ToArray());
        await fixture.DeliverNativeMessage(sender, offer.OperationId.ToArray(), grants, transport);
        Assert.Empty(await fixture.ReopenAccount().ListPendingAttachmentOperationsAsync());
        var retainedOperation = Assert.Single(await fixture.ReopenAccount().ListAttachmentOperationsAsync());
        Assert.True(retainedOperation.Stored); Assert.False(retainedOperation.WorkStopped);
        Assert.Equal(Convert.ToHexStringLower(offer.OperationId.Span), retainedOperation.Operation);
        var cached = await fixture.ReadRetainedAttachmentStore(sender, offer.OperationId, manifest);
        Assert.NotNull(cached); Assert.False(cached.IngressDispatched);
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        using var changed = ApplicationCoreCodec.AuthorDam1(manifest.NetworkId.Span, manifest.ObjectId.Span,
            manifest.BlobCapability.Span, manifest.ObjectKey.Span, manifest.TotalPlaintextBytes,
            manifest.Chunks, manifest.ExpiresAtUnixSeconds + 1, manifest.Filename, manifest.MediaType);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReadRetainedAttachmentStore(sender, offer.OperationId, changed));
        var again = await fixture.ReadRetainedAttachmentStore(sender, offer.OperationId, manifest);
        Assert.NotNull(again); Assert.False(again.IngressDispatched);
    }

    private sealed partial class Fixture
    {
        internal async Task<ClientMailboxStoreResult?> ReadRetainedAttachmentStore(Did2MessagingSessionScope scope,
            ReadOnlyMemory<byte> operation, ParsedDam1 manifest)
        {
            var account = ReopenAccount(); var source = Source(account);
            var own = await source.VerifyForOwnPreKeyAuthoringAsync(account, default);
            using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
            return await SenderCompactionOwner().ReadRetainedDirectAttachmentStoreAsync(1_000, verifier, scope,
                operation, manifest, own, source, default);
        }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task PendingAttachmentProjectionFindsOnlyOriginalOwnedOfferAcrossColdReopen()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        var assetOperation = Bytes(32, 0xe1);
        using var asset = await fixture.PrepareOwnedAsset(sender, assetOperation, [1, 2, 3], "pending.bin", "application/octet-stream", 4_000_000);
        // An arbitrary caller operation is never permission to create an offer.
        await Assert.ThrowsAsync<IOException>(() => fixture.RetryOwnedAttachmentOffer(sender, Bytes(32, 0xe2), assetOperation));
        Assert.Empty(await fixture.ReopenAccount().ListPendingAttachmentOperationsAsync());
        using var authored = await fixture.CreateOwnedAttachmentOffer(sender, assetOperation);
        using var manifestBytes = asset.OwnManifest(); using var manifest = manifestBytes.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
        using var root = await fixture.CompletedContactSendStorage(true).ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
        var before = root.Use(bytes => bytes.ToArray());
        try
        {
            for (var reopen = 0; reopen < 2; reopen++)
            {
                var account = fixture.ReopenAccount();
                var pending = Assert.Single(await account.ListPendingAttachmentOperationsAsync());
                Assert.Equal(Convert.ToHexStringLower(authored.OperationId.Span), pending.Operation);
                Assert.Equal(Convert.ToHexString(sender.Conversation), pending.ConversationId);
                Assert.Equal(Convert.ToHexStringLower(manifest.ObjectId.Span), pending.ObjectId);
                Assert.False(pending.Stored); Assert.False(pending.WorkStopped);
                Assert.Empty(await account.ListPendingTextOperationsAsync());
                using var retry = await fixture.RetryOwnedAttachmentOffer(sender, authored.OperationId, assetOperation);
                Assert.Equal(authored.ExactDmc2.ToArray(), retry.ExactDmc2.ToArray());
            }
            using var after = await fixture.CompletedContactSendStorage(true).ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidDataException();
            Assert.True(after.Use(bytes => bytes.SequenceEqual(before)));
        }
        finally { CryptographicOperations.ZeroMemory(before); }
    }
}
