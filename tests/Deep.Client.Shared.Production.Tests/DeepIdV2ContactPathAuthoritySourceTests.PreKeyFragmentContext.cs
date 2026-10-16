using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task PreKeyFragments_OneCommandSealsBothSelectedPathsWithoutFullReacquisition()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        var source = fixture.Source();
        var staged = await fixture.Accounts.EnsureOwnPreKeyInventoryAsync(source);
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(fixture.Accounts, default);
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
        var placement = ContactServicePlacementFactory.Create(fresh.Network,
            ContactServiceRequestKind.PublishPreKeyInventory, publication.Manifest.Field(2));
        var sequence = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(staged.ExactXpp1.Span,
            placement.ViewHash.Span, staged.ExactDid2.Span, staged.ExactDca1.Span, staged.ExactXps1.Span);
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        var transport = new DeepIdV2PublicationOnionTransport(source, custody);
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(custody.Entropy),
            new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
        var before = fixture.ProofRequests;
        var sealedFrames = 0;
        foreach (var replica in placement.RankedReplicaNodeIds)
        foreach (var exact in sequence)
        {
            var request = ContactResolveCanonicalPathRequest.FromDid2BoundedPublication(
                DeepIdV2BoundedPreKeyPublicationCodec.Decode(exact), publication.Manifest.Field(2).Span,
                Math.Min(BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(15).Span), placement.ValidUntilUnixSeconds));
            var prepared = await transport.PreparePreKeyPublicationAsync(request, replica, fresh, default);
            Assert.Same(fresh.Network, prepared.Authority.Network);
            using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request, default);
            Assert.False(built.Frame.IsEmpty);
            await source.RecheckOwnPreKeyAuthoringAsync(fresh, default);
            sealedFrames++;
        }
        Assert.Equal(sequence.Count * 2, sealedFrames);
        Assert.Equal(before, fixture.ProofRequests);
        Assert.Null(await fixture.Accounts.ReadOwnPreKeyCommitPairAsync());
        await source.VerifyForOwnPreKeyAuthoringAsync(fixture.Accounts, default);
        Assert.Equal(before + 1, fixture.ProofRequests); // Independent next acquisition.
        // Real signed/native encrypted path/frame evidence only: no socket,
        // synthetic XIC1, successful publication or physical claim.
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task PreKeyFragments_ExpiredOrCancelledContextRejectsBeforeGuardReservation(bool cancel)
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var staged = await fixture.Accounts.EnsureOwnPreKeyInventoryAsync(source);
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(fixture.Accounts, default);
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
        var placement = ContactServicePlacementFactory.Create(fresh.Network,
            ContactServiceRequestKind.PublishPreKeyInventory, publication.Manifest.Field(2));
        var sequence = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(staged.ExactXpp1.Span,
            placement.ViewHash.Span, staged.ExactDid2.Span, staged.ExactDca1.Span, staged.ExactXps1.Span);
        var request = ContactResolveCanonicalPathRequest.FromDid2BoundedPublication(
            DeepIdV2BoundedPreKeyPublicationCodec.Decode(sequence[0]), publication.Manifest.Field(2).Span,
            Math.Min(BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(15).Span), placement.ValidUntilUnixSeconds));
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        var transport = new DeepIdV2PublicationOnionTransport(source, custody);
        using var cancelled = new CancellationTokenSource();
        if (cancel) cancelled.Cancel();
        else fixture.Sample += 100_000; // Expire real signed freshness, never extend it.
        var before = fixture.ProofRequests;
        if (cancel)
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await transport.PreparePreKeyPublicationAsync(request, placement.RankedReplicaNodeIds[0], fresh, cancelled.Token));
        else
            await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                await transport.PreparePreKeyPublicationAsync(request, placement.RankedReplicaNodeIds[0], fresh, default));
        Assert.Equal(before, fixture.ProofRequests);
        Assert.Null(await custody.Guards.ReadAsync(default));
        Assert.Equal(staged.ExactXpp1.ToArray(), (await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync())!.ExactXpp1.ToArray());
        Assert.Null(await fixture.Accounts.ReadOwnPreKeyCommitPairAsync());
    }
}
