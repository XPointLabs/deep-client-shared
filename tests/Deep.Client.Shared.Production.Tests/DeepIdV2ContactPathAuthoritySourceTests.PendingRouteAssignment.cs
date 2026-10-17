using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2PendingRoute_ThresholdCompletesExactProposalAcrossViewButRejectsChangedEpoch(bool changedEpoch)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckPendingRouteAssignmentAsync(changedEpoch);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckPendingRouteAssignmentAsync(bool changedEpoch)
        {
            // Real signed account, history, current proof and witnesses. This
            // models a frozen proposal crossing publication, not device delivery.
            var inventory = await accounts.EnsureOwnPreKeyInventoryAsync(Source());
            var first = await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var delegation = DeepIdV2ContactAuthorizationCodec.Verify(
                DeepIdV2ContactAuthorizationCodec.Decode(inventory.ExactDca1.Span), checkpoint.Binding, checkpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(first.Proof, delegation, Boot, Sample);
            using var secrets = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            var time = new OnionTrustedTimeAuthority(this);
            var advertisement = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(recipient, first.Network,
                first.Authority, secrets!, 100, Bytes(32, 0xd1), Bytes(32, 0xd2), ScalarMult.Base(Bytes(32, 0xd3)),
                first.Proof.TrustedLowerUnixSeconds, 1_400, time);
            var exactProposal = advertisement.CanonicalBytes.ToArray();
            var originalThreshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(recipient,
                first.Network, first.Authority, exactProposal, CreateRouteWitnesses(),
                first.Proof.TrustedLowerUnixSeconds, 1_400, time);

            await AdvanceNetworkAsync();
            if (changedEpoch) AuthorSignedEpochAdvance();
            ProofTime = 1_100; Sample = 200;
            var reopened = ReopenAccount();
            NetworkStore = await ReopenNetworkStoreAsync();
            var next = await Source(reopened).VerifyForOwnPreKeyAuthoringAsync(reopened, default);
            var current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(next.Proof, delegation, Boot, Sample);
            Assert.NotEqual(first.Network.ProtectedLkg!.ViewGeneration, next.Network.ProtectedLkg!.ViewGeneration);

            if (changedEpoch)
            {
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(current, next.Network, next.Authority,
                        exactProposal, CreateRouteWitnesses(), current.TrustedLowerUnixSeconds, 1_400, time));
                return;
            }

            // Fully signed old issuance is not authority to issue NOW, even
            // though its original assignment remains independently eligible.
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await DeepIdV2ContactRouteVerifier.VerifyThresholdAsync(current, next.Network,
                    next.Authority, exactProposal, originalThreshold, time));
            var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(current, next.Network, next.Authority,
                exactProposal, CreateRouteWitnesses(), current.TrustedLowerUnixSeconds, 1_400, time);
            var completed = await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(current, next.Network,
                next.Authority, secrets!, exactProposal, threshold, 2, time);
            await completed.EnsureCurrentAsync();
            Assert.Equal(exactProposal, completed.Route.Authorization.CanonicalBytes.ToArray());
            Assert.Equal(advertisement.Field(5).ToArray(), threshold.LiveRoute.Field(6).ToArray());
            Assert.Equal(next.Network.ProtectedLkg!.ViewCoreReference.ToArray(), threshold.LiveRoute.Field(8).ToArray());
        }
    }
}
