using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("renew")]
    [InlineData("diagnostic")]
    [InlineData("repeated")]
    [InlineData("clock")]
    [InlineData("cancel")]
    [InlineData("nonce")]
    public async Task Did2PermanentRead_CoherentHeadAcquisitionBeforeEffects(string mode)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckPermanentReadCoherenceAsync(mode);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckPermanentReadCoherenceAsync(string mode)
        {
            // Genuine signatures, independent nonce-bound directory proofs and
            // protected stores. The existing response adapter is in-process;
            // this does not claim socket, TLS, ONION or device E2E coverage.
            var intent = Bytes(32, 0xc5);
            var configuration = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd1));
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(intent, configuration, threshold, reopen: false);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnContactPublicationCommitAsync(intent, Source(), configuration,
                threshold, "DID2 publisher", new OwnedPublicationSource(this, route), replicas);
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            var reader = peerAccounts!;
            using var command = Source(reader).OpenCommandReadScope();
            var source = command.Source;
            var transport = new SyntheticPermanentRead(this, source, replicas.ExactPublication);
            var original = await reader.ResolvePermanentContactAsync(address, source, transport);
            var captured = await source.VerifyForOwnPreKeyAuthoringAsync(reader, default);
            retainedIssuanceHistory = new()
            {
                [genesis.ProtectedHead.LogGeneration] = genesis.ProtectedHead,
                [head.ProtectedHead.LogGeneration] = head.ProtectedHead
            };
            var next = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority, head.ProtectedHead,
                new(head.ExactAllTransitions, [checkpoint, peerCheckpoint!], [], 990, 1_500, 2), witnesses);
            var later = mode == "repeated"
                ? await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority, next.ProtectedHead,
                    new(next.ExactAllTransitions, [checkpoint, peerCheckpoint!], [], 990, 1_500, 2), witnesses)
                : null;
            using var cancelled = new CancellationTokenSource();
            OnNextDirectoryProof = () =>
            {
                head = next; retainedIssuanceHistory![head.ProtectedHead.LogGeneration] = head.ProtectedHead;
                if (mode == "clock") Sample = captured.Proof.MonotonicSample - 1;
                if (mode == "cancel") cancelled.Cancel();
                if (mode == "nonce") corruptGroupAcquisitionNonce = true;
                // Skip the retry's own proof; move again only at its peer read.
                if (later is not null) OnNextDirectoryProof = () => OnNextDirectoryProof = () =>
                {
                    head = later; retainedIssuanceHistory![head.ProtectedHead.LogGeneration] = head.ProtectedHead;
                };
            };
            var before = ProofRequests; var fetches = NetworkClosureFetches;
            if (mode == "diagnostic")
            {
                var peer = await reader.FetchContactPeerProofAsync(original.Candidate, peerProofs!, captured.Authority, default);
                var error = await Assert.ThrowsAsync<DeepIdV2RouteContextException>(async () =>
                    await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(original.Candidate, peer,
                        captured.Network, captured.Authority, source.RendezvousTrustedTime));
                Assert.Equal(DeepIdV2RouteContextCheck.DirectoryHead, error.Check);
                Assert.Equal("CurrentContext", error.Data["Deep.ContactRoute.Phase"]);
                Assert.Equal("DirectoryHead", error.Data["Deep.ContactRoute.Check"]);
                Assert.Equal("DID2 current route context failed (DirectoryHead).", error.Message);
                Assert.Equal(before + 1, ProofRequests); Assert.Equal(fetches, NetworkClosureFetches);
            }
            else if (mode == "renew")
            {
                var renewed = await source.VerifyPermanentContactAsync(original.Candidate, default);
                Assert.NotSame(captured, renewed.Own);
                Assert.Equal(next.ProtectedHead.LogGeneration, renewed.Own.Proof.NextProtectedLkg.LogGeneration);
                Assert.Equal(next.ProtectedHead.LogGeneration, renewed.Contact.Authorization.Freshness.NextProtectedLkg.LogGeneration);
                Assert.Same(original.Candidate, renewed.Contact.Candidate);
                Assert.Equal(before + 3, ProofRequests); Assert.Equal(fetches + 1, NetworkClosureFetches);
                // Repeating read-only verification is idempotent and needs no
                // additional whole-context acquisition once heads agree.
                _ = await source.VerifyPermanentContactAsync(original.Candidate, default);
                Assert.Equal(before + 4, ProofRequests); Assert.Equal(fetches + 1, NetworkClosureFetches);
            }
            else
            {
                var error = await Record.ExceptionAsync(async () =>
                    await source.VerifyPermanentContactAsync(original.Candidate, cancelled.Token));
                Assert.NotNull(error);
                if (mode == "repeated")
                {
                    var context = Assert.IsType<DeepIdV2RouteContextException>(error);
                    Assert.Equal(DeepIdV2RouteContextCheck.DirectoryHead, context.Check);
                    Assert.Equal(before + 3, ProofRequests); Assert.Equal(fetches + 1, NetworkClosureFetches);
                }
                else
                {
                    Assert.IsNotType<DeepIdV2RouteContextException>(error);
                    if (mode == "cancel") Assert.IsAssignableFrom<OperationCanceledException>(error);
                    Assert.Equal(before + 1, ProofRequests); Assert.Equal(fetches, NetworkClosureFetches);
                }
            }
            Assert.Equal(1, transport.Calls);
            Assert.False(await reader.HasOwnStagedPreKeyInventoryAsync());
        }
    }
}
