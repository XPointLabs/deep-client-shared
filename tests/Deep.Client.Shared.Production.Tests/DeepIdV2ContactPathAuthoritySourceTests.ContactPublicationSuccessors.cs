using System.Buffers.Binary;
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
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Did2PublicationSuccessors_RealExpiredObjectAndTwoReplicaLineage(int mode)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckContactPublicationSuccessorsAsync(mode);
    }

    [Fact]
    public void Did2PublicationSuccessors_HistoricalFactsAreClosedNotDispatchAuthority()
    {
        foreach (var type in new[] { typeof(VerifiedDeepIdV2ContactObjectPredecessor), typeof(VerifiedDeepIdV2PublicationPredecessor) })
        {
            Assert.Empty(type.GetConstructors());
            Assert.DoesNotContain(type.GetMethods(), value => value.Name is "EnsureCurrentAsync" or "SignAsync" or "DispatchAsync");
        }
    }

    private sealed partial class Fixture
    {
        // Real account/device/witness/node crypto; in-process replica results.
        // This is NOT physical transport or node persistence evidence.
        internal async Task CheckContactPublicationSuccessorsAsync(int mode)
        {
            var identity = (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText;
            var source = Source(); var staged = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var current = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span),
                checkpoint.Binding, checkpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(current.Proof, dca, Boot, Sample);
            using var device = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            var time = new OnionTrustedTimeAuthority(this);
            var expiry = current.Proof.TrustedUpperUnixSeconds + 20;
            var advertisement = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(recipient, current.Network, current.Authority,
                device!, 100, Bytes(32, 0xd1), Bytes(32, 0xd2), ScalarMult.Base(Bytes(32, 0xd3)),
                current.Proof.TrustedLowerUnixSeconds, expiry, time);
            var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(recipient, current.Network, current.Authority,
                advertisement.CanonicalBytes, witnesses.Select(value => new RouteWitness(value)).ToArray(),
                current.Proof.TrustedLowerUnixSeconds, expiry, time);
            var route = await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(recipient, current.Network, current.Authority,
                device!, advertisement.CanonicalBytes, threshold, 2, time);
            var services = new[] { DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span) };
            var capability = (await accounts.GetCurrentAsync())!.PermanentId.ResolverReadCapability.ToArray();
            try
            {
                var contact = await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(route, device!, services, "Successor QA", capability);
                var publication = await DeepIdV2PublicationAuthorityAuthor.AuthorGenesisRequestAsync(route, contact, device!,
                    Bytes(32, 0xe1), Bytes(32, 0xe2), Bytes(32, 0xe3));
                var authorized = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(route, publication.WireRequest, PublicationWitnesses());
                var result = PublicationResult(route, authorized.ExactXpu1);
                Assert.Equal(0UL, (await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(route, contact,
                    publication.WireRequest, authorized.ExactXpu1, result)).Generation);
                Sample += 20;
                await Assert.ThrowsAsync<CryptographicException>(async () => await route.EnsureCurrentAsync());
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreAsync(
                    route, contact.Closure.CanonicalBytes, contact.ProtectedDcr1, capability));
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(
                    route, contact, publication.WireRequest, authorized.ExactXpu1, result));

                for (var generation = 1UL; generation <= 2; generation++)
                {
                    var priorRoute = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, current.Network,
                        current.Authority, route.ExactXir1V2, route.ExactRouteClosure, time);
                    var priorObject = await DeepIdV2ContactObjectAuthor.VerifyPredecessorAsync(recipient, current.Network,
                        current.Authority, priorRoute, contact.Closure.CanonicalBytes, contact.ProtectedDcr1, capability, time);
                    var priorPublication = await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(recipient, current.Network,
                        current.Authority, priorObject, publication.WireRequest, authorized.ExactXpu1, result, time);
                    Assert.Equal(generation - 1, priorPublication.Generation);

                    if (mode == 1 && generation == 1)
                    {
                        var badCipher = contact.ProtectedDcr1.ToArray(); badCipher[^1] ^= 1;
                        await RequireRouteRejectionAsync(async () => await DeepIdV2ContactObjectAuthor.VerifyPredecessorAsync(recipient,
                            current.Network, current.Authority, priorRoute, contact.Closure.CanonicalBytes, badCipher, capability, time));
                        var badResult = PublicationResult(route, authorized.ExactXpu1, corruptReceipt: true);
                        await RequireRouteRejectionAsync(async () => await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(recipient,
                            current.Network, current.Authority, priorObject, publication.WireRequest, authorized.ExactXpu1, badResult, time));
                        var mutableDcr = contact.Closure.CanonicalBytes.ToArray(); var mutableCipher = contact.ProtectedDcr1.ToArray();
                        var mutableCapability = capability.ToArray();
                        var copying = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                        { Array.Clear(mutableDcr); Array.Clear(mutableCipher); Array.Clear(mutableCapability); return new(Boot, Sample); }));
                        var copied = await DeepIdV2ContactObjectAuthor.VerifyPredecessorAsync(recipient, current.Network, current.Authority,
                            priorRoute, mutableDcr, mutableCipher, mutableCapability, copying);
                        Assert.Equal(priorObject.CiphertextHash.ToArray(), copied.CiphertextHash.ToArray());
                        var mutableXpu = authorized.ExactXpu1.ToArray(); var mutableXpo = result.ToArray();
                        var publicationClock = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                        { Array.Clear(mutableXpu); Array.Clear(mutableXpo); return new(Boot, Sample); }));
                        priorPublication = await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(recipient, current.Network,
                            current.Authority, copied, publication.WireRequest, mutableXpu, mutableXpo, publicationClock);
                        Assert.Equal(0UL, priorPublication.Generation);
                        var neverReads = 0;
                        var never = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                        { neverReads++; return new(Boot, Sample); }));
                        await RequireRouteRejectionAsync(async () => await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(recipient,
                            current.Network, current.Authority, priorObject, publication.WireRequest, new byte[93_033], result, never));
                        Assert.Equal(0, neverReads);
                        var forgedPublisher = ContactPublicationAuthorityWireCodec.EncodeRequest(publication.WireRequest);
                        forgedPublisher[^1] ^= 1;
                        await RequireRouteRejectionAsync(async () => await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(recipient,
                            current.Network, current.Authority, priorObject, ContactPublicationAuthorityWireCodec.DecodeRequest(forgedPublisher),
                            authorized.ExactXpu1, result, time));
                    }

                    var nextExpiry = expiry + 20 + generation * 10;
                    var nextAdvertisement = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(recipient, current.Network,
                        current.Authority, device!, advertisement.CanonicalBytes, Bytes(32, (byte)(0xf0 + generation)),
                        Bytes(32, (byte)(0xf3 + generation)), ScalarMult.Base(Bytes(32, (byte)(0xf6 + generation))), nextExpiry, time);
                    var nextThreshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(recipient, current.Network,
                        current.Authority, priorRoute, nextAdvertisement.CanonicalBytes,
                        witnesses.Select(value => new RouteWitness(value)).ToArray(), nextExpiry, time);
                    var request = new ContactRouteAuthorityWireRequest(Network, Bytes(32, (byte)(0xc0 + generation)),
                        current.Proof.QueriedDirectoryLeafKey.Span, current.Proof.NextProtectedLkg.LogGeneration,
                        current.Proof.NextProtectedLkg.CoreHash.Span, staged.ExactDca1.Span, nextAdvertisement.CanonicalBytes.Span);
                    var issuance = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(recipient, current.Network,
                        current.Authority, request, nextThreshold, current.Proof.ExactAdh1, time);
                    var nextRoute = await DeepIdV2ContactRouteAuthor.CompleteSuccessorAsync(recipient, current.Network,
                        current.Authority, device!, priorRoute, nextAdvertisement.CanonicalBytes, nextThreshold, 2, time);
                    var nextContact = await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(nextRoute, issuance, priorObject,
                        device!, services, "Successor QA", capability);
                    Assert.Equal(generation, BinaryPrimitives.ReadUInt64BigEndian(nextContact.Closure.Bundle.Field(8).Span));
                    Assert.Equal(contact.Closure.Bundle.ObjectHash.ToArray(), nextContact.Closure.Bundle.Field(9).ToArray());
                    Assert.Equal(contact.Closure.Bundle.Field(7).ToArray(), nextContact.Closure.Bundle.Field(7).ToArray());
                    Assert.Equal(contact.LocatorHash.ToArray(), nextContact.LocatorHash.ToArray());
                    var restored = await DeepIdV2ContactObjectAuthor.RestoreAsync(nextRoute, nextContact.Closure.CanonicalBytes,
                        nextContact.ProtectedDcr1, capability);
                    Assert.Equal(nextContact.ProtectedDcr1.ToArray(), restored.ProtectedDcr1.ToArray());
                    var nextPublication = await DeepIdV2PublicationAuthorityAuthor.AuthorSuccessorRequestAsync(nextRoute, nextContact,
                        device!, priorPublication, Bytes(32, (byte)(0xb0 + generation)), Bytes(32, (byte)(0xb3 + generation)));
                    Assert.Equal(priorObject.CiphertextHash.ToArray(), nextPublication.WireRequest.PredecessorObjectHash.ToArray());
                    Assert.NotEqual(nextContact.Closure.Bundle.Field(9).ToArray(), nextPublication.WireRequest.PredecessorObjectHash.ToArray());
                    Assert.Equal(publication.WireRequest.OwnerRetrieveCapability.ToArray(), nextPublication.WireRequest.OwnerRetrieveCapability.ToArray());

                    if (mode == 2 && generation == 1)
                    {
                        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(
                            nextRoute, issuance, priorObject, device!, services, "Changed profile", capability));
                        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorGenesisRequestAsync(
                            nextRoute, nextContact, device!, Bytes(32, 0xa1), Bytes(32, 0xa2), Bytes(32, 0xa3)));
                        var untouched = witnesses.Select(value => new PublicationWitness(value)).ToArray();
                        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(
                            nextRoute, nextPublication.WireRequest, untouched));
                        Assert.All(untouched, signer => Assert.Equal(0, signer.Calls));
                        foreach (var invalid in new[] {
                            UntrustedPublicationCopy(nextPublication.WireRequest, nextContact.Closure.Bundle.Field(9), null),
                            UntrustedPublicationCopy(nextPublication.WireRequest, null, Bytes(32, 0xa9)) })
                        {
                            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdSuccessorAsync(
                                nextRoute, invalid, priorPublication, untouched));
                            Assert.All(untouched, signer => Assert.Equal(0, signer.Calls));
                        }
                        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorSuccessorRequestAsync(
                            route, contact, device!, priorPublication, Bytes(32, 0xa1), Bytes(32, 0xa2)));
                    }
                    if (mode == 3 && generation == 1)
                    {
                        var saved = Sample;
                        var nextHistory = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, current.Network,
                            current.Authority, nextRoute.ExactXir1V2, nextRoute.ExactRouteClosure, time);
                        var nextObjectHistory = await DeepIdV2ContactObjectAuthor.VerifyPredecessorAsync(recipient, current.Network,
                            current.Authority, nextHistory, nextContact.Closure.CanonicalBytes, nextContact.ProtectedDcr1, capability, time);
                        AuthoredDeepIdV2ContactObject futureContact;
                        AuthoredDeepIdV2PublicationRequest futurePublication;
                        VerifiedDeepIdV2PublicationAuthorization futureAuthorization;
                        try
                        {
                            Sample = saved + 1;
                            futureContact = await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(nextRoute, issuance,
                                priorObject, device!, services, "Successor QA", capability);
                            DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(futureContact.Closure, dca,
                                BinaryPrimitives.ReadUInt64BigEndian(futureContact.Closure.Bundle.Field(17).Span));
                            futurePublication = await DeepIdV2PublicationAuthorityAuthor.AuthorSuccessorRequestAsync(nextRoute, nextContact,
                                device!, priorPublication, Bytes(32, 0xa4), Bytes(32, 0xa5));
                            futureAuthorization = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdSuccessorAsync(nextRoute,
                                futurePublication.WireRequest, priorPublication, PublicationWitnesses());
                        }
                        finally { Sample = saved; } // Simulate independently earlier current time for negative verification only.
                        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.VerifyPredecessorAsync(
                            recipient, current.Network, current.Authority, nextHistory, futureContact.Closure.CanonicalBytes,
                            futureContact.ProtectedDcr1, capability, time));
                        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(
                            recipient, current.Network, current.Authority, nextObjectHistory, futurePublication.WireRequest,
                            futureAuthorization.ExactXpu1, PublicationResult(nextRoute, futureAuthorization.ExactXpu1), time));
                        var delayed = new PublicationWitness(witnesses[0], () => Sample = current.Proof.FreshnessDeadlineMonotonicSeconds);
                        try
                        {
                            await RequireRouteRejectionAsync(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdSuccessorAsync(
                                nextRoute, nextPublication.WireRequest, priorPublication, [delayed, new PublicationWitness(witnesses[1])]));
                            Assert.Equal(1, delayed.Calls);
                        }
                        finally { Sample = saved; } // Fixture fault cleanup only.
                        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(
                            recipient, current.Network, current.Authority, priorObject, publication.WireRequest,
                            authorized.ExactXpu1, result, time, cancelled.Token));
                        var reads = 0;
                        var reversing = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() => new(Boot, ++reads == 1 ? Sample : Sample - 1)));
                        await RequireRouteRejectionAsync(async () => await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(recipient,
                            current.Network, current.Authority, priorObject, publication.WireRequest, authorized.ExactXpu1, result, reversing));
                    }
                    var nextAuthorized = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdSuccessorAsync(nextRoute,
                        nextPublication.WireRequest, priorPublication, PublicationWitnesses());
                    var response = await nextPublication.VerifyResponseAsync(nextAuthorized.ExactXpu1);
                    Assert.Equal(nextAuthorized.ExactXpu1.ToArray(), response.ExactXpu1.ToArray());
                    var nextResult = PublicationResult(nextRoute, nextAuthorized.ExactXpu1);
                    Assert.Equal(generation, (await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(nextRoute, nextContact,
                        nextPublication.WireRequest, nextAuthorized.ExactXpu1, nextResult)).Generation);
                    route = nextRoute; contact = nextContact; advertisement = nextAdvertisement;
                    publication = nextPublication; authorized = nextAuthorized; result = nextResult;
                }
                Assert.Equal(identity, (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText);

                static ContactPublicationAuthorityWireRequest UntrustedPublicationCopy(ContactPublicationAuthorityWireRequest original,
                    ReadOnlyMemory<byte>? predecessorHash, ReadOnlyMemory<byte>? ownerCapability) => new(original.NetworkId.Span,
                        original.RequestNonce.Span, original.DirectoryLookupKey.Span, original.MinimumAdh1Generation,
                        original.MinimumAdh1CoreHash.Span, original.ExactDca1.Span, original.ExactDcr1.Span, original.ExactRouteClosure.Span,
                        original.OperationId.Span, original.Generation, (predecessorHash ?? original.PredecessorObjectHash).Span,
                        original.ObjectCiphertext.Span, original.IssuedAtUnixSeconds, original.ExpiresAtUnixSeconds,
                        original.EffectiveExpiresAtUnixSeconds, (ownerCapability ?? original.OwnerRetrieveCapability).Span,
                        original.PublisherSignature.Span);
            }
            finally { CryptographicOperations.ZeroMemory(capability); }
        }
    }
}
