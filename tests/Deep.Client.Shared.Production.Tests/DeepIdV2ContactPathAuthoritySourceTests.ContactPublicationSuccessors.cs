using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
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
    public async Task Did2PreKeyServiceSuccession_NativeOwnerAndIssuerKeepIdentityAndLocator()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckContactPublicationSuccessorsAsync(4);
    }

    [Fact]
    public async Task Did2PreKeyServiceHistory_SignedFiveSixSevenOwnerAndIndependentIssuer()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckContactPublicationSuccessorsAsync(5);
    }

    [Fact]
    public async Task Did2RecordedRouteHistory_CompletedFiveRecordedSixLiveSevenKeepsIndependentIssuerAndFurtherOffset()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckContactPublicationSuccessorsAsync(6);
    }

    [Fact]
    public void Did2PublicationSuccessors_HistoricalFactsAreClosedNotDispatchAuthority()
    {
        foreach (var type in new[] { typeof(VerifiedDeepIdV2ContactObjectPredecessor), typeof(VerifiedDeepIdV2PublicationPredecessor), typeof(VerifiedDeepIdV2PublicationIssuerPredecessor) })
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
            var source = Source(); var staged = await accounts.EnsureOwnPreKeyInventoryAsync(source);
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
            if (mode == 0)
            {
                var changed = advertisement.CanonicalBytes.ToArray();
                var pmtOffset = changed.AsSpan().IndexOf(advertisement.Field(5).Span);
                Assert.True(pmtOffset >= 0);
                changed[pmtOffset + advertisement.Field(5).Length - 1] ^= 1;
                var error = await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2ContactRouteVerifier.VerifyAdvertisementAsync(recipient, current.Network,
                        current.Authority, changed, time));
                Assert.Equal("pmt-reference", error.Data["Deep.ContactRoute.Scope"]);
                Assert.Single(error.Data);
            }
            var route = await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(recipient, current.Network, current.Authority,
                device!, advertisement.CanonicalBytes, threshold, 2, time);
            var services = new[] { DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span) };
            using var prekeyAuthor = mode is 4 or 5 ? await accounts.OpenLocalPreKeyAuthoringAuthorityAsync() : null;
            if (mode is 4 or 5)
            {
                // A separately signed short-lived service candidate makes the
                // actual predecessor expire before recovery. Do not replace
                // the protected staged inventory: custody is a separate gate.
                var serviceContext = new Dpk2AuthoringContext(ApplicationCoreVerifier.StartDmd1Lineage(checkpoint.Directory).Next,
                    1, 1, 1, current.Proof.TrustedLowerUnixSeconds, current.Proof.TrustedLowerUnixSeconds,
                    current.Proof.TrustedUpperUnixSeconds + (mode == 5 ? 1UL : 10UL));
                services[0] = DeepIdV2PreKeyServiceCodec.Decode(prekeyAuthor!.AuthorPreKeyServiceV2(
                    serviceContext, checkpoint.Binding, 32, 1).ExactXps1.Span);
            }
            var capability = (await accounts.GetCurrentAsync())!.PermanentId.ResolverReadCapability.ToArray();
            try
            {
                if (mode == 5)
                    for (var serviceGeneration = 2UL; serviceGeneration <= 5; serviceGeneration++)
                        services[0] = AuthorNextService(services[0], current.Proof.TrustedLowerUnixSeconds,
                            checked(current.Proof.TrustedUpperUnixSeconds + serviceGeneration));
                var contact = await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(route, device!, services, "Successor QA", capability);
                var publication = await DeepIdV2PublicationAuthorityAuthor.AuthorGenesisRequestAsync(route, contact, device!,
                    Bytes(32, 0xe1), Bytes(32, 0xe2), Bytes(32, 0xe3));
                if (mode == 4)
                    Assert.Equal(BinaryPrimitives.ReadUInt64BigEndian(services[0].Field(11).Span),
                        publication.WireRequest.ExpiresAtUnixSeconds);
                var authorized = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(route, publication.WireRequest, PublicationWitnesses());
                var initialPrivatePackage = mode == 6 ? DeepIdV2ContactMailboxRouteCodec.Decode(
                    DeepIdV2ContactMailboxRouteCodec.Encode(route)) : null;
                var result = PublicationResult(route, authorized.ExactXpu1);
                Assert.Equal(0UL, (await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(route, contact,
                    publication.WireRequest, authorized.ExactXpu1, result)).Generation);
                if (mode == 4)
                {
                    var later = AuthorNextService(services[0], current.Proof.TrustedLowerUnixSeconds,
                        checked(BinaryPrimitives.ReadUInt64BigEndian(services[0].Field(11).Span) + 60));
                    var initial = await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(route, device!,
                        [later], "Later service genesis QA", capability);
                    Assert.Equal(later.CanonicalBytes.ToArray(), initial.Closure.Bundle.Field(12).Span[5..].ToArray());
                    var damaged = later.CanonicalBytes.ToArray(); damaged[^1] ^= 1;
                    await RequireRouteRejectionAsync(async () => await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(route,
                        device!, [DeepIdV2PreKeyServiceCodec.Decode(damaged)], "Later service genesis QA", capability));
                }
                if (mode == 0)
                {
                    var rejected = Xpo1Codec.Encode(authorized.ExactXpu1.Span, Xpo1Status.Expired,
                        ContactServiceMutationOutcome.None, current.Proof.TrustedUpperUnixSeconds, 0,
                        ContactServicePaddingClass.Bytes256, []);
                    var error = await Assert.ThrowsAsync<CryptographicException>(async () =>
                        await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(route, contact,
                            publication.WireRequest, authorized.ExactXpu1, rejected));
                    Assert.Equal((ushort)Xpo1Status.Expired, error.Data["Deep.ContactPublication.Status"]);
                    Assert.Equal((byte)ContactServiceMutationOutcome.None, error.Data["Deep.ContactPublication.MutationOutcome"]);
                    Assert.Equal(2, error.Data.Count);
                }
                Sample += 20;
                await Assert.ThrowsAsync<CryptographicException>(async () => await route.EnsureCurrentAsync());
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreAsync(
                    route, contact.Closure.CanonicalBytes, contact.ProtectedDcr1, capability));
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(
                    route, contact, publication.WireRequest, authorized.ExactXpu1, result));

                for (var generation = 1UL; generation <= (mode == 6 ? 7UL : 2UL); generation++)
                {
                    VerifiedDeepIdV2ContactRouteRecordedHistory? recordedHistory = null;
                    if (mode == 6 && generation == 6)
                    {
                        var anchor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, current.Network,
                            current.Authority, route.ExactXir1V2, route.ExactRouteClosure, time);
                        var recordedExpiry = expiry + 20 + generation * 10;
                        var recordedAdvertisement = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(
                            recipient, current.Network, current.Authority, device!, advertisement.CanonicalBytes,
                            Bytes(32, 0x91), Bytes(32, 0x92), ScalarMult.Base(Bytes(32, 0x93)), recordedExpiry, time);
                        var recordedRequest = new ContactRouteAuthorityWireRequest(Network, Bytes(32, 0x94),
                            current.Proof.QueriedDirectoryLeafKey.Span, current.Proof.NextProtectedLkg.LogGeneration,
                            current.Proof.NextProtectedLkg.CoreHash.Span, staged.ExactDca1.Span, recordedAdvertisement.CanonicalBytes.Span,
                            anchor.ExactXir1V2.Span, anchor.ExactRouteClosure.Span);
                        var recordedThreshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(recipient,
                            current.Network, current.Authority, anchor, recordedRequest.ExactXra1,
                            witnesses.Select(value => new RouteWitness(value)).ToArray(), recordedExpiry, time);
                        var pair = new DeepIdV2ContactRouteRecordedPair(ContactRouteAuthorityWireCodec.EncodeRequest(recordedRequest),
                            ContactRouteAuthorityWireCodec.EncodeResponse(recordedRequest, new(Network, recordedRequest.RequestNonce.Span,
                                recordedThreshold.Selection.CanonicalBytes.Span, recordedThreshold.LiveRoute.CanonicalBytes.Span,
                                recordedThreshold.Successor.CanonicalBytes.Span, current.Proof.ExactAdh1.Span)));
                        var elapsed = checked(recordedExpiry - current.Proof.TrustedLowerUnixSeconds + 20);
                        ProofTime += elapsed; Sample += elapsed;
                        current = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
                        recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(current.Proof, dca, Boot, Sample);
                        anchor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, current.Network,
                            current.Authority, route.ExactXir1V2, route.ExactRouteClosure, time);
                        recordedHistory = await DeepIdV2ContactRouteVerifier.VerifyRecordedHistoryAsync(recipient,
                            current.Network, current.Authority, anchor, [pair], time);
                        Assert.Equal(5UL, BinaryPrimitives.ReadUInt64BigEndian(route.Invite.Field(3).Span));
                        Assert.Equal(6UL, BinaryPrimitives.ReadUInt64BigEndian(recordedAdvertisement.Field(3).Span));
                        Assert.Equal(contact.Closure.CanonicalBytes.ToArray(),
                            (await DeepIdV2ContactObjectAuthor.VerifyPredecessorAsync(recipient, current.Network, current.Authority,
                                anchor, contact.Closure.CanonicalBytes, contact.ProtectedDcr1, capability, time)).Closure.CanonicalBytes.ToArray());
                    }
                    var priorRoute = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, current.Network,
                        current.Authority, route.ExactXir1V2, route.ExactRouteClosure, time);
                    var priorObject = await DeepIdV2ContactObjectAuthor.VerifyPredecessorAsync(recipient, current.Network,
                        current.Authority, priorRoute, contact.Closure.CanonicalBytes, contact.ProtectedDcr1, capability, time);
                    var priorPublication = await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(recipient, current.Network,
                        current.Authority, priorObject, publication.WireRequest, authorized.ExactXpu1, result, time);
                    Assert.Equal(generation - 1, priorPublication.Generation);
                    var issuerPredecessor = await DeepIdV2PublicationCommitVerifier.VerifyIssuerPredecessorAsync(recipient,
                        current.Network, current.Authority, publication.WireRequest, authorized.ExactXpu1, result, time);
                    Assert.Equal(priorPublication.Generation, issuerPredecessor.Generation);

                    if (mode == 1 && generation == 1)
                    {
                        var badCipher = contact.ProtectedDcr1.ToArray(); badCipher[^1] ^= 1;
                        await RequireRouteRejectionAsync(async () => await DeepIdV2ContactObjectAuthor.VerifyPredecessorAsync(recipient,
                            current.Network, current.Authority, priorRoute, contact.Closure.CanonicalBytes, badCipher, capability, time));
                        var badResult = PublicationResult(route, authorized.ExactXpu1, corruptReceipt: true);
                        await RequireRouteRejectionAsync(async () => await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(recipient,
                            current.Network, current.Authority, priorObject, publication.WireRequest, authorized.ExactXpu1, badResult, time));
                        await RequireRouteRejectionAsync(async () => await DeepIdV2PublicationCommitVerifier.VerifyIssuerPredecessorAsync(recipient,
                            current.Network, current.Authority, publication.WireRequest, authorized.ExactXpu1, badResult, time));
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
                        await RequireRouteRejectionAsync(async () => await DeepIdV2PublicationCommitVerifier.VerifyIssuerPredecessorAsync(recipient,
                            current.Network, current.Authority, publication.WireRequest, authorized.ExactXpu1, new byte[16_385], never));
                        Assert.Equal(0, neverReads);
                        var forgedPublisher = ContactPublicationAuthorityWireCodec.EncodeRequest(publication.WireRequest);
                        forgedPublisher[^1] ^= 1;
                        await RequireRouteRejectionAsync(async () => await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(recipient,
                            current.Network, current.Authority, priorObject, ContactPublicationAuthorityWireCodec.DecodeRequest(forgedPublisher),
                            authorized.ExactXpu1, result, time));
                    }

                    var nextExpiry = recordedHistory is null ? expiry + 20 + generation * 10 : current.Proof.TrustedUpperUnixSeconds + 30;
                    if (mode == 6 && generation == 7) nextExpiry = current.Proof.TrustedUpperUnixSeconds + 40;
                    var nextAdvertisement = recordedHistory is null
                        ? await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(recipient, current.Network,
                            current.Authority, device!, advertisement.CanonicalBytes, Bytes(32, (byte)(0xf0 + generation)),
                            Bytes(32, (byte)(0xf3 + generation)), ScalarMult.Base(Bytes(32, (byte)(0xf6 + generation))), nextExpiry, time)
                        : await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAfterRecordedHistoryAsync(recipient, current.Network,
                            current.Authority, device!, recordedHistory, Bytes(32, 0xa1), Bytes(32, 0xa2),
                            ScalarMult.Base(Bytes(32, 0xa3)), nextExpiry, time);
                    var request = new ContactRouteAuthorityWireRequest(Network, Bytes(32, (byte)(0xc0 + generation)),
                        current.Proof.QueriedDirectoryLeafKey.Span, current.Proof.NextProtectedLkg.LogGeneration,
                        current.Proof.NextProtectedLkg.CoreHash.Span, staged.ExactDca1.Span, nextAdvertisement.CanonicalBytes.Span,
                        priorRoute.ExactXir1V2.Span, priorRoute.ExactRouteClosure.Span);
                    var nextThreshold = recordedHistory is null
                        ? await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(recipient, current.Network,
                            current.Authority, priorRoute, nextAdvertisement.CanonicalBytes,
                            witnesses.Select(value => new RouteWitness(value)).ToArray(), nextExpiry, time)
                        : await DeepIdV2ContactRouteAuthor.AuthorThresholdAfterRecordedHistoryAsync(recipient, current.Network,
                            current.Authority, recordedHistory, nextAdvertisement.CanonicalBytes,
                            witnesses.Select(value => new RouteWitness(value)).ToArray(), nextExpiry, time);
                    var issuance = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(recipient, current.Network,
                        current.Authority, request, nextThreshold, current.Proof.ExactAdh1, time, recordedHistory: recordedHistory);
                    var nextRoute = mode == 6
                        ? await DeepIdV2ContactRouteAuthor.CompleteRetainedSuccessorAsync(recipient, current.Network,
                            current.Authority, device!, priorRoute, issuance, 2, time)
                        : await DeepIdV2ContactRouteAuthor.CompleteSuccessorAsync(recipient, current.Network,
                            current.Authority, device!, priorRoute, nextAdvertisement.CanonicalBytes, nextThreshold, 2, time);
                    if (mode == 6 && generation >= 6)
                    {
                        Assert.Equal(generation + 1, BinaryPrimitives.ReadUInt64BigEndian(nextAdvertisement.Field(3).Span));
                        Assert.Equal(generation, BinaryPrimitives.ReadUInt64BigEndian(nextRoute.Invite.Field(3).Span));
                        Assert.Equal(generation, BinaryPrimitives.ReadUInt64BigEndian(nextRoute.Route.Reachability.Field(3).Span));
                    }
                    ParsedXps1V2[] serviceHistory = [];
                    if (mode is 4 or 5)
                    {
                        var window = await nextRoute.ReadCurrentTimeAsync();
                        var old = services[0];
                        var oldExpiry = BinaryPrimitives.ReadUInt64BigEndian(old.Field(11).Span);
                        if (generation == 1) Assert.True(oldExpiry <= window.LowerUnixSeconds);
                        Assert.Throws<CryptographicException>(() => AuthorNextService(old,
                            BinaryPrimitives.ReadUInt64BigEndian(old.Field(10).Span), oldExpiry));
                        Assert.Throws<CryptographicException>(() => AuthorNextService(old,
                            window.LowerUnixSeconds, checked(oldExpiry + 60), minimum: 33));
                        foreach (var invalid in new[]
                        {
                            SignHostileServiceFixture(old, BinaryPrimitives.ReadUInt64BigEndian(old.Field(10).Span), oldExpiry),
                            SignHostileServiceFixture(old, window.LowerUnixSeconds, checked(oldExpiry + 60), minimum: 33)
                        })
                            await RequireRouteRejectionAsync(async () => await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(
                                nextRoute, issuance, priorObject, device!, [invalid], "Successor QA", capability));
                        if (mode == 5 && generation == 1)
                        {
                            Assert.Equal(5UL, BinaryPrimitives.ReadUInt64BigEndian(old.Field(5).Span));
                            var intermediate = AuthorNextService(old, BinaryPrimitives.ReadUInt64BigEndian(old.Field(10).Span),
                                checked(oldExpiry + 1));
                            Assert.True(BinaryPrimitives.ReadUInt64BigEndian(intermediate.Field(11).Span) <= window.LowerUnixSeconds);
                            serviceHistory = [intermediate];
                            services[0] = AuthorNextService(intermediate, window.LowerUnixSeconds, checked(oldExpiry + 60));
                            Assert.Equal(7UL, BinaryPrimitives.ReadUInt64BigEndian(services[0].Field(5).Span));
                            foreach (var invalidHistory in InvalidHistory(old, intermediate, services[0]))
                                await RequireRouteRejectionAsync(async () => await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(
                                    nextRoute, issuance, priorObject, device!, services, "Successor QA", capability,
                                    preKeyServiceHistory: invalidHistory));
                        }
                        else if (mode == 4)
                            services[0] = AuthorNextService(old, window.LowerUnixSeconds, checked(oldExpiry + 60));
                        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                            await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(nextRoute, issuance,
                                priorObject, device!, services, "Successor QA", capability, cancelled.Token));
                    }
                    var nextContact = await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(nextRoute, issuance, priorObject,
                        device!, services, "Successor QA", capability, preKeyServiceHistory: serviceHistory);
                    Assert.Equal(serviceHistory.Select(value => Convert.ToHexString(SHA256.HashData(value.CanonicalBytes.Span))),
                        nextContact.Closure.PreKeyServiceHistory.Select(value => Convert.ToHexString(SHA256.HashData(value.CanonicalBytes.Span))));
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
                    Assert.Equal(result.ToArray(), nextPublication.WireRequest.ExactPriorXpo1.ToArray());
                    await DeepIdV2PublicationAuthorityAuthor.VerifyIssuerSuccessorRequestAsync(nextRoute, nextPublication.WireRequest, issuerPredecessor);
                    if (mode == 5 && generation == 1)
                    {
                        var old = DeepIdV2PreKeyServiceCodec.Decode(priorObject.Closure.Bundle.Field(12).Span[5..]);
                        var untouched = witnesses.Select(value => new PublicationWitness(value)).ToArray();
                        foreach (var invalidHistory in InvalidHistory(old, serviceHistory[0], services[0]))
                        {
                            // The ordinary author cannot mint hostile histories.
                            // This fixture re-signs only its own fresh account's
                            // request, preserving the authentic prior receipts.
                            await RequireRouteRejectionAsync(async () =>
                            {
                                var invalid = SignedHistoryRequest(nextPublication.WireRequest, invalidHistory);
                                await DeepIdV2PublicationAuthorityAuthor.AuthorIssuerThresholdSuccessorAsync(
                                    nextRoute, invalid, issuerPredecessor, untouched);
                            });
                            Assert.All(untouched, signer => Assert.Equal(0, signer.Calls));
                        }
                        // Generic resolution accepts the authenticated suffix
                        // with no witnesses; only the real prior XPS5 rejects it.
                        var omitted = SignedHistoryRequest(nextPublication.WireRequest, []);
                        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(
                            DeepIdV2ResolverClosureCodec.Decode(omitted.ExactDcr1.Span), dca,
                            (await nextRoute.ReadCurrentTimeAsync()).UpperUnixSeconds);
                        await RequireRouteRejectionAsync(async () => await DeepIdV2PublicationAuthorityAuthor.VerifyIssuerSuccessorRequestAsync(
                            nextRoute, omitted, issuerPredecessor));
                    }
                    if (mode is 4 or 5)
                    {
                        // The active target5 path independently verifies the
                        // current signed submission and the same old lineage.
                        var currentSubmission = await DeepIdV2PublicationCurrentAuthor.AuthorOwnedRequestAsync(
                            nextRoute, nextContact, nextPublication.WireRequest, device!);
                        Assert.NotNull(await DeepIdV2PublicationCurrentAuthor.VerifyIssuerRequestAsync(
                            nextRoute, currentSubmission, issuerPredecessor));
                        Assert.Equal(ContactPublicationAuthorityWireCodec.EncodeRequest(nextPublication.WireRequest),
                            ContactPublicationAuthorityWireCodec.EncodeRequest(currentSubmission.OriginalRequest));
                    }

                    if (mode == 2 && generation == 1)
                    {
                        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(
                            nextRoute, issuance, priorObject, device!, services, "Changed profile", capability));
                        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorGenesisRequestAsync(
                            nextRoute, nextContact, device!, Bytes(32, 0xa1), Bytes(32, 0xa2), Bytes(32, 0xa3)));
                        var untouched = witnesses.Select(value => new PublicationWitness(value)).ToArray();
                        var exact = ContactPublicationAuthorityWireCodec.EncodeRequest(nextPublication.WireRequest);
                        var priorOffset = exact.Length - 64 - nextPublication.WireRequest.ExactPriorXpo1.Length - 4;
                        foreach (var mutation in new[] { "v2", "prior-size", "missing-prior", "truncated", "trailing", "padding" })
                        {
                            var invalidWire = exact.ToArray();
                            if (mutation == "v2") invalidWire[1] = 2;
                            if (mutation == "prior-size") BinaryPrimitives.WriteUInt32BigEndian(invalidWire.AsSpan(priorOffset), 16_385);
                            if (mutation == "missing-prior")
                            {
                                invalidWire = [.. exact.AsSpan(0, priorOffset), 0, 0, 0, 0, .. exact.AsSpan(exact.Length - 64)];
                                BinaryPrimitives.WriteUInt32BigEndian(invalidWire.AsSpan(4), checked((uint)invalidWire.Length));
                            }
                            if (mutation == "truncated") invalidWire = invalidWire[..^1];
                            if (mutation == "trailing") invalidWire = [.. invalidWire, 0];
                            if (mutation == "padding") invalidWire[^65] ^= 1;
                            Assert.ThrowsAny<Exception>(() => ContactPublicationAuthorityWireCodec.DecodeRequest(invalidWire));
                        }
                        Assert.ThrowsAny<Exception>(() => new ContactPublicationAuthorityWireRequest(
                            publication.WireRequest.NetworkId.Span, publication.WireRequest.RequestNonce.Span,
                            publication.WireRequest.DirectoryLookupKey.Span, publication.WireRequest.MinimumAdh1Generation,
                            publication.WireRequest.MinimumAdh1CoreHash.Span, publication.WireRequest.ExactDca1.Span,
                            publication.WireRequest.ExactDcr1.Span, publication.WireRequest.ExactRouteClosure.Span,
                            publication.WireRequest.OperationId.Span, 0, new byte[32], publication.WireRequest.ObjectCiphertext.Span,
                            publication.WireRequest.IssuedAtUnixSeconds, publication.WireRequest.ExpiresAtUnixSeconds,
                            publication.WireRequest.EffectiveExpiresAtUnixSeconds, publication.WireRequest.OwnerRetrieveCapability.Span,
                            publication.WireRequest.PublisherSignature.Span, result.AsSpan()));
                        var substitutedReceipts = nextPublication.WireRequest.ExactPriorXpo1.ToArray();
                        // Canonical zero padding is unchanged; a receipt signature
                        // substitution parses but invalidates the full publisher signature.
                        var receiptCursor = 12;
                        while (BinaryPrimitives.ReadUInt16BigEndian(substitutedReceipts.AsSpan(receiptCursor)) != 19)
                            receiptCursor += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(substitutedReceipts.AsSpan(receiptCursor + 4)));
                        exact[priorOffset + 4 + receiptCursor + 8 + 192] ^= 1;
                        Assert.NotEqual(ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(nextPublication.WireRequest),
                            ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(ContactPublicationAuthorityWireCodec.DecodeRequest(exact)));
                        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorIssuerThresholdSuccessorAsync(
                            nextRoute, ContactPublicationAuthorityWireCodec.DecodeRequest(exact), issuerPredecessor, untouched));
                        Assert.All(untouched, signer => Assert.Equal(0, signer.Calls));
                        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(
                            nextRoute, nextPublication.WireRequest, untouched));
                        Assert.All(untouched, signer => Assert.Equal(0, signer.Calls));
                        Assert.ThrowsAny<Exception>(() => UntrustedPublicationCopy(nextPublication.WireRequest, nextContact.Closure.Bundle.Field(9), null));
                        foreach (var invalid in new[] {
                            UntrustedPublicationCopy(nextPublication.WireRequest, null, Bytes(32, 0xa9)) })
                        {
                            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdSuccessorAsync(
                                nextRoute, invalid, priorPublication, untouched));
                            Assert.All(untouched, signer => Assert.Equal(0, signer.Calls));
                            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorIssuerThresholdSuccessorAsync(
                                nextRoute, invalid, issuerPredecessor, untouched));
                            Assert.All(untouched, signer => Assert.Equal(0, signer.Calls));
                        }
                        await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorSuccessorRequestAsync(
                            route, contact, device!, priorPublication, Bytes(32, 0xa1), Bytes(32, 0xa2)));
                    }
                    if (mode is 3 or 4 or 5 && generation == 1)
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
                                priorObject, device!, services, "Successor QA", capability, preKeyServiceHistory: serviceHistory);
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
                        var issuerDelayed = new PublicationWitness(witnesses[0], () => Sample = current.Proof.FreshnessDeadlineMonotonicSeconds);
                        try
                        {
                            await RequireRouteRejectionAsync(async () => await DeepIdV2PublicationAuthorityAuthor.AuthorIssuerThresholdSuccessorAsync(
                                nextRoute, nextPublication.WireRequest, issuerPredecessor, [issuerDelayed, new PublicationWitness(witnesses[1])]));
                            Assert.Equal(1, issuerDelayed.Calls);
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
                    var opaqueRequest = Xpu1Codec.Decode(nextAuthorized.ExactXpu1.Span);
                    var opaquePlacement = Deep.Protocol.XPointNetworkV1.ContactServicePlacementFactory.Create(current.Network,
                        Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.PublishInvite, opaqueRequest.LocatorHash);
                    var opaque = await Xpa1PublicationAuthorizationVerifier.VerifyAsync(opaqueRequest, current.Authority,
                        current.Proof, opaquePlacement, time, default);
                    Assert.Equal(generation, opaque.Generation);
                    await opaque.EnsureCurrentAsync();
                    Assert.Equal(generation, (await DeepIdV2PublicationCommitVerifier.VerifyOwnedRetainedIntentAsync(
                        nextRoute, nextContact, nextPublication.WireRequest, nextAuthorized.ExactXpu1)).Generation);
                    Assert.Equal(generation, (await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(
                        nextRoute, nextPublication.WireRequest, nextAuthorized.ExactXpu1)).Generation);
                    var issuerAuthorized = await DeepIdV2PublicationAuthorityAuthor.AuthorIssuerThresholdSuccessorAsync(nextRoute,
                        nextPublication.WireRequest, issuerPredecessor, PublicationWitnesses());
                    Assert.Equal(nextAuthorized.ExactXpu1.ToArray(), issuerAuthorized.ExactXpu1.ToArray());
                    Assert.Equal(nextAuthorized.ExactXpu1.ToArray(), (await DeepIdV2PublicationAuthorityAuthor.VerifyIssuerSuccessorResponseAsync(
                        nextRoute, nextPublication.WireRequest, issuerPredecessor, issuerAuthorized.ExactXpu1)).ExactXpu1.ToArray());
                    var response = await nextPublication.VerifyResponseAsync(nextAuthorized.ExactXpu1);
                    Assert.Equal(nextAuthorized.ExactXpu1.ToArray(), response.ExactXpu1.ToArray());
                    var nextResult = PublicationResult(nextRoute, nextAuthorized.ExactXpu1);
                    Assert.Equal(generation, (await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(nextRoute, nextContact,
                        nextPublication.WireRequest, nextAuthorized.ExactXpu1, nextResult)).Generation);
                    if (mode == 6 && generation >= 6)
                        await CheckRecordedPrivateControlAsync(nextRoute, route, initialPrivatePackage!, current.Proof, issuance,
                            expectedWitness: generation == 6);
                    route = nextRoute; contact = nextContact; advertisement = nextAdvertisement;
                    publication = nextPublication; authorized = nextAuthorized; result = nextResult;
                }
                Assert.Equal(identity, (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText);

                IEnumerable<ParsedXps1V2[]> InvalidHistory(ParsedXps1V2 old, ParsedXps1V2 intermediate, ParsedXps1V2 endpoint)
                {
                    yield return []; // Missing required hop.
                    yield return [old]; // Unnecessary prefix with a missing hop.
                    yield return [intermediate, intermediate];
                    yield return [endpoint];
                    yield return [intermediate, endpoint];
                    yield return [intermediate, AuthorNextService(endpoint,
                        BinaryPrimitives.ReadUInt64BigEndian(endpoint.Field(10).Span),
                        checked(BinaryPrimitives.ReadUInt64BigEndian(endpoint.Field(11).Span) + 1))];
                    var issued = BinaryPrimitives.ReadUInt64BigEndian(intermediate.Field(10).Span);
                    var expires = BinaryPrimitives.ReadUInt64BigEndian(intermediate.Field(11).Span);
                    yield return [SignHostileServiceFixture(old, issued, expires,
                        mutate: fields => fields[1] = Bytes(32, 0xa6))];
                    yield return [SignHostileServiceFixture(old, issued, expires,
                        mutate: fields => fields[2] = Bytes(32, 0xa7))];
                    yield return [SignHostileServiceFixture(old, issued, expires,
                        mutate: fields => fields[5] = Bytes(32, 0xa8))];
                    yield return [SignHostileServiceFixture(old, issued, expires,
                        mutate: fields => fields[5] = SHA256.HashData(endpoint.CanonicalBytes.Span))];
                    yield return [SignHostileServiceFixture(old, issued, expires, minimum: 33)];
                    var damaged = intermediate.CanonicalBytes.ToArray(); damaged[^1] ^= 1;
                    yield return [DeepIdV2PreKeyServiceCodec.Decode(damaged)];
                }

                ContactPublicationAuthorityWireRequest SignedHistoryRequest(ContactPublicationAuthorityWireRequest original,
                    IReadOnlyList<ParsedXps1V2> history)
                {
                    var exact = original.ExactDcr1.ToArray();
                    var supportOffset = 12;
                    var fields = new List<byte[]>();
                    while (supportOffset < exact.Length)
                    {
                        var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(supportOffset + 4)));
                        fields.Add(exact.AsSpan(supportOffset + 8, length).ToArray()); supportOffset += 8 + length;
                    }
                    var support = new List<byte>(); var artifactOffset = 0; ushort count = 0;
                    while (artifactOffset < fields[3].Length)
                    {
                        var kind = BinaryPrimitives.ReadUInt16BigEndian(fields[3].AsSpan(artifactOffset));
                        var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(fields[3].AsSpan(artifactOffset + 2)));
                        if (kind != 3) { support.AddRange(fields[3].AsSpan(artifactOffset, 6 + length).ToArray()); count++; }
                        artifactOffset += 6 + length;
                    }
                    foreach (var item in history.OrderBy(value => Convert.ToHexString(SHA256.HashData(value.CanonicalBytes.Span)), StringComparer.Ordinal))
                    {
                        var header = new byte[6]; BinaryPrimitives.WriteUInt16BigEndian(header, 3);
                        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(2), 352);
                        support.AddRange(header); support.AddRange(item.CanonicalBytes.ToArray()); count++;
                    }
                    fields[2] = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(fields[2], count); fields[3] = support.ToArray();
                    var changed = new byte[12 + fields.Sum(value => 8 + value.Length)]; exact.AsSpan(0, 12).CopyTo(changed);
                    var offset = 12;
                    for (var i = 0; i < fields.Count; i++)
                    {
                        BinaryPrimitives.WriteUInt16BigEndian(changed.AsSpan(offset), checked((ushort)(i + 1)));
                        BinaryPrimitives.WriteUInt32BigEndian(changed.AsSpan(offset + 4), checked((uint)fields[i].Length));
                        fields[i].CopyTo(changed, offset + 8); offset += 8 + fields[i].Length;
                    }
                    _ = DeepIdV2ResolverClosureCodec.Decode(changed);
                    // An issuer authenticates the publisher's exact opaque
                    // ciphertext candidate; it cannot assert decryption. Its
                    // independent plaintext lineage must reject this request.
                    var cipher = new byte[changed.Length + 40];
                    original.ObjectCiphertext.Span[..Math.Min(original.ObjectCiphertext.Length, cipher.Length)].CopyTo(cipher);
                    var unsigned = UntrustedPublicationCopy(original, null, null, changed, cipher);
                    var signature = SignPublicFixture(ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(unsigned));
                    try { return UntrustedPublicationCopy(original, null, null, changed, cipher, signature); }
                    finally { CryptographicOperations.ZeroMemory(signature); CryptographicOperations.ZeroMemory(cipher); }
                }

                ParsedXps1V2 AuthorNextService(ParsedXps1V2 predecessor, ulong issued, ulong expires, ushort minimum = 32)
                {
                    var context = new Dpk2AuthoringContext(ApplicationCoreVerifier.StartDmd1Lineage(checkpoint.Directory).Next,
                        checked(BinaryPrimitives.ReadUInt64BigEndian(predecessor.Field(5).Span) + 1), 1, 1, issued, issued, expires);
                    return DeepIdV2PreKeyServiceCodec.Decode(prekeyAuthor!.AuthorPreKeyServiceV2(context, checkpoint.Binding,
                        minimum, 1, predecessor.CanonicalBytes.Span).ExactXps1.Span);
                }

                // Adversarial signatures use only this freshly created
                // fixture's own key. The hardened production author must not
                // mint these invalid successors for a negative consumer test.
                ParsedXps1V2 SignHostileServiceFixture(ParsedXps1V2 predecessor, ulong issued, ulong expires, ushort minimum = 32,
                    Action<ReadOnlyMemory<byte>[]>? mutate = null)
                {
                    byte[] Number(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
                    var policy = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(policy, minimum);
                    ReadOnlyMemory<byte>[] fields = [predecessor.Field(1), predecessor.Field(2), predecessor.Field(3), predecessor.Field(4),
                        Number(checked(BinaryPrimitives.ReadUInt64BigEndian(predecessor.Field(5).Span) + 1)), SHA256.HashData(predecessor.CanonicalBytes.Span),
                        predecessor.Field(7), policy, predecessor.Field(9), Number(issued), Number(expires)];
                    mutate?.Invoke(fields);
                    var signature = SignPublicFixture(DeepIdV2PreKeyServiceCodec.CreateSignatureInput(fields));
                    try
                    {
                        var signed = DeepIdV2PreKeyServiceCodec.Decode(DeepIdV2PreKeyServiceCodec.Encode(fields, signature));
                        DeepIdV2PreKeyServiceCodec.VerifyDeviceSignature(signed,
                            checkpoint.Binding.Identity.ActiveDevices.Single().Certificate.DeviceEd25519PublicKey.Span);
                        return signed;
                    }
                    finally { CryptographicOperations.ZeroMemory(signature); }
                }

                byte[] SignPublicFixture(byte[] input)
                {
                    using var owned = device!.ExportOwnedPersistenceCopy();
                    var seed = new byte[32]; var agreement = new byte[32]; var deviceId = new byte[32]; var handle = new byte[32];
                    byte[]? privateKey = null;
                    try
                    {
                        owned.CopyTo(seed, agreement, deviceId, handle);
                        privateKey = PublicKeyAuth.GenerateKeyPair(seed).PrivateKey;
                        return PublicKeyAuth.SignDetached(input, privateKey);
                    }
                    finally
                    {
                        foreach (var secret in new[] { seed, agreement, deviceId, handle, privateKey })
                            if (secret is not null) CryptographicOperations.ZeroMemory(secret);
                    }
                }

                static ContactPublicationAuthorityWireRequest UntrustedPublicationCopy(ContactPublicationAuthorityWireRequest original,
                    ReadOnlyMemory<byte>? predecessorHash, ReadOnlyMemory<byte>? ownerCapability,
                    ReadOnlyMemory<byte>? exactDcr = null, ReadOnlyMemory<byte>? objectCiphertext = null,
                    ReadOnlyMemory<byte>? signature = null) => new(original.NetworkId.Span,
                        original.RequestNonce.Span, original.DirectoryLookupKey.Span, original.MinimumAdh1Generation,
                        original.MinimumAdh1CoreHash.Span, original.ExactDca1.Span, (exactDcr ?? original.ExactDcr1).Span, original.ExactRouteClosure.Span,
                        original.OperationId.Span, original.Generation, (predecessorHash ?? original.PredecessorObjectHash).Span,
                        (objectCiphertext ?? original.ObjectCiphertext).Span, original.IssuedAtUnixSeconds, original.ExpiresAtUnixSeconds,
                        original.EffectiveExpiresAtUnixSeconds, (ownerCapability ?? original.OwnerRetrieveCapability).Span,
                        (signature ?? original.PublisherSignature).Span, original.ExactPriorXpo1.Span);
            }
            finally { CryptographicOperations.ZeroMemory(capability); }
        }
    }
}
