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
    [Fact]
    public async Task Did2PublicationCurrent_CurrentSubmissionRejectsHostileFramingPublisherAndClock()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckRetainedPublicationIntentAsync(9);
    }
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task Did2PublicationIntent_ExpiredEnvelopeKeepsExactIntentWithoutCommitOrDispatch(int mode)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckRetainedPublicationIntentAsync(mode);
    }

    [Fact]
    public void Did2PublicationIntent_OwnerAndIssuerFactsHaveNoMutationOrSerializationFactory()
    {
        foreach (var type in new[] { typeof(VerifiedDeepIdV2OwnedPublicationIntent), typeof(VerifiedDeepIdV2IssuerPublicationIntent) })
        {
            Assert.Empty(type.GetConstructors());
            Assert.DoesNotContain(type.GetMethods(), method => method.Name is "EnsureCurrentAsync" or "DispatchAsync" or
                "SignAsync" or "CommitAsync" or "Parse" or "Deserialize");
            Assert.Equal(new[] { "Generation", "RequestHash" }, type.GetProperties().Select(property => property.Name).Order().ToArray());
        }
    }

    private sealed partial class Fixture
    {
        internal async Task CheckRetainedPublicationIntentAsync(int mode)
        {
            var source = Source(); var staged = await accounts.EnsureOwnPreKeyInventoryAsync(source);
            var initial = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span),
                checkpoint.Binding, checkpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(initial.Proof, dca, Boot, Sample);
            using var device = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            Action? onRead = null;
            var reads = 0;
            var time = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
            { reads++; onRead?.Invoke(); return new(Boot, Sample); }));
            var expiry = initial.Proof.TrustedUpperUnixSeconds + 200;
            var advertisement = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(recipient, initial.Network,
                initial.Authority, device!, 100, Bytes(32, 0xb1), Bytes(32, 0xb2), ScalarMult.Base(Bytes(32, 0xb3)),
                initial.Proof.TrustedLowerUnixSeconds, expiry, time);
            var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(recipient, initial.Network, initial.Authority,
                advertisement.CanonicalBytes, witnesses.Select(value => new RouteWitness(value)).ToArray(),
                initial.Proof.TrustedLowerUnixSeconds, expiry, time);
            var original = await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(recipient, initial.Network,
                initial.Authority, device!, advertisement.CanonicalBytes, threshold, 2, time);
            var resolver = (await accounts.GetCurrentAsync())!.PermanentId.ResolverReadCapability.ToArray();
            try
            {
                var contact = await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(original, device!,
                    [DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span)], "Retained intent QA", resolver);
                var authored = await DeepIdV2PublicationAuthorityAuthor.AuthorGenesisRequestAsync(original, contact, device!,
                    Bytes(32, 0xb4), Bytes(32, 0xb5), Bytes(32, 0xb6));
                var authorization = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(original,
                    authored.WireRequest, PublicationWitnesses());
                var exact = authorization.ExactXpu1.ToArray();
                var request = Xpu1Codec.Decode(exact);
                var nextTime = checked(request.ExpiresAtUnixSeconds + (mode >= 5 ? 11UL : 1UL));
                Sample = checked(Sample + nextTime - ProofTime); ProofTime = nextTime;
                var current = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
                recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(current.Proof, dca, Boot, Sample);
                var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(recipient, current.Network, current.Authority,
                    original.ExactXir1V2, original.ExactRouteClosure, time);
                var restored = await DeepIdV2ContactObjectAuthor.RestoreAsync(route, contact.Closure.CanonicalBytes,
                    contact.ProtectedDcr1, resolver);
                var before = ContactPublicationAuthorityWireCodec.EncodeRequest(authored.WireRequest);
                var expired = await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(route, authored.WireRequest, exact));
                Assert.Equal("request-window", expired.Data["Deep.ContactPublication.RequestScope"]);
                var owned = await DeepIdV2PublicationCommitVerifier.VerifyOwnedRetainedIntentAsync(route, restored, authored.WireRequest, exact);
                var issuer = await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route, authored.WireRequest, exact);
                Assert.Equal(0UL, owned.Generation); Assert.Equal(owned.Generation, issuer.Generation);
                Assert.Equal(request.RequestHash.ToArray(), owned.RequestHash.ToArray());
                Assert.Equal(owned.RequestHash.ToArray(), issuer.RequestHash.ToArray());
                Assert.Equal(before, ContactPublicationAuthorityWireCodec.EncodeRequest(authored.WireRequest));
                if (mode >= 5)
                {
                    await CheckCurrentPublicationCryptoAsync(mode, route, restored, authored.WireRequest, device!,
                        callback => onRead = callback);
                    return;
                }

                if (mode == 0)
                {
                    var changedWitness = exact.ToArray();
                    var witnessOffset = changedWitness.AsSpan().IndexOf(request.ExactXpa1.Span);
                    Assert.True(witnessOffset >= 0);
                    changedWitness[witnessOffset + request.ExactXpa1.Length - 1] ^= 1;
                    await Assert.ThrowsAsync<CryptographicException>(async () =>
                        await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route, authored.WireRequest, changedWitness));
                    var changedPublisher = before.ToArray(); changedPublisher[^1] ^= 1;
                    var forged = ContactPublicationAuthorityWireCodec.DecodeRequest(changedPublisher);
                    await Assert.ThrowsAsync<CryptographicException>(async () =>
                        await DeepIdV2PublicationCommitVerifier.VerifyOwnedRetainedIntentAsync(route, restored, forged, exact));
                    var changedCiphertext = contact.ProtectedDcr1.ToArray(); changedCiphertext[^1] ^= 1;
                    await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                        await DeepIdV2ContactObjectAuthor.RestoreAsync(route, contact.Closure.CanonicalBytes, changedCiphertext, resolver));
                }
                if (mode == 1)
                {
                    var mutable = exact.ToArray(); onRead = () => Array.Clear(mutable);
                    var copied = await DeepIdV2PublicationCommitVerifier.VerifyOwnedRetainedIntentAsync(route, restored,
                        authored.WireRequest, mutable);
                    onRead = null;
                    Assert.All(mutable, value => Assert.Equal(0, value));
                    Assert.Equal(request.RequestHash.ToArray(), copied.RequestHash.ToArray());
                    var baseline = reads;
                    foreach (var hostile in new[] { Array.Empty<byte>(), new byte[93_033] })
                        await Assert.ThrowsAsync<CryptographicException>(async () =>
                            await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route, authored.WireRequest, hostile));
                    Assert.Equal(baseline, reads);
                }
                if (mode == 2)
                {
                    using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                    var baseline = reads;
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                        await DeepIdV2PublicationCommitVerifier.VerifyOwnedRetainedIntentAsync(route, restored,
                            authored.WireRequest, exact, cancelled.Token));
                    Assert.Equal(baseline, reads);
                    using var during = new CancellationTokenSource(); onRead = during.Cancel;
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                        await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route, authored.WireRequest,
                            exact, during.Token));
                    onRead = null;
                }
                if (mode == 3)
                {
                    var saved = Sample;
                    var count = 0;
                    onRead = () => Sample = ++count == 1 ? saved + 1 : saved;
                    await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                        await DeepIdV2PublicationCommitVerifier.VerifyOwnedRetainedIntentAsync(route, restored, authored.WireRequest, exact));
                    onRead = null; Sample = saved;
                    Sample += expiry - ProofTime + 1;
                    await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                        await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route, authored.WireRequest, exact));
                }
                if (mode == 4)
                {
                    // Genuine device/witness signatures from a later observation,
                    // not a tampered timestamp or fabricated publisher signature.
                    var saved = Sample;
                    AuthoredDeepIdV2PublicationRequest future;
                    VerifiedDeepIdV2PublicationAuthorization signedFuture;
                    try
                    {
                        Sample = saved + 1;
                        future = await DeepIdV2PublicationAuthorityAuthor.AuthorGenesisRequestAsync(route, restored, device!,
                            Bytes(32, 0xb7), Bytes(32, 0xb8), Bytes(32, 0xb9));
                        signedFuture = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(route,
                            future.WireRequest, PublicationWitnesses());
                    }
                    finally { Sample = saved; }
                    await Assert.ThrowsAsync<CryptographicException>(async () =>
                        await DeepIdV2PublicationCommitVerifier.VerifyOwnedRetainedIntentAsync(route, restored,
                            future.WireRequest, signedFuture.ExactXpu1));
                    await Assert.ThrowsAsync<CryptographicException>(async () =>
                        await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route,
                            future.WireRequest, signedFuture.ExactXpu1));
                }
                // Neither result can stand in for genuine durable replica receipts.
                var none = Xpo1Codec.Encode(exact, Xpo1Status.Unauthorized, ContactServiceMutationOutcome.None,
                    ProofTime, 0, ContactServicePaddingClass.Bytes256, []);
                await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(route, restored, authored.WireRequest, exact, none));
            }
            finally { onRead = null; CryptographicOperations.ZeroMemory(resolver); }
        }
    }
}
