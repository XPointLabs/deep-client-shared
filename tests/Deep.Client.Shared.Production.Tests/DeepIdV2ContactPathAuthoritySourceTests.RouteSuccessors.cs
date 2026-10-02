using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Sodium;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public void Did2AdvertisementSuccessor_PublicApiHasNoCallerIssueTimeOrGenericSigner()
    {
        var method = Assert.Single(typeof(DeepIdV2ContactRouteAuthor).GetMethods(),
            value => value.Name == nameof(DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync));
        var times = method.GetParameters().Where(value => value.ParameterType == typeof(ulong)).ToArray();
        Assert.Equal("expiresAtUnixSeconds", Assert.Single(times).Name);
        Assert.Equal(typeof(ValueTask<ContactRecord>), method.ReturnType);
        Assert.DoesNotContain(method.GetParameters(), value => typeof(Delegate).IsAssignableFrom(value.ParameterType));
        Assert.Equal(typeof(CancellationToken), method.GetParameters()[^1].ParameterType);
    }

    [Fact]
    public async Task Did2AdvertisementSuccessor_ExpiredPredecessorExactLineageAndNoGenesisThreshold()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckAdvertisementSuccessorAsync(0);
    }

    [Fact]
    public async Task Did2AdvertisementSuccessor_HostilePredecessorBoundsExpiryAndOwnedKeys()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckAdvertisementSuccessorAsync(1);
    }

    [Fact]
    public async Task Did2AdvertisementSuccessor_ClockContinuityAndCancellationFailClosed()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckAdvertisementSuccessorAsync(2);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckAdvertisementSuccessorAsync(int mode)
        {
            // Genuine protected DID2 account, signatures and independently verified
            // directory/network. The clock/transport are local fixture inputs,
            // not physical device or live coordination evidence.
            var source = Source();
            var staged = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var current = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(
                DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span), checkpoint.Binding, checkpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(current.Proof, dca, Boot, Sample);
            using var secrets = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            var time = new OnionTrustedTimeAuthority(this);
            var expiry = checked(current.Proof.TrustedUpperUnixSeconds + 20);
            var predecessor = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(recipient, current.Network,
                current.Authority, secrets!, 100, Bytes(32, 0xd1), Bytes(32, 0xd2), ScalarMult.Base(Bytes(32, 0xd3)),
                current.Proof.TrustedLowerUnixSeconds, expiry, time);
            var exact = predecessor.CanonicalBytes.ToArray();
            var sample = checked(Sample + 20);
            var successorExpiry = checked(expiry + 30);
            var expiredClock = new CallbackRendezvousClock(() => new(Boot, sample));

            async Task<ContactRecord> Renew(ReadOnlyMemory<byte>? prior = null,
                ReadOnlyMemory<byte>? policy = null, ReadOnlyMemory<byte>? keyId = null,
                ReadOnlyMemory<byte>? publicKey = null, ulong? nextExpiry = null,
                OnionTrustedTimeAuthority? clock = null, OwnedGenesisDeviceSecrets? signer = null,
                CancellationToken ct = default) =>
                await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(recipient, current.Network,
                    current.Authority, signer ?? secrets!, prior ?? exact, policy ?? Bytes(32, 0xe1),
                    keyId ?? Bytes(32, 0xe2), publicKey ?? ScalarMult.Base(Bytes(32, 0xe3)),
                    nextExpiry ?? successorExpiry, clock ?? new(expiredClock), ct);

            if (mode == 0)
            {
                var oldFailure = await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2ContactRouteVerifier.VerifyAdvertisementAsync(recipient, current.Network,
                        current.Authority, exact, new(expiredClock)));
                Assert.Equal("DID2 route time coverage failed (XRA1; Expiry).", oldFailure.Message);
                var mutablePrior = exact.ToArray(); var policy = Bytes(32, 0xe1); var keyId = Bytes(32, 0xe2);
                var sealing = ScalarMult.Base(Bytes(32, 0xe3)); var wantedSealing = sealing.ToArray(); var reads = 0;
                var mutableClock = new CallbackRendezvousClock(() =>
                {
                    reads++; Array.Clear(mutablePrior); Array.Clear(policy); Array.Clear(keyId); Array.Clear(sealing);
                    return new(Boot, sample);
                });
                var successor = await Renew(mutablePrior, policy, keyId, sealing, clock: new(mutableClock));
                Assert.True(reads >= 2);
                Assert.Equal(550, successor.CanonicalBytes.Length);
                Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(successor.Field(3).Span));
                Assert.Equal(predecessor.CoreHash.ToArray(), successor.Field(4).ToArray());
                Assert.NotEqual(predecessor.ArtifactHash.ToArray(), successor.Field(4).ToArray());
                foreach (var tag in new[] { 1, 2, 5, 6, 7, 8, 14, 15 })
                    Assert.Equal(predecessor.Field(tag).ToArray(), successor.Field(tag).ToArray());
                Assert.Equal(Bytes(32, 0xe1), successor.Field(9).ToArray());
                Assert.Equal(Bytes(32, 0xe2), successor.Field(10).ToArray());
                Assert.Equal(wantedSealing, successor.Field(11).ToArray());
                Assert.Equal(current.Proof.TrustedLowerUnixSeconds + 20,
                    BinaryPrimitives.ReadUInt64BigEndian(successor.Field(12).Span));
                Assert.Equal(successorExpiry, BinaryPrimitives.ReadUInt64BigEndian(successor.Field(13).Span));
                await DeepIdV2ContactRouteVerifier.VerifyAdvertisementAsync(recipient, current.Network,
                    current.Authority, successor.CanonicalBytes, new(expiredClock));
                // Explicit successor authoring is not permission to run a genesis
                // threshold or to make the expired predecessor current again.
                var signers = witnesses.Select(value => new RouteWitness(value)).ToArray();
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(recipient, current.Network, current.Authority,
                        successor.CanonicalBytes, signers, current.Proof.TrustedLowerUnixSeconds + 20,
                        successorExpiry, new(expiredClock)));
                Assert.All(signers, signer => Assert.Equal(0, signer.Calls));
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2ContactRouteVerifier.VerifyAdvertisementAsync(recipient, current.Network,
                        current.Authority, exact, new(expiredClock)));
                var next = await Renew(successor.CanonicalBytes, nextExpiry: successorExpiry + 10);
                Assert.Equal(2UL, BinaryPrimitives.ReadUInt64BigEndian(next.Field(3).Span));
                Assert.Equal(successor.CoreHash.ToArray(), next.Field(4).ToArray());
            }
            else if (mode == 1)
            {
                var reads = 0;
                var counting = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                { reads++; return new(Boot, sample); }));
                foreach (var size in new[] { 0, 549, 551, 1_000_000 })
                    await Assert.ThrowsAsync<CryptographicException>(() => Renew(new byte[size], clock: counting));
                Assert.Equal(0, reads);
                var overflow = exact.ToArray();
                BinaryPrimitives.WriteUInt64BigEndian(overflow.AsSpan(FieldOffset(overflow, 3)), ulong.MaxValue);
                overflow[FieldOffset(overflow, 4)] = 1;
                await Assert.ThrowsAsync<CryptographicException>(() => Renew(overflow, clock: counting));
                Assert.Equal(0, reads);
                foreach (var tag in new[] { 1, 5, 14, 15, 16 })
                {
                    var corrupt = exact.ToArray(); corrupt[FieldOffset(corrupt, tag) + (tag is 5 or 15 ? 6 : 0)] ^= 1;
                    await RequireRouteRejectionAsync(async () => await Renew(corrupt));
                }
                var version = exact.ToArray(); version[5] = 2;
                await RequireRouteRejectionAsync(async () => await Renew(version));
                await Assert.ThrowsAsync<CryptographicException>(() => Renew(nextExpiry: expiry));
                await Assert.ThrowsAsync<CryptographicException>(() => Renew(nextExpiry: expiry - 1));
                await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Renew(nextExpiry: expiry + 2_592_001));
                var lowOrder = new byte[32]; lowOrder[0] = 1;
                await Assert.ThrowsAnyAsync<CryptographicException>(() => Renew(publicKey: lowOrder));
                await Assert.ThrowsAsync<CryptographicException>(() => Renew(publicKey:
                    checkpoint.Binding.Identity.ActiveDevices.Single().Certificate.DeviceX25519PublicKey));
                using var unrelated = new OwnedGenesisDeviceSecrets();
                await Assert.ThrowsAsync<CryptographicException>(() => Renew(signer: unrelated));
            }
            else
            {
                var reads = 0;
                var reversing = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                    new(Boot, ++reads == 1 ? sample : sample - 1)));
                await Assert.ThrowsAsync<CryptographicException>(() => Renew(clock: reversing));
                Assert.True(reads >= 2);
                reads = 0;
                var switchedBoot = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                    new(++reads == 1 ? Boot : Bytes(16, 0xf4), sample)));
                await RequireRouteRejectionAsync(async () => await Renew(clock: switchedBoot));
                Assert.True(reads >= 2);
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                reads = 0;
                var never = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                { reads++; return new(Boot, sample); }));
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Renew(clock: never, ct: cancelled.Token));
                Assert.Equal(0, reads);
                using var lateCancel = new CancellationTokenSource();
                var late = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                { lateCancel.Cancel(); return new(Boot, sample); }));
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Renew(clock: late, ct: lateCancel.Token));
                var staleProof = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                    new(Boot, current.Proof.FreshnessDeadlineMonotonicSeconds)));
                await RequireRouteRejectionAsync(async () => await Renew(clock: staleProof));
            }
            Assert.Equal(exact, predecessor.CanonicalBytes.ToArray());
            using var journal = await RouteState();
            Assert.Empty(journal.Entries); // No caller-side author is a durable adoption.
        }
    }
}
