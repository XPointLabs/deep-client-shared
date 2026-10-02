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
    public async Task Did2CurrentRoute_RealAccountThresholdInviteBindingHostileWitnessAndClock()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckCurrentRouteAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckCurrentRouteAsync()
        {
            var source = Source();
            var staged = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var current = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(
                DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span), checkpoint.Binding, checkpoint.Directory);
            // Different nonce-bound proof/DTT1 bytes, same exact authenticated
            // head/view. They must not be confused with unrelated authority.
            ProofTime += 2;
            var second = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            Assert.False(current.Proof.ExactDtt1.Span.SequenceEqual(second.Proof.ExactDtt1.Span));
            Assert.True(second.Proof.TrustedLowerUnixSeconds > current.Proof.TrustedLowerUnixSeconds);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(second.Proof, dca, Boot, Sample);
            using var secrets = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            var time = new OnionTrustedTimeAuthority(this);
            var issued = current.Proof.TrustedLowerUnixSeconds;
            var expiry = checked(current.Proof.TrustedUpperUnixSeconds + 20);
            var policy = Bytes(32, 0xd1); var keyId = Bytes(32, 0xd2); var sealingPublic = ScalarMult.Base(Bytes(32, 0xd3));
            var expectedPolicy = policy.ToArray(); var expectedKey = sealingPublic.ToArray(); var clockReads = 0;
            // A range admissible for only the recipient is not admissible for
            // the conservative union with the independently verified network.
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(
                recipient, current.Network, current.Authority, secrets!, 100, policy, keyId, sealingPublic,
                second.Proof.TrustedLowerUnixSeconds, expiry, time));
            var mutatingClock = new CallbackRendezvousClock(() =>
            {
                clockReads++;
                Array.Clear(policy); Array.Clear(keyId); Array.Clear(sealingPublic);
                return new(Boot, Sample);
            });
            var xra = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(recipient, current.Network,
                current.Authority, secrets!, 100, policy, keyId, sealingPublic, issued, expiry, new(mutatingClock));
            Assert.True(clockReads >= 2);
            Assert.Equal(expectedPolicy, xra.Field(9).ToArray()); Assert.Equal(expectedKey, xra.Field(11).ToArray());
            var signers = witnesses.Select(w => new RouteWitness(w)).ToArray();
            var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(recipient, current.Network,
                current.Authority, xra.CanonicalBytes, signers, issued, expiry, time);
            Assert.All(signers, signer => Assert.Equal(3, signer.Calls));
            var route = await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(recipient, current.Network,
                current.Authority, secrets!, xra.CanonicalBytes, threshold, 2, time);
            Assert.Equal(611, route.ExactXir1V2.Length);
            Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(route.Invite.Field(16).Span[4..6]));
            Assert.Equal(xra.CanonicalBytes.ToArray(), route.Route.Authorization.CanonicalBytes.ToArray());
            Assert.Equal(route.Route.Route.Field(10).ToArray(), route.Route.Reachability.Field(10).ToArray());
            await route.EnsureCurrentAsync();
            var verifiedAgain = await DeepIdV2ContactRouteVerifier.VerifyAsync(recipient, current.Network,
                current.Authority, route.ExactXir1V2, route.ExactRouteClosure, time);
            await verifiedAgain.EnsureCurrentAsync();
            await CheckMailboxGrantRequestsAsync(route);
            var mutableInvite = route.ExactXir1V2.ToArray(); var mutableClosure = route.ExactRouteClosure.ToArray();
            var copyClock = new CallbackRendezvousClock(() =>
            {
                Array.Clear(mutableInvite); Array.Clear(mutableClosure);
                return new(Boot, Sample);
            });
            var copied = await DeepIdV2ContactRouteVerifier.VerifyAsync(recipient, current.Network, current.Authority,
                mutableInvite, mutableClosure, new(copyClock));
            Assert.Equal(route.ExactXir1V2.ToArray(), copied.ExactXir1V2.ToArray());
            Assert.Equal(route.ExactRouteClosure.ToArray(), copied.ExactRouteClosure.ToArray());
            Assert.Empty(typeof(VerifiedDeepIdV2ContactRouteClosure).GetConstructors());
            Assert.Equal(route.ExactRouteClosure.ToArray(), ContactRouteClosureCodec.Decode(route.ExactRouteClosure.Span).ExactBytes.ToArray());

            // Hostile syntax/version/record bytes never become current route authority.
            var downgraded = route.ExactXir1V2.ToArray(); downgraded[5] = 1;
            await Assert.ThrowsAnyAsync<FormatException>(async () => await DeepIdV2ContactRouteVerifier.VerifyAsync(
                recipient, current.Network, current.Authority, downgraded, route.ExactRouteClosure, time));
            foreach (var tag in new[] { 6, 7, 8, 12, 15, 16, 17, 18 })
            {
                var changed = route.ExactXir1V2.ToArray(); changed[FieldOffset(changed, tag)] ^= 0x10;
                await RequireRouteRejectionAsync(async () => await DeepIdV2ContactRouteVerifier.VerifyAsync(
                    recipient, current.Network, current.Authority, changed, route.ExactRouteClosure, time));
            }
            var trailing = route.ExactRouteClosure.ToArray().Append((byte)0).ToArray();
            await Assert.ThrowsAnyAsync<FormatException>(async () => await DeepIdV2ContactRouteVerifier.VerifyAsync(
                recipient, current.Network, current.Authority, route.ExactXir1V2, trailing, time));
            foreach (var tag in new[] { 10, 11, 13, 18, 19 })
            {
                // First LP32 record is XRR1; its unreferenced own bytes must
                // still bind deposit, policy, quota, issuer and signature.
                var changed = route.ExactRouteClosure.ToArray();
                var xrrBytes = route.Route.Reachability.CanonicalBytes.ToArray();
                changed[5 + FieldOffset(xrrBytes, tag)] ^= 0x10;
                await RequireRouteRejectionAsync(async () => await DeepIdV2ContactRouteVerifier.VerifyAsync(
                    recipient, current.Network, current.Authority, route.ExactXir1V2, changed, time));
            }
            var changedThreshold = threshold.LiveRoute.CanonicalBytes.ToArray();
            changedThreshold[FieldOffset(changedThreshold, 21) + 32] ^= 0x10;
            var unverified = new ParsedDeepIdV2RouteThreshold(threshold.Selection.CanonicalBytes.Span,
                changedThreshold, threshold.Successor.CanonicalBytes.Span);
            await RequireRouteRejectionAsync(async () => await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(
                recipient, current.Network, current.Authority, secrets!, xra.CanonicalBytes, unverified, 2, time));

            using var unrelated = new OwnedGenesisDeviceSecrets();
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(
                recipient, current.Network, current.Authority, unrelated, xra.CanonicalBytes, threshold, 2, time));
            var lowOrder = new byte[32]; lowOrder[0] = 1;
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(
                recipient, current.Network, current.Authority, secrets!, 100, expectedPolicy, Bytes(32, 0xd2), lowOrder, issued, expiry, time));
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(
                recipient, current.Network, current.Authority, secrets!, 100, expectedPolicy, Bytes(32, 0xd2),
                checkpoint.Binding.Identity.ActiveDevices.Single().Certificate.DeviceX25519PublicKey, issued, expiry, time));

            var duplicate = new RouteWitness(witnesses[0]);
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(
                recipient, current.Network, current.Authority, xra.CanonicalBytes, [duplicate, duplicate], issued, expiry, time));
            Assert.Equal(0, duplicate.Calls);
            var bad = new RouteWitness(witnesses[0], corrupt: true);
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(
                recipient, current.Network, current.Authority, xra.CanonicalBytes, [bad, new RouteWitness(witnesses[1])], issued, expiry, time));
            Assert.Equal(1, bad.Calls);
            var delayed = new RouteWitness(witnesses[0], afterSign: () => Sample = second.Proof.FreshnessDeadlineMonotonicSeconds);
            var switchedBoot = new CallbackRendezvousClock(() => new(Bytes(16, 0xf4), Sample));
            var never = new RouteWitness(witnesses[0]);
            await RequireRouteRejectionAsync(async () => await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(
                recipient, current.Network, current.Authority, xra.CanonicalBytes, [never, new RouteWitness(witnesses[1])],
                issued, expiry, new(switchedBoot)));
            Assert.Equal(0, never.Calls);
            try
            {
                await RequireRouteRejectionAsync(async () => await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(
                    recipient, current.Network, current.Authority, xra.CanonicalBytes, [delayed, new RouteWitness(witnesses[1])], issued, expiry, time));
                Assert.Equal(1, delayed.Calls);
                await RequireRouteRejectionAsync(async () => await route.EnsureCurrentAsync());
            }
            finally { Sample = 100; } // Fixture clock fault cleanup; no runtime recovery API.
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await route.EnsureCurrentAsync(cancelled.Token));
        }

        private static int FieldOffset(byte[] record, int target)
        {
            var offset = 12;
            while (offset < record.Length)
            {
                var tag = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(offset));
                var size = checked((int)BinaryPrimitives.ReadUInt32BigEndian(record.AsSpan(offset + 4)));
                if (tag == target) return offset + 8;
                offset = checked(offset + 8 + size);
            }
            throw new InvalidDataException("Fixture field is absent.");
        }

        private static async Task RequireRouteRejectionAsync(Func<Task> action)
        {
            var error = await Record.ExceptionAsync(action);
            Assert.True(error is CryptographicException or FormatException or OnionBoundaryException,
                $"Expected an explicit authority/format rejection, got {error?.GetType().Name ?? "success"}.");
        }
    }

    private sealed class RouteWitness(Signer signer, bool corrupt = false, Action? afterSign = null)
        : IContactRouteAuthorityWitnessSigner
    {
        internal int Calls { get; private set; }
        public ReadOnlyMemory<byte> WitnessId => signer.WitnessId;
        public async ValueTask<int> SignAsync(ContactRouteAuthoritySigningRequest request, Memory<byte> signature64, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++;
            await Task.Yield(); // Exercise actual asynchronous boundary.
            var signature = signer.SignCommit(request.SigningInput);
            try { signature.CopyTo(signature64); if (corrupt) signature64.Span[0] ^= 1; }
            finally { CryptographicOperations.ZeroMemory(signature); }
            afterSign?.Invoke(); return 64;
        }
    }
}
