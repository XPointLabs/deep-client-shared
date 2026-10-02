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
    public async Task Did2RouteRenewal_ExpiredRealRouteBecomesCurrentSuccessorWithoutNewGenesis()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckRouteRenewalAsync(0);
    }

    [Fact]
    public async Task Did2RouteRenewal_HostileHistoryAndWrongLineageRejectBeforeWitnesses()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckRouteRenewalAsync(1);
    }

    [Fact]
    public async Task Did2RouteRenewal_ImmutableInputsAndClockDiscontinuityRejectRelease()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckRouteRenewalAsync(2);
    }

    [Fact]
    public async Task Did2RouteRenewal_ReusesExactCurrentSelectionWhenOnlyLiveRouteExpired()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckRouteRenewalAsync(3);
    }

    [Fact]
    public void Did2RouteRenewal_PredecessorIsNotConstructibleOrCurrentRouteAuthority()
    {
        Assert.Empty(typeof(VerifiedDeepIdV2ContactRoutePredecessor).GetConstructors());
        Assert.False(typeof(VerifiedDeepIdV2ContactRouteClosure).IsAssignableFrom(typeof(VerifiedDeepIdV2ContactRoutePredecessor)));
        Assert.DoesNotContain(typeof(VerifiedDeepIdV2ContactRoutePredecessor).GetMethods(),
            value => value.Name is "EnsureCurrentAsync" or "ReadCurrentTimeAsync" or "SignAsync");
        var threshold = Assert.Single(typeof(DeepIdV2ContactRouteAuthor).GetMethods(),
            value => value.Name == nameof(DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync));
        Assert.Equal("expiresAtUnixSeconds", Assert.Single(threshold.GetParameters(),
            value => value.ParameterType == typeof(ulong)).Name);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckRouteRenewalAsync(int mode)
        {
            var identityBefore = (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText;
            var source = Source(); var staged = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var current = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(
                DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span), checkpoint.Binding, checkpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(current.Proof, dca, Boot, Sample);
            using var secrets = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            var time = new OnionTrustedTimeAuthority(this);
            var expiry = current.Proof.TrustedUpperUnixSeconds + 20;
            var xra = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(recipient, current.Network, current.Authority,
                secrets!, 100, Bytes(32, 0xd1), Bytes(32, 0xd2), ScalarMult.Base(Bytes(32, 0xd3)),
                current.Proof.TrustedLowerUnixSeconds, expiry, time);
            var genesisThreshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(recipient, current.Network, current.Authority,
                xra.CanonicalBytes, witnesses.Select(value => new RouteWitness(value)).ToArray(),
                current.Proof.TrustedLowerUnixSeconds, expiry, time);
            if (mode == 3)
            {
                // Genuine witness-signed wider selection, shorter live route.
                // Completion still uses the real owned device author/verifier.
                var shortRoute = ResignRenewalWitnessRecord(genesisThreshold.LiveRoute,
                    new() { [18] = RenewalU64(expiry - 10) }, 21);
                var reference = ContactCodec.ArtifactReference("XRC1", shortRoute).CanonicalBytes;
                var shortCheckpoint = ResignRenewalWitnessRecord(genesisThreshold.Successor,
                    new() { [4] = shortRoute.CoreHash, [5] = reference, [6] = reference, [11] = RenewalU64(expiry - 10) }, 14);
                genesisThreshold = new(genesisThreshold.Selection.CanonicalBytes.Span,
                    shortRoute.CanonicalBytes.Span, shortCheckpoint.CanonicalBytes.Span);
            }
            var old = await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(recipient, current.Network, current.Authority,
                secrets!, xra.CanonicalBytes, genesisThreshold, 2, time);
            var oldInvite = old.ExactXir1V2.ToArray(); var oldClosure = old.ExactRouteClosure.ToArray();
            Sample += mode == 3 ? 10UL : 20UL; // Actual fixture time advances; no runtime time override.
            var expired = await Assert.ThrowsAsync<CryptographicException>(async () => await old.EnsureCurrentAsync());
            Assert.Equal(mode == 3 ? "DID2 route time coverage failed (XRC1; Expiry)." :
                "DID2 route time coverage failed (XRA1; Expiry).", expired.Message);
            var predecessor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, current.Network,
                current.Authority, oldInvite, oldClosure, time);
            var nextExpiry = expiry + 30;
            var nextXra = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(recipient, current.Network,
                current.Authority, secrets!, xra.CanonicalBytes, Bytes(32, 0xe1), Bytes(32, 0xe2),
                ScalarMult.Base(Bytes(32, 0xe3)), nextExpiry, time);

            async Task<ParsedDeepIdV2RouteThreshold> Threshold(VerifiedDeepIdV2ContactRoutePredecessor? prior = null,
                ReadOnlyMemory<byte>? advertisement = null, RouteWitness[]? signers = null,
                OnionTrustedTimeAuthority? clock = null, CancellationToken ct = default) =>
                await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(recipient, current.Network, current.Authority,
                    prior ?? predecessor, advertisement ?? nextXra.CanonicalBytes,
                    signers ?? witnesses.Select(value => new RouteWitness(value)).ToArray(),
                    mode == 3 ? expiry - 5 : nextExpiry, clock ?? time, ct);

            if (mode == 0)
            {
                var signers = witnesses.Select(value => new RouteWitness(value)).ToArray();
                var threshold = await Threshold(signers: signers);
                Assert.All(signers, value => Assert.Equal(3, value.Calls));
                var route = await DeepIdV2ContactRouteAuthor.CompleteSuccessorAsync(recipient, current.Network, current.Authority,
                    secrets!, predecessor, nextXra.CanonicalBytes, threshold, 2, time);
                await route.EnsureCurrentAsync();
                var verified = await DeepIdV2ContactRouteVerifier.VerifyAsync(recipient, current.Network,
                    current.Authority, route.ExactXir1V2, route.ExactRouteClosure, time);
                Assert.Equal(route.ExactRouteClosure.ToArray(), verified.ExactRouteClosure.ToArray());
                foreach (var record in new[] { route.Route.Authorization, route.Route.Route, route.Route.Reachability })
                    Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(record.Field(3).Span));
                Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(route.Invite.Field(3).Span));
                Assert.Equal(2UL, BinaryPrimitives.ReadUInt64BigEndian(route.Route.Successor.Field(3).Span));
                foreach (var tag in new[] { 1, 2, 6, 10, 14, 15 })
                    Assert.Equal(old.Route.Route.Field(tag).ToArray(), route.Route.Route.Field(tag).ToArray());
                Assert.Equal(old.Route.Route.CoreHash.ToArray(), route.Route.Route.Field(4).ToArray());
                Assert.Equal(old.Route.Route.CoreHash.ToArray(), route.Route.Successor.Field(4).ToArray());
                Assert.Equal(ContactCodec.ArtifactReference("XRC1", old.Route.Route).CanonicalBytes.ToArray(),
                    route.Route.Successor.Field(6).ToArray());
                Assert.Equal(old.Route.Reachability.Field(2).ToArray(), route.Route.Reachability.Field(2).ToArray());
                Assert.Equal(old.Route.Reachability.CoreHash.ToArray(), route.Route.Reachability.Field(4).ToArray());
                Assert.Equal(old.Invite.Field(2).ToArray(), route.Invite.Field(2).ToArray());
                Assert.Equal(old.Invite.ObjectHash.ToArray(), route.Invite.Field(4).ToArray());
                Assert.NotEqual(old.Route.Selection.CanonicalBytes.ToArray(), route.Route.Selection.CanonicalBytes.ToArray());
                foreach (var tag in Enumerable.Range(1, 7))
                    Assert.Equal(old.Route.Selection.Field(tag).ToArray(), route.Route.Selection.Field(tag).ToArray());
                Assert.True(BinaryPrimitives.ReadUInt64BigEndian(route.Invite.Field(13).Span) >=
                    BinaryPrimitives.ReadUInt64BigEndian(old.Invite.Field(13).Span));
                await Assert.ThrowsAsync<CryptographicException>(async () => await old.EnsureCurrentAsync());
                var nextPredecessor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, current.Network,
                    current.Authority, route.ExactXir1V2, route.ExactRouteClosure, time);
                var secondXra = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(recipient, current.Network,
                    current.Authority, secrets!, nextXra.CanonicalBytes, Bytes(32, 0xf1), Bytes(32, 0xf2),
                    ScalarMult.Base(Bytes(32, 0xf3)), nextExpiry + 10, time);
                var secondThreshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(recipient, current.Network,
                    current.Authority, nextPredecessor, secondXra.CanonicalBytes,
                    witnesses.Select(value => new RouteWitness(value)).ToArray(), nextExpiry + 10, time);
                var secondRoute = await DeepIdV2ContactRouteAuthor.CompleteSuccessorAsync(recipient, current.Network,
                    current.Authority, secrets!, nextPredecessor, secondXra.CanonicalBytes, secondThreshold, 2, time);
                Assert.Equal(2UL, BinaryPrimitives.ReadUInt64BigEndian(secondRoute.Invite.Field(3).Span));
                Assert.Equal(route.Invite.ObjectHash.ToArray(), secondRoute.Invite.Field(4).ToArray());
                await secondRoute.EnsureCurrentAsync();
            }
            else if (mode == 1)
            {
                var reads = 0; var never = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                { reads++; return new(Boot, Sample); }));
                foreach (var (invite, closure) in new[] { (new byte[610], oldClosure), (oldInvite, new byte[23296]),
                             (oldInvite, oldClosure.Append((byte)0).ToArray()) })
                    await RequireRouteRejectionAsync(async () => await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(
                        recipient, current.Network, current.Authority, invite, closure, never));
                Assert.Equal(0, reads);
                foreach (var (recordIndex, tag, signatureOffset) in new[] { (0, 19, 0), (2, 21, 32), (3, 14, 32), (5, 11, 32) })
                {
                    var corrupt = oldClosure.ToArray(); var offset = 1;
                    for (var i = 0; i < recordIndex; i++) offset += 4 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(corrupt.AsSpan(offset)));
                    var size = checked((int)BinaryPrimitives.ReadUInt32BigEndian(corrupt.AsSpan(offset))); offset += 4;
                    corrupt[offset + FieldOffset(corrupt.AsSpan(offset, size).ToArray(), tag) + signatureOffset] ^= 1;
                    await RequireRouteRejectionAsync(async () => await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(
                        recipient, current.Network, current.Authority, oldInvite, corrupt, time));
                }
                var forgedInvite = oldInvite.ToArray(); forgedInvite[FieldOffset(forgedInvite, 17)] ^= 1;
                await RequireRouteRejectionAsync(async () => await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(
                    recipient, current.Network, current.Authority, forgedInvite, oldClosure, time));
                var zeroCalls = witnesses.Select(value => new RouteWitness(value)).ToArray();
                await Assert.ThrowsAsync<CryptographicException>(() => Threshold(advertisement: xra.CanonicalBytes, signers: zeroCalls));
                Assert.All(zeroCalls, value => Assert.Equal(0, value.Calls));
                var gap = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(recipient, current.Network,
                    current.Authority, secrets!, nextXra.CanonicalBytes, Bytes(32, 0xf1), Bytes(32, 0xf2),
                    ScalarMult.Base(Bytes(32, 0xf3)), nextExpiry + 10, time);
                await Assert.ThrowsAsync<CryptographicException>(() => Threshold(advertisement: gap.CanonicalBytes, signers: zeroCalls));
                Assert.All(zeroCalls, value => Assert.Equal(0, value.Calls));
                var unrelatedGenesis = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(recipient, current.Network,
                    current.Authority, secrets!, 100, Bytes(32, 0xd1), Bytes(32, 0xd2), ScalarMult.Base(Bytes(32, 0xd3)),
                    current.Proof.TrustedLowerUnixSeconds + 20, nextExpiry, time);
                var otherLineage = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(recipient, current.Network,
                    current.Authority, secrets!, unrelatedGenesis.CanonicalBytes, Bytes(32, 0xf1), Bytes(32, 0xf2),
                    ScalarMult.Base(Bytes(32, 0xf3)), nextExpiry + 10, time);
                await Assert.ThrowsAsync<CryptographicException>(() => Threshold(advertisement: otherLineage.CanonicalBytes, signers: zeroCalls));
                Assert.All(zeroCalls, value => Assert.Equal(0, value.Calls));
                var threshold = await Threshold();
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(
                    recipient, current.Network, current.Authority, secrets!, nextXra.CanonicalBytes, threshold, 2, time));
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.CompleteSuccessorAsync(
                    recipient, current.Network, current.Authority, secrets!, predecessor, nextXra.CanonicalBytes, threshold, 3, time));
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.CompleteSuccessorAsync(
                    recipient, current.Network, current.Authority, secrets!, predecessor, nextXra.CanonicalBytes, genesisThreshold, 2, time));
                using var otherDevice = new OwnedGenesisDeviceSecrets();
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.CompleteSuccessorAsync(
                    recipient, current.Network, current.Authority, otherDevice, predecessor, nextXra.CanonicalBytes, threshold, 2, time));
                var delayed = new RouteWitness(witnesses[0], afterSign: () => Sample = current.Proof.FreshnessDeadlineMonotonicSeconds);
                await RequireRouteRejectionAsync(async () => await Threshold(signers: [delayed, new RouteWitness(witnesses[1])]));
                Assert.Equal(1, delayed.Calls);
                Sample = 120; // Local fault cleanup only; no runtime recovery bypass.
            }
            else if (mode == 2)
            {
                var mutableInvite = oldInvite.ToArray(); var mutableClosure = oldClosure.ToArray();
                var copyClock = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                { Array.Clear(mutableInvite); Array.Clear(mutableClosure); return new(Boot, Sample); }));
                var copied = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, current.Network,
                    current.Authority, mutableInvite, mutableClosure, copyClock);
                Assert.Equal(oldInvite, copied.ExactXir1V2.ToArray()); Assert.Equal(oldClosure, copied.ExactRouteClosure.ToArray());
                var mutableXra = nextXra.CanonicalBytes.ToArray();
                var witnessesBefore = witnesses.Select(value => new RouteWitness(value)).ToArray();
                var originalSigners = witnessesBefore.ToArray();
                var mutatedInputs = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                { Array.Clear(mutableXra); Array.Clear(witnessesBefore); return new(Boot, Sample); }));
                var threshold = await Threshold(advertisement: mutableXra, signers: witnessesBefore, clock: mutatedInputs);
                Assert.All(originalSigners, value => Assert.Equal(3, value.Calls));
                var calls = 0;
                var reversing = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                    new(Boot, ++calls == 1 ? Sample : Sample - 1)));
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(
                    recipient, current.Network, current.Authority, oldInvite, oldClosure, reversing));
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Threshold(ct: cancelled.Token));
                var switched = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() => new(Bytes(16, 0xf8), Sample)));
                await RequireRouteRejectionAsync(async () => await DeepIdV2ContactRouteAuthor.CompleteSuccessorAsync(recipient,
                    current.Network, current.Authority, secrets!, predecessor, nextXra.CanonicalBytes, threshold, 2, switched));
            }
            else
            {
                var signers = witnesses.Select(value => new RouteWitness(value)).ToArray();
                var threshold = await Threshold(signers: signers);
                Assert.All(signers, value => Assert.Equal(2, value.Calls));
                Assert.Equal(old.Route.Selection.CanonicalBytes.ToArray(), threshold.Selection.CanonicalBytes.ToArray());
                var completed = await DeepIdV2ContactRouteAuthor.CompleteSuccessorAsync(recipient, current.Network,
                    current.Authority, secrets!, predecessor, nextXra.CanonicalBytes, threshold, 2, time);
                await completed.EnsureCurrentAsync();
                Assert.Equal(old.Route.Route.Field(10).ToArray(), completed.Route.Route.Field(10).ToArray());
                Assert.Equal(old.Route.Route.Field(15).ToArray(), completed.Route.Route.Field(15).ToArray());
            }
            Assert.Equal(identityBefore, (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText);
            Assert.Equal(oldInvite, old.ExactXir1V2.ToArray()); Assert.Equal(oldClosure, old.ExactRouteClosure.ToArray());
            using var journal = await RouteState(); Assert.Empty(journal.Entries);
        }

        private ContactRecord ResignRenewalWitnessRecord(ContactRecord original,
            Dictionary<int, ReadOnlyMemory<byte>> replacements, int receiptTag)
        {
            var bytes = original.CanonicalBytes.ToArray();
            foreach (var (tag, value) in replacements)
            {
                Assert.Equal(original.Field(tag).Length, value.Length);
                value.Span.CopyTo(bytes.AsSpan(FieldOffset(bytes, tag)));
            }
            var provisional = ContactCodec.Decode(original.Magic, bytes);
            var receipts = provisional.Field(receiptTag).ToArray();
            var input = provisional.SignatureInput;
            for (var offset = 0; offset < receipts.Length; offset += 96)
            {
                var id = receipts.AsSpan(offset, 32).ToArray();
                var signer = witnesses.Single(value => value.WitnessId.Span.SequenceEqual(id));
                var signature = signer.SignCommit(input);
                try { signature.CopyTo(receipts, offset + 32); }
                finally { CryptographicOperations.ZeroMemory(signature); }
            }
            receipts.CopyTo(bytes, FieldOffset(bytes, receiptTag));
            return ContactCodec.Decode(original.Magic, bytes);
        }

        private static byte[] RenewalU64(ulong value)
        {
            var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes;
        }
    }
}
