using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.AccountDirectoryV1;
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
    [InlineData(4)]
    [InlineData(5)]
    public async Task Did2RetainedIssuance_RealHeadEvidenceCompletionObjectAndPublication(int mode)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckRetainedIssuanceAsync(mode);
    }

    [Fact]
    public void Did2RetainedIssuance_IsClosedAndNotCurrentOrSigningAuthority()
    {
        Assert.Empty(typeof(VerifiedDeepIdV2ContactRouteIssuance).GetConstructors());
        Assert.False(typeof(VerifiedDeepIdV2ContactRouteClosure).IsAssignableFrom(typeof(VerifiedDeepIdV2ContactRouteIssuance)));
        Assert.DoesNotContain(typeof(VerifiedDeepIdV2ContactRouteIssuance).GetMethods(),
            value => value.Name is "EnsureCurrentAsync" or "ReadCurrentTimeAsync" or "SignAsync");
    }

    private sealed partial class Fixture
    {
        private Dictionary<ulong, AccountDirectoryProtectedLkg>? retainedIssuanceHistory;
        internal async Task CheckRetainedIssuanceAsync(int mode)
        {
            var accountBefore = (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText;
            var source = Source(); var staged = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var initial = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(
                DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span), checkpoint.Binding, checkpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(initial.Proof, dca, Boot, Sample);
            using var secrets = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            var time = new OnionTrustedTimeAuthority(this);
            var expiry = initial.Proof.TrustedUpperUnixSeconds + 30;
            var xra = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(recipient, initial.Network, initial.Authority,
                secrets!, 100, Bytes(32, 0xd1), Bytes(32, 0xd2), ScalarMult.Base(Bytes(32, 0xd3)),
                initial.Proof.TrustedLowerUnixSeconds, expiry, time);
            var request = new ContactRouteAuthorityWireRequest(Network, Bytes(32, 0xe1), initial.Proof.QueriedDirectoryLeafKey.Span,
                head.ProtectedHead.LogGeneration, head.CoreHash.Span, staged.ExactDca1.Span, xra.CanonicalBytes.Span);
            var signing = initial;
            if (mode == 1)
            {
                await Advance();
                signing = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
                recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(signing.Proof, dca, Boot, Sample);
            }
            var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(recipient, signing.Network, signing.Authority,
                xra.CanonicalBytes, witnesses.Select(value => new RouteWitness(value)).ToArray(),
                signing.Proof.TrustedLowerUnixSeconds, expiry, time);
            var issuanceAdh = signing.Proof.ExactAdh1.ToArray();
            var issuanceGeneration = signing.Proof.NextProtectedLkg.LogGeneration;
            var issuanceHash = signing.Proof.NextProtectedLkg.CoreHash.ToArray();
            await Advance();
            var current = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(current.Proof, dca, Boot, Sample);
            Assert.Equal(mode == 1 ? 3UL : 2UL, current.Proof.NextProtectedLkg.LogGeneration);
            // Default fresh mint/adoption boundaries keep DR42's strict semantics.
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteVerifier.VerifyThresholdAsync(
                recipient, current.Network, current.Authority, xra.CanonicalBytes, threshold, time));
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(
                recipient, current.Network, current.Authority, secrets!, xra.CanonicalBytes, threshold, 2, time));

            async Task<VerifiedDeepIdV2ContactRouteIssuance> Verify(ReadOnlyMemory<byte>? adh = null,
                ContactRouteAuthorityWireRequest? pending = null, OnionTrustedTimeAuthority? clock = null,
                ParsedDeepIdV2RouteThreshold? response = null, CancellationToken ct = default) =>
                await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(recipient, current.Network,
                    current.Authority, pending ?? request, response ?? threshold, adh ?? issuanceAdh, clock ?? time, ct);

            if (mode == 2)
            {
                var reads = 0; var never = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                { reads++; return new(Boot, Sample); }));
                foreach (var bytes in new[] { Array.Empty<byte>(), new byte[4097], issuanceAdh.Append((byte)0).ToArray() })
                    await RequireRouteRejectionAsync(async () => await Verify(adh: bytes, clock: never));
                var corrupt = issuanceAdh.ToArray(); corrupt[^1] ^= 1;
                await RequireRouteRejectionAsync(async () => await Verify(adh: corrupt, clock: never));
                await RequireRouteRejectionAsync(async () => await Verify(adh: current.Proof.ExactAdh1, clock: never));
                Assert.Equal(0, reads);
                foreach (var pending in new[] {
                    CopyRequest(issuanceGeneration + 1, issuanceHash),
                    CopyRequest(issuanceGeneration, Bytes(32, 0xe3)),
                    new ContactRouteAuthorityWireRequest(Network, request.RequestNonce.Span, Bytes(32, 0xe4),
                        request.MinimumAdh1Generation, request.MinimumAdh1CoreHash.Span, request.ExactDca1.Span, request.ExactXra1.Span) })
                    await RequireRouteRejectionAsync(async () => await Verify(pending: pending));
                var changedDca = request.ExactDca1.ToArray(); changedDca[^1] ^= 1;
                var wrongDca = new ContactRouteAuthorityWireRequest(Network, request.RequestNonce.Span,
                    request.DirectoryLookupKey.Span, request.MinimumAdh1Generation, request.MinimumAdh1CoreHash.Span,
                    changedDca, request.ExactXra1.Span);
                await RequireRouteRejectionAsync(async () => await Verify(pending: wrongDca));
                var badXrc = threshold.LiveRoute.CanonicalBytes.ToArray();
                badXrc[FieldOffset(badXrc, 21) + 32] ^= 1;
                var forged = new ParsedDeepIdV2RouteThreshold(threshold.Selection.CanonicalBytes.Span, badXrc,
                    threshold.Successor.CanonicalBytes.Span);
                await RequireRouteRejectionAsync(async () => await Verify(response: forged));
                // Genuine ADH signatures plus genuine threshold signatures:
                // the current-floor/time bounds, not a bad signature, reject.
                var futureHead = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority, head.ProtectedHead,
                    new(head.ExactAllTransitions, [checkpoint], [], 990, 1_500, 2), witnesses);
                var futureError = await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await Verify(adh: futureHead.ExactAdh1, response: Reanchor(futureHead)));
                Assert.Equal("Retained route issuance differs from the exact request, current authority or verified bounds.", futureError.Message);
                var wrongWindow = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority, genesis.ProtectedHead,
                    new([], [], [checkpoint], 1_110, 1_500, 2), witnesses);
                var windowError = await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await Verify(adh: wrongWindow.ExactAdh1, pending: CopyRequest(0, genesis.CoreHash.ToArray()), response: Reanchor(wrongWindow)));
                Assert.Equal("Retained threshold does not bind its authenticated issuance head/time.", windowError.Message);
            }
            else if (mode == 3)
            {
                var mutable = issuanceAdh.ToArray(); var original = mutable.ToArray();
                var copying = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                { Array.Clear(mutable); return new(Boot, Sample); }));
                var copied = await Verify(adh: mutable, clock: copying);
                Assert.Equal(original, copied.ExactIssuanceAdh1.ToArray());
                var escaped = copied.ExactIssuanceAdh1.ToArray(); Array.Clear(escaped);
                Assert.Equal(original, copied.ExactIssuanceAdh1.ToArray());
                using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await Verify(ct: cancellation.Token));
                var reads = 0;
                var reverse = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                    new(Boot, ++reads == 1 ? Sample + 1 : Sample)));
                await RequireRouteRejectionAsync(async () => await Verify(clock: reverse));
            }
            var issuance = await Verify();
            if (mode == 4)
            {
                var reads = 0;
                var crossing = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                    new(Boot, ++reads == 1 ? Sample : Sample + 30)));
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.CompleteRetainedGenesisAsync(
                    recipient, current.Network, current.Authority, secrets!, issuance, 2, crossing));
                var before = Sample;
                try
                {
                    Sample += 30;
                    await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.CompleteRetainedGenesisAsync(
                        recipient, current.Network, current.Authority, secrets!, issuance, 2, time));
                    await RequireRouteRejectionAsync(async () => await Verify());
                }
                finally { Sample = before; }
            }
            var route = await DeepIdV2ContactRouteAuthor.CompleteRetainedGenesisAsync(recipient, current.Network,
                current.Authority, secrets!, issuance, 2, time);
            await route.EnsureCurrentAsync();
            if (mode == 5)
            {
                var predecessor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, current.Network,
                    current.Authority, route.ExactXir1V2, route.ExactRouteClosure, time);
                var nextXra = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(recipient, current.Network,
                    current.Authority, secrets!, xra.CanonicalBytes, Bytes(32, 0xa1), Bytes(32, 0xa2),
                    ScalarMult.Base(Bytes(32, 0xa3)), expiry + 20, time);
                var nextThreshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(recipient, current.Network,
                    current.Authority, predecessor, nextXra.CanonicalBytes,
                    witnesses.Select(value => new RouteWitness(value)).ToArray(), expiry + 20, time);
                var nextRequest = new ContactRouteAuthorityWireRequest(Network, Bytes(32, 0xa4), current.Proof.QueriedDirectoryLeafKey.Span,
                    current.Proof.NextProtectedLkg.LogGeneration, current.Proof.NextProtectedLkg.CoreHash.Span,
                    staged.ExactDca1.Span, nextXra.CanonicalBytes.Span, predecessor.ExactXir1V2.Span, predecessor.ExactRouteClosure.Span);
                var nextAdh = current.Proof.ExactAdh1;
                var exactRequest = ContactRouteAuthorityWireCodec.EncodeRequest(nextRequest);
                var parsedRequest = ContactRouteAuthorityWireCodec.DecodeRequest(exactRequest);
                Assert.True(parsedRequest.HasPredecessor);
                Assert.Equal(exactRequest, ContactRouteAuthorityWireCodec.EncodeRequest(parsedRequest));
                Assert.Equal(predecessor.ExactXir1V2.ToArray(), parsedRequest.ExactPredecessorXir1V2.ToArray());
                Assert.Equal(predecessor.ExactRouteClosure.ToArray(), parsedRequest.ExactPredecessorRouteClosure.ToArray());
                var mutableInvite = predecessor.ExactXir1V2.ToArray(); var mutableRoute = predecessor.ExactRouteClosure.ToArray();
                var ownedRequest = new ContactRouteAuthorityWireRequest(Network, nextRequest.RequestNonce.Span,
                    nextRequest.DirectoryLookupKey.Span, nextRequest.MinimumAdh1Generation, nextRequest.MinimumAdh1CoreHash.Span,
                    nextRequest.ExactDca1.Span, nextRequest.ExactXra1.Span, mutableInvite, mutableRoute);
                Array.Clear(mutableInvite); Array.Clear(mutableRoute);
                Assert.Equal(exactRequest, ContactRouteAuthorityWireCodec.EncodeRequest(ownedRequest));
                Assert.Throws<ArgumentException>(() => new ContactRouteAuthorityWireRequest(Network, nextRequest.RequestNonce.Span,
                    nextRequest.DirectoryLookupKey.Span, nextRequest.MinimumAdh1Generation, nextRequest.MinimumAdh1CoreHash.Span,
                    nextRequest.ExactDca1.Span, nextRequest.ExactXra1.Span));
                foreach (var mutation in new[] { "v2", "truncated", "trailing", "hostile", "one-sided", "network", "genesis" })
                {
                    var damaged = exactRequest.ToArray();
                    if (mutation == "v2") BinaryPrimitives.WriteUInt16BigEndian(damaged, 2);
                    if (mutation == "truncated") damaged = damaged[..^1];
                    if (mutation == "trailing") damaged = damaged.Append((byte)0).ToArray();
                    if (mutation == "hostile") BinaryPrimitives.WriteUInt32BigEndian(damaged.AsSpan(ContactRouteAuthorityWireCodec.RequestPrefixBytes), uint.MaxValue);
                    if (mutation == "one-sided") damaged = [.. damaged[..ContactRouteAuthorityWireCodec.RequestPrefixBytes], 0, 0, 0, 0,
                        .. damaged[(ContactRouteAuthorityWireCodec.RequestPrefixBytes + 4 + DeepIdV2InviteRendezvousCodec.CanonicalLength)..]];
                    if (mutation == "network") damaged[ContactRouteAuthorityWireCodec.RequestPrefixBytes + 4 + 20] ^= 1;
                    if (mutation == "genesis") { damaged.AsSpan(685, 8).Clear(); damaged.AsSpan(701, 32).Clear(); }
                    BinaryPrimitives.WriteUInt32BigEndian(damaged.AsSpan(4), checked((uint)damaged.Length));
                    var error = Record.Exception(() => ContactRouteAuthorityWireCodec.DecodeRequest(damaged));
                    Assert.True(error is FormatException or ArgumentException or CryptographicException, mutation);
                }
                await Advance();
                var advanced = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
                var nextRecipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(advanced.Proof, dca, Boot, Sample);
                var nextIssuance = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(nextRecipient,
                    advanced.Network, advanced.Authority, nextRequest, nextThreshold, nextAdh, time);
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.CompleteRetainedGenesisAsync(
                    nextRecipient, advanced.Network, advanced.Authority, secrets!, nextIssuance, 2, time));
                var successor = await DeepIdV2ContactRouteAuthor.CompleteRetainedSuccessorAsync(nextRecipient,
                    advanced.Network, advanced.Authority, secrets!, predecessor, nextIssuance, 2, time);
                await successor.EnsureCurrentAsync();
                var wrongPredecessor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(nextRecipient,
                    advanced.Network, advanced.Authority, successor.ExactXir1V2, successor.ExactRouteClosure, time);
                var mismatchReads = 0;
                var mismatchClock = new OnionTrustedTimeAuthority(new CallbackRendezvousClock(() =>
                { mismatchReads++; return new(Boot, Sample); }));
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteAuthor.CompleteRetainedSuccessorAsync(
                    nextRecipient, advanced.Network, advanced.Authority, secrets!, wrongPredecessor, nextIssuance, 2, mismatchClock));
                Assert.Equal(0, mismatchReads);
                Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(successor.Invite.Field(3).Span));
                Assert.Equal(route.Invite.ObjectHash.ToArray(), successor.Invite.Field(4).ToArray());
                Assert.Equal(route.Route.Route.CoreHash.ToArray(), successor.Route.Route.Field(4).ToArray());
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.AuthorRetainedGenesisAsync(
                    successor, issuance, secrets!, [DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span)],
                    "Wrong issuance", (await accounts.GetCurrentAsync())!.PermanentId.ResolverReadCapability));
            }
            var services = new[] { DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span) };
            var capability = (await accounts.GetCurrentAsync())!.PermanentId.ResolverReadCapability.ToArray();
            try
            {
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(
                    route, secrets!, services, "Retained QA", capability));
                var contact = await DeepIdV2ContactObjectAuthor.AuthorRetainedGenesisAsync(route, issuance,
                    secrets!, services, "Retained QA", capability);
                Assert.Equal(issuanceGeneration, BinaryPrimitives.ReadUInt64BigEndian(contact.Closure.Bundle.Field(21).Span));
                Assert.Equal(issuanceHash, contact.Closure.Bundle.Field(21).Span[8..].ToArray());
                var restored = await DeepIdV2ContactObjectAuthor.RestoreAsync(route, contact.Closure.CanonicalBytes,
                    contact.ProtectedDcr1, capability);
                Assert.Equal(contact.ProtectedDcr1.ToArray(), restored.ProtectedDcr1.ToArray());
                var publication = await DeepIdV2PublicationAuthorityAuthor.AuthorGenesisRequestAsync(route, contact,
                    secrets!, Bytes(32, 0xf1), Bytes(32, 0xf2), Bytes(32, 0xf3));
                Assert.Equal(issuanceGeneration, publication.WireRequest.MinimumAdh1Generation);
                Assert.Equal(issuanceHash, publication.WireRequest.MinimumAdh1CoreHash.ToArray());
                await DeepIdV2PublicationAuthorityAuthor.VerifyRequestAsync(route, publication.WireRequest);
                var authorization = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(route,
                    publication.WireRequest, PublicationWitnesses());
                var verified = await publication.VerifyResponseAsync(authorization.ExactXpu1);
                Assert.Equal(authorization.ExactXpu1.ToArray(), verified.ExactXpu1.ToArray());
            }
            finally { CryptographicOperations.ZeroMemory(capability); }
            Assert.Equal(accountBefore, (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText);

            ContactRouteAuthorityWireRequest CopyRequest(ulong generation, byte[] hash) =>
                new(Network, request.RequestNonce.Span, request.DirectoryLookupKey.Span, generation, hash,
                    request.ExactDca1.Span, request.ExactXra1.Span);
            ParsedDeepIdV2RouteThreshold Reanchor(AuthoredAccountDirectoryHeadMutation anchor)
            {
                var reference = HeadReference(anchor.CoreHash.Span);
                var live = ResignRenewalWitnessRecord(threshold.LiveRoute, new() { [19] = reference }, 21);
                var liveReference = ContactCodec.ArtifactReference("XRC1", live).CanonicalBytes;
                var checkpointRecord = ResignRenewalWitnessRecord(threshold.Successor,
                    new() { [4] = live.CoreHash, [5] = liveReference, [6] = liveReference, [12] = reference }, 14);
                return new(threshold.Selection.CanonicalBytes.Span, live.CanonicalBytes.Span, checkpointRecord.CanonicalBytes.Span);
            }
            async Task Advance()
            {
                retainedIssuanceHistory ??= new() { [0] = genesis.ProtectedHead };
                retainedIssuanceHistory[head.ProtectedHead.LogGeneration] = head.ProtectedHead;
                routeRequestPriorHead = head;
                head = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority, head.ProtectedHead,
                    new(head.ExactAllTransitions, [checkpoint], [], 990, 1_500, 2), witnesses);
                retainedIssuanceHistory[head.ProtectedHead.LogGeneration] = head.ProtectedHead;
            }
        }
    }
}
