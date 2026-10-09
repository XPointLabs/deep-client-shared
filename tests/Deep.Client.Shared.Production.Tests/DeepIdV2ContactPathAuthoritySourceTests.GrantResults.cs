using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0UL)] [InlineData(1UL)] [InlineData(5UL)]
    public async Task Did2GrantResults_IssuerPreservesTheSignedRequestStart(ulong elapsed)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckGrantRequestStartAsync(elapsed);
    }

    [Fact]
    public async Task Did2GrantResults_RealRootIssuerRouteAndFullIntervalRejectSubstitution()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckGrantResultsAsync();
    }

    [Fact]
    public async Task Did2MailboxPolicySource_RejectsMissingInvalidOrAmbiguousIssuerBeforeNetworkAdvance()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckMailboxPolicySourceAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckGrantRequestStartAsync(ulong elapsed)
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold);
            using var holder = new GrantHolder();
            var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, Bytes(32, 0xc7), holder);
            var originalStart = BinaryPrimitives.ReadUInt64BigEndian(request.Record.Field(9).Span);
            Sample = checked(Sample + elapsed); ProofTime = checked(ProofTime + elapsed);
            var response = await IssueOwnedGrantAsync(request, route, retrieve: false, default);
            var result = ContactCodec.Decode("XMC2", response);
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(result.Field(8).Span);
            Assert.Equal(originalStart, grant.NotBeforeUnixSeconds);
            var retained = await DeepIdV2MailboxGrantResultVerifier.VerifyRetainedSuccessAsync(route,
                request.ExactXmg2, response, operational.ExactPma2);
            await retained.EnsureCurrentAsync();
        }

        private int mailboxPolicyFault;
        private byte[]? rotatedIssuerPma;
        private IReadOnlyList<ReadOnlyMemory<byte>> MailboxPolicies()
        {
            var exact = (rotatedIssuerPma is not null ? (ReadOnlyMemory<byte>)rotatedIssuerPma :
                successor?.ExactPma2 ?? operational.ExactPma2).ToArray();
            if (mailboxPolicyFault == 1) exact[^1] ^= 1;
            if (mailboxPolicyFault == 2) exact[FieldOffset(exact, 5)] ^= 1;
            return mailboxPolicyFault == 3 ? [exact, exact.ToArray()] : [exact];
        }

        internal async Task CheckMailboxPolicySourceAsync()
        {
            var source = Source();
            foreach (var fault in new[] { 1, 2, 3 })
            {
                mailboxPolicyFault = fault;
                await RequireRouteRejectionAsync(async () => await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default));
                Assert.Null(await NetworkStore.ReadAsync(default));
            }
            mailboxPolicyFault = 0;
            var current = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            Assert.Equal(operational.ExactPma2.ToArray(), current.MailboxAuthority.ExactPma2.ToArray());
            var before = (await NetworkStore.ReadAsync(default))!;
            mailboxPolicyFault = 1;
            await RequireRouteRejectionAsync(async () => await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default));
            Assert.Equal(before.Revision, (await NetworkStore.ReadAsync(default))!.Revision);
            mailboxPolicyFault = 0;
        }

        internal async Task CheckGrantResultsAsync()
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold);
            var window = await route.ReadCurrentTimeAsync();
            using var holder = new GrantHolder();
            var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, Bytes(32, 0xb1), holder);
            var crypto = new SodiumMailboxCapabilityCrypto();
            MailboxAuthenticatedGrant Grant(AuthoredMailboxGrantRequest authored, byte issuerMarker) => new()
            {
                Domain = authored.Domain, Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = Network, Epoch = BinaryPrimitives.ReadUInt64BigEndian(route.Route.Selection.Field(4).Span),
                Generation = 1, Serial = Bytes(16, 0x91), NotBeforeUnixSeconds = window.LowerUnixSeconds,
                ExpiresAtUnixSeconds = window.UpperUnixSeconds + 10, OverlapUntilUnixSeconds = 0,
                PlacementCommitment = MailboxPlacementCommitment.Compute(new BlindedPlacementId(route.Route.Reachability.Field(10).Span)),
                MembershipCommitment = SHA256.HashData(route.Route.Projection.CanonicalBytes.Span),
                SelectionInput = route.Route.Selection.Field(3),
                IssuerPublicKey = PublicKey(issuerMarker), HolderPublicKey = authored.HolderPublicKey,
                IssuerSignature = new byte[64],
            };
            ContactRecord Result(AuthoredMailboxGrantRequest authored, MailboxAuthenticatedGrant grant, byte issuerMarker) =>
                MailboxGrantResultAuthor.AuthorSuccess(authored.Record, route.ExactRouteClosure.Span,
                    crypto.SignGrant(grant, Bytes(32, issuerMarker)), window.UpperUnixSeconds, window.UpperUnixSeconds + 15);
            var grant = Grant(request, 0x31);
            var response = Result(request, grant, 0x31);
            var verified = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(route, request,
                response.CanonicalBytes, operational.ExactPma2);
            await verified.EnsureCurrentAsync();
            Assert.Equal(MailboxCapabilityDomain.Deposit, verified.Domain);
            Assert.Equal(SHA256.HashData(route.Route.Projection.CanonicalBytes.Span), verified.MembershipCommitment.ToArray());
            Assert.Empty(typeof(VerifiedDeepIdV2MailboxGrant).GetConstructors());
            Assert.Equal(response.CanonicalBytes.ToArray(), verified.ExactXmc2.ToArray());
            var restoredRequest = await DeepIdV2MailboxGrantRequestAuthor.RestoreDepositAsync(route,
                request.LocatorHash, request.HolderPublicKey, request.ExactXmg2);
            Assert.Equal(request.ExactXmg2.ToArray(), restoredRequest.ExactXmg2.ToArray());
            var retained = await DeepIdV2MailboxGrantResultVerifier.VerifyRetainedSuccessAsync(route,
                request.ExactXmg2, response.CanonicalBytes, operational.ExactPma2);
            Assert.Equal(verified.ExactGrant.ToArray(), retained.ExactGrant.ToArray());
            var futureResponse = MailboxGrantResultAuthor.AuthorSuccess(request.Record, route.ExactRouteClosure.Span,
                crypto.SignGrant(grant, Bytes(32, 0x31)), window.UpperUnixSeconds + 1, window.UpperUnixSeconds + 15);
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantResultVerifier.VerifyRetainedSuccessAsync(
                route, request.ExactXmg2, futureResponse.CanonicalBytes, operational.ExactPma2));
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.RestoreDepositAsync(
                route, Bytes(32, 0xb3), request.HolderPublicKey, request.ExactXmg2));
            await Assert.ThrowsAsync<ArgumentException>(async () => await DeepIdV2MailboxGrantRequestAuthor.RestoreDepositAsync(
                route, new byte[32], request.HolderPublicKey, request.ExactXmg2));
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.RestoreDepositAsync(
                route, request.LocatorHash, Bytes(32, 0xb4), request.ExactXmg2));
            Assert.True(MemoryMarshal.TryGetArray(verified.ExactGrant, out var exported));
            exported.AsSpan().Clear();
            Assert.Equal(response.Field(8).ToArray(), verified.ExactGrant.ToArray());

            var retrieve = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(route, Bytes(32, 0xb1), Bytes(32, 0xb2), holder);
            var retrieved = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(route, retrieve,
                Result(retrieve, Grant(retrieve, 0x32), 0x32).CanonicalBytes, operational.ExactPma2);
            Assert.Equal(MailboxCapabilityDomain.Retrieve, retrieved.Domain);
            await retrieved.EnsureCurrentAsync();
            var restoredRetrieve = await DeepIdV2MailboxGrantRequestAuthor.RestoreRetrieveAsync(route,
                retrieve.LocatorHash, Bytes(32, 0xb2), retrieve.HolderPublicKey, retrieve.ExactXmg2);
            Assert.Equal(retrieve.ExactXmg2.ToArray(), restoredRetrieve.ExactXmg2.ToArray());
            foreach (var original in new[] { request, retrieve })
            {
                var changedBytes = original.ExactXmg2.ToArray();
                Bytes(32, 0xbe).CopyTo(changedBytes, FieldOffset(changedBytes, 11));
                var changedRecord = ContactCodec.Decode("XMG2", changedBytes);
                var proof = new byte[64];
                await holder.SignMailboxGrantRequestAsync(changedRecord.SignatureInput, proof, default);
                proof.CopyTo(changedBytes, FieldOffset(changedBytes, 12));
                ContactCodec.VerifyMailboxGrantHolderSignature(ContactCodec.Decode("XMG2", changedBytes));
                if (original.Domain == MailboxCapabilityDomain.Deposit)
                    await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.RestoreDepositAsync(
                        route, original.LocatorHash, original.HolderPublicKey, changedBytes));
                else
                    await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.RestoreRetrieveAsync(
                        route, original.LocatorHash, Bytes(32, 0xb2), original.HolderPublicKey, changedBytes));
                var changedResponse = Result(original, Grant(original, original.Domain == MailboxCapabilityDomain.Deposit ? (byte)0x31 : (byte)0x32),
                    original.Domain == MailboxCapabilityDomain.Deposit ? (byte)0x31 : (byte)0x32).CanonicalBytes.ToArray();
                SHA256.HashData(changedBytes).CopyTo(changedResponse, FieldOffset(changedResponse, 5));
                Bytes(32, 0xbe).CopyTo(changedResponse, FieldOffset(changedResponse, 7));
                ContactCodec.ValidateMailboxGrantResultBinding(ContactCodec.Decode("XMG2", changedBytes), ContactCodec.Decode("XMC2", changedResponse));
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantResultVerifier.VerifyRetainedSuccessAsync(
                    route, changedBytes, changedResponse, operational.ExactPma2));
                CryptographicOperations.ZeroMemory(proof);
            }
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantRequestAuthor.RestoreRetrieveAsync(
                route, retrieve.LocatorHash, Bytes(32, 0xb3), retrieve.HolderPublicKey, retrieve.ExactXmg2));

            // A valid winner may outlive its acquisition window. Restore must
            // not retry an expired pending request or expire the grant early.
            var shortBytes = request.ExactXmg2.ToArray();
            BinaryPrimitives.WriteUInt64BigEndian(shortBytes.AsSpan(FieldOffset(shortBytes, 10)), window.UpperUnixSeconds + 4);
            var shortRecord = ContactCodec.Decode("XMG2", shortBytes);
            var shortSignature = new byte[64];
            await holder.SignMailboxGrantRequestAsync(shortRecord.SignatureInput, shortSignature, default);
            shortSignature.CopyTo(shortBytes, FieldOffset(shortBytes, 12));
            var shortRequest = await DeepIdV2MailboxGrantRequestAuthor.RestoreDepositAsync(route,
                request.LocatorHash, request.HolderPublicKey, shortBytes);
            var shortResponse = MailboxGrantResultAuthor.AuthorSuccess(shortRequest.Record, route.ExactRouteClosure.Span,
                crypto.SignGrant(grant, Bytes(32, 0x31)), window.UpperUnixSeconds, window.UpperUnixSeconds + 4);
            var sampleAtShort = Sample;
            try
            {
                Sample += 5;
                await RequireRouteRejectionAsync(async () => await DeepIdV2MailboxGrantRequestAuthor.RestoreDepositAsync(
                    route, request.LocatorHash, request.HolderPublicKey, shortBytes));
                await RequireRouteRejectionAsync(async () => await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(
                    route, shortRequest, shortResponse.CanonicalBytes, operational.ExactPma2));
                var stillCurrent = await DeepIdV2MailboxGrantResultVerifier.VerifyRetainedSuccessAsync(
                    route, shortBytes, shortResponse.CanonicalBytes, operational.ExactPma2);
                await stillCurrent.EnsureCurrentAsync();
            }
            finally { Sample = sampleAtShort; CryptographicOperations.ZeroMemory(shortSignature); }

            foreach (var changed in new[]
            {
                grant with { MembershipCommitment = Bytes(32, 0x92) },
                grant with { IssuerPublicKey = PublicKey(0x32) },
                grant with { ExpiresAtUnixSeconds = window.UpperUnixSeconds },
                grant with { ExpiresAtUnixSeconds = route.Network.MaximumRecordExpiryUnixSeconds + 1 },
                grant with { NotBeforeUnixSeconds = window.LowerUnixSeconds + 1 },
                grant with { Lifecycle = MailboxCapabilityLifecycle.Overlap, OverlapUntilUnixSeconds = window.UpperUnixSeconds + 5 },
            })
                await RequireRouteRejectionAsync(async () => await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(
                    route, request, Result(request, changed, changed.IssuerPublicKey.Span.SequenceEqual(PublicKey(0x32)) ? (byte)0x32 : (byte)0x31).CanonicalBytes,
                    operational.ExactPma2));

            foreach (var offset in new[] { FieldOffset(response.CanonicalBytes.ToArray(), 2),
                FieldOffset(response.CanonicalBytes.ToArray(), 5), FieldOffset(response.CanonicalBytes.ToArray(), 7),
                FieldOffset(response.CanonicalBytes.ToArray(), 8) + 24, // epoch
                FieldOffset(response.CanonicalBytes.ToArray(), 8) + 176, // holder
                FieldOffset(response.CanonicalBytes.ToArray(), 8) + 208, // signed selector
                FieldOffset(response.CanonicalBytes.ToArray(), 8) + 240 }) // issuer signature
            {
                var changed = response.CanonicalBytes.ToArray(); changed[offset] ^= 1;
                await RequireRouteRejectionAsync(async () => await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(
                    route, request, changed, operational.ExactPma2));
            }
            var damagedPma = operational.ExactPma2.ToArray(); damagedPma[^1] ^= 1;
            await RequireRouteRejectionAsync(async () => await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(
                route, request, response.CanonicalBytes, damagedPma));
            var failed = MailboxGrantResultAuthor.AuthorFailure(request.Record,
                MailboxGrantAcquisitionResultCode.Unavailable, window.UpperUnixSeconds, window.UpperUnixSeconds + 15);
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(
                route, request, failed.CanonicalBytes, operational.ExactPma2));

            // Owned copies survive hostile input mutation during the first await.
            byte[]? mutableResult = null, mutablePma = null;
            var capturingClock = new CallbackRendezvousClock(() =>
            {
                if (mutableResult is not null) Array.Clear(mutableResult);
                if (mutablePma is not null) Array.Clear(mutablePma);
                return new(Boot, Sample);
            });
            var capturingRoute = await DeepIdV2ContactRouteVerifier.VerifyAsync(route.Recipient, route.Network,
                route.NetworkAuthority, route.ExactXir1V2, route.ExactRouteClosure, new(capturingClock));
            mutableResult = response.CanonicalBytes.ToArray(); mutablePma = operational.ExactPma2.ToArray();
            var captured = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(capturingRoute, request, mutableResult, mutablePma);
            Assert.Equal(response.CanonicalBytes.ToArray(), captured.ExactXmc2.ToArray());
            Assert.Equal(operational.ExactPma2.ToArray(), captured.ExactPma2.ToArray());

            var reads = 0; var inject = false;
            var expiringClock = new CallbackRendezvousClock(() => new(Boot,
                inject && ++reads == 2 ? route.Recipient.Freshness.FreshnessDeadlineMonotonicSeconds : Sample));
            var expiringRoute = await DeepIdV2ContactRouteVerifier.VerifyAsync(route.Recipient, route.Network,
                route.NetworkAuthority, route.ExactXir1V2, route.ExactRouteClosure, new(expiringClock));
            inject = true;
            await RequireRouteRejectionAsync(async () => await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(
                expiringRoute, request, response.CanonicalBytes, operational.ExactPma2));
            Assert.Equal(2, reads);
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(
                route, request, response.CanonicalBytes, operational.ExactPma2, cancelled.Token));
            var before = Sample;
            try
            {
                Sample = before + 10; // grant expires at authenticated upper bound
                await RequireRouteRejectionAsync(async () => await verified.EnsureCurrentAsync());
            }
            finally { Sample = before; } // fixture fault cleanup only
        }
    }
}
