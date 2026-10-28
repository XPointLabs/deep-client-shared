using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2RecordedRouteRecovery_OwnedCurrentViewDispatchBuildsActualFramesForBothModes()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckRecordedRecoveryDispatchAsync(0);
    }

    [Theory]
    [InlineData(1)] // Different current view.
    [InlineData(2)] // Cross-network envelope/base request is rejected before path promotion.
    [InlineData(3)] // Actual signed request's trusted-time lease expires before dispatch.
    [InlineData(4)] // Wrapper exceeds current placement's signed deadline.
    public async Task Did2RecordedRouteRecovery_OwnedDispatchRejectsHostileScopeAndExpiryWithoutMutation(int fault)
    {
        await using var fixture = fault == 3
            ? await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true, initialMailboxAuthorityExpiry: 1_235)
            : await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckRecordedRecoveryDispatchAsync(fault);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckRecordedRecoveryDispatchAsync(int fault)
        {
            var seeded = await SeedRecordedRenewalAsync();
            var probe = new RecoveryDispatchProbe(this, seeded.Backend, fault);
            var before = await RouteSnapshot();
            try
            {
                if (fault == 0)
                {
                    var completed = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), probe, seeded.Backend, seeded.Backend);
                    Assert.Equal(1UL, completed.Generation);
                    Assert.Equal(new[] { DeepIdV2ContactRouteRecoveryMode.ReadRecordedWinner,
                        DeepIdV2ContactRouteRecoveryMode.IssueAfterRecordedHistory }, probe.PreparedModes);
                    Assert.Equal(2, probe.BuiltFrames);
                    Assert.Equal(1, seeded.Backend.RecoveryReads); Assert.Equal(1, seeded.Backend.RecoveryIssues);
                }
                else
                {
                    await Assert.ThrowsAsync<RecoveryDispatchProbeCompleteException>(() =>
                        accounts.EnsureOwnPermanentContactPublishedAsync(Source(), probe, seeded.Backend, seeded.Backend));
                    var after = await RouteSnapshot();
                    try { Assert.Equal(before, after); }
                    finally { CryptographicOperations.ZeroMemory(after); }
                    Assert.Equal(0, seeded.Backend.RecoveryReads); Assert.Equal(0, seeded.Backend.RecoveryIssues);
                    Assert.Equal(0, probe.BuiltFrames); Assert.Empty(probe.PreparedModes);
                }
            }
            finally
            {
                foreach (var bytes in new[] { before, seeded.Permanent, seeded.Original, seeded.Pending })
                    CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    private sealed class RecoveryDispatchProbe(Fixture fixture, RenewalBackend backend, int fault)
        : IDid2ContactRouteThresholdSource, IDid2ContactRouteRecoverySource
    {
        internal List<DeepIdV2ContactRouteRecoveryMode> PreparedModes { get; } = [];
        internal int BuiltFrames { get; private set; }

        public ValueTask<ContactRouteAuthorityWireResponse> FetchAsync(ContactRouteAuthorityWireRequest request,
            DeepIdV2CurrentContactAuthorization authorization, VerifiedOnionNetworkContext network,
            VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority time,
            Did2OwnedContactTransportContext operation, CancellationToken ct) =>
            backend.FetchAsync(request, authorization, network, authority, time, operation, ct);

        public async ValueTask<ContactRouteAuthorityWireResponse> RecoverAsync(DeepIdV2ContactRouteRecoveryWireRequest request,
            Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            operation.RequireActive();
            var exact = ContactCoordinationOnionCodec.EncodeRequest(ContactCoordinationTarget.RouteRecovery, request.CanonicalBytes.Span);
            var canonical = ContactResolveCanonicalPathRequest.Decode(exact);
            Assert.False(canonical.HasExplicitPlacementBinding); Assert.Empty(canonical.ProjectionReference.ToArray());
            Assert.Equal(request.ViewHash.ToArray(), canonical.ViewHash.ToArray());
            var placement = ContactServicePlacementFactory.Create(operation.Network, canonical.RequestKind, canonical.ShardKey);
            var current = new ContactResolvePathAuthority(operation.Network, placement);
            var paths = new ContactResolvePrivacyPathProvider(fixture.Source(operation.Custody.Owner), operation.Custody.Guards);
            var guardsBefore = await operation.Custody.Guards.ReadAsync(ct);
            if (fault != 0)
            {
                var changed = request.CanonicalBytes.ToArray();
                switch (fault)
                {
                    case 1: changed[128] ^= 1; break;
                    case 2: changed[8] ^= 1; break;
                    case 3:
                        // The production lease uses TimeProvider.System, not
                        // the fixture's directory-proof sample counter.
                        var remaining = Math.Min(checked(backend.CurrentDeadline - fixture.Sample),
                            checked(operation.Network.MaximumRecordExpiryUnixSeconds - backend.RecoveryDispatchTrustedUpper));
                        Assert.InRange(remaining, 1UL, 27UL);
                        await Task.Delay(TimeSpan.FromSeconds(remaining + 1), ct); break;
                    case 4:
                        BinaryPrimitives.WriteUInt64BigEndian(changed.AsSpan(160), placement.ValidUntilUnixSeconds);
                        BinaryPrimitives.WriteUInt64BigEndian(changed.AsSpan(168), checked(placement.ValidUntilUnixSeconds + 1)); break;
                }
                if (fault == 3)
                {
                    var error = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
                        await paths.PrepareWithAuthorityAsync(OnionOperation.ContactResolve, canonical, ReadOnlyMemory<byte>.Empty,
                            current, ct, ownedOperation: operation));
                    Assert.Equal("trusted-time-expired", error.Code);
                }
                else if (fault == 2)
                {
                    Assert.Throws<FormatException>(() => ContactCoordinationOnionCodec.EncodeRequest(ContactCoordinationTarget.RouteRecovery, changed));
                }
                else
                {
                    var hostile = ContactResolveCanonicalPathRequest.Decode(
                        ContactCoordinationOnionCodec.EncodeRequest(ContactCoordinationTarget.RouteRecovery, changed));
                    var error = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
                        await paths.PrepareWithAuthorityAsync(OnionOperation.ContactResolve, hostile, ReadOnlyMemory<byte>.Empty,
                            current, ct, ownedOperation: operation));
                    Assert.Equal("placement-request-mismatch", error.Code);
                }
                Assert.Equal(guardsBefore?.Revision, (await operation.Custody.Guards.ReadAsync(ct))?.Revision);
                throw new RecoveryDispatchProbeCompleteException();
            }
            var prepared = await paths.PrepareWithAuthorityAsync(OnionOperation.ContactResolve, canonical,
                ReadOnlyMemory<byte>.Empty, current, ct, ownedOperation: operation);
            Assert.Equal(exact, prepared.Attempt.Request.CanonicalBytes.ToArray());
            var ledger = new CapturingEntropyLedger(operation.Custody.Entropy);
            var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(ledger),
                new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
            using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request, ct);
            Assert.True(built.Frame.Length > exact.Length);
            Assert.Equal(OnionEntropyCommitOutcome.Duplicate, await operation.Custody.Entropy.CommitAsync(ledger.LastBatch!, ct));
            PreparedModes.Add(request.Mode); BuiltFrames++;
            operation.RequireActive();
            return await backend.RecoverAsync(request, operation, ct);
        }
    }

    private sealed class RecoveryDispatchProbeCompleteException : IOException { }

    private sealed partial class RenewalBackend
    {
        internal ulong RecoveryDispatchTrustedUpper => authorization.TrustedUpperUnixSeconds;
    }
}
