using System.Runtime.InteropServices;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2RetainedRead_TimelyCopiedReplySurvivesClosedTransportLoanAndColdReopensExactWinner()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        var original = await fixture.PrepareRetainedPublicationAsync(elapsed: true);
        var issuer = new RetainedReadCourier(fixture, original);
        var courier = new DeadlineRetainedReadCourier(fixture, issuer) { ProbeHeldCustody = true };
        using var parent = new CancellationTokenSource();
        Task? guardProbe = null, entropyProbe = null;
        byte[]? exactResponse = null;
        var copied = 0;
        using (Did2MailboxInstallationTestHooks.Push(point =>
        {
            if (point != Did2MailboxInstallationFailpoint.AfterRetainedGrantReplyCopied) return;
            copied++;
            Assert.False(parent.IsCancellationRequested);
            Assert.True(courier.TransportToken.IsCancellationRequested);
            var dispatch = Assert.IsType<Did2OwnedContactTransportContext>(courier.Dispatch);
            Assert.ThrowsAny<OperationCanceledException>(dispatch.RequireActive);
            // Caller CancellationToken.None must not revive either borrowed adapter.
            guardProbe = dispatch.Custody.Guards.ReadAsync(CancellationToken.None).AsTask();
            entropyProbe = dispatch.Custody.Entropy.CommitAsync(
                Assert.IsType<OnionEntropyCommitmentBatch>(courier.ReservedBatch), CancellationToken.None).AsTask();
            exactResponse = Assert.IsType<byte[]>(courier.ReturnedResponse).ToArray();
            courier.ReturnedResponse![^1] ^= 1; // The transport's mutable buffer is no longer the owner's input.
        }))
        {
            var result = await fixture.Accounts.AcquireOwnPermanentContactRetrieveGrantAsync(
                fixture.Source(), courier, parent.Token);
            Assert.Equal(1, copied);
            Assert.NotNull(guardProbe); Assert.NotNull(entropyProbe);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => guardProbe!);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => entropyProbe!);
            Assert.Equal(exactResponse, result.ExactXmc2.ToArray());
            Assert.Equal(issuer.Request.ToArray(), result.ExactXmg2.ToArray());
            Assert.Equal(1, issuer.Calls); Assert.Equal(1, issuer.Issuer.Calls);
            await fixture.AssertInstalledGrantSqlAsync(result.ExactGrant, own: true);
            var cold = fixture.ReopenAccount();
            var reopened = await cold.AcquireOwnPermanentContactRetrieveGrantAsync(fixture.Source(cold), courier);
            Assert.Equal(result.ExactXmg2.ToArray(), reopened.ExactXmg2.ToArray());
            Assert.Equal(result.ExactXmc2.ToArray(), reopened.ExactXmc2.ToArray());
            Assert.Equal(1, issuer.Calls); Assert.Equal(1, issuer.Issuer.Calls);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2RetainedRead_LateTransportOrCancelledParentCannotAdoptAndColdRetryKeepsOriginal(bool cancelParent)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        var original = await fixture.PrepareRetainedPublicationAsync(elapsed: true);
        var issuer = new RetainedReadCourier(fixture, original);
        var courier = new DeadlineRetainedReadCourier(fixture, issuer);
        using var parent = new CancellationTokenSource();
        CancellationTokenSource? dispatchDeadline = null;
        var copied = 0;
        using (Did2MailboxInstallationTestHooks.PushRetainedGrantTransport(value => dispatchDeadline = value))
        using (Did2MailboxInstallationTestHooks.Push(point =>
        {
            if (point != Did2MailboxInstallationFailpoint.AfterRetainedGrantReplyCopied) return;
            copied++;
            if (cancelParent) parent.Cancel();
        }))
        {
            if (!cancelParent) courier.BeforeReturn = () =>
                Assert.IsAssignableFrom<CancellationTokenSource>(dispatchDeadline).Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                fixture.Accounts.AcquireOwnPermanentContactRetrieveGrantAsync(fixture.Source(), courier, parent.Token));
        }
        Assert.Equal(cancelParent ? 1 : 0, copied);
        Assert.Equal(cancelParent, parent.IsCancellationRequested);
        using (var pending = await fixture.ReadPeerGrantsAsync(own: true))
        {
            Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(Assert.Single(pending.Entries).Value));
            Assert.Null(Assert.Single(pending.Selections).Value.Current);
        }
        courier.BeforeReturn = null;
        var cold = fixture.ReopenAccount();
        var recovered = await cold.AcquireOwnPermanentContactRetrieveGrantAsync(fixture.Source(cold), courier);
        Assert.Equal(issuer.Request.ToArray(), recovered.ExactXmg2.ToArray());
        Assert.Equal(2, issuer.Calls); Assert.Equal(1, issuer.Issuer.Calls);
        await fixture.AssertInstalledGrantSqlAsync(recovered.ExactGrant, own: true);
    }

    private sealed class DeadlineRetainedReadCourier(Fixture fixture, RetainedReadCourier inner)
        : IDid2RetainedMailboxReadGrantTransport
    {
        internal bool ProbeHeldCustody { get; init; }
        internal Did2OwnedContactTransportContext? Dispatch { get; private set; }
        internal CancellationToken TransportToken { get; private set; }
        internal byte[]? ReturnedResponse { get; private set; }
        internal OnionEntropyCommitmentBatch? ReservedBatch { get; private set; }
        internal Action? BeforeReturn { get; set; }

        public async ValueTask<ReadOnlyMemory<byte>> AcquireRetainedReadAsync(AuthoredMailboxGrantRequest request,
            Did2OwnedContactTransportContext dispatch, CancellationToken ct)
        {
            Dispatch = dispatch; TransportToken = ct;
            var response = await inner.AcquireRetainedReadAsync(request, dispatch, ct);
            if (ProbeHeldCustody)
            {
                var canonical = ContactResolveCanonicalPathRequest.Decode(request.ExactXmg2.Span);
                var placement = ContactServicePlacementFactory.Create(dispatch.Network, canonical.RequestKind, canonical.ShardKey);
                var paths = new ContactResolvePrivacyPathProvider(fixture.Source(dispatch.Custody.Owner), dispatch.Custody.Guards);
                var prepared = await paths.PrepareWithAuthorityAsync(OnionOperation.ContactResolve, canonical,
                    ReadOnlyMemory<byte>.Empty, new(dispatch.Network, placement), ct, dispatch.RetainedReadRequest, dispatch);
                var ledger = new CapturingEntropyLedger(dispatch.Custody.Entropy);
                var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(ledger),
                    new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
                using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request, ct);
                Assert.True(built.Frame.Length > request.ExactXmg2.Length);
                ReservedBatch = Assert.IsType<OnionEntropyCommitmentBatch>(ledger.LastBatch);
            }
            Assert.True(MemoryMarshal.TryGetArray(response, out var segment));
            Assert.Equal(0, segment.Offset); Assert.Equal(segment.Array!.Length, segment.Count);
            ReturnedResponse = segment.Array;
            BeforeReturn?.Invoke(); // Deliberately noncooperative courier: the owner must reject a late result itself.
            return response;
        }
    }
}
