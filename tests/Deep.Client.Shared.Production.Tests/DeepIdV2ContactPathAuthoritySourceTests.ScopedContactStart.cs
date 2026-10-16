using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ScopedContactStart_FirstClaimStoreAndColdRetryKeepOriginalWithoutReacquiringBetweenPhases()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xe1);
        var driver = await fixture.PrepareFreshContactStart(intent);
        driver.Claim.ExpectedNetworkFetches = fixture.NetworkClosureFetches + 2;
        var started = await driver.Start(intent, default);
        Assert.True(started.StorageReceipt.IngressDispatched);
        Assert.Equal(1, driver.Claim.Calls); Assert.Equal(0, driver.Claim.GenericCalls);
        Assert.Equal(1, driver.Store.Calls);
        Assert.NotNull(driver.Claim.Loan);
        Assert.Throws<ObjectDisposedException>(() => driver.Claim.Loan!.RequireActive());
        var exact = driver.Claim.Request!.ToArray(); var reads = driver.Read.Calls;
        fixture.ColdReopenCompactionStorage();
        var retained = await fixture.ReplayInitialStartWithoutResolver(intent, driver.Grants, driver.Store);
        Assert.False(retained.StorageReceipt.IngressDispatched);
        Assert.Equal(started.StorageReceipt.Cursor, retained.StorageReceipt.Cursor);
        Assert.Equal(1, driver.Claim.Calls); Assert.Equal(reads, driver.Read.Calls);
        Assert.Equal(1, driver.Store.Calls); Assert.Equal(exact, driver.Claim.Request);
        await fixture.VerifyNativeApplicationStartOperation(intent);
    }

    [Theory]
    [InlineData("expiry")]
    [InlineData("cancel")]
    [InlineData("signature")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ScopedContactStart_ExpiredCancelledOrInvalidResultCannotReachStoreAndKeepsRequest(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xe2);
        var driver = await fixture.PrepareFreshContactStart(intent);
        driver.Claim.ExpectedNetworkFetches = fixture.NetworkClosureFetches + 2;
        using var cancel = new CancellationTokenSource();
        driver.Claim.BadSignature = fault == "signature";
        driver.Claim.BeforeReturn = () => {
            if (fault == "expiry") fixture.Sample += 121;
            if (fault == "cancel") cancel.Cancel();
        };
        if (fault == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(() => driver.Start(intent, cancel.Token));
        else if (fault == "signature") await Assert.ThrowsAsync<ApplicationCoreFormatException>(() => driver.Start(intent, cancel.Token));
        else await Assert.ThrowsAsync<CryptographicException>(() => driver.Start(intent, cancel.Token));
        Assert.Equal(1, driver.Claim.Calls); Assert.Equal(0, driver.Claim.GenericCalls);
        Assert.Equal(0, driver.Store.Calls);
        Assert.Throws<ObjectDisposedException>(() => driver.Claim.Loan!.RequireActive());
        var exact = driver.Claim.Request!;
        var custody = await fixture.ReopenAccount().OpenOwnClaimRequestCustodyAsync();
        var parsed = DeepIdV2PreKeyClaimRequestCodec.Decode(exact);
        Assert.Equal(exact, (await custody.FindAsync(parsed.Field(2), default))!.Value.ToArray());
        var result = await custody.FindResultAsync(parsed.Field(2), default);
        Assert.Equal(fault == "expiry", result is not null);
        Assert.Empty(await fixture.ReopenAccount().ListConversationsAsync());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ScopedContactStart_LateReplyAfterCancellationCannotOutliveOwnerLoan()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xe3);
        var driver = await fixture.PrepareFreshContactStart(intent);
        driver.Claim.ExpectedNetworkFetches = fixture.NetworkClosureFetches + 2;
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        driver.Claim.DelayReturn = release.Task;
        using var cancel = new CancellationTokenSource();
        var start = driver.Start(intent, cancel.Token);
        try
        {
            await driver.Claim.Entered.Task.WaitAsync(TimeSpan.FromMinutes(2));
            cancel.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => start);
            Assert.Throws<ObjectDisposedException>(() => driver.Claim.Loan!.RequireActive());
            release.TrySetResult();
            await Assert.ThrowsAsync<ObjectDisposedException>(() => driver.Claim.PendingOwnedSend!);
            Assert.Equal(0, driver.Store.Calls); Assert.Equal(1, driver.Claim.Calls);
            var custody = await fixture.ReopenAccount().OpenOwnClaimRequestCustodyAsync();
            var request = DeepIdV2PreKeyClaimRequestCodec.Decode(driver.Claim.Request!);
            Assert.Equal(driver.Claim.Request, (await custody.FindAsync(request.Field(2), default))!.Value.ToArray());
            Assert.Null(await custody.FindResultAsync(request.Field(2), default));
            Assert.Empty(await fixture.ReopenAccount().ListConversationsAsync());
        }
        finally
        {
            cancel.Cancel(); release.TrySetResult();
            try { await start; } catch (OperationCanceledException) { }
            if (driver.Claim.PendingOwnedSend is { } pending)
                try { await pending; } catch (ObjectDisposedException) { }
        }
    }

    [Theory]
    [InlineData("floor")]
    [InlineData("expiry")]
    [InlineData("foreign")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ScopedContactStart_ChangedFloorExpiredProofOrForeignAccountCannotReuseScope(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.CheckOwnedContactScopeRefusesAsync(Bytes(32, 0xe4), fault);
    }

    private sealed class FreshOwnedClaimOnion(Fixture fixture, ParsedXpp1V2 publication) : IDid2OwnedExactContactResolveOnionTransport
    {
        internal int Calls, GenericCalls, ExpectedNetworkFetches;
        internal bool BadSignature;
        internal Action? BeforeReturn;
        internal Task? DelayReturn, PendingOwnedSend;
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal byte[]? Request;
        internal Did2OwnedContactTransportContext? Loan;
        public ValueTask<ExactContactResolveOnionResponse> SendExactAsync(ContactResolveCanonicalPathRequest request,
            ReadOnlyMemory<byte> requiredExitReplicaId, CancellationToken ct = default)
        {
            GenericCalls++;
            throw new InvalidOperationException("The scoped claim must use the explicit owned loan.");
        }
        public ValueTask<ExactContactResolveOnionResponse> SendOwnedExactAsync(ContactResolveCanonicalPathRequest canonical,
            ReadOnlyMemory<byte> requiredExitReplicaId, Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            var pending = SendOwnedCoreAsync(canonical, requiredExitReplicaId, operation, ct);
            PendingOwnedSend = pending;
            return new(pending);
        }

        private async Task<ExactContactResolveOnionResponse> SendOwnedCoreAsync(ContactResolveCanonicalPathRequest canonical,
            ReadOnlyMemory<byte> requiredExitReplicaId, Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            operation.RequireActive(); ct.ThrowIfCancellationRequested(); Calls++; Loan = operation;
            Assert.Equal(ExpectedNetworkFetches, fixture.NetworkClosureFetches);
            Request = canonical.ExactRequest.ToArray();
            var request = DeepIdV2PreKeyClaimRequestCodec.Decode(Request);
            var authority = new ContactResolvePathAuthority(operation.Network, ContactServicePlacementFactory.Create(
                operation.Network, canonical.RequestKind, canonical.ShardKey));
            Assert.Equal(authority.Placement.RankedReplicaNodeIds[0].ToArray(), requiredExitReplicaId.ToArray());
            var result = fixture.AuthorClaimResult(request, authority, publication, false,
                badSignature: BadSignature, serverTime: fixture.CurrentProofTime);
            Entered.TrySetResult();
            if (DelayReturn is not null) await DelayReturn; // Deliberately ignores cancellation.
            BeforeReturn?.Invoke(); operation.RequireActive();
            return new(result, authority);
        }
    }

    private sealed partial class Fixture
    {
        private int networkClosureFetches;
        internal int NetworkClosureFetches => Volatile.Read(ref networkClosureFetches);
        internal async Task CheckOwnedContactScopeRefusesAsync(byte[] intent, string fault)
        {
            await PrepareNativeHelloCompletion(intent, preSessionCut: "draft");
            var account = ReopenAccount(); var source = Source(account);
            var authority = await source.VerifyPermanentContactAsync(nativeMessagingContact!.Candidate, default);
            var before = await ContactDraftHashAsync(innerStorage);
            if (fault == "floor")
            {
                var floor = (await NetworkStore.ReadAsync(default))!;
                await NetworkStore.CompareExchangeAsync(floor.Revision, new(floor.Revision + 1, floor.ProtectedLkg, true), default);
                Assert.True((await NetworkStore.ReadAsync(default))!.ForkLatched);
            }
            if (fault == "expiry") Sample = authority.Own.Proof.FreshnessDeadlineMonotonicSeconds;
            if (fault == "foreign") { account = peerAccounts!; source = Source(account); }
            await Assert.ThrowsAsync<CryptographicException>(() => account.PrepareOwnedInitialContactDraftAsync(intent, authority, source, default));
            Assert.Equal(before, await ContactDraftHashAsync(innerStorage));
        }
        private static async Task<byte[]> ContactDraftHashAsync(IDeepSecureStorage secure)
        {
            using var value = await secure.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot) ?? throw new InvalidDataException();
            return value.Use(bytes => SHA256.HashData(bytes));
        }
        internal async Task<(Func<byte[], CancellationToken, Task<DeepIdV2ContactStartResult>> Start,
            FreshOwnedClaimOnion Claim, SyntheticPermanentRead Read, OwnedGrantTransport Grants, OwnedStoreFixture Store)>
            PrepareFreshContactStart(byte[] intent)
        {
            // Real protected draft and native inventory, but no preclaim or
            // completed session. The public Start below must perform them.
            await PrepareNativeHelloCompletion(intent, preSessionCut: "draft");
            var peer = peerAccounts!;
            var staged = await peer.EnsureOwnPreKeyInventoryAsync(Source(peer));
            var claim = new FreshOwnedClaimOnion(this, DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span));
            var account = ReopenAccount(); var source = Source(account);
            var read = new SyntheticPermanentRead(this, source, nativeMessagingPublication);
            var grants = new OwnedGrantTransport(this, ownerOnPrimary: true);
            var store = new OwnedStoreFixture(this, null, ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent), null);
            return ((operation, ct) => account.StartContactAsync(nativeMessagingContact!.Candidate.Address, operation,
                source, read, claim, grants, store, ct), claim, read, grants, store);
        }
    }
}
