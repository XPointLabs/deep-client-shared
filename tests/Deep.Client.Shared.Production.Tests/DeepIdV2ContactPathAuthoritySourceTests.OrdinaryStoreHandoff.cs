using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Protocol.ContactV1;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("unrelated")] [InlineData("target")] [InlineData("cancel")] [InlineData("expiry")] [InlineData("lost")] [InlineData("revoked")] [InlineData("quorum")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OrdinaryStore_ActualWaitRejoinsSelectedCustodyBeforeOutcome(string fault)
    {
        // Actual native preparation, grants, protected CAS, SQLCipher, path
        // construction and signed two-replica quorum. The network wait is an
        // in-process boundary fixture, not socket or physical-device evidence.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancel = new CancellationTokenSource();
        var erased = false; var actualPrivateBuffers = new List<byte[]>();
        using var privateLoans = Did2StoreHandoffTestHooks.Push((closed, observation) =>
        {
            if (!closed)
            {
                actualPrivateBuffers.AddRange(observation.GrantBuffers);
                var secrets = observation.Account.Verified.DeviceSecrets;
                foreach (var field in secrets.GetType().GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic))
                    if (field.FieldType == typeof(byte[])) actualPrivateBuffers.Add((byte[])field.GetValue(secrets)!);
                actualPrivateBuffers.AddRange(((byte[][])typeof(Did2StorePublicEvidence).GetField("records",
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(observation.Evidence)!).Where(bytes => bytes.Length != 0));
                actualPrivateBuffers.Add((byte[])typeof(SqliteDeepMailboxStore).GetField("encryptionKey",
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(observation.Store)!);
                var holder = observation.Loan.GetType().GetField("holder", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(observation.Loan)!;
                actualPrivateBuffers.Add((byte[])holder.GetType().GetField("seed", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(holder)!);
                Assert.True(actualPrivateBuffers.All(bytes => bytes.AsSpan().IndexOfAnyExcept((byte)0) >= 0));
            }
            else
            {
                Assert.True(actualPrivateBuffers.All(bytes => bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0));
                Assert.Throws<ObjectDisposedException>(() => observation.Context.RequireCurrentAsync(default).GetAwaiter().GetResult());
                Assert.ThrowsAny<OperationCanceledException>(() => observation.Context.Custody.Guards.ReadAsync(default).GetAwaiter().GetResult());
                erased = true;
            }
        });
        test.Transport.CorruptNetworkReply = fault == "quorum";
        test.Transport.NetworkWait = async ct =>
        {
            entered.TrySetResult();
            await release.Task;
            if (fault == "lost") throw new IOException("Lost exact original after actual handoff.");
        };
        var pending = fixture.DeliverNativeMessage(test.Scope, test.Operation, test.Grants, test.Transport, cancel.Token);
        try
        {
            await EnteredOrFailedStoreWait(entered.Task, pending);
            byte[] expectedRoot;
            // Acquiring the actual account lease proves it is released during wait.
            using (await fixture.AcquireOrdinaryStoreFixtureLease())
            {
                expectedRoot = await fixture.ReviseStoreWaitRoot(test.Scope, test.Operation, fault == "target");
                if (fault == "expiry") fixture.AdvanceStoreSettlementClock(
                    fixture.StoreWaitGrantExpiry(test.Transport.ExactRequest!) + 6);
                if (fault == "cancel") cancel.Cancel();
            }
            if (fault == "revoked") await fixture.AdvanceStoreWaitMinimumGeneration(test.Transport.ExactRequest!);
            release.TrySetResult();
            if (fault == "unrelated")
            {
                var result = await pending;
                Assert.True(result.IngressDispatched); Assert.NotNull(result.Cursor);
                Assert.Empty(await fixture.ListNativePendingText());
            }
            else
            {
                await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => pending);
                Assert.Equal(test.Operation, Assert.Single(await fixture.ListNativePendingText()).LogicalOperation.ToArray());
            }
            Assert.True(erased);
            Assert.True(actualPrivateBuffers.All(bytes => bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0));
            Assert.Equal(expectedRoot, await fixture.ReadSendRootForStoppedWork());
            Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
            using var sends = await fixture.ReadMailboxSends();
            var original = Assert.Single(sends.Entries).Value;
            Assert.True(original.Prepared); Assert.Equal(1UL, original.Counter);
            if (fault != "target") Assert.Equal(SHA256.HashData(test.Transport.ExactRequest!), original.MauHash.ToArray());
            CryptographicOperations.ZeroMemory(expectedRoot);
        }
        finally
        {
            release.TrySetResult();
            _ = await Record.ExceptionAsync(() => pending);
        }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OrdinaryStore_DistinctRealGrantsOverlapAndPreserveBothRootWrites()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var first = await fixture.PrepareStoreMonotonicityCase("ordinary");
        using var text = await fixture.CreateOwnedText(first.Scope, "Independent next grant during first network wait");
        var operation = text.OperationId.ToArray();
        using var sent = await fixture.SendOwnedMessage(first.Scope, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        var enteredFirst = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var enteredSecond = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirst = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSecond = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        first.Transport.NetworkWait = async ct => { enteredFirst.TrySetResult(); await releaseFirst.Task; };
        var pendingFirst = first.Deliver();
        await enteredFirst.Task.WaitAsync(TimeSpan.FromSeconds(60));
        // This existing producer authors/verifies a genuine independently held
        // successor grant. It does not synthesize counters or Store outcomes.
        using (await fixture.AcquireOrdinaryStoreFixtureLease())
        {
            using var before = await fixture.ReadMailboxSends();
            var firstStripe = ProtectedDeepIdV2AccountOwner.MailboxGrantFlightStripe(Assert.Single(before.Entries).Value.GrantHash);
            var independent = false;
            for (byte marker = 0x99; marker < 0xa1; marker++)
            {
                await fixture.StageVerifiedGrantSuccessorAsync(first.Grants, own: true, seedMarker: marker);
                using var current = await fixture.ReadPeerGrantsAsync(own: true);
                var selected = Assert.Single(current.Selections).Value.Current!;
                var grant = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(current.Entries[selected]).Span).Field(8);
                if (ProtectedDeepIdV2AccountOwner.MailboxGrantFlightStripe(SHA256.HashData(grant.Span)) == firstStripe) continue;
                independent = true; break;
            }
            Assert.True(independent, "The overlap fixture requires independently signed grants on distinct lock stripes.");
        }
        var second = new OwnedStoreFixture(fixture, first.Scope, operation, sent.ExactEnvelope.ToArray()) { Cursor = 2 };
        second.NetworkWait = async ct => { enteredSecond.TrySetResult(); await releaseSecond.Task; };
        var pendingSecond = fixture.DeliverNativeMessage(first.Scope, operation, first.Grants, second);
        await enteredSecond.Task.WaitAsync(TimeSpan.FromSeconds(60));
        Assert.False(pendingFirst.IsCompleted); Assert.False(pendingSecond.IsCompleted);
        byte[] exactRoot;
        using (await fixture.AcquireOrdinaryStoreFixtureLease()) exactRoot = await fixture.ReadSendRootForStoppedWork();
        using (var sends = await fixture.ReadMailboxSends())
        {
            Assert.Equal(2, sends.Entries.Count); Assert.Equal(2, sends.Floors.Count);
            Assert.Equal(2, sends.Entries.Values.Select(entry => Convert.ToHexString(entry.GrantHash)).Distinct().Count());
            Assert.All(sends.Entries.Values, entry => Assert.Equal(1UL, entry.Counter));
        }
        releaseSecond.TrySetResult(); Assert.Equal(2UL, (await pendingSecond).Cursor);
        releaseFirst.TrySetResult(); Assert.Equal(1UL, (await pendingFirst).Cursor);
        Assert.Equal(exactRoot, await fixture.ReadSendRootForStoppedWork());
        Assert.Empty(await fixture.ListNativePendingText());
        Assert.Equal(1, first.Transport.Calls); Assert.Equal(1, second.Calls);
        CryptographicOperations.ZeroMemory(exactRoot);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OrdinaryStore_SameGrantQueuesThenUnknownPinsLaterCounterAcrossColdReopen()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var first = await fixture.PrepareStoreMonotonicityCase("ordinary");
        using var text = await fixture.CreateOwnedText(first.Scope, "Later work keeps the original grant order");
        var operation = text.OperationId.ToArray();
        using var sent = await fixture.SendOwnedMessage(first.Scope, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        first.Transport.NetworkWait = async ct =>
        { entered.TrySetResult(); await release.Task; throw new IOException("Lost original response after handoff."); };
        var pendingFirst = first.Deliver();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(60));
        var later = new OwnedStoreFixture(fixture, first.Scope, operation, sent.ExactEnvelope.ToArray());
        var pendingLater = fixture.DeliverNativeMessage(first.Scope, operation, first.Grants, later);
        Assert.NotSame(pendingLater, await Task.WhenAny(pendingLater, Task.Delay(TimeSpan.FromMilliseconds(200))));
        Assert.Equal(0, later.Calls);
        release.TrySetResult();
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => pendingFirst);
        await Assert.ThrowsAsync<IOException>(() => pendingLater);
        var original = first.Transport.ExactRequest!.ToArray();
        fixture.ColdReopenStoreSettlement(first.Scope);
        await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(first.Scope, operation, first.Grants, later));
        Assert.Equal(0, later.Calls);
        using (var sends = await fixture.ReadMailboxSends())
        { Assert.Single(sends.Entries); Assert.Equal(1UL, Assert.Single(sends.Floors).Value.HighestCounter); }
        fixture.Sample += 40; fixture.ProofTime += 40;
        first.Transport.NetworkWait = null;
        var recovered = await first.Deliver();
        Assert.True(recovered.IngressDispatched); Assert.Equal(original, first.Transport.ExactRequest);
        var second = await fixture.DeliverNativeMessage(first.Scope, operation, first.Grants, later);
        Assert.True(second.IngressDispatched);
        using (var sends = await fixture.ReadMailboxSends())
        { Assert.Equal(2, sends.Entries.Count); Assert.Equal(2UL, Assert.Single(sends.Floors).Value.HighestCounter); }
        Assert.Empty(await fixture.ListNativePendingText());
        // An older exact original remains recoverable after a newer counter is
        // settled. Ordering must never make it wait for its own successors.
        var originalCalls = first.Transport.Calls;
        _ = await first.Deliver();
        Assert.Equal(originalCalls, first.Transport.Calls);
        Assert.Equal(original, first.Transport.ExactRequest);
        using (var sends = await fixture.ReadMailboxSends())
        { Assert.Equal(2UL, Assert.Single(sends.Floors).Value.HighestCounter); }
        CryptographicOperations.ZeroMemory(original);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OrdinaryStore_ForgedStoredMarkerCannotOvertakeUnknownLowerCounter()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var first = await fixture.PrepareStoreMonotonicityCase("ordinary");
        using var text = await fixture.CreateOwnedText(first.Scope, "Later work requires an independent signed lower outcome");
        var operation = text.OperationId.ToArray();
        using var sent = await fixture.SendOwnedMessage(first.Scope, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        first.Transport.LoseReply = true;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(first.Deliver);
        var original = first.Transport.ExactRequest!.ToArray();
        var before = await fixture.ReadSendRootForStoppedWork();
        var native = (await fixture.ReadMessagingFloor(first.Scope)).Exact.ToArray();
        using (await fixture.AcquireOrdinaryStoreFixtureLease())
            await fixture.ForgeStoreWaitLocalStoredMarker(first.Scope, first.Operation);
        var later = new OwnedStoreFixture(fixture, first.Scope, operation, sent.ExactEnvelope.ToArray());
        foreach (var cold in new[] { false, true })
        {
            if (cold) fixture.ColdReopenStoreSettlement(first.Scope);
            var error = await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(first.Scope, operation, first.Grants, later));
            Assert.Equal("Resume the exact unknown grant request before a later counter.", error.Message);
            Assert.Equal(0, later.Calls);
            Assert.Equal(before, await fixture.ReadSendRootForStoppedWork());
            Assert.Equal(native, (await fixture.ReadMessagingFloor(first.Scope)).Exact.ToArray());
        }
        using var sends = await fixture.ReadMailboxSends();
        var retained = Assert.Single(sends.Entries).Value;
        Assert.Equal(SHA256.HashData(original), retained.MauHash.ToArray());
        Assert.Equal(1UL, Assert.Single(sends.Floors).Value.HighestCounter);
        Assert.Equal(1, first.Transport.Calls); Assert.Equal(1, first.Grants.Calls);
        CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(native);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OrdinaryStore_ProductOnionAndHttpPathHandsOffBeforeAccountSuspension()
    {
        // Real product path and HTTP transport, with an in-process HTTP handler.
        // This is no claim of TLS/socket/node/device qualification.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new StoreWaitHttpHandler(async request =>
        {
            Assert.Equal(System.Net.HttpVersion.Version20, request.Version);
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.NotEmpty(await request.Content!.ReadAsByteArrayAsync());
            Assert.Null(fixture.TryAcquireOrdinaryStoreFixtureLease());
            entered.TrySetResult();
            await release.Task;
            throw new IOException("HTTP outcome lost after actual frame dispatch.");
        });
        var factory = new ActualStoreWaitFactory(handler);
        var pending = fixture.DeliverNativeMessage(test.Scope, test.Operation, test.Grants, factory);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(60));
        using (await fixture.AcquireOrdinaryStoreFixtureLease())
        {
            await Assert.ThrowsAsync<ObjectDisposedException>(() => factory.Context!.RequireCurrentAsync(default).AsTask());
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => factory.Context!.Custody.Guards.ReadAsync(default).AsTask());
        }
        release.TrySetResult();
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => pending);
        Assert.Equal(1, handler.Calls);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => factory.Context!.RequireCurrentAsync(default).AsTask());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => factory.Context!.Custody.Guards.ReadAsync(default).AsTask());
        using var sends = await fixture.ReadMailboxSends();
        Assert.True(Assert.Single(sends.Entries).Value.Prepared);
        Assert.Equal(test.Operation, Assert.Single(await fixture.ListNativePendingText()).LogicalOperation.ToArray());
    }

    private sealed class ActualStoreWaitFactory(HttpMessageHandler handler) : IDid2OwnedMailboxTransportFactory
    {
        internal Did2OwnedMailboxTransportContext? Context;
        public IClientMailboxBinaryIngress Create(Did2OwnedMailboxTransportContext context, IMailboxClientDecodePolicyProvider policy)
        {
            Context = context;
            return new DeepIdV2MailboxOnionTransport(context, PrivacyMailboxRouteSelection.Primary, policy,
                entry => new PrivacyManagedIngressHttpTransport(new HttpClient(handler, disposeHandler: false)
                    { BaseAddress = new Uri("https://ordinary-store.invalid"), Timeout = Timeout.InfiniteTimeSpan }));
        }
    }
    private sealed class StoreWaitHttpHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        internal int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        { Calls++; return send(request); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OrdinaryStore_LateReplyKeepsPendingThenExactHistoricalSettlementRecovers(bool distinctIssuance)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: distinctIssuance ? 1_200UL : null);
        var test = await fixture.PrepareStoreMonotonicityCase("ordinary");
        if (distinctIssuance)
        { await fixture.AdvanceNetworkAsync(expiry: 6_000); fixture.AdvanceStoreSettlementClock(1_100); }
        test.Grants.MaximumFixtureGrantLifetimeSeconds = 120;
        test.Transport.BeforeReturnedReply = expiry => fixture.AdvanceStoreSettlementClock(expiry + 6);
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        var original = test.Transport.ExactRequest!.ToArray();
        var reply = test.Transport.CopyOriginalQuorumForFixture();
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        Assert.Equal(test.Operation, Assert.Single(await fixture.ListNativePendingText()).LogicalOperation.ToArray());
        fixture.ColdReopenStoreSettlement(test.Scope);
        // Existing historical settlement authenticates this exact retained
        // original; this is no new grant, dispatch, message or application ACK.
        var settled = await fixture.AdoptStoreSettlement(test, reply);
        Assert.False(settled.IngressDispatched); Assert.NotNull(settled.Cursor);
        var recovered = await test.Deliver();
        Assert.Equal(settled.Cursor, recovered.Cursor); Assert.False(recovered.IngressDispatched);
        Assert.Equal(original, test.Transport.ExactRequest);
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        Assert.Empty(await fixture.ListNativePendingText());
        foreach (var bytes in new[] { original, reply, native }) CryptographicOperations.ZeroMemory(bytes);
    }

    private static async Task EnteredOrFailedStoreWait(Task entered, Task pending)
    {
        var first = await Task.WhenAny(entered, pending).WaitAsync(TimeSpan.FromSeconds(60));
        if (ReferenceEquals(first, pending)) await pending;
        Assert.True(entered.IsCompletedSuccessfully, "The actual network handoff was not reached.");
    }

    private sealed partial class Fixture
    {
        internal async Task ForgeStoreWaitLocalStoredMarker(Did2MessagingSessionScope scope, byte[] operation)
        {
            using var raw = await innerStorage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ?? throw new InvalidOperationException();
            var before = raw.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2DirectTextJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
            state.RetainStore(Convert.ToHexString(operation), CurrentProofTime);
            var next = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
            try { Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, before, next)); }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(next); }
        }
        private bool storeWaitRetainPolicyHistory;
        internal async Task AdvanceStoreWaitMinimumGeneration(byte[] originalRequest)
        {
            await AdvanceNetworkAsync(expiry: 6_000);
            var exact = successor!.ExactPma2.ToArray();
            BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(FieldOffset(exact, 7), 8), 2);
            var provisional = ContactCodec.Decode("PMA2", exact);
            var rows = provisional.Field(16).ToArray();
            for (var offset = 0; offset < rows.Length; offset += 96)
                root.SignCommit(provisional.SignatureInput).CopyTo(rows, offset + 32);
            rows.CopyTo(exact, FieldOffset(exact, 16));
            rotatedIssuerPma = ContactCodec.Decode("PMA2", exact).CanonicalBytes.ToArray();
            storeWaitRetainPolicyHistory = true;
            AuthorSignedEpochAdvance();
            AdvanceStoreSettlementClock(Math.Max(1_100UL, CurrentProofTime));
            var original = Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxAuthenticatedClientRequestCodec.Decode(originalRequest).Presentation.Grant;
            Assert.Equal(1UL, original.Generation);
            Assert.True(CurrentProofTime < original.ExpiresAtUnixSeconds);
            var account = ReopenAccount();
            var current = await Source(account).VerifyForOwnPreKeyAuthoringAsync(account, default);
            Assert.Equal(2UL, current.MailboxAuthority.MinimumGrantGeneration);
        }
        internal HeldDeepIdV2AccountLease? TryAcquireOrdinaryStoreFixtureLease() =>
            new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock")).TryAcquire();
        internal ValueTask<HeldDeepIdV2AccountLease> AcquireOrdinaryStoreFixtureLease() =>
            new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock")).AcquireAsync(default);
        internal ulong StoreWaitGrantExpiry(byte[] exact) =>
            Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxAuthenticatedClientRequestCodec.Decode(exact).Presentation.Grant.ExpiresAtUnixSeconds;
        internal async Task<byte[]> ReviseStoreWaitRoot(Did2MessagingSessionScope scope, byte[] operation, bool target)
        {
            using var raw = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidOperationException();
            var before = raw.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2MailboxSendJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
            if (target)
            {
                var selected = state.Current(scope.Hash, operation)!;
                var changed = selected.Exact.ToArray(); changed[264] ^= 1;
                state.Entries[selected.Name] = ProtectedDid2MailboxSendJournal.Entry.Decode(changed);
                selected.Dispose(); CryptographicOperations.ZeroMemory(changed);
            }
            state.Revision++;
            var next = ProtectedDid2MailboxSendJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
            try
            {
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, before, next));
                return next.ToArray();
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(next); }
        }
    }
}
