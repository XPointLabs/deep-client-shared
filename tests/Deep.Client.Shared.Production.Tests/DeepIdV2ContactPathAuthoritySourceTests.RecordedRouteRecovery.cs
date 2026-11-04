using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public void Did2RecordedRouteRecovery_NextIntentMatchesFrozenPublicPrimitiveAndJournalBounds()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "docs", "survival-program", "releases", "v3.0.0",
            "specs", "contact-route-recovery-v1.vectors.json"))) directory = directory.Parent;
        Assert.NotNull(directory);
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(directory!.FullName, "docs", "survival-program", "releases",
            "v3.0.0", "specs", "contact-route-recovery-v1.vectors.json")));
        var vector = document.RootElement.GetProperty("nextIntentPrimitive");
        byte[] Bytes(string name) => Convert.FromHexString(vector.GetProperty(name).GetString()!);
        Assert.Equal(Bytes("expectedHex"), ProtectedDid2ContactRenewalClosure.DeriveNextIntent(Bytes("networkHex"), Bytes("accountHex"),
            Bytes("instanceHex"), Bytes("permanentIntentHex"), Bytes("completedBaseEntryHashHex"), Bytes("oldPhase1Hex"), Bytes("recordedResponseHex")));
        Assert.Equal(41_753, ProtectedDid2ContactRenewalClosure.MaximumBytes);
        Assert.Equal(184, ProtectedDid2ContactRenewalClosure.OriginBytes);
        Assert.Equal(10, ProtectedDid2ContactRouteJournal.Version);
    }

    [Theory]
    [InlineData(0)] // Before the atomic journal/two-sidecar transaction.
    [InlineData(1)] // Uncertain completion after the atomic transaction.
    [InlineData(2)] // Lost release after independent atomic readback.
    public async Task Did2RecordedRouteRecovery_AtomicClosureColdReopenAndPromotionPreserveEveryOriginal(int crash)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true, objectHorizonWindow: true);
        await fixture.CheckOwnedRecordedRecoveryAsync(crash);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public async Task Did2RecordedRouteRecovery_ThreeChainedWinnersAndClosedFourthCapacity(int count)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true, objectHorizonWindow: true);
        await fixture.CheckStagedRecordedChainAsync(count, rejectFourth: count == 3);
    }

    [Theory]
    [InlineData(0)] // Forward closure exists, active request was substituted.
    [InlineData(1)] // Forward closure exists, origin custody is missing.
    public async Task Did2RecordedRouteRecovery_ForwardLookupRequiresExactActiveRequestAndOrigin(int fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true, objectHorizonWindow: true);
        await fixture.CheckStagedRecordedChainAsync(1, false, fault);
    }

    [Theory]
    [InlineData(0)] // Cancellation after the external read callback.
    [InlineData(1)] // Actual freshness expires after the callback.
    [InlineData(2)] // Trusted boot changes after the callback.
    [InlineData(3)] // Actual protected history anchor disappears after callback.
    public async Task Did2RecordedRouteRecovery_CallbackChangesCannotClosePendingCustody(int fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckRecordedRecoveryCallbackAsync(fault);
    }

    private sealed partial class Fixture
    {
        private Task<VerifiedDeepIdV2PublicationCommit> EnsureRecordedReopenedAsync(RenewalBackend backend)
        {
            var reopened = ReopenAccount();
            return reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend);
        }

        private async Task<(RenewalBackend Backend, byte[] Permanent, byte[] Original, byte[] Pending)> SeedRecordedRenewalAsync()
        {
            await SeedShortPermanentProposalAsync();
            var backend = new RenewalBackend(this);
            await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend);
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            var permanent = plan.Intent.ToArray(); byte[] original;
            using (var state = await RouteState()) original = state.Entries[Convert.ToHexString(permanent)].Exact.ToArray();
            ProofTime += 60; Sample += 60;
            await SeedShortPendingRenewalAsync(20);
            backend.LoseRouteResponse = true;
            await Assert.ThrowsAsync<IOException>(() => accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend));
            byte[] pending;
            using (var state = await RouteState()) pending = Assert.Single(state.Entries.Values, entry => entry.Phase == 1).Exact.ToArray();
            await AdvancePastRecordedPendingAsync();
            await backend.PrepareRecoveryAsync();
            return (backend, permanent, original, pending);
        }

        private async Task AdvancePastRecordedPendingAsync()
        {
            using var state = await RouteState(); var pending = Assert.Single(state.Entries.Values, entry => entry.Phase == 1);
            var expiry = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", pending.Record(1).Span).Field(13).Span);
            var target = checked(expiry + 20); var elapsed = target > CurrentProofTime ? target - CurrentProofTime : 1;
            ProofTime += elapsed; Sample += elapsed;
        }

        internal async Task CheckOwnedRecordedRecoveryAsync(int crash, int count = 1, bool rejectFourth = false)
        {
            var seeded = await SeedRecordedRenewalAsync(); var backend = seeded.Backend;
            var originals = new List<byte[]> { seeded.Pending }; var closed = new List<string>();
            try
            {
                for (var index = 0; index < count; index++)
                {
                    var before = await RouteSnapshot(); var old = originals[^1];
                    var point = crash == 0 ? Did2ContactRouteFailpoint.BeforeRecordedClosure :
                        crash == 2 ? Did2ContactRouteFailpoint.AfterRecordedClosureReadback : Did2ContactRouteFailpoint.AfterRecordedClosure;
                    var hit = false;
                    using (Did2ContactRouteTestHooks.Push(actual =>
                        { if (actual == point) { hit = true; throw new IOException("Interrupted recorded-winner closure."); } }))
                        await Assert.ThrowsAsync<IOException>(() => accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend));
                    Assert.True(hit, "The intended durable closure boundary was not reached.");
                    if (crash == 0)
                    {
                        var actual = await RouteSnapshot();
                        try { Assert.True(before.AsSpan().SequenceEqual(actual), "Pre-CAS interruption changed protected journal."); }
                        finally { CryptographicOperations.ZeroMemory(actual); }
                        using var absent = await storage.ReadOwnedAsync(ProtectedDid2ContactRenewalClosure.ClosedSlot(old.AsSpan(0, 32)));
                        Assert.Null(absent);
                        using (Did2ContactRouteTestHooks.Push(actual =>
                            { if (actual == Did2ContactRouteFailpoint.AfterRecordedClosure) throw new IOException("Stop after actual atomic closure."); }))
                            await Assert.ThrowsAsync<IOException>(() => accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend));
                    }
                    CryptographicOperations.ZeroMemory(before);
                    var slot = ProtectedDid2ContactRenewalClosure.ClosedSlot(old.AsSpan(0, 32)); closed.Add(slot);
                    using var owned = await storage.ReadOwnedAsync(slot); Assert.NotNull(owned);
                    using var generation = await storage.ReadOwnedAsync("deep.store.v2.sql-generation");
                    var instance = generation!.Use(bytes => bytes.Slice(56, 32).ToArray());
                    try
                    {
                        using var closure = owned!.Use(bytes => ProtectedDid2ContactRenewalClosure.Decode(bytes, Network,
                            checkpoint.Directory.Record.DeepAccountId.Span, instance));
                        Assert.True(closure.ExactOldPhase1.Span.SequenceEqual(old), "Closure changed immutable original phase1 bytes.");
                        using var state = await RouteState();
                        Assert.True(state.Entries[Convert.ToHexString(seeded.Permanent)].Exact.SequenceEqual(seeded.Original),
                            "Recorded closure changed the last completed publication.");
                        var next = Assert.Single(state.Entries.Values, entry => entry.Phase == 1);
                        Assert.True(next.Exact[..32].SequenceEqual(closure.NextIntent.Span), "Active proposal differs from atomic closure target.");
                        using var batch = await storage.ReadOwnedBatchAsync([ProtectedDid2ContactRouteJournal.Slot, slot,
                            ProtectedDid2ContactRenewalClosure.OriginSlot(closure.NextRequestHash.Span)]);
                        Assert.All(Enumerable.Range(0, 3), position => Assert.NotNull(batch[position]));
                        batch[2]!.Use(bytes => { closure.RequireOrigin(bytes, closure.NextRequestHash.Span); return true; });
                        originals.Add(next.Exact.ToArray());
                    }
                    finally { CryptographicOperations.ZeroMemory(instance); }
                    ColdReopenCompactionStorage(); await backend.PrepareRecoveryAsync();
                    if (index + 1 < count || rejectFourth)
                    {
                        backend.LoseRouteResponse = true;
                        await Assert.ThrowsAsync<IOException>(() => EnsureRecordedReopenedAsync(backend));
                        await AdvancePastRecordedPendingAsync(); await backend.PrepareRecoveryAsync();
                    }
                }
                if (rejectFourth)
                {
                    var before = await RouteSnapshot(); var signatures = backend.RouteSignings;
                    await Assert.ThrowsAsync<IOException>(() => EnsureRecordedReopenedAsync(backend));
                    var after = await RouteSnapshot();
                    try { Assert.True(before.AsSpan().SequenceEqual(after), "Fourth recorded winner changed bounded custody."); }
                    finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
                    Assert.Equal(signatures, backend.RouteSignings);
                    return;
                }
                using (Did2ContactRouteTestHooks.Push(actual =>
                    { if (actual == Did2ContactRouteFailpoint.AfterRenewalPromotion) throw new IOException("Lost promotion reply."); }))
                    await Assert.ThrowsAsync<IOException>(() => EnsureRecordedReopenedAsync(backend));
                ColdReopenCompactionStorage(); await backend.PrepareRecoveryAsync();
                var calls = (backend.RouteSignings, backend.PublicationSignings);
                var completed = await EnsureRecordedReopenedAsync(backend);
                Assert.Equal(1UL, completed.Generation);
                Assert.Equal(calls, (backend.RouteSignings, backend.PublicationSignings));
                using var promoted = await RouteState(); var current = promoted.Entries[Convert.ToHexString(seeded.Permanent)];
                Assert.Equal(7, current.Phase);
                Assert.Equal((ulong)count + 1, BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", current.Record(1).Span).Field(3).Span));
                Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(DeepIdV2InviteRendezvousCodec.Decode(current.Record(5).Span).Field(3).Span));
                var retained = Assert.Single(promoted.Entries.Values, value => value.Phase == 7 &&
                    !value.Exact[..32].SequenceEqual(seeded.Permanent));
                Assert.True(retained.Exact[32..].SequenceEqual(seeded.Original.AsSpan(32)), "Promotion changed retained signed base beyond local intent prefix.");
                // Actual account restoration after promotion resolves origin
                // backwards through immutable custody, including the re-bound
                // completed base entry. Sidecar self-consistency is insufficient.
                var restored = await EnsureRecordedReopenedAsync(backend);
                Assert.True(restored.ExactXpo1.Span.SequenceEqual(completed.ExactXpo1.Span), "Cold restore changed promoted exact winner.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seeded.Permanent); CryptographicOperations.ZeroMemory(seeded.Original);
                foreach (var value in originals) CryptographicOperations.ZeroMemory(value);
            }
        }

        internal async Task CheckRecordedRecoveryCallbackAsync(int fault)
        {
            var seeded = await SeedRecordedRenewalAsync(); var backend = seeded.Backend;
            var before = await RouteSnapshot(); using var cancellation = new CancellationTokenSource();
            backend.AfterRecoveryReply = () =>
            {
                if (fault == 0) cancellation.Cancel();
                if (fault == 1) Sample = backend.CurrentDeadline;
                if (fault == 2) thresholdClockOverride = _ => ValueTask.FromResult(new OnionMonotonicReading(Bytes(16, 0xee), Sample));
                if (fault == 3) DamageHistoryAnchorAsync(corrupt: false).GetAwaiter().GetResult();
            };
            try
            {
                var error = await Record.ExceptionAsync(() => accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend, cancellation.Token));
                Assert.True(error is OperationCanceledException or CryptographicException or InvalidDataException,
                    "Changed current authority after recovery read did not fail closed.");
                var after = await RouteSnapshot();
                try { Assert.True(before.AsSpan().SequenceEqual(after), "Rejected recovery callback changed protected pending work."); }
                finally { CryptographicOperations.ZeroMemory(after); }
                using var absent = await storage.ReadOwnedAsync(ProtectedDid2ContactRenewalClosure.ClosedSlot(seeded.Pending.AsSpan(0, 32)));
                Assert.Null(absent); Assert.Equal(1, backend.RecoveryReads); Assert.Equal(0, backend.RecoveryIssues);
            }
            finally
            {
                foreach (var value in new[] { before, seeded.Permanent, seeded.Original, seeded.Pending }) CryptographicOperations.ZeroMemory(value);
            }
        }

        // Real short signed proposals and positive winners exercise the
        // authenticated three-link custody reader without inventing multi-day
        // authority. This is custody/restore coverage, not three full owner
        // recovery cycles. The crash test above covers the production closure.
        internal async Task CheckStagedRecordedChainAsync(int count, bool rejectFourth, int forwardFault = -1,
            string? retainedReadDefect = null)
        {
            var seeded = await SeedRecordedRenewalAsync(); var backend = seeded.Backend;
            var pairs = new List<DeepIdV2ContactRouteRecordedPair>(); var configuration = Did2OwnedPermanentContactPlan.Configuration();
            try
            {
                for (var index = 0; index < count; index++)
                {
                    var fresh = await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default);
                    var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(
                        (await accounts.ReadOwnStagedPreKeyPublicationAsync())!.ExactDca1.Span), checkpoint.Binding, checkpoint.Directory);
                    var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, Boot, Sample);
                    using var state = await RouteState(); var old = Assert.Single(state.Entries.Values, value => value.Phase == 1);
                    var basis = state.Entries[Convert.ToHexString(seeded.Permanent)];
                    var prior = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(authorization, fresh.Network, fresh.Authority,
                        basis.Record(5), basis.Record(6), new(this));
                    pairs.Add(backend.RecordedPair(old.Record(12)));
                    var history = await DeepIdV2ContactRouteVerifier.VerifyRecordedHistoryAsync(authorization, fresh.Network,
                        fresh.Authority, prior, pairs, new(this));
                    using var device = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                        checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
                    var scalar = Bytes(32, (byte)(0x81 + index)); var key = Bytes(32, (byte)(0x91 + index)); var nonce = Bytes(32, (byte)(0xa1 + index));
                    var before = await RouteSnapshot();
                    using var generation = await storage.ReadOwnedAsync("deep.store.v2.sql-generation");
                    var instance = generation!.Use(bytes => bytes.Slice(56, 32).ToArray());
                    byte[]? after = null;
                    try
                    {
                        var advertisement = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAfterRecordedHistoryAsync(authorization,
                            fresh.Network, fresh.Authority, device!, history, configuration.AntiSpamHash, key,
                            DeepIdentityCrypto.DeriveX25519PublicKey(scalar), fresh.Proof.TrustedUpperUnixSeconds + 20, new(this));
                        var request = new ContactRouteAuthorityWireRequest(Network, nonce, fresh.Proof.QueriedDirectoryLeafKey.Span,
                            fresh.Proof.NextProtectedLkg.LogGeneration, fresh.Proof.NextProtectedLkg.CoreHash.Span, dca.Record.CanonicalBytes.Span,
                            advertisement.CanonicalBytes.Span, prior.ExactXir1V2.Span, prior.ExactRouteClosure.Span);
                        var response = pairs[^1].ExactResponse.ToArray();
                        var intent = ProtectedDid2ContactRenewalClosure.DeriveNextIntent(Network, checkpoint.Directory.Record.DeepAccountId.Span,
                            instance, seeded.Permanent, SHA256.HashData(basis.Exact), old.Exact, response);
                        var next = ProtectedDid2ContactRouteJournal.Entry.Proposal(intent, configuration, scalar, key, nonce,
                            dca.Record.CanonicalBytes, advertisement, request, Network, checkpoint.Directory.Record.DeepAccountId.Span);
                        using var closure = ProtectedDid2ContactRenewalClosure.Create(Network, checkpoint.Directory.Record.DeepAccountId.Span,
                            instance, seeded.Permanent, SHA256.HashData(basis.Exact), old, next, response);
                        var closedSlot = ProtectedDid2ContactRenewalClosure.ClosedSlot(old.Exact[..32]);
                        var originSlot = ProtectedDid2ContactRenewalClosure.OriginSlot(closure.NextRequestHash.Span);
                        state.Entries.Remove(Convert.ToHexString(old.Exact[..32])); state.Entries.Add(Convert.ToHexString(intent), next);
                        after = ProtectedDid2ContactRouteJournal.Encode(state, Network, checkpoint.Directory.Record.DeepAccountId.Span, instance);
                        var closureBytes = closure.Exact.ToArray(); var originBytes = closure.EncodeOrigin();
                        try
                        {
                            Assert.True(await storage.CompareExchangeAndInsertAsync(ProtectedDid2ContactRouteJournal.Slot, before, after,
                                [new(closedSlot, closureBytes), new(originSlot, originBytes)]), "Fixture atomic closure comparison failed.");
                        }
                        finally { CryptographicOperations.ZeroMemory(closureBytes); CryptographicOperations.ZeroMemory(originBytes); }
                        old.Dispose();
                        using var readback = await storage.ReadOwnedBatchAsync([ProtectedDid2ContactRouteJournal.Slot, closedSlot, originSlot]);
                        Assert.All(Enumerable.Range(0, 3), position => Assert.NotNull(readback[position]));
                        readback[2]!.Use(bytes => { closure.RequireOrigin(bytes, closure.NextRequestHash.Span); return true; });
                        await backend.RecordPositiveAsync(request, history);
                        if (forwardFault >= 0 && index + 1 == count)
                        {
                            if (forwardFault == 1) await storage.DeleteBatchAsync([originSlot]);
                            else
                            {
                                var substituted = ProtectedDid2ContactRouteJournal.Entry.Proposal(intent, configuration, scalar, key,
                                    Bytes(32, 0xe1), dca.Record.CanonicalBytes, advertisement,
                                    new ContactRouteAuthorityWireRequest(Network, Bytes(32, 0xe1), request.DirectoryLookupKey.Span,
                                        request.MinimumAdh1Generation, request.MinimumAdh1CoreHash.Span, request.ExactDca1.Span,
                                        request.ExactXra1.Span, request.ExactPredecessorXir1V2.Span, request.ExactPredecessorRouteClosure.Span),
                                    Network, checkpoint.Directory.Record.DeepAccountId.Span);
                                state.Entries[Convert.ToHexString(intent)].Dispose(); state.Entries[Convert.ToHexString(intent)] = substituted;
                                var changed = ProtectedDid2ContactRouteJournal.Encode(state, Network, checkpoint.Directory.Record.DeepAccountId.Span, instance);
                                try { Assert.True(await storage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, after, changed)); }
                                finally { CryptographicOperations.ZeroMemory(changed); }
                            }
                        }
                        CryptographicOperations.ZeroMemory(intent);
                    }
                    finally
                    {
                        foreach (var value in new[] { scalar, key, nonce, before, instance, after }) if (value is not null) CryptographicOperations.ZeroMemory(value);
                    }
                    ColdReopenCompactionStorage();
                    if (index + 1 < count || rejectFourth) await AdvancePastRecordedPendingAsync();
                    await backend.PrepareRecoveryAsync();
                }
                if (count == 3) await backend.VerifyRecordedOrderRejectionsAsync(pairs);
                var snapshot = await RouteSnapshot(); var calls = (backend.RouteSignings, backend.RecoveryReads, backend.RecoveryIssues);
                try
                {
                    if (forwardFault >= 0 || rejectFourth)
                    {
                        var error = await Record.ExceptionAsync(() => EnsureRecordedReopenedAsync(backend));
                        Assert.True(error is IOException or CryptographicException or InvalidDataException, "Invalid recorded forward custody did not reject.");
                        if (rejectFourth)
                            Assert.Equal("Recorded renewal history capacity is exhausted.", Assert.IsType<IOException>(error).Message);
                        var actual = await RouteSnapshot();
                        try { Assert.True(snapshot.AsSpan().SequenceEqual(actual), "Rejected bounded recovery changed custody."); }
                        finally { CryptographicOperations.ZeroMemory(actual); }
                        Assert.Equal(calls, (backend.RouteSignings, backend.RecoveryReads, backend.RecoveryIssues));
                    }
                    else
                    {
                        var committed = await EnsureRecordedReopenedAsync(backend);
                        Assert.Equal(1UL, committed.Generation);
                        Assert.Equal(calls.RouteSignings, backend.RouteSignings);
                        if (retainedReadDefect is not null)
                            await CheckRetainedRecordedPublicationAfterPromotionAsync(seeded.Permanent, seeded.Original,
                                seeded.Pending, retainedReadDefect);
                    }
                }
                finally { CryptographicOperations.ZeroMemory(snapshot); }
            }
            finally { foreach (var value in new[] { seeded.Permanent, seeded.Original, seeded.Pending }) CryptographicOperations.ZeroMemory(value); }
        }
    }

    private sealed partial class RenewalBackend
    {
        internal int RecoveryReads, RecoveryIssues;
        internal Action? AfterRecoveryReply;
        internal async Task VerifyRecordedOrderRejectionsAsync(IReadOnlyList<DeepIdV2ContactRouteRecordedPair> pairs)
        {
            var first = pairs[0].Request;
            var anchor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(authorization, network, authority,
                first.ExactPredecessorXir1V2, first.ExactPredecessorRouteClosure, time);
            foreach (var invalid in new[] { pairs.Reverse().ToArray(), pairs.Skip(1).ToArray(), new[] { pairs[0], pairs[2] } })
            {
                var error = await Record.ExceptionAsync(async () => await DeepIdV2ContactRouteVerifier.VerifyRecordedHistoryAsync(
                    authorization, network, authority, anchor, invalid, time));
                Assert.True(error is CryptographicException or FormatException, "Noncontiguous recorded history did not reject.");
            }
        }
        internal DeepIdV2ContactRouteRecordedPair RecordedPair(ReadOnlyMemory<byte> exactRequest)
        {
            var request = ContactRouteAuthorityWireCodec.DecodeRequest(exactRequest.Span);
            var number = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", request.ExactXra1.Span).Field(3).Span);
            if (!routeRequests.TryGetValue(number, out var saved) || !saved.AsSpan().SequenceEqual(exactRequest.Span) ||
                !routeWinners.TryGetValue(number, out var response)) throw new CryptographicException("Fixture exact positive row is absent.");
            return new(saved, ContactRouteAuthorityWireCodec.EncodeResponse(request, response));
        }
        internal async Task RecordPositiveAsync(ContactRouteAuthorityWireRequest request, VerifiedDeepIdV2ContactRouteRecordedHistory history)
        {
            var number = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", request.ExactXra1.Span).Field(3).Span);
            RequireExact(routeRequests, number, ContactRouteAuthorityWireCodec.EncodeRequest(request));
            var expiry = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", request.ExactXra1.Span).Field(13).Span);
            var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAfterRecordedHistoryAsync(authorization, network, authority,
                history, request.ExactXra1, RecoveryFixture.CreateRouteWitnesses(), expiry, time, default);
            routeWinners.Add(number, new(request.NetworkId.Span, request.RequestNonce.Span, threshold.Selection.CanonicalBytes.Span,
                threshold.LiveRoute.CanonicalBytes.Span, threshold.Successor.CanonicalBytes.Span, authorization.Freshness.ExactAdh1.Span)); RouteSignings++;
        }
        internal async Task PrepareRecoveryAsync()
        {
            var fresh = await RecoveryFixture.Source().VerifyForOwnPreKeyAuthoringAsync(RecoveryFixture.Accounts, default);
            var checkpoint = fresh.Proof.CurrentCheckpoint!;
            var delegation = DeepIdV2ContactAuthorizationCodec.Verify(authorization.Authorization.Record, checkpoint.Binding, checkpoint.Directory);
            var reading = await RecoveryFixture.ReadAsync(default);
            authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, delegation, reading.BootId.Span, reading.SampleSeconds);
            network = fresh.Network; authority = fresh.Authority; time = new OnionTrustedTimeAuthority(RecoveryFixture);
        }

        public async ValueTask<ContactRouteAuthorityWireResponse> RecoverAsync(DeepIdV2ContactRouteRecoveryWireRequest request,
            Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            operation.RequireActive();
            await DeepIdV2ContactRouteVerifier.VerifyRecoveryRequestAsync(authorization, network, authority, request, time, ct);
            foreach (var pair in request.History)
            {
                var number = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", pair.Request.ExactXra1.Span).Field(3).Span);
                if (!routeRequests.TryGetValue(number, out var savedRequest) || !routeWinners.TryGetValue(number, out var savedResponse) ||
                    !savedRequest.AsSpan().SequenceEqual(pair.ExactRequest.Span) ||
                    !ContactRouteAuthorityWireCodec.EncodeResponse(pair.Request, savedResponse).AsSpan().SequenceEqual(pair.ExactResponse.Span))
                    throw new CryptographicException("Fixture issuer has no exact positive history row.");
            }
            var basis = request.BaseRequest;
            var generation = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", basis.ExactXra1.Span).Field(3).Span);
            if (request.Mode == DeepIdV2ContactRouteRecoveryMode.ReadRecordedWinner)
            {
                RecoveryReads++;
                if (!routeRequests.TryGetValue(generation, out var saved) || !saved.AsSpan().SequenceEqual(request.ExactBaseRequest.Span) ||
                    !routeWinners.TryGetValue(generation, out var winner)) throw new CryptographicException("Fixture recorded positive winner is absent.");
                AfterRecoveryReply?.Invoke(); return winner;
            }
            RecoveryIssues++;
            var anchor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(authorization, network, authority,
                basis.ExactPredecessorXir1V2, basis.ExactPredecessorRouteClosure, time, ct);
            var history = await DeepIdV2ContactRouteVerifier.VerifyRecordedHistoryAsync(authorization, network, authority,
                anchor, request.History, time, ct);
            RequireExact(routeRequests, generation, request.ExactBaseRequest.ToArray());
            if (!routeWinners.TryGetValue(generation, out var response))
            {
                var expiry = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", basis.ExactXra1.Span).Field(13).Span);
                if (RecoveryThresholdLifetimeSeconds is { } lifetime)
                    expiry = Math.Min(expiry, checked(authorization.TrustedUpperUnixSeconds + lifetime));
                var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAfterRecordedHistoryAsync(authorization, network,
                    authority, history, basis.ExactXra1, RecoveryFixture.CreateRouteWitnesses(), expiry, time, ct);
                response = new(basis.NetworkId.Span, basis.RequestNonce.Span, threshold.Selection.CanonicalBytes.Span,
                    threshold.LiveRoute.CanonicalBytes.Span, threshold.Successor.CanonicalBytes.Span, authorization.Freshness.ExactAdh1.Span);
                routeWinners.Add(generation, response); RouteSignings++;
            }
            if (LoseRouteResponse) { LoseRouteResponse = false; throw new IOException("Lost exact recovered route winner."); }
            AfterRecoveryReply?.Invoke(); return response;
        }

        private async Task<VerifiedDeepIdV2ContactRouteRecordedHistory?> RecordedHistoryForPublicationAsync(
            ContactPublicationAuthorityWireRequest original, CancellationToken ct)
        {
            if (original.Generation == 0) return null;
            var prior = ContactPublicationAuthorityWireCodec.DecodeRequest(publicationRequests[original.Generation - 1]);
            var priorContact = DeepIdV2ResolverClosureCodec.Decode(prior.ExactDcr1.Span);
            var anchor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(authorization, network, authority,
                priorContact.Bundle.Field(14)[40..], prior.ExactRouteClosure, time, ct);
            var previousAdvertisement = ContactRouteClosureCodec.Decode(prior.ExactRouteClosure.Span).Authorization;
            var candidate = ContactRouteClosureCodec.Decode(original.ExactRouteClosure.Span).Authorization;
            var nextHash = candidate.Field(4).ToArray(); var pairs = new List<DeepIdV2ContactRouteRecordedPair>();
            while (!nextHash.AsSpan().SequenceEqual(previousAdvertisement.CoreHash.Span))
            {
                if (pairs.Count == 3) throw new CryptographicException("Fixture issuer history exceeds its bound.");
                var exact = routeRequests.Values.SingleOrDefault(value =>
                    ContactCodec.Decode("XRA1", ContactRouteAuthorityWireCodec.DecodeRequest(value).ExactXra1.Span).CoreHash.Span.SequenceEqual(nextHash)) ??
                    throw new CryptographicException("Fixture issuer historical row is absent.");
                var request = ContactRouteAuthorityWireCodec.DecodeRequest(exact);
                var advertisement = ContactCodec.Decode("XRA1", request.ExactXra1.Span);
                var number = BinaryPrimitives.ReadUInt64BigEndian(advertisement.Field(3).Span);
                if (!routeWinners.TryGetValue(number, out var response)) throw new CryptographicException("Fixture issuer positive winner is absent.");
                pairs.Add(new(exact, ContactRouteAuthorityWireCodec.EncodeResponse(request, response))); nextHash = advertisement.Field(4).ToArray();
            }
            if (pairs.Count == 0) return null;
            pairs.Reverse();
            return await DeepIdV2ContactRouteVerifier.VerifyRecordedHistoryAsync(authorization, network, authority, anchor, pairs, time, ct);
        }
    }
}



