using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2OwnedCoordination_HeldSqlGuardsAndEntropyBuildWithoutRecursiveLease()
    {
        await using var fixture = await Fixture.CreateAsync();
        using var remote = new OwnedRouteThreshold(fixture) { ProbeHeldCustody = true };
        using (Did2ContactRouteTestHooks.Push(point =>
            { if (point == Did2ContactRouteFailpoint.AfterThreshold) throw new IOException("End the isolated owned coordination attempt."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.EnsureRoute(Bytes(32, 0xc4),
                new(100, 2, Bytes(32, 0xd1)), remote, reopen: true));
        Assert.True(remote.BuiltHeldFrame);
        Assert.NotNull(remote.BorrowedCustody); Assert.NotNull(remote.ReservedBatch);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => remote.BorrowedCustody.Guards.ReadAsync(default).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => remote.BorrowedCustody.Entropy.CommitAsync(remote.ReservedBatch, default).AsTask());
    }

    [Fact]
    public void Did2OwnedRoute_ByteBudgetMatchesProtectedStoreAndRejectsOversizeBeforeEntries()
    {
        Assert.Equal(461_123, ProtectedDid2ContactRouteJournal.MaximumEntryBytes);
        Assert.Equal(DeepSecureStorageRegistration.MaximumValueBytes, ProtectedDid2ContactRouteJournal.MaximumBytes);
        var reservation = 4 + ProtectedDid2ContactRouteJournal.MaximumEntryBytes;
        Assert.True(ProtectedDid2ContactRouteJournal.HeaderBytes + 2 * reservation <= ProtectedDid2ContactRouteJournal.MaximumBytes);
        Assert.True(ProtectedDid2ContactRouteJournal.HeaderBytes + 3 * reservation > ProtectedDid2ContactRouteJournal.MaximumBytes);
        var network = Bytes(16, 0x11); var account = Bytes(32, 0x12); var instance = Bytes(32, 0x13);
        var oversize = new byte[ProtectedDid2ContactRouteJournal.MaximumBytes + 1];
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactRouteJournal.Decode(oversize, network, account, instance));
    }

    [Fact]
    public async Task Did2OwnedRoute_CommittedPhasesResumeExactAndBadThresholdCannotPoisonCustody()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckOwnedRouteAsync();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    public void Did2OwnedRoute_EmptyJournalRejectsHostileHeaderBeforeEntries(int mode)
    {
        var network = Bytes(16, 0x11); var account = Bytes(32, 0x12); var instance = Bytes(32, 0x13);
        var bytes = ProtectedDid2ContactRouteJournal.Empty(network, account, instance);
        if (mode == 0) bytes[0] = 1;
        if (mode == 1) bytes[1] = 1;
        if (mode == 2) BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), 129);
        if (mode == 3) bytes[11] = 2;
        if (mode == 4) bytes[60] ^= 1;
        if (mode == 5) bytes = bytes.Append((byte)0).ToArray();
        if (mode == 6) bytes[0] = 3;
        if (mode == 7) bytes[0] = 4;
        if (mode == 8) bytes[0] = 5;
        if (mode == 9) bytes[0] = 6;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactRouteJournal.Decode(bytes, network, account, instance));
    }

    private sealed partial class Fixture
    {
        internal async Task CheckOwnedRouteAsync()
        {
            var intent = Bytes(32, 0xc4); var configuration = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd1));
            using var remote = new OwnedRouteThreshold(this);
            foreach (var (point, phase) in new[] { (Did2ContactRouteFailpoint.AfterProposal, 1),
                (Did2ContactRouteFailpoint.AfterThreshold, 2), (Did2ContactRouteFailpoint.AfterComplete, 3) })
            {
                var hit = false;
                using (Did2ContactRouteTestHooks.Push(actual =>
                { if (actual == point) { hit = true; throw new IOException("Injected committed route response loss."); } }))
                    await Assert.ThrowsAsync<IOException>(() => EnsureRoute(intent, configuration, remote, reopen: true));
                Assert.True(hit);
                var snapshot = await RouteSnapshot();
                try
                {
                    Assert.Equal((byte)phase, snapshot[ProtectedDid2ContactRouteJournal.HeaderBytes + 4 + 32]);
                    Assert.Equal((ulong)phase + 1, BinaryPrimitives.ReadUInt64BigEndian(snapshot.AsSpan(4)));
                    Assert.Equal(phase == 1 ? 0 : 1, remote.Calls);
                }
                finally { CryptographicOperations.ZeroMemory(snapshot); }
            }
            var completed = await EnsureRoute(intent, configuration, remote, reopen: true);
            var before = await RouteSnapshot();
            try
            {
                var repeated = await EnsureRoute(intent, configuration, remote, reopen: true);
                Assert.True(CryptographicOperations.FixedTimeEquals(completed.ExactXir1V2.Span, repeated.ExactXir1V2.Span));
                Assert.True(CryptographicOperations.FixedTimeEquals(completed.ExactRouteClosure.Span, repeated.ExactRouteClosure.Span));
                var after = await RouteSnapshot();
                try { Assert.True(CryptographicOperations.FixedTimeEquals(before, after)); }
                finally { CryptographicOperations.ZeroMemory(after); }
                Assert.Equal(1, remote.Calls); // Never reissue a durably adopted threshold.
                await Assert.ThrowsAsync<CryptographicException>(() => EnsureRoute(intent,
                    new(101, 2, Bytes(32, 0xd1)), remote));
                Assert.Equal(1, remote.Calls);
            }
            finally { CryptographicOperations.ZeroMemory(before); }

            await CheckOwnedContactObjectAsync(intent, configuration, remote);

            // A bad signed-response envelope must leave phase1 reusable,
            // not persist a poisoned phase2 and strand the metadata key.
            var secondIntent = Bytes(32, 0xc5); using var faulty = new OwnedRouteThreshold(this) { CorruptResponse = true };
            await RequireRouteRejectionAsync(async () => await EnsureRoute(secondIntent, configuration, faulty));
            Assert.Equal(1, faulty.Calls);
            using (var state = await RouteState())
                Assert.Equal((byte)1, state.Entries[Convert.ToHexString(secondIntent)].Phase);
            faulty.CorruptResponse = false;
            var recovered = await EnsureRoute(secondIntent, configuration, faulty, reopen: true);
            await recovered.EnsureCurrentAsync();
            Assert.Equal(2, faulty.Calls);
            Assert.True(faulty.StableProposal); Assert.True(faulty.StableNonce);

            // Key/canonical-record damage fails closed; never regenerate.
            var good = await RouteSnapshot(); var damaged = good.ToArray();
            // X25519 clamps the lowest three scalar bits. Alter an effective
            // bit, not an ignored encoding bit that derives the same key.
            damaged[ProtectedDid2ContactRouteJournal.HeaderBytes + 4 + 74] ^= 8;
            try
            {
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, good, damaged));
                await RequireRouteRejectionAsync(async () => await EnsureRoute(intent, configuration, remote, reopen: true));
                Assert.Equal(1, remote.Calls);
            }
            finally
            {
                // Fixture fault cleanup only; there is no runtime repair API.
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, damaged, good));
                CryptographicOperations.ZeroMemory(good); CryptographicOperations.ZeroMemory(damaged);
            }
            await innerStorage.DeleteBatchAsync([ProtectedDid2ContactRouteJournal.Slot]);
            await Assert.ThrowsAsync<InvalidDataException>(() => EnsureRoute(intent, configuration, remote, reopen: true));
            Assert.Equal(1, remote.Calls);
            using var missing = await innerStorage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot);
            Assert.Null(missing);
        }
        internal Task<VerifiedDeepIdV2ContactRouteClosure> EnsureRoute(byte[] intent, Did2ContactRouteConfiguration config,
            OwnedRouteThreshold threshold, bool reopen = false)
        {
            var account = reopen ? ReopenAccount() : accounts;
            return account.EnsureOwnContactRouteAsync(intent, Source(account), config, threshold);
        }
        private async Task<byte[]> RouteSnapshot()
        {
            using var value = await innerStorage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot);
            return value!.Use(bytes => bytes.ToArray());
        }
        private async Task<ProtectedDid2ContactRouteJournal.State> RouteState()
        {
            var bytes = await RouteSnapshot();
            using var record = await innerStorage.ReadOwnedAsync("deep.store.v2.sql-generation");
            var instance = record!.Use(value => value.Slice(56, 32).ToArray());
            try { return ProtectedDid2ContactRouteJournal.Decode(bytes, Network, checkpoint.Binding.Record.DeepAccountId.Span, instance); }
            finally { CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(instance); }
        }
    }

    // Actual witness signatures, only in-process coordination. No socket or
    // live Registry/nonce-ledger/platform-protection/device claim is made.
    private sealed class OwnedRouteThreshold(Fixture fixture) : IDid2ContactRouteThresholdSource, IDisposable
    {
        internal bool ProbeHeldCustody { get; set; }
        internal bool BuiltHeldFrame { get; private set; }
        internal DeepIdV2OnionClientCustody? BorrowedCustody { get; private set; }
        internal OnionEntropyCommitmentBatch? ReservedBatch { get; private set; }
        internal int Calls { get; private set; }
        internal bool CorruptResponse { get; set; }
        internal bool StableProposal { get; private set; } = true;
        internal bool StableNonce { get; private set; } = true;
        internal bool StableRequest { get; private set; } = true;
        internal bool LoseNextResponse { get; set; }
        internal List<byte[]> Requests { get; } = [];
        internal List<ulong> CurrentHeadGenerations { get; } = [];
        private byte[]? proposal, nonce, pendingRequest;
        private ContactRouteAuthorityWireResponse? winner;
        internal ReadOnlyMemory<byte> WinnerHead => winner?.ExactIssuanceAdh1 ?? ReadOnlyMemory<byte>.Empty;
        internal bool CorruptIssuanceHead { get; set; }
        internal bool WrongResponseNonce { get; set; }
        public async ValueTask<ContactRouteAuthorityWireResponse> FetchAsync(ContactRouteAuthorityWireRequest exactPendingRequest,
            DeepIdV2CurrentContactAuthorization authorization, VerifiedOnionNetworkContext network,
            VerifiedXPointNetworkAuthority authority,
            OnionTrustedTimeAuthority trustedTime, Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            Calls++;
            var exactXra1 = exactPendingRequest.ExactXra1;
            var durableNonce32 = exactPendingRequest.RequestNonce;
            var encodedRequest = ContactRouteAuthorityWireCodec.EncodeRequest(exactPendingRequest);
            Requests.Add(encodedRequest);
            CurrentHeadGenerations.Add(authorization.Freshness.NextProtectedLkg.LogGeneration);
            StableRequest &= pendingRequest is null || CryptographicOperations.FixedTimeEquals(pendingRequest, encodedRequest);
            pendingRequest ??= encodedRequest.ToArray();
            if (!StableRequest) throw new CryptographicException("Fixture permanent journal rejects changed request under nonce.");
            if (ProbeHeldCustody)
            {
                operation.RequireActive();
                var exact = ContactCoordinationOnionCodec.EncodeRequest(ContactCoordinationTarget.Route,
                    encodedRequest);
                var request = Deep.Client.Shared.Services.XPointNetworkV1.ContactResolveCanonicalPathRequest.Decode(exact);
                var placement = ContactServicePlacementFactory.Create(operation.Network, request.RequestKind, request.ShardKey);
                var paths = new Deep.Client.Shared.Services.XPointNetworkV1.ContactResolvePrivacyPathProvider(
                    fixture.Source(operation.Custody.Owner), operation.Custody.Guards);
                var prepared = await paths.PrepareWithAuthorityAsync(OnionOperation.ContactResolve, request,
                    ReadOnlyMemory<byte>.Empty, new(operation.Network, placement), ct);
                var ledger = new CapturingEntropyLedger(operation.Custody.Entropy);
                var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(ledger),
                    new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
                using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request, ct);
                Assert.True(built.Frame.Length > exact.Length);
                Assert.Equal(OnionEntropyCommitOutcome.Duplicate,
                    await operation.Custody.Entropy.CommitAsync(ledger.LastBatch!, ct));
                BorrowedCustody = operation.Custody; ReservedBatch = ledger.LastBatch; BuiltHeldFrame = true;
                operation.RequireActive();
            }
            StableProposal &= proposal is null || CryptographicOperations.FixedTimeEquals(proposal, exactXra1.Span);
            StableNonce &= nonce is null || CryptographicOperations.FixedTimeEquals(nonce, durableNonce32.Span);
            proposal ??= exactXra1.ToArray(); nonce ??= durableNonce32.ToArray();
            var xra = ContactCodec.Decode("XRA1", exactXra1.Span);
            if (winner is null)
            {
                var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(authorization, network, authority, exactXra1,
                    fixture.CreateRouteWitnesses(), authorization.TrustedLowerUnixSeconds,
                    BinaryPrimitives.ReadUInt64BigEndian(xra.Field(13).Span), trustedTime, ct);
                winner = new(exactPendingRequest.NetworkId.Span, durableNonce32.Span, threshold.Selection.CanonicalBytes.Span,
                    threshold.LiveRoute.CanonicalBytes.Span, threshold.Successor.CanonicalBytes.Span,
                    authorization.Freshness.ExactAdh1.Span);
            }
            if (LoseNextResponse)
            { LoseNextResponse = false; throw new IOException("Injected threshold response loss after retaining exact signed winner."); }
            if (!CorruptResponse && !CorruptIssuanceHead && !WrongResponseNonce) return winner;
            var broken = winner.ExactXrc1.ToArray(); if (CorruptResponse) broken[^1] ^= 1;
            var head = winner.ExactIssuanceAdh1.ToArray(); if (CorruptIssuanceHead) head[^1] ^= 1;
            var returnedNonce = winner.RequestNonce.ToArray(); if (WrongResponseNonce) returnedNonce[0] ^= 1;
            return new(winner.NetworkId.Span, returnedNonce, winner.ExactPms2.Span, broken, winner.ExactXss1.Span, head);
        }
        public void Dispose()
        {
            if (proposal is not null) CryptographicOperations.ZeroMemory(proposal);
            if (nonce is not null) CryptographicOperations.ZeroMemory(nonce);
            if (pendingRequest is not null) CryptographicOperations.ZeroMemory(pendingRequest);
            foreach (var request in Requests) CryptographicOperations.ZeroMemory(request);
        }
    }
    private sealed partial class Fixture
    {
        internal IReadOnlyList<IContactRouteAuthorityWitnessSigner> CreateRouteWitnesses() =>
            witnesses.Select(w => (IContactRouteAuthorityWitnessSigner)new RouteWitness(w)).ToArray();
    }
}
