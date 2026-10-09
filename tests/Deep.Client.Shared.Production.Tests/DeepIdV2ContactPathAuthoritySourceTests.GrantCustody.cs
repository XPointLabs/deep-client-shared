using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2GrantCustody_TwoAccountsPersistBeforeCallbackLoseResponseAndReopenExactWinner()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckGrantCustodyAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2GrantCustody_ExpiredUnknownClosesUnderActualLeaseWithoutReissueAndSurvivesBothFaults(bool failAfterClosure)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckExpiredGrantAcquisitionAsync(failAfterClosure);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2GrantCustody_LateResultAuthenticatesBothDirectionsAndColdResumesEveryAdoptionFault(bool retrieve)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckLateGrantResultAsync(retrieve);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2GrantCustody_ExactReplyMayCrossOriginalWindowButNotCurrentAuthority(bool retrieve)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckGrantReplyCrossesOriginalWindowAsync(retrieve);
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
    public void Did2GrantCustody_HeaderRejectsBeforeReadingEntries(int fault)
    {
        var network = Bytes(16, 0x11); var account = Bytes(32, 0x12); var instance = Bytes(32, 0x13);
        var exact = ProtectedDid2MailboxGrantJournal.Empty(network, account, instance);
        if (fault == 0) exact[0] = 1; // Retired custody rejects even when empty.
        if (fault == 1) exact[1] = 1;
        if (fault == 2) BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), 129);
        if (fault == 3) exact[11] = 0;
        if (fault == 4) exact[60] ^= 1;
        if (fault == 5) exact = exact.Append((byte)0).ToArray();
        if (fault == 6) exact[0] = 2;
        if (fault == 7) exact[94] = 1;
        if (fault == 8) exact[0] = 3;
        if (fault == 9) exact[0] = 4;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxGrantJournal.Decode(exact, network, account, instance));
    }

    private sealed partial class Fixture
    {
        internal async Task CheckLateGrantResultAsync(bool retrieve)
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold,
                new OwnedPublicationSource(this, route), replicas);
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            var reader = retrieve ? accounts : peerAccounts!;
            DeepIdV2ContactPathAuthoritySource ReaderSource() => retrieve ? Source(reader) : GrantReaderSource(reader);
            VerifiedDeepIdV2PermanentContactResolveClosure? contact = null;
            async Task RefreshContact()
            {
                if (!retrieve) contact = await reader.ResolvePermanentContactAsync(address, ReaderSource(),
                    new SyntheticPermanentRead(this, ReaderSource(), replicas.ExactPublication));
            }
            await RefreshContact();
            var transport = new OwnedGrantTransport(this, selfRetrieve: retrieve) { LoseResponse = true, Route = route };
            await Assert.ThrowsAsync<IOException>(() => retrieve ?
                reader.AcquireOwnPermanentContactRetrieveGrantAsync(ReaderSource(), transport) :
                reader.AcquirePermanentContactDepositGrantAsync(contact!, ReaderSource(), transport));
            byte[] original;
            using (var state = await ReadPeerGrantsAsync(own: retrieve)) original = Assert.Single(state.Entries).Value.ToArray();
            // Controlled signed successor for codec graph assertions only; no
            // production renewal or second protected acquisition is dispatched.
            var successor = await PrepareLateGraphSuccessorAsync(original, transport.Route!, retrieve);
            var requestExpiry = ProtectedDid2MailboxGrantJournal.RequestExpiry(original);
            var before = await transport.Route!.ReadCurrentTimeAsync();
            var nextTime = checked(requestExpiry + ProofTime - before.LowerUnixSeconds);
            Sample = checked(Sample + nextTime - ProofTime); ProofTime = nextTime;
            reader = retrieve ? ReopenAccount() : ReopenGrantReader();
            Assert.Equal(1, await reader.CloseExpiredMailboxAcquisitionsAsync(ReaderSource()));
            byte[] closedOriginal;
            using (var state = await ReadPeerGrantsAsync(own: retrieve)) closedOriginal = Assert.Single(state.Entries).Value.ToArray();
            await RefreshContact();
            async Task<(ReadOnlyMemory<byte> ExactXmc2, ReadOnlyMemory<byte> ExactGrant)> Accept(ReadOnlyMemory<byte> packet)
            {
                if (retrieve)
                {
                    var result = await reader.AcceptOwnPermanentContactRetrieveGrantResultAsync(ReaderSource(), packet);
                    return (result.ExactXmc2, result.ExactGrant);
                }
                var deposit = await reader.AcceptPermanentContactDepositGrantResultAsync(contact!, ReaderSource(), packet);
                return (deposit.ExactXmc2, deposit.ExactGrant);
            }
            async Task<(ReadOnlyMemory<byte> ExactXmc2, ReadOnlyMemory<byte> ExactGrant)> Resume()
            {
                if (retrieve)
                {
                    var result = await reader.ResumeOwnPermanentContactRetrieveGrantResultAsync(ReaderSource());
                    return (result.ExactXmc2, result.ExactGrant);
                }
                var deposit = await reader.ResumePermanentContactDepositGrantResultAsync(contact!, ReaderSource());
                return (deposit.ExactXmc2, deposit.ExactGrant);
            }
            var exact = transport.OriginalResponse.ToArray();
            var corrupted = exact.ToArray(); corrupted[^1] ^= 1;
            await RequireRouteRejectionAsync(async () => await Accept(corrupted));
            await Assert.ThrowsAsync<InvalidDataException>(() => Accept(exact.AsMemory(1)));
            using (var unchanged = await ReadPeerGrantsAsync(own: retrieve))
                Assert.True(ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(Assert.Single(unchanged.Entries).Value));
            var failpoints = new[] { Did2MailboxInstallationFailpoint.BeforeLateResult,
                Did2MailboxInstallationFailpoint.AfterLateResult, Did2MailboxInstallationFailpoint.BeforeLateAdoption,
                Did2MailboxInstallationFailpoint.AfterLateAdoption, Did2MailboxInstallationFailpoint.BeforeSql,
                Did2MailboxInstallationFailpoint.AfterSql };
            foreach (var point in failpoints)
            {
                reader = retrieve ? ReopenAccount() : ReopenGrantReader();
                using (Did2MailboxInstallationTestHooks.Push(actual =>
                    { if (actual == point) throw new IOException("Injected late grant handover interruption."); }))
                    await Assert.ThrowsAsync<IOException>(() => point is Did2MailboxInstallationFailpoint.BeforeLateResult or
                        Did2MailboxInstallationFailpoint.AfterLateResult ? Accept(exact) : Resume());
                using var state = await ReadPeerGrantsAsync(own: retrieve);
                var entry = Assert.Single(state.Entries).Value;
                Assert.Equal(ProtectedDid2MailboxGrantJournal.Request(original).ToArray(), ProtectedDid2MailboxGrantJournal.Request(entry).ToArray());
                Assert.Equal(ProtectedDid2MailboxGrantJournal.Seed(original).ToArray(), ProtectedDid2MailboxGrantJournal.Seed(entry).ToArray());
                Assert.Equal(requestExpiry, ProtectedDid2MailboxGrantJournal.ClosedLower(entry));
                var selected = Assert.Single(state.Selections).Value;
                if (point == Did2MailboxInstallationFailpoint.BeforeLateResult)
                { Assert.True(ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(entry)); Assert.Null(selected.Current); }
                else if (point is Did2MailboxInstallationFailpoint.AfterLateResult or Did2MailboxInstallationFailpoint.BeforeLateAdoption)
                {
                    Assert.True(ProtectedDid2MailboxGrantJournal.IsLateCandidate(entry)); Assert.Null(selected.Current);
                    Assert.Equal(exact, ProtectedDid2MailboxGrantJournal.Response(entry).ToArray());
                    Assert.Throws<CryptographicException>(() => ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(state,
                        Assert.Single(state.Selections).Key, SHA256.HashData(ContactCodec.Decode("XMC2", exact).Field(8).Span)));
                }
                else { Assert.True(ProtectedDid2MailboxGrantJournal.IsLateAdopted(entry)); Assert.NotNull(selected.Current); }
                Assert.Equal(1, transport.Calls);
            }
            reader = retrieve ? ReopenAccount() : ReopenGrantReader();
            var verified = await Resume();
            Assert.Equal(exact, verified.ExactXmc2.ToArray());
            await AssertInstalledGrantSqlAsync(verified.ExactGrant, own: retrieve);
            CheckLateSelectionGraph(closedOriginal, successor, verified);
            var ordinaryGrant = retrieve ? (await reader.AcquireOwnPermanentContactRetrieveGrantAsync(ReaderSource(), transport)).ExactGrant :
                (await reader.AcquirePermanentContactDepositGrantAsync(contact!, ReaderSource(), transport)).ExactGrant;
            Assert.Equal(verified.ExactGrant.ToArray(), ordinaryGrant.ToArray());
            Assert.Equal(1, transport.Calls);
            using (var state = await ReadPeerGrantsAsync(own: retrieve))
            {
                Assert.Equal(5UL, state.Revision);
                var winner = Assert.Single(state.Entries).Value;
                Assert.True(ProtectedDid2MailboxGrantJournal.IsLateAdopted(winner));
                Assert.Equal(ProtectedDid2MailboxGrantJournal.OriginalPolicy(original).ToArray(), ProtectedDid2MailboxGrantJournal.OriginalPolicy(winner).ToArray());
                Assert.Equal(ProtectedDid2MailboxGrantJournal.OriginalRoute(original).ToArray(), ProtectedDid2MailboxGrantJournal.OriginalRoute(winner).ToArray());
            }
            // A real reply does not bypass expiry after a successful adoption.
            // Independently current source verification may also reject an old
            // route; either way custody and its exact result cannot be replaced.
            var grantExpiry = MailboxAuthenticatedCapabilityCodec.DecodeGrant(verified.ExactGrant.Span).ExpiresAtUnixSeconds;
            var elapsed = checked(grantExpiry - before.LowerUnixSeconds);
            Sample = checked(100 + elapsed); ProofTime = checked(1_100 + elapsed);
            reader = retrieve ? ReopenAccount() : ReopenGrantReader();
            await RequireRouteRejectionAsync(async () => await Accept(exact));
            using (var unchanged = await ReadPeerGrantsAsync(own: retrieve))
                Assert.Equal(exact, ProtectedDid2MailboxGrantJournal.Response(Assert.Single(unchanged.Entries).Value).ToArray());
            foreach (var bytes in new[] { original, closedOriginal, successor, exact, corrupted }) CryptographicOperations.ZeroMemory(bytes);
        }

        private async Task<byte[]> PrepareLateGraphSuccessorAsync(byte[] original,
            VerifiedDeepIdV2ContactRouteClosure route, bool retrieve)
        {
            if (retrieve)
            {
                var parsed = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(original).Span);
                var seedRead = Bytes(32, 0x9b);
                try
                {
                    var (host, requestRead, pendingRead) = await PrepareRetainedGraphRequestAsync(original, parsed, route.Network, seedRead);
                    try
                    {
                        var exactRead = await IssueRetainedFixtureGrantAsync(requestRead, parsed, host, route.Network, default);
                        var verifiedRead = await host.VerifyRetainedReadSuccessAsync(parsed.ExactBytes, requestRead.ExactXmg2, exactRead);
                        return ProtectedDid2MailboxGrantJournal.WithWinner(pendingRead, verifiedRead.ExactXmc2.Span, Network);
                    }
                    finally { CryptographicOperations.ZeroMemory(pendingRead); }
                }
                finally { CryptographicOperations.ZeroMemory(seedRead); }
            }
            var record = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(original).Span);
            var seed = Bytes(32, 0x9b);
            using var signer = ReachabilityMailboxHolderAuthority.OpenRetained(route, record.Field(3), record.Field(4),
                retrieve ? MailboxCapabilityDomain.Retrieve : MailboxCapabilityDomain.Deposit, seed);
            var request = retrieve ? await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(route, record.Field(3), record.Field(4), signer) :
                await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, record.Field(3), signer);
            var policy = await CurrentGrantPolicyAsync(route);
            var pending = ProtectedDid2MailboxGrantJournal.Pending(seed, route, request, policy, Network);
            var exact = await IssueOwnedGrantAsync(request, route, retrieve, default);
            var verified = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(route, request, exact, operational.ExactPma2);
            try { return ProtectedDid2MailboxGrantJournal.WithWinner(pending, verified.ExactXmc2.Span, Network); }
            finally { foreach (var bytes in new[] { seed, pending, exact }) CryptographicOperations.ZeroMemory(bytes); }
        }

        private void CheckLateSelectionGraph(byte[] closed, byte[] successor,
            (ReadOnlyMemory<byte> ExactXmc2, ReadOnlyMemory<byte> ExactGrant) verified)
        {
            var account = Bytes(32, 0x11); var instance = Bytes(32, 0x12);
            var old = ProtectedDid2MailboxGrantJournal.Acquisition(closed);
            var scope = Convert.ToHexString(closed.AsSpan(0, 32));
            using var state = new ProtectedDid2MailboxGrantJournal.State { Revision = 3 };
            state.Entries.Add(old, closed.ToArray()); state.Selections.Add(scope, new(null, null, old));
            byte[] Encode() => ProtectedDid2MailboxGrantJournal.Encode(state, Network, account, instance);
            // A newer winner is adopted first; a later result for its predecessor
            // must be retained without rolling this selection back.
            var pending = successor.ToArray(); pending[96] = 1; pending.AsSpan(535, 510).Clear();
            ProtectedDid2MailboxGrantJournal.AddPending(state, pending); state.Revision++;
            var newer = ProtectedDid2MailboxGrantJournal.Acquisition(pending);
            var ready = ProtectedDid2MailboxGrantJournal.WithWinner(pending, ProtectedDid2MailboxGrantJournal.Response(successor).Span, Network);
            state.Entries[newer] = ready; CryptographicOperations.ZeroMemory(pending); state.Revision++;
            ProtectedDid2MailboxGrantJournal.PromoteWinner(state, scope); state.Revision++;
            var late = ProtectedDid2MailboxGrantJournal.WithLateWinner(state.Entries[old], verified.ExactXmc2.Span, Network);
            CryptographicOperations.ZeroMemory(state.Entries[old]); state.Entries[old] = late; state.Revision++;
            var received = Encode();
            using (var cold = ProtectedDid2MailboxGrantJournal.Decode(received, Network, account, instance))
            {
                Assert.Equal(newer, cold.Selections[scope].Current);
                Assert.True(ProtectedDid2MailboxGrantJournal.IsLateCandidate(cold.Entries[old]));
                Assert.Equal(old, ProtectedDid2MailboxGrantJournal.Acquisition(ProtectedDid2MailboxGrantJournal.RequireLateResultForResume(cold, scope)));
                Assert.Throws<CryptographicException>(() => ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(cold, scope,
                    SHA256.HashData(verified.ExactGrant.Span)));
                Assert.Throws<IOException>(() => ProtectedDid2MailboxGrantJournal.RequireOldestAdoptedDeposit(cold, Convert.FromHexString(old)));
            }
            ProtectedDid2MailboxGrantJournal.AdoptLateWinner(state, old); state.Revision++;
            Assert.Equal(newer, state.Selections[scope].Current); Assert.Null(state.Selections[scope].Pending);
            Assert.Equal(old, ProtectedDid2MailboxGrantJournal.Acquisition(ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(state, scope,
                SHA256.HashData(verified.ExactGrant.Span))));
            var adopted = Encode();
            using (var cold = ProtectedDid2MailboxGrantJournal.Decode(adopted, Network, account, instance))
            {
                Assert.Equal(newer, cold.Selections[scope].Current);
                if (ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(cold.Entries[old]).Span).Field(6).Span[0] == (byte)MailboxCapabilityDomain.Deposit)
                {
                    Assert.Throws<IOException>(() => ProtectedDid2MailboxGrantJournal.RequireOldestAdoptedDeposit(cold, Convert.FromHexString(newer)));
                    var nextRequest = ProtectedDid2MailboxGrantJournal.Request(cold.Entries[newer]).ToArray();
                    var retired = ProtectedDid2MailboxGrantJournal.RemoveOldestAdoptedDeposit(cold, Convert.FromHexString(old), Network, account, instance);
                    using var remaining = ProtectedDid2MailboxGrantJournal.Decode(retired, Network, account, instance);
                    Assert.Equal(newer, remaining.Selections[scope].Current); Assert.Equal(newer, remaining.Selections[scope].RetainedTail);
                    Assert.Equal(nextRequest, ProtectedDid2MailboxGrantJournal.Request(Assert.Single(remaining.Entries).Value).ToArray());
                    var empty = ProtectedDid2MailboxGrantJournal.RemoveOldestAdoptedDeposit(remaining, Convert.FromHexString(newer), Network, account, instance);
                    using var final = ProtectedDid2MailboxGrantJournal.Decode(empty, Network, account, instance);
                    Assert.Empty(final.Entries); Assert.Empty(final.Selections);
                    foreach (var bytes in new[] { retired, empty, nextRequest }) CryptographicOperations.ZeroMemory(bytes);
                }
                else Assert.Throws<IOException>(() => ProtectedDid2MailboxGrantJournal.RequireOldestAdoptedDeposit(cold, Convert.FromHexString(old)));
            }
            state.Selections[scope] = state.Selections[scope] with { Current = old };
            Assert.Throws<InvalidDataException>(() => Encode()); state.Selections[scope] = state.Selections[scope] with { Current = newer };

            // Independent graph: a newer pending request survives late adoption.
            using var staged = new ProtectedDid2MailboxGrantJournal.State { Revision = 4 };
            staged.Entries.Add(old, ProtectedDid2MailboxGrantJournal.WithLateWinner(closed, verified.ExactXmc2.Span, Network));
            staged.Selections.Add(scope, new(null, null, old));
            var candidate = successor.ToArray(); candidate[96] = 1; candidate.AsSpan(535, 510).Clear();
            ProtectedDid2MailboxGrantJournal.AddPending(staged, candidate); staged.Revision++;
            ProtectedDid2MailboxGrantJournal.AdoptLateWinner(staged, old); staged.Revision++;
            Assert.Equal(old, staged.Selections[scope].Current); Assert.Equal(newer, staged.Selections[scope].Pending);
            var pendingGraph = ProtectedDid2MailboxGrantJournal.Encode(staged, Network, account, instance);
            using var resumed = ProtectedDid2MailboxGrantJournal.Decode(pendingGraph, Network, account, instance);
            Assert.Equal(newer, resumed.Selections[scope].Pending);
            foreach (var bytes in new[] { received, adopted, pendingGraph }) CryptographicOperations.ZeroMemory(bytes);
        }

        internal async Task CheckGrantReplyCrossesOriginalWindowAsync(bool retrieve)
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold,
                new OwnedPublicationSource(this, route), replicas);
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            var reader = retrieve ? accounts : peerAccounts!;
            DeepIdV2ContactPathAuthoritySource ReaderSource() => retrieve ? Source(reader) : GrantReaderSource(reader);
            VerifiedDeepIdV2PermanentContactResolveClosure? contact = null;
            async Task Resolve()
            {
                if (!retrieve) contact = await reader.ResolvePermanentContactAsync(address, ReaderSource(),
                    new SyntheticPermanentRead(this, ReaderSource(), replicas.ExactPublication));
            }
            await Resolve();
            var transport = new OwnedGrantTransport(this, selfRetrieve: retrieve) { LoseResponse = true, Route = route };
            async Task<(ReadOnlyMemory<byte> ExactXmg2, ReadOnlyMemory<byte> ExactXmc2, ReadOnlyMemory<byte> ExactGrant)> Acquire()
            {
                if (retrieve)
                {
                    var result = await reader.AcquireOwnPermanentContactRetrieveGrantAsync(ReaderSource(), transport);
                    return (result.ExactXmg2, result.ExactXmc2, result.ExactGrant);
                }
                var deposit = await reader.AcquirePermanentContactDepositGrantAsync(contact!, ReaderSource(), transport);
                return (deposit.ExactXmg2, deposit.ExactXmc2, deposit.ExactGrant);
            }
            await Assert.ThrowsAsync<IOException>(() => Acquire());
            ulong expiry;
            using (var state = await ReadPeerGrantsAsync(own: retrieve)) expiry = ProtectedDid2MailboxGrantJournal.RequestExpiry(Assert.Single(state.Entries).Value);
            var time = await transport.Route!.ReadCurrentTimeAsync();
            var nextTime = checked(expiry - (time.UpperUnixSeconds - ProofTime) - 10);
            Sample = checked(Sample + nextTime - ProofTime); ProofTime = nextTime;
            reader = retrieve ? ReopenAccount() : ReopenGrantReader(); await Resolve();
            transport.LoseResponse = false;
            transport.BeforeReturn = () => { Sample += 20; ProofTime += 20; return Task.CompletedTask; };
            var actual = await Acquire();
            Assert.Equal(transport.OriginalRequest.ToArray(), actual.ExactXmg2.ToArray());
            Assert.Equal(transport.OriginalResponse.ToArray(), actual.ExactXmc2.ToArray());
            Assert.True(transport.ExactRetry); Assert.Equal(2, transport.Calls);
            Assert.True((await transport.Route!.ReadCurrentTimeAsync()).LowerUnixSeconds >= expiry);
            await AssertInstalledGrantSqlAsync(actual.ExactGrant, own: retrieve);
        }

        internal async Task CheckExpiredGrantAcquisitionAsync(bool failAfterClosure)
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold,
                new OwnedPublicationSource(this, route), new OwnedPublicationReplica(this, route));
            var transport = new OwnedGrantTransport(this, selfRetrieve: true) { LoseResponse = true, Route = route };
            await Assert.ThrowsAsync<IOException>(() => accounts.AcquireOwnPermanentContactRetrieveGrantAsync(Source(), transport));
            byte[] original;
            ulong expiry, ceiling;
            using (var pending = await ReadPeerGrantsAsync(own: true))
            {
                original = Assert.Single(pending.Entries).Value.ToArray();
                expiry = ProtectedDid2MailboxGrantJournal.RequestExpiry(original);
                ceiling = ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(original);
                Assert.True(ceiling > expiry);
                Assert.Equal(operational.ExactPma2.ToArray(), ProtectedDid2MailboxGrantJournal.OriginalPolicy(original).ToArray());
                Assert.Equal(transport.Route!.ExactRouteClosure.ToArray(), ProtectedDid2MailboxGrantJournal.OriginalRoute(original).ToArray());
            }
            var originalTime = await transport.Route!.ReadCurrentTimeAsync();
            var lowerUncertainty = checked(ProofTime - originalTime.LowerUnixSeconds);
            var successorTemplate = await PrepareClosedGrantCandidateAsync(original, transport.Route!);
            var reopened = ReopenAccount();
            Assert.Equal(0, await reopened.CloseExpiredMailboxAcquisitionsAsync(Source(reopened)));
            // A time interval straddling request expiry forbids dispatch, but its
            // lower bound does not yet prove the owned closure transition.
            var straddlingTime = checked(expiry + lowerUncertainty - 1);
            Sample = checked(Sample + straddlingTime - ProofTime); ProofTime = straddlingTime;
            reopened = ReopenAccount();
            Assert.Equal(0, await reopened.CloseExpiredMailboxAcquisitionsAsync(Source(reopened)));
            using (var unchanged = await ReadPeerGrantsAsync(own: true)) Assert.Equal(original, Assert.Single(unchanged.Entries).Value);
            Sample++; ProofTime++;
            reopened = ReopenAccount();
            using (Did2MailboxInstallationTestHooks.Push(point =>
                { if (point == Did2MailboxInstallationFailpoint.BeforeClosure) throw new IOException("Injected before unknown closure."); }))
                await Assert.ThrowsAsync<IOException>(() => reopened.CloseExpiredMailboxAcquisitionsAsync(Source(reopened)));
            using (var unchanged = await ReadPeerGrantsAsync(own: true)) Assert.Equal(original, Assert.Single(unchanged.Entries).Value);
            reopened = ReopenAccount();
            if (failAfterClosure)
            {
                using (Did2MailboxInstallationTestHooks.Push(point =>
                    { if (point == Did2MailboxInstallationFailpoint.AfterClosure) throw new IOException("Injected after unknown closure."); }))
                    await Assert.ThrowsAsync<IOException>(() => reopened.CloseExpiredMailboxAcquisitionsAsync(Source(reopened)));
            }
            else Assert.Equal(1, await reopened.CloseExpiredMailboxAcquisitionsAsync(Source(reopened)));
            using (var closed = await ReadPeerGrantsAsync(own: true))
            {
                var entry = Assert.Single(closed.Entries).Value;
                Assert.Equal(3UL, closed.Revision); Assert.True(ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(entry));
                Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(entry));
                Assert.Equal(ProtectedDid2MailboxGrantJournal.Request(original).ToArray(), ProtectedDid2MailboxGrantJournal.Request(entry).ToArray());
                Assert.Equal(ProtectedDid2MailboxGrantJournal.Seed(original).ToArray(), ProtectedDid2MailboxGrantJournal.Seed(entry).ToArray());
                Assert.Equal(ProtectedDid2MailboxGrantJournal.OriginalPolicy(original).ToArray(), ProtectedDid2MailboxGrantJournal.OriginalPolicy(entry).ToArray());
                Assert.Equal(ProtectedDid2MailboxGrantJournal.OriginalRoute(original).ToArray(), ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).ToArray());
                Assert.Equal(ceiling, ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(entry));
                Assert.Equal(expiry, ProtectedDid2MailboxGrantJournal.ClosedLower(entry));
                var selection = Assert.Single(closed.Selections);
                Assert.Null(selection.Value.Current); Assert.Null(selection.Value.Pending);
                Assert.Equal(ProtectedDid2MailboxGrantJournal.Acquisition(entry), selection.Value.RetainedTail);
                Assert.Throws<IOException>(() => ProtectedDid2MailboxGrantJournal.AcquisitionForNewWork(closed, selection.Key));
                Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxGrantJournal.PromoteWinner(closed, selection.Key));
                CheckClosedGrantShape(closed, successorTemplate);
            }
            reopened = ReopenAccount();
            Assert.Equal(0, await reopened.CloseExpiredMailboxAcquisitionsAsync(Source(reopened)));
            transport.LoseResponse = false;
            await Assert.ThrowsAsync<IOException>(() => reopened.AcquireOwnPermanentContactRetrieveGrantAsync(Source(reopened), transport));
            Assert.Equal(1, transport.Calls); // Closure/reopen never consults the issuer.
            CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(successorTemplate);
        }

        private void CheckClosedGrantShape(ProtectedDid2MailboxGrantJournal.State closed, byte[] successorTemplate)
        {
            var account = Bytes(32, 0x11); var instance = Bytes(32, 0x12);
            var exact = ProtectedDid2MailboxGrantJournal.Encode(closed, Network, account, instance);
            using var cold = ProtectedDid2MailboxGrantJournal.Decode(exact, Network, account, instance);
            Assert.Equal(exact, ProtectedDid2MailboxGrantJournal.Encode(cold, Network, account, instance));
            var entry = Assert.Single(cold.Entries).Value;
            foreach (var offset in new[] { 96, 1077, 1085, 1093, 1095, 1097 })
            {
                var damaged = entry.ToArray();
                if (offset == 1085) BinaryPrimitives.WriteUInt64BigEndian(damaged.AsSpan(offset, 8),
                    ProtectedDid2MailboxGrantJournal.RequestExpiry(entry) - 1);
                else damaged[offset] ^= 1;
                cold.Entries[Assert.Single(cold.Entries).Key] = damaged;
                if (offset == 1097)
                    Assert.Throws<ContactFormatException>(() => ProtectedDid2MailboxGrantJournal.Encode(cold, Network, account, instance));
                else Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxGrantJournal.Encode(cold, Network, account, instance));
                cold.Entries[Assert.Single(cold.Entries).Key] = entry; CryptographicOperations.ZeroMemory(damaged);
            }
            // Future renewal can retain a closed predecessor without pretending
            // it is a current winner; no runtime successor issuance is activated.
            // Prepared earlier under an actual current route; this shape-only
            // staging after closure grants no authority to dispatch expired work.
            var successor = successorTemplate.ToArray();
            ProtectedDid2MailboxGrantJournal.AddPending(cold, successor); cold.Revision++;
            var staged = ProtectedDid2MailboxGrantJournal.Encode(cold, Network, account, instance);
            using var restarted = ProtectedDid2MailboxGrantJournal.Decode(staged, Network, account, instance);
            Assert.Equal(2, restarted.Entries.Count);
            Assert.Equal(entry, restarted.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(entry)]);
            Assert.Null(Assert.Single(restarted.Selections).Value.Current);
            foreach (var bytes in new[] { exact, staged }) CryptographicOperations.ZeroMemory(bytes);
        }

        private async Task<byte[]> PrepareClosedGrantCandidateAsync(byte[] original, VerifiedDeepIdV2ContactRouteClosure route)
        {
            var seed = Bytes(32, 0x9a);
            try
            {
                var parsed = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(original).Span);
                var (_, _, pending) = await PrepareRetainedGraphRequestAsync(original, parsed, route.Network, seed);
                return pending;
            }
            finally { CryptographicOperations.ZeroMemory(seed); }
        }

        private DeepIdV2AccountService ReopenGrantReader() => new(peerStorage, Path.Combine(directory, "peer"),
            Network, 1, new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
            DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
        internal DeepIdV2ContactPathAuthoritySource GrantReaderSource(DeepIdV2AccountService account) =>
            new(bootstrap.GenesisPin, account, peerProofs!, closure, peerNetworkStore!, this);

        internal async Task<ProtectedDid2MailboxGrantJournal.State> ReadPeerGrantsAsync(bool own = false)
        {
            var selected = own ? innerStorage : peerStorage;
            using var key = await selected.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidOperationException();
            using var root = await selected.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidOperationException();
            var scope = key.Use(record => record.Slice(24, 64).ToArray());
            try { return root.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, Network,
                scope.AsSpan(0, 32), scope.AsSpan(32, 32))); }
            finally { CryptographicOperations.ZeroMemory(scope); }
        }

        internal async Task CheckGrantCustodyAsync()
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            var configuration = Did2OwnedPermanentContactPlan.Configuration();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), configuration, threshold, reopen: false);
            var publication = new OwnedPublicationSource(this, route);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold, publication, replicas);
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            var reader = peerAccounts!; var source = GrantReaderSource(reader);
            var resolved = await reader.ResolvePermanentContactAsync(address, source,
                new SyntheticPermanentRead(this, source, replicas.ExactPublication));
            var transport = new OwnedGrantTransport(this) { CorruptResponse = true };
            await RequireRouteRejectionAsync(async () => await reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport));
            using (var pending = await ReadPeerGrantsAsync())
            {
                Assert.Equal(2UL, pending.Revision);
                Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(Assert.Single(pending.Entries).Value));
            }
            transport.CorruptResponse = false; transport.LoseResponse = true;
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            await Assert.ThrowsAsync<IOException>(() => reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport));
            using (var pending = await ReadPeerGrantsAsync()) Assert.Equal(2UL, pending.Revision);
            transport.LoseResponse = false;
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            using (Did2MailboxInstallationTestHooks.Push(point =>
                { if (point == Did2MailboxInstallationFailpoint.BeforeSelection) throw new IOException("Injected before selection."); }))
                await Assert.ThrowsAsync<IOException>(() => reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport));
            using (var candidate = await ReadPeerGrantsAsync())
            {
                Assert.Equal(3UL, candidate.Revision);
                Assert.True(ProtectedDid2MailboxGrantJournal.HasWinner(Assert.Single(candidate.Entries).Value));
                var selection = Assert.Single(candidate.Selections).Value;
                Assert.Null(selection.Current); Assert.NotNull(selection.Pending);
            }
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            using (Did2MailboxInstallationTestHooks.Push(point =>
                { if (point == Did2MailboxInstallationFailpoint.BeforeSql) throw new IOException("Injected before owned installation."); }))
                await Assert.ThrowsAsync<IOException>(() => reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport));
            Assert.Equal(3, transport.Calls);
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            using (Did2MailboxInstallationTestHooks.Push(point =>
                { if (point == Did2MailboxInstallationFailpoint.AfterSql) throw new IOException("Injected after owned installation."); }))
                await Assert.ThrowsAsync<IOException>(() => reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport));
            Assert.Equal(3, transport.Calls); // Committed winner must not be reissued after either interruption.
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            Did2OwnedMailboxTransportContext? heldPath = null;
            VerifiedDeepIdV2MailboxGrant verified;
            using (Did2MailboxInstallationTestHooks.PushHeldPath(async (context, installed, ct) =>
            {
                heldPath = context; var before = ProofRequests;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(5));
                var network = await context.GetCurrentForMailboxAsync(installed.PlacementCommitment, timeout.Token);
                Assert.Equal(Network, network.NetworkId.ToArray());
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await context.GetCurrentForMailboxAsync(Bytes(32, 0x99), timeout.Token));
                Assert.Equal(before, ProofRequests); // Readonly held floors: no recursive account-lock/fetch.
            }))
                verified = await reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport);
            Assert.NotNull(heldPath);
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await heldPath.RequireCurrentAsync(default));
            await AssertInstalledGrantSqlAsync(verified.ExactGrant, own: false);
            Assert.Equal(3, transport.Calls); Assert.True(transport.ExactRetry);
            Assert.True(transport.BuiltHeldFrame);
            using (var winner = await ReadPeerGrantsAsync())
            {
                Assert.Equal(4UL, winner.Revision);
                var entry = Assert.Single(winner.Entries).Value;
                var selection = Assert.Single(winner.Selections).Value;
                Assert.Equal(ProtectedDid2MailboxGrantJournal.Acquisition(entry), selection.Current);
                Assert.Null(selection.Pending);
                Assert.True(ProtectedDid2MailboxGrantJournal.HasWinner(entry));
                Assert.Equal(verified.ExactXmg2.ToArray(), ProtectedDid2MailboxGrantJournal.Request(entry).ToArray());
                Assert.Equal(verified.ExactXmc2.ToArray(), ProtectedDid2MailboxGrantJournal.Response(entry).ToArray());
                await CheckIndependentAcquisitionsAsync(winner, transport.Route!, verified);
                // A corrupted seed, winner, phase or reserved byte is not repaired.
                foreach (var offset in new[] { 32, 96, 97, 100 + 435 + 32 })
                {
                    var damaged = entry.ToArray(); damaged[offset] ^= 1;
                    using var changed = new ProtectedDid2MailboxGrantJournal.State { Revision = 3 };
                    changed.Entries.Add(winner.Entries.Keys.Single(), damaged);
                    void Encode() => ProtectedDid2MailboxGrantJournal.Encode(changed,
                        Network, Bytes(32, 0x11), Bytes(32, 0x12));
                    if (offset == 32) Assert.Throws<CryptographicException>(Encode);
                    else if (offset is 96 or 97) Assert.Throws<InvalidDataException>(Encode);
                    else Assert.Throws<ContactFormatException>(Encode);
                }
            }
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            var reopened = await reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport);
            Assert.Equal(verified.ExactXmg2.ToArray(), reopened.ExactXmg2.ToArray());
            Assert.Equal(verified.ExactXmc2.ToArray(), reopened.ExactXmc2.ToArray());
            await AssertInstalledGrantSqlAsync(reopened.ExactGrant, own: false);
            Assert.Equal(3, transport.Calls); // Retained winner makes no issuer callback.
            Assert.False(await reader.HasOwnStagedPreKeyInventoryAsync()); // Not a session/acceptance/ACK.
            Assert.NotNull(transport.Dispatch);
            Assert.Throws<ObjectDisposedException>(() => transport.Dispatch.RequireActive());
            // The unpublished peer cannot acquire owner retrieval using a
            // public resolve/deposit grant as a substitute for phase7 custody.
            var unpublished = new OwnedGrantTransport(this, selfRetrieve: true);
            await Assert.ThrowsAsync<CryptographicException>(() => reader.AcquireOwnPermanentContactRetrieveGrantAsync(source, unpublished));
            Assert.Equal(0, unpublished.Calls);

            var retrieval = new OwnedGrantTransport(this, selfRetrieve: true) { LoseResponse = true };
            await Assert.ThrowsAsync<IOException>(() => accounts.AcquireOwnPermanentContactRetrieveGrantAsync(Source(), retrieval));
            using (var pending = await ReadPeerGrantsAsync(own: true))
            {
                Assert.Equal(2UL, pending.Revision);
                Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(Assert.Single(pending.Entries).Value));
            }
            retrieval.LoseResponse = false;
            var ownerReopened = ReopenAccount();
            var retrieved = await ownerReopened.AcquireOwnPermanentContactRetrieveGrantAsync(Source(ownerReopened), retrieval);
            Assert.Equal(MailboxCapabilityDomain.Retrieve, retrieved.Domain);
            Assert.Equal(2, retrieval.Calls); Assert.True(retrieval.ExactRetry); Assert.True(retrieval.BuiltHeldFrame);
            Assert.NotEqual(ContactCodec.Decode("XMG2", verified.ExactXmg2.Span).Field(5).ToArray(),
                ContactCodec.Decode("XMG2", retrieved.ExactXmg2.Span).Field(5).ToArray());
            using (var winner = await ReadPeerGrantsAsync(own: true))
            {
                var entry = Assert.Single(winner.Entries).Value;
                Assert.Equal(4UL, winner.Revision); Assert.True(ProtectedDid2MailboxGrantJournal.HasWinner(entry));
                Assert.Equal(retrieved.ExactXmc2.ToArray(), ProtectedDid2MailboxGrantJournal.Response(entry).ToArray());
            }
            ownerReopened = ReopenAccount();
            var retrieveAgain = await ownerReopened.AcquireOwnPermanentContactRetrieveGrantAsync(Source(ownerReopened), retrieval);
            Assert.Equal(retrieved.ExactXmg2.ToArray(), retrieveAgain.ExactXmg2.ToArray());
            Assert.Equal(retrieved.ExactXmc2.ToArray(), retrieveAgain.ExactXmc2.ToArray());
            Assert.Equal(2, retrieval.Calls);
            await AssertInstalledGrantSqlAsync(retrieveAgain.ExactGrant, own: true);
            await peerStorage.DeleteBatchAsync([ProtectedDid2MailboxGrantJournal.Slot]);
            await Assert.ThrowsAsync<InvalidDataException>(() => ReopenGrantReader().GetCurrentAsync());
        }

        private async Task CheckIndependentAcquisitionsAsync(ProtectedDid2MailboxGrantJournal.State original,
            VerifiedDeepIdV2ContactRouteClosure route, VerifiedDeepIdV2MailboxGrant first)
        {
            var account = Bytes(32, 0x11); var instance = Bytes(32, 0x12);
            var originalExact = ProtectedDid2MailboxGrantJournal.Encode(original, Network, account, instance);
            using var state = ProtectedDid2MailboxGrantJournal.Decode(originalExact, Network, account, instance);
            var scope = Assert.Single(state.Selections).Key;
            var firstName = Assert.Single(state.Entries).Key;
            var firstGrant = SHA256.HashData(first.ExactGrant.Span);
            var locator = ContactCodec.Decode("XMG2", first.ExactXmg2.Span).Field(3);
            byte[] Encode() => ProtectedDid2MailboxGrantJournal.Encode(state, Network, account, instance);
            var seed = Bytes(32, 0x98);
            using var holder = ReachabilityMailboxHolderAuthority.OpenRetained(route, locator,
                route.Route.Reachability.Field(10), MailboxCapabilityDomain.Deposit, seed);
            var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, locator, holder);
            var policy = await CurrentGrantPolicyAsync(route);
            var successor = ProtectedDid2MailboxGrantJournal.Pending(seed, route, request, policy, Network);
            ProtectedDid2MailboxGrantJournal.AddPending(state, successor); state.Revision++;
            var successorName = ProtectedDid2MailboxGrantJournal.Acquisition(successor);
            Assert.NotEqual(firstName, successorName);
            Assert.Equal(firstName, state.Selections[scope].Current);
            Assert.Equal(successorName, state.Selections[scope].Pending);
            Assert.Equal(firstName, ProtectedDid2MailboxGrantJournal.Acquisition(
                ProtectedDid2MailboxGrantJournal.AcquisitionForNewWork(state, scope)!));
            Assert.Equal(first.ExactXmc2.ToArray(), ProtectedDid2MailboxGrantJournal.Response(
                ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(state, scope, firstGrant)).ToArray());
            Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxGrantJournal.PromoteWinner(state, scope));
            var response = await IssueOwnedGrantAsync(request, route, retrieve: false, default);
            var verified = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(route, request, response, operational.ExactPma2);
            var next = ProtectedDid2MailboxGrantJournal.WithWinner(successor, verified.ExactXmc2.Span, Network);
            state.Entries[successorName] = next; CryptographicOperations.ZeroMemory(successor); state.Revision++;
            var candidate = Encode();
            using (var coldCandidate = ProtectedDid2MailboxGrantJournal.Decode(candidate, Network, account, instance))
            {
                Assert.Equal(firstName, coldCandidate.Selections[scope].Current);
                Assert.Equal(successorName, coldCandidate.Selections[scope].Pending);
                Assert.Equal(firstName, ProtectedDid2MailboxGrantJournal.Acquisition(
                    ProtectedDid2MailboxGrantJournal.AcquisitionForNewWork(coldCandidate, scope)!));
                Assert.Equal(first.ExactXmc2.ToArray(), ProtectedDid2MailboxGrantJournal.Response(
                    ProtectedDid2MailboxGrantJournal.CurrentWinner(coldCandidate, scope)!).ToArray());
                Assert.Throws<CryptographicException>(() => { _ = ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(
                    coldCandidate, scope, SHA256.HashData(verified.ExactGrant.Span)); });
            }
            ProtectedDid2MailboxGrantJournal.PromoteWinner(state, scope); state.Revision++;
            var promoted = Encode();
            using (var cold = ProtectedDid2MailboxGrantJournal.Decode(promoted, Network, account, instance))
            {
                Assert.Equal(successorName, cold.Selections[scope].Current); Assert.Null(cold.Selections[scope].Pending);
                Assert.Equal(first.ExactXmc2.ToArray(), ProtectedDid2MailboxGrantJournal.Response(
                    ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(cold, scope, firstGrant)).ToArray());
                Assert.Equal(verified.ExactXmc2.ToArray(), ProtectedDid2MailboxGrantJournal.Response(
                    ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(cold, scope, SHA256.HashData(verified.ExactGrant.Span))).ToArray());
                Assert.Equal(promoted, ProtectedDid2MailboxGrantJournal.Encode(cold, Network, account, instance));
            }
            // Hostile pointers/predecessors cannot pick a winner or orphan old custody.
            var selectionOffset = ProtectedDid2MailboxGrantJournal.HeaderBytes + state.Entries.Values.Sum(entry => 4 + entry.Length);
            foreach (var offset in new[] { 92, 94, selectionOffset, selectionOffset + 32, selectionOffset + 64,
                selectionOffset + 96, ProtectedDid2MailboxGrantJournal.HeaderBytes + 4 + 1045 })
            {
                var damaged = promoted.ToArray(); damaged[offset] ^= 1;
                Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxGrantJournal.Decode(damaged, Network, account, instance));
                CryptographicOperations.ZeroMemory(damaged);
            }
            var selected = state.Selections[scope];
            state.Selections[scope] = new(firstName, null, successorName); // Valid history cannot select an older winner.
            Assert.Throws<InvalidDataException>(Encode); state.Selections[scope] = selected;
            state.Selections[scope] = new(firstName, null, firstName); // Orphan successor, not an authorized rollback.
            Assert.Throws<InvalidDataException>(Encode); state.Selections[scope] = selected;
            Assert.Throws<CryptographicException>(() => ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(state, scope, Bytes(32, 0xa1)));
            Assert.Equal(Assert.Single(original.Entries).Value, state.Entries[firstName]);
            foreach (var bytes in new[] { originalExact, candidate, promoted, response, seed }) CryptographicOperations.ZeroMemory(bytes);
        }

        // Controlled, actual signed producer fixture. This stages selection for
        // consumer tests; it is NOT runtime renewal/compaction or device evidence.
        internal async Task StageVerifiedGrantSuccessorAsync(OwnedGrantTransport transport, bool own, bool currentRetainedAuthority = false)
        {
            var selected = own ? innerStorage : peerStorage;
            using var generation = await selected.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidOperationException();
            var ownerScope = generation.Use(record => record.Slice(24, 64).ToArray());
            using var root = await selected.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidOperationException();
            var snapshot = root.Use(bytes => bytes.ToArray());
            byte[] seed = [], response = [];
            try
            {
                using var state = ProtectedDid2MailboxGrantJournal.Decode(snapshot, Network, ownerScope.AsSpan(0, 32), ownerScope.AsSpan(32));
                var old = state.Entries[Convert.ToHexString(SHA256.HashData(transport.OriginalRequest.Span))];
                var scope = Convert.ToHexString(old.AsSpan(0, 32));
                var original = old.ToArray();
                var requestRecord = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(old).Span);
                var locator = requestRecord.Field(3); var capability = requestRecord.Field(4);
                var domain = (MailboxCapabilityDomain)requestRecord.Field(6).Span[0];
                seed = Bytes(32, 0x99);
                byte[] pending, next;
                if (domain == MailboxCapabilityDomain.Deposit)
                {
                    // Deposit remains the genuine current-only producer. It
                    // cannot borrow a retained Retrieve request or issuer.
                    var route = transport.Route ?? throw new InvalidOperationException();
                    using var holder = ReachabilityMailboxHolderAuthority.OpenRetained(route, locator, capability, domain, seed);
                    var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, locator, holder);
                    var policy = await CurrentGrantPolicyAsync(route);
                    pending = ProtectedDid2MailboxGrantJournal.Pending(seed, route, request, policy, Network);
                    ProtectedDid2MailboxGrantJournal.AddPending(state, pending); await Save();
                    response = await IssueOwnedGrantAsync(request, route, retrieve: false, default);
                    var verified = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(route, request, response, operational.ExactPma2);
                    next = ProtectedDid2MailboxGrantJournal.WithWinner(pending, verified.ExactXmc2.Span, Network);
                }
                else
                {
                    Assert.Equal(MailboxCapabilityDomain.Retrieve, domain);
                    var parsed = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(old).Span);
                    var currentAccount = own ? ReopenAccount() : ReopenGrantReader();
                    var currentSource = own ? Source(currentAccount) : GrantReaderSource(currentAccount);
                    var fresh = currentRetainedAuthority ? await currentSource.VerifyForOwnPreKeyAuthoringAsync(currentAccount, default) : null;
                    var network = fresh?.Network ?? transport.Dispatch!.Network;
                    var (host, request, retainedPending) = await PrepareRetainedGraphRequestAsync(original, parsed, network, seed, fresh);
                    pending = retainedPending;
                    ProtectedDid2MailboxGrantJournal.AddPending(state, pending); await Save();
                    response = await IssueRetainedFixtureGrantAsync(request, parsed, host, network, default);
                    var verified = await host.VerifyRetainedReadSuccessAsync(parsed.ExactBytes, request.ExactXmg2, response);
                    next = ProtectedDid2MailboxGrantJournal.WithWinner(pending, verified.ExactXmc2.Span, Network);
                }
                state.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(pending)] = next;
                CryptographicOperations.ZeroMemory(pending); await Save();
                ProtectedDid2MailboxGrantJournal.PromoteWinner(state, scope); await Save();
                Assert.Equal(original, ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(state, scope,
                    SHA256.HashData(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(old).Span).Field(8).Span)));
                CryptographicOperations.ZeroMemory(original);

                async Task Save()
                {
                    state.Revision++;
                    var exact = ProtectedDid2MailboxGrantJournal.Encode(state, Network, ownerScope.AsSpan(0, 32), ownerScope.AsSpan(32));
                    try
                    {
                        Assert.True(await selected.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, snapshot, exact));
                        using var readback = await selected.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidOperationException();
                        Assert.True(readback.Use(bytes => bytes.SequenceEqual(exact)));
                        CryptographicOperations.ZeroMemory(snapshot); snapshot = exact.ToArray();
                    }
                    finally { CryptographicOperations.ZeroMemory(exact); }
                }
            }
            finally { foreach (var bytes in new[] { ownerScope, snapshot, seed, response }) CryptographicOperations.ZeroMemory(bytes); }
        }

        private async Task<(VerifiedMailboxHostAuthorityV2 Host, AuthoredMailboxGrantRequest Request, byte[] Pending)>
            PrepareRetainedGraphRequestAsync(byte[] original, ParsedContactRouteClosure route, VerifiedOnionNetworkContext network, byte[] seed,
                DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority? currentAuthority = null)
        {
            var prior = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(original).Span);
            var fresh = currentAuthority ?? await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(network, bootstrap.Authority,
                currentAuthority?.MailboxAuthority.ExactPma2 ?? operational.ExactPma2, new OnionTrustedTimeAuthority(this));
            using var signer = ReachabilityMailboxHolderAuthority.OpenRetainedRead(route, Network, prior.Field(3), prior.Field(4),
                seed, token => host.EnsureCurrentAsync(token).AsTask());
            var request = await host.AuthorRetainedReadRequestAsync(route.ExactBytes, prior.Field(3), prior.Field(4), signer);
            return (host, request, ProtectedDid2MailboxGrantJournal.PendingRetainedRead(seed, route, request, fresh.MailboxAuthority, Network));
        }

        internal async Task<byte[]> IssueRetainedFixtureGrantAsync(AuthoredMailboxGrantRequest request,
            ParsedContactRouteClosure original, VerifiedMailboxHostAuthorityV2 host, VerifiedOnionNetworkContext network, CancellationToken ct)
        {
            var horizon = checked(OriginalAdmissionEnd(original) + 2_592_000UL);
            var tuple = MailboxRetainedReadEvidenceAuthentication.CreateTuple(SHA256.HashData(request.ExactXmg2.Span),
                request.Record.Field(3).Span, MailboxGrantCapabilityDigest.Compute(request.Record.Field(4).Span, request.Domain), original.ExactHash.Span, horizon);
            var placement = ContactServicePlacementFactory.Create(network, ContactServiceRequestKind.AcquireMailboxGrant, request.Record.Field(3));
            var evidence = placement.RankedReplicaNodeIds.Select(id => new DeepIdV2MailboxGrantReplicaEvidence(id.Span,
                PublicationReceipt(id, MailboxRetainedReadEvidenceAuthentication.GetSigningBytes(tuple)))).ToArray();
            var candidate = await host.VerifyRetainedReadIssuanceAsync(request.ExactXmg2, original.ExactBytes, horizon, evidence, ct);
            var issuer = new FixtureMailboxIssuer(0x32);
            var result = (await candidate.AuthorSuccessAsync(issuer, ct)).ToArray();
            Assert.Equal(1, issuer.Calls); return result;
        }

        private async Task<VerifiedMailboxAuthorityV2> CurrentGrantPolicyAsync(VerifiedDeepIdV2ContactRouteClosure route)
        {
            var time = await route.ReadCurrentTimeAsync();
            return MailboxAuthorityV2Verifier.Verify(route.NetworkAuthority, operational.ExactPma2.Span,
                time.LowerUnixSeconds, time.UpperUnixSeconds);
        }

        // Test-only independent SQLCipher observer. No runtime authority is
        // constructed by this reader, and no key/path/payload is logged.
        internal async Task AssertInstalledGrantSqlAsync(ReadOnlyMemory<byte> exactGrant, bool own)
        {
            var selected = own ? innerStorage : peerStorage;
            using var root = await selected.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidOperationException();
            var record = root.Use(bytes => bytes.ToArray());
            var context = new byte["Deep/STORE-V2/application-state-key"u8.Length + 1 + 80];
            byte[] key = [];
            try
            {
                var domain = "Deep/STORE-V2/application-state-key"u8;
                domain.CopyTo(context); record.AsSpan(8, 80).CopyTo(context.AsSpan(domain.Length + 1));
                key = HMACSHA256.HashData(record.AsSpan(88, 32), context);
                var accountPath = own ? Path.Combine(directory, "deep-store-v2-account.dsv2") :
                    Path.Combine(directory, "peer", "deep-store-v2-account.dsv2");
                using var sql = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = accountPath + ".application.dmb1", Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
                sql.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, MailboxRandomKeyTestEncoding.Apply(sql, key));
                using var read = sql.CreateCommand();
                foreach (var table in new[] { "mailbox_credential_scopes", "mailbox_credential_epochs", "mailbox_credential_grants" })
                {
                    read.CommandText = $"SELECT COUNT(*) FROM {table};";
                    Assert.Equal(1, Convert.ToInt32(read.ExecuteScalar()));
                }
                foreach (var table in new[] { "mailbox_prepared_batches", "mailbox_prepared_batch_targets", "transport_outbox_items" })
                {
                    read.CommandText = $"SELECT COUNT(*) FROM {table};";
                    Assert.Equal(0, Convert.ToInt32(read.ExecuteScalar())); // Installation is not dispatch.
                }
                read.CommandText = "SELECT canonical_grant FROM mailbox_credential_grants;";
                Assert.Equal(exactGrant.ToArray(), (byte[])read.ExecuteScalar()!);
                read.CommandText = "SELECT scope_kind FROM mailbox_credential_scopes;";
                Assert.Equal(own ? 1 : 2, Convert.ToInt32(read.ExecuteScalar()));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(record); CryptographicOperations.ZeroMemory(context);
                CryptographicOperations.ZeroMemory(key);
            }
        }

        internal async Task<byte[]> IssueOwnedGrantAsync(AuthoredMailboxGrantRequest request,
            VerifiedDeepIdV2ContactRouteClosure route, bool retrieve, CancellationToken ct)
        {
            var effective = BinaryPrimitives.ReadUInt64BigEndian(route.Route.Reachability.Field(17).Span);
            var tuple = MailboxGrantRouteEvidenceAuthentication.CreateTuple(SHA256.HashData(request.ExactXmg2.Span),
                request.Record.Field(3).Span, MailboxGrantCapabilityDigest.Compute(request.Record.Field(4).Span, request.Domain),
                (byte)request.Domain, 1, route.Route.ExactHash.Span, effective);
            var signing = MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(tuple);
            var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.ResolveInvite, request.Record.Field(3));
            var evidence = placement.RankedReplicaNodeIds.Select(id =>
            {
                var marker = Enumerable.Range(0x70, 3).Single(value => PublicKey((byte)value).AsSpan().SequenceEqual(id.Span));
                var pair = PublicKeyAuth.GenerateKeyPair(Bytes(32, (byte)marker));
                try { return new DeepIdV2MailboxGrantReplicaEvidence(id.Span, PublicKeyAuth.SignDetached(signing, pair.PrivateKey)); }
                finally { CryptographicOperations.ZeroMemory(pair.PrivateKey); }
            }).ToArray();
            var time = new OnionTrustedTimeAuthority(this);
            var invalid = evidence[0].Signature.ToArray(); invalid[^1] ^= 1;
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantIssuanceVerifier.VerifyAsync(
                route.Network, route.NetworkAuthority, operational.ExactPma2, request.ExactXmg2, route.ExactRouteClosure,
                effective, [new(evidence[0].NodeId.Span, invalid), evidence[1]], time, ct));
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2MailboxGrantIssuanceVerifier.VerifyAsync(
                route.Network, route.NetworkAuthority, operational.ExactPma2, request.ExactXmg2, route.ExactRouteClosure,
                effective, [evidence[0], evidence[0]], time, ct));
            var authorized = await DeepIdV2MailboxGrantIssuanceVerifier.VerifyAsync(route.Network, route.NetworkAuthority,
                operational.ExactPma2, request.ExactXmg2, route.ExactRouteClosure, effective, evidence, time, ct);
            var wrong = new FixtureMailboxIssuer(retrieve ? (byte)0x31 : (byte)0x32);
            await Assert.ThrowsAsync<CryptographicException>(async () => await authorized.AuthorSuccessAsync(wrong, ct));
            Assert.Equal(0, wrong.Calls);
            var issuer = new FixtureMailboxIssuer(retrieve ? (byte)0x32 : (byte)0x31);
            var exact = (await authorized.AuthorSuccessAsync(issuer, ct)).ToArray();
            Assert.Equal(1, issuer.Calls);
            Assert.Equal(request.Record.Field(10).ToArray(), ContactCodec.Decode("XMC2", exact).Field(6).ToArray());
            return exact;
        }
    }

    // Actual account/native PQ/SQLCipher/protected custody and role signatures;
    // only the private issuer transport is in-process, not socket/device evidence.
    private sealed class OwnedGrantTransport(Fixture fixture, bool selfRetrieve = false, bool? ownerOnPrimary = null) : IDid2MailboxGrantTransport
    {
        internal bool CorruptResponse { get; set; }
        internal bool LoseResponse { get; set; }
        internal int Calls { get; private set; }
        internal bool ExactRetry { get; private set; } = true;
        internal Did2OwnedContactTransportContext? Dispatch { get; private set; }
        internal bool BuiltHeldFrame { get; private set; }
        // Prior verified fixture route, used only by current-route graph tests.
        // Retained issuance below always reads the actual protected request root.
        internal VerifiedDeepIdV2ContactRouteClosure? Route { get; set; }
        internal Func<Task>? BeforeReturn { get; set; }
        private byte[]? requestBytes, responseBytes;
        internal ReadOnlyMemory<byte> OriginalRequest => requestBytes ?? throw new InvalidOperationException();
        internal ReadOnlyMemory<byte> OriginalResponse => responseBytes ?? throw new InvalidOperationException();
        public async ValueTask<ReadOnlyMemory<byte>> AcquireAsync(AuthoredMailboxGrantRequest request,
            VerifiedDeepIdV2ContactRouteClosure route, Did2OwnedContactTransportContext dispatch, CancellationToken ct)
        {
            Assert.Equal(MailboxCapabilityDomain.Deposit, request.Domain); Route = route;
            return await SendAsync(request, dispatch, () => fixture.IssueOwnedGrantAsync(request, route, retrieve: false, ct), ct);
        }
        public async ValueTask<ReadOnlyMemory<byte>> AcquireRetainedReadAsync(AuthoredMailboxGrantRequest request,
            Did2OwnedContactTransportContext dispatch, CancellationToken ct)
        {
            Assert.Equal(MailboxCapabilityDomain.Retrieve, request.Domain);
            using var custody = await fixture.ReadPeerGrantsAsync(own: ownerOnPrimary ?? selfRetrieve);
            var pending = Assert.Single(custody.Entries.Values,
                value => ProtectedDid2MailboxGrantJournal.Request(value).Span.SequenceEqual(request.ExactXmg2.Span));
            var original = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(pending).Span);
            return await SendAsync(request, dispatch, async () =>
            {
                var host = await fixture.RetainedReadHostAsync(dispatch, ct);
                return await fixture.IssueRetainedFixtureGrantAsync(request, original, host, dispatch.Network, ct);
            }, ct);
        }
        private async ValueTask<ReadOnlyMemory<byte>> SendAsync(AuthoredMailboxGrantRequest request,
            Did2OwnedContactTransportContext dispatch, Func<Task<byte[]>> issue, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++; Dispatch = dispatch; dispatch.RequireActive();
            using (var custody = await fixture.ReadPeerGrantsAsync(own: ownerOnPrimary ?? selfRetrieve))
            {
                var entry = Assert.Single(custody.Entries.Values,
                    value => ProtectedDid2MailboxGrantJournal.Request(value).Span.SequenceEqual(request.ExactXmg2.Span));
                Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(entry));
                Assert.Equal(request.ExactXmg2.ToArray(), ProtectedDid2MailboxGrantJournal.Request(entry).ToArray());
            }
            if (Calls == 1)
            {
                var canonical = ContactResolveCanonicalPathRequest.Decode(request.ExactXmg2.Span);
                Assert.Equal(ContactServiceRequestKind.AcquireMailboxGrant, canonical.RequestKind);
                var placement = ContactServicePlacementFactory.Create(dispatch.Network, canonical.RequestKind, canonical.ShardKey);
                var source = (ownerOnPrimary ?? selfRetrieve) ? fixture.Source(dispatch.Custody.Owner) : fixture.GrantReaderSource(dispatch.Custody.Owner);
                var paths = new ContactResolvePrivacyPathProvider(source, dispatch.Custody.Guards);
                var prepared = await paths.PrepareWithAuthorityAsync(OnionOperation.ContactResolve, canonical,
                    ReadOnlyMemory<byte>.Empty, new(dispatch.Network, placement), ct, dispatch.RetainedReadRequest);
                var ledger = new CapturingEntropyLedger(dispatch.Custody.Entropy);
                var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(ledger),
                    new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
                using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request, ct);
                Assert.True(built.Frame.Length > request.ExactXmg2.Length);
                Assert.Equal(OnionEntropyCommitOutcome.Duplicate,
                    await dispatch.Custody.Entropy.CommitAsync(ledger.LastBatch!, ct));
                dispatch.RequireActive(); BuiltHeldFrame = true;
            }
            var exact = request.ExactXmg2.ToArray();
            if (requestBytes is null) requestBytes = exact;
            else { ExactRetry &= requestBytes.AsSpan().SequenceEqual(exact); Assert.True(ExactRetry); }
            if (responseBytes is null)
            {
                responseBytes = await issue();
            }
            if (LoseResponse) throw new IOException("Injected lost private grant response.");
            var response = responseBytes.ToArray(); if (CorruptResponse) response[^1] ^= 1;
            if (BeforeReturn is not null) await BeforeReturn();
            return response;
        }
    }

    private sealed class FixtureMailboxIssuer(byte marker) : IMailboxGrantIssuerSigner
    {
        public ReadOnlyMemory<byte> Ed25519PublicKey => PublicKey(marker);
        internal int Calls { get; private set; }
        public ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingBytes, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++;
            var pair = PublicKeyAuth.GenerateKeyPair(Bytes(32, marker));
            try { return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(signingBytes.ToArray(), pair.PrivateKey)); }
            finally { CryptographicOperations.ZeroMemory(pair.PrivateKey); }
        }
    }
}
