using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")] [InlineData("AfterStage")] [InlineData("AfterHistoryAdopted")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2UnusedAdoptedDeposit_ActualWinnerRetirementColdHandoverPreservesOtherRoots(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var acquisition = await fixture.PrepareUnusedAdoptedDepositAsync();
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        var preserved = await fixture.ReadUnusedDepositOtherRootsAsync();
        using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        var reader = fixture.UsedDepositAccount(initial: false);
        using (var exclusion = await reader.OpenMailboxEpochExclusionAsync(acquisition, fixture.GrantReaderSource(reader)))
        {
            if (fault == "none") await exclusion.RetireUnusedAdoptedDepositAcquisitionAsync(verifier, default);
            else
            {
                var hit = false;
                using (Did2CompactionTestHooks.Push(point =>
                    { if (point.ToString() == fault) { hit = true; throw new IOException("Interrupted unused adopted Deposit retirement."); } }))
                    await Assert.ThrowsAsync<IOException>(() => exclusion.RetireUnusedAdoptedDepositAcquisitionAsync(verifier, default));
                Assert.True(hit);
            }
        }
        fixture.ColdReopenReceiverStoreStorage();
        await fixture.ResumeUnusedAdoptedDepositPlanAsync();
        using (var grants = await fixture.ReadPeerGrantsAsync()) { Assert.Empty(grants.Entries); Assert.Empty(grants.Selections); }
        Assert.Equal(preserved, await fixture.ReadUnusedDepositOtherRootsAsync());
        foreach (var bytes in new[] { acquisition, preserved }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2UnusedAdoptedDeposit_NormalReadMaintenanceRetiresWinnerBeforeNewRead()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var acquisition = await fixture.PrepareUnusedAdoptedDepositAsync();
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        var issuer = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var terminal = new OwnedReadTerminal(fixture, []) { ReturnEmptyPage = true };
        var result = await fixture.SynchronizeNativeReceiver(issuer, terminal);
        Assert.Equal(0, result.ProcessedEnvelopes); Assert.Equal(1, issuer.Calls); Assert.Equal(1, terminal.RetrieveCalls);
        using var grants = await fixture.ReadPeerGrantsAsync();
        Assert.DoesNotContain(Convert.ToHexString(acquisition), grants.Entries.Keys);
        Assert.All(grants.Entries.Values, entry => Assert.Equal((byte)MailboxCapabilityDomain.Retrieve,
            ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span).Field(6).Span[0]));
        var committed = await fixture.ReadUnusedDepositOtherRootsAsync(includeGrantAndPlan: true);
        fixture.ColdReopenReceiverStoreStorage();
        Assert.Equal(committed, await fixture.ReadUnusedDepositOtherRootsAsync(includeGrantAndPlan: true));
        CryptographicOperations.ZeroMemory(committed);
        CryptographicOperations.ZeroMemory(acquisition);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2UnusedAdoptedDeposit_MissingUsedTransportRowCannotTurnNativeStoreIntoUnusedWinner()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(isInitial: false);
        _ = await fixture.DeliverCompletedCaseWithExactRetry(test);
        await fixture.CleanupSettledStoreCase(test, "accept");
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        byte[] acquisition;
        using (var grants = await fixture.ReadPeerGrantsAsync()) acquisition = Convert.FromHexString(Assert.Single(grants.Entries).Key);
        var reader = fixture.UsedDepositAccount(initial: false);
        using (var exclusion = await reader.OpenMailboxEpochExclusionAsync(acquisition, fixture.GrantReaderSource(reader)))
            await exclusion.RetireIdleMailboxCounterFloorAsync();
        // Hostile deletion in this disposable SQL fixture only. Native history,
        // original evidence MAC and protected custody remain genuine/unchanged.
        await fixture.WithAuthoredApplicationConnectionAsync(test.Scope, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM transport_outbox_items WHERE (account_scope,logical_id) IN (SELECT account_scope,logical_id FROM mailbox_store_public_evidence WHERE scope_hash=$scope AND native_operation_id=$operation);";
            command.Parameters.AddWithValue("$scope", test.Scope.Hash.ToArray()); command.Parameters.AddWithValue("$operation", test.Operation);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        var before = await fixture.ReadUnusedDepositOtherRootsAsync(includeGrantAndPlan: true);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var issuerCalls = test.Grants.Calls; var transportCalls = test.Transport.Calls;
        for (var iteration = 0; iteration < 2; iteration++)
        {
            var error = await Record.ExceptionAsync(async () =>
            {
                using var prepared = await fixture.CreateOwnedText(test.Scope, "must reject missing original native Store custody");
            });
            Assert.True(error is CryptographicException or InvalidDataException or IOException, error?.GetType().Name ?? "Missing used SQL authorized unused retirement.");
            Assert.Equal(before, await fixture.ReadUnusedDepositOtherRootsAsync(includeGrantAndPlan: true));
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            fixture.ColdReopenReceiverStoreStorage();
        }
        Assert.Equal(issuerCalls, test.Grants.Calls); Assert.Equal(transportCalls, test.Transport.Calls);
        foreach (var bytes in new[] { acquisition, before, native }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2UnusedAdoptedDeposit_OtherHolderNativeStoreDoesNotMakeUnusedSuccessorUsed()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(isInitial: false);
        test.Grants.MaximumFixtureGrantLifetimeSeconds = 120;
        var stored = await fixture.DeliverCompletedCaseWithExactRetry(test);
        await fixture.CleanupSettledStoreCase(test, "accept");
        await fixture.AcquireUnusedSuccessorForCompletedDepositAsync();
        using (var grants = await fixture.ReadPeerGrantsAsync()) Assert.Equal(2, grants.Entries.Count);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var ingressCalls = test.Transport.Calls;
        byte[] firstOperation = [], secondOperation = [];
        try
        {
            // Maintenance retires at most one excluded holder per business call.
            // The new live draft must pin the remaining holder across cold reopen.
            using (var command = await fixture.CreateOwnedText(test.Scope, "retire the original excluded holder"))
                firstOperation = command.OperationId.ToArray();
            using (var grants = await fixture.ReadPeerGrantsAsync()) Assert.Single(grants.Entries);
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            fixture.ColdReopenReceiverStoreStorage();
            using (var command = await fixture.CreateOwnedText(test.Scope, "live ordinary work pins the remaining holder"))
                secondOperation = command.OperationId.ToArray();
            using (var grants = await fixture.ReadPeerGrantsAsync()) Assert.Single(grants.Entries);
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());

            // Clear only real unsent work through its owner, never fixture deletion
            // or a relaxed dependency guard. Another holder's original Store is
            // still not evidence that this unused successor was used.
            await fixture.CancelNativeMessagingWork(test.Scope, firstOperation);
            fixture.ColdReopenReceiverStoreStorage();
            using (var grants = await fixture.ReadPeerGrantsAsync()) Assert.Single(grants.Entries);
            await fixture.CancelNativeMessagingWork(test.Scope, secondOperation);
            fixture.ColdReopenReceiverStoreStorage();
            using (var command = await fixture.CreateOwnedText(test.Scope, "retire the unused excluded successor")) { }
            using (var grants = await fixture.ReadPeerGrantsAsync()) { Assert.Empty(grants.Entries); Assert.Empty(grants.Selections); }
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            fixture.ColdReopenReceiverStoreStorage();
            var cached = await test.Deliver(); Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
            Assert.Equal(ingressCalls, test.Transport.Calls);
        }
        finally
        {
            foreach (var bytes in new[] { native, firstOperation, secondOperation }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private sealed partial class Fixture
    {
        internal Task ResumeUnusedAdoptedDepositPlanAsync() => PeerRetirementOwner().ResumeOwnedLocalCompactionAsync(default);

        internal async Task AcquireUnusedSuccessorForCompletedDepositAsync()
        {
            ulong refresh;
            using (var grants = await ReadPeerGrantsAsync())
            {
                var first = Assert.Single(grants.Entries).Value;
                var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2",
                    ProtectedDid2MailboxGrantJournal.Response(first).Span).Field(8).Span);
                refresh = ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds);
            }
            // Fresh proof/read, not a stretched short XIQ response. Retain the
            // exact actual adopted primary publication for this same contact.
            var center = checked(refresh - 5);
            if (CurrentProofTime < center) { var delta = center - CurrentProofTime; ProofTime += delta; Sample += delta; }
            var plan = await accounts.ReadOwnPermanentContactPlanAsync(); byte[] publication;
            using (var routes = await RouteState())
            {
                var entry = routes.Entries[Convert.ToHexString(plan.Intent.Span)]; Assert.Equal(7, entry.Phase);
                publication = ContactPublicationAuthorityWireCodec.DecodeResponse(
                    ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span), entry.Record(10).Span).ExactXpu1.ToArray();
            }
            try
            {
                var reader = ReopenGrantReader(); var source = GrantReaderSource(reader);
                var contact = await reader.ResolvePermanentContactAsync((await accounts.GetCurrentAsync())!.PermanentId,
                    source, new SyntheticPermanentRead(this, source, publication));
                var issuer = new OwnedGrantTransport(this) { MaximumFixtureGrantLifetimeSeconds = 120 };
                _ = await reader.AcquirePermanentContactDepositGrantAsync(contact, source, issuer); Assert.Equal(1, issuer.Calls);
            }
            finally { CryptographicOperations.ZeroMemory(publication); }
        }

        internal async Task<byte[]> PrepareUnusedAdoptedDepositAsync()
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold, new OwnedPublicationSource(this, route), replicas);
            _ = await EnsurePrivateReplyPublicationAsync(peerAccounts!);
            var reader = ReopenGrantReader(); var source = GrantReaderSource(reader);
            var contact = await reader.ResolvePermanentContactAsync((await accounts.GetCurrentAsync())!.PermanentId,
                source, new SyntheticPermanentRead(this, source, replicas.ExactPublication));
            var issuer = new OwnedGrantTransport(this);
            _ = await reader.AcquirePermanentContactDepositGrantAsync(contact, source, issuer);
            Assert.Equal(1, issuer.Calls);
            using var grants = await ReadPeerGrantsAsync();
            var entry = Assert.Single(grants.Entries);
            Assert.True(ProtectedDid2MailboxGrantJournal.HasWinner(entry.Value));
            using var sends = await ReadMailboxSends(); Assert.Empty(sends.Entries); Assert.Empty(sends.Floors);
            return Convert.FromHexString(entry.Key);
        }

        internal async Task<byte[]> ReadUnusedDepositOtherRootsAsync(bool includeGrantAndPlan = false)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var slot in new[] { ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MailboxSendJournal.Slot,
                ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot,
                SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, ProtectedDid2ContactStartJournal.Slot,
                ProtectedDid2ContactAcceptJournal.Slot, ProtectedInitialKeyRetirementJournal.Slot, ProtectedDph2PreClaimJournal.Slot })
            { using var raw = await peerStorage.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); raw.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; }); }
            if (includeGrantAndPlan)
            foreach (var slot in new[] { ProtectedDid2MailboxGrantJournal.Slot, Did2CompactionPlan.Slot })
            { using var raw = await peerStorage.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); raw.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; }); }
            return hash.GetHashAndReset();
        }
    }
}
