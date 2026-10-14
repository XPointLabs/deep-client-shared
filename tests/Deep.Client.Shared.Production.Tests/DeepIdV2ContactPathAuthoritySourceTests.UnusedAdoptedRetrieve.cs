using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")] [InlineData("AfterStage")] [InlineData("AfterSqlRecorded")]
    [InlineData("AfterHistoryAdopted")] [InlineData("AfterPartsDeleted")] [InlineData("AfterPlanCleared")]
    public async Task Did2UnusedAdoptedRetrieve_ActualReplacementReadAndEveryColdGrantHandover(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var prepared = await fixture.PrepareUnusedRetrieveReplacementAsync(originalUsed: false);
        var before = await fixture.OwnUnusedRetrieveGuardsAsync();
        var account = fixture.ReopenAccount();
        using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        using (var exclusion = await account.OpenMailboxEpochExclusionAsync(prepared.Original, fixture.Source(account)))
        {
            if (fault == "none") await exclusion.RetireUnusedAdoptedRetrieveAcquisitionAsync(verifier, default);
            else
            {
                var hit = false;
                using (Did2CompactionTestHooks.Push(point =>
                    { if (point.ToString() == fault) { hit = true; throw new IOException("Interrupted never-used Retrieve retirement."); } }))
                    await Assert.ThrowsAsync<IOException>(() => exclusion.RetireUnusedAdoptedRetrieveAcquisitionAsync(verifier, default));
                Assert.True(hit);
            }
        }
        fixture.ColdReopenCompactionStorage();
        await fixture.ResumeOwnUnusedRetrievePlanAsync();
        await fixture.AssertUnusedRetrieveOriginalRemovedAsync(prepared.Original, prepared.Replacement);
        Assert.Equal(before, await fixture.OwnUnusedRetrieveGuardsAsync());
        Assert.Equal(1, prepared.ReplacementIssuer.Calls); Assert.Equal(1, prepared.Terminal.RetrieveCalls);
        foreach (var bytes in new[] { prepared.Original, prepared.Replacement, before }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    public async Task Did2UnusedAdoptedRetrieve_NormalReadWaitsForReplacementThenRetiresOriginal()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var prepared = await fixture.PrepareUnusedRetrieveReplacementAsync(originalUsed: false);
        Assert.Equal(0, (await fixture.SynchronizeNativeSender(prepared.ReplacementIssuer, prepared.Terminal)).ProcessedEnvelopes);
        await fixture.AssertUnusedRetrieveOriginalRemovedAsync(prepared.Original, prepared.Replacement);
        fixture.ColdReopenCompactionStorage();
        Assert.Equal(0, (await fixture.SynchronizeNativeSender(prepared.ReplacementIssuer, prepared.Terminal)).ProcessedEnvelopes);
        await fixture.AssertUnusedRetrieveOriginalRemovedAsync(prepared.Original, prepared.Replacement);
        Assert.Equal(1, prepared.ReplacementIssuer.Calls); Assert.Equal(3, prepared.Terminal.RetrieveCalls);
        foreach (var bytes in new[] { prepared.Original, prepared.Replacement }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    public async Task Did2UnusedAdoptedRetrieve_DeletedSqlAfterFloorRetirementCannotEraseOriginalUse()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var prepared = await fixture.PrepareUnusedRetrieveReplacementAsync(originalUsed: true);
        await fixture.DeleteUsedOriginalRetrieveTransportAsync(prepared.Original);
        var before = await fixture.OwnUnusedRetrieveGuardsAsync(includeGrantAndPlan: true);
        var issuerCalls = prepared.ReplacementIssuer.Calls; var ingressCalls = prepared.Terminal.RetrieveCalls;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            await Assert.ThrowsAsync<IOException>(() => fixture.SynchronizeNativeSender(prepared.ReplacementIssuer, prepared.Terminal));
            Assert.Equal(before, await fixture.OwnUnusedRetrieveGuardsAsync(includeGrantAndPlan: true));
            fixture.ColdReopenCompactionStorage();
        }
        Assert.Equal(issuerCalls, prepared.ReplacementIssuer.Calls); Assert.Equal(ingressCalls, prepared.Terminal.RetrieveCalls);
        foreach (var bytes in new[] { prepared.Original, prepared.Replacement, before }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData("BeforeReadIntent", false)] [InlineData("AfterReadIntent", false)]
    [InlineData("BeforeReadIntent", true)] [InlineData("AfterReadIntent", true)]
    public async Task Did2UnusedAdoptedRetrieve_ReadIntentReservationResumesExactPhaseOneBeforeSigning(string fault, bool cancel)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true);
        _ = await fixture.PrepareRetainedPublicationAsync(elapsed: false);
        fixture.TrackMailboxDispatchClock();
        var issuer = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: true);
        var terminal = new OwnedReadTerminal(fixture, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
        using var cancellation = new CancellationTokenSource();
        var hit = false;
        using (Did2MailboxInstallationTestHooks.Push(point =>
            { if (point.ToString() == fault) { hit = true; if (cancel) cancellation.Cancel(); else throw new IOException("Interrupted actual read-intent reservation."); } }))
        {
            var account = fixture.ReopenAccount();
            var error = await Record.ExceptionAsync(() => account.SynchronizeOwnMailboxAsync(fixture.Source(account), issuer, terminal, cancellation.Token));
            if (cancel) Assert.IsAssignableFrom<OperationCanceledException>(error);
            else Assert.IsType<IOException>(error);
        }
        Assert.True(hit); Assert.Equal(1, issuer.Calls); Assert.Equal(0, terminal.RetrieveCalls);
        byte[] originalCycle;
        using (var read = await fixture.ReadPeerMailboxReads(own: true))
        { Assert.Equal(1, read.Phase); originalCycle = read.Active!.RetrieveBody.ToArray(); Assert.Empty(read.Counters); }
        using (var grants = await fixture.ReadPeerGrantsAsync(own: true))
            Assert.Equal(fault == "AfterReadIntent", ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(Assert.Single(grants.Entries).Value));
        fixture.ColdReopenCompactionStorage();
        Assert.Equal(0, (await fixture.SynchronizeNativeSender(issuer, terminal)).ProcessedEnvelopes);
        Assert.Equal(1, issuer.Calls); Assert.Equal(1, terminal.RetrieveCalls);
        using (var grants = await fixture.ReadPeerGrantsAsync(own: true))
            Assert.True(ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(Assert.Single(grants.Entries).Value));
        using (var read = await fixture.ReadPeerMailboxReads(own: true))
        { Assert.Equal(0, read.Phase); Assert.Null(read.Active); Assert.Equal(1UL, Assert.Single(read.Counters).Value); }
        await fixture.AssertOriginalReadBodyAsync(originalCycle);
        CryptographicOperations.ZeroMemory(originalCycle);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Did2UnusedAdoptedRetrieve_LostIntentRejectsBeforeInstallationAndCycleMutation(bool captured)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true);
        _ = await fixture.PrepareRetainedPublicationAsync(elapsed: false);
        fixture.TrackMailboxDispatchClock();
        var issuer = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: true);
        var terminal = new OwnedReadTerminal(fixture, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
        if (captured)
        {
            using (Deep.Client.Shared.Services.ClientMailboxRetrieveTestHooks.Push(point =>
                { if (point == Deep.Client.Shared.Services.ClientMailboxRetrieveFailpoint.AfterPageCommit) throw new IOException("Interrupted captured original read."); }))
                await Assert.ThrowsAsync<Deep.Client.Shared.Services.ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SynchronizeNativeSender(issuer, terminal));
        }
        else Assert.Equal(0, (await fixture.SynchronizeNativeSender(issuer, terminal)).ProcessedEnvelopes);
        await fixture.ClearReadIntentInDisposableGrantAsync();
        var before = await fixture.OwnUnusedRetrieveGuardsAsync(includeGrantAndPlan: true);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.SynchronizeNativeSender(issuer, terminal));
            Assert.Equal(before, await fixture.OwnUnusedRetrieveGuardsAsync(includeGrantAndPlan: true));
            fixture.ColdReopenCompactionStorage();
        }
        Assert.Equal(1, issuer.Calls); Assert.Equal(1, terminal.RetrieveCalls);
        CryptographicOperations.ZeroMemory(before);
    }

    [Fact]
    public void Did2UnusedAdoptedRetrieve_PriorEmptyGenerationCannotInventNeverUsedCustody()
    {
        var network = Bytes(16, 0x41); var account = Bytes(32, 0x42); var instance = Bytes(32, 0x43);
        var empty = ProtectedDid2MailboxGrantJournal.Empty(network, account, instance);
        Assert.Equal((byte)6, empty[0]); empty[0] = 5;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxGrantJournal.Decode(empty, network, account, instance));
    }

    private sealed partial class Fixture
    {
        internal async Task<(byte[] Original, byte[] Replacement, OwnedGrantTransport ReplacementIssuer, OwnedReadTerminal Terminal)>
            PrepareUnusedRetrieveReplacementAsync(bool originalUsed)
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            TrackMailboxDispatchClock();
            var originalIssuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
            var originalTerminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            var account = ReopenAccount();
            if (originalUsed) Assert.Equal(0, (await SynchronizeNativeSender(originalIssuer, originalTerminal)).ProcessedEnvelopes);
            else _ = await account.AcquireOwnPermanentContactRetrieveGrantAsync(Source(account), originalIssuer);
            byte[] original;
            using (var grants = await ReadPeerGrantsAsync(own: true))
            { var entry = Assert.Single(grants.Entries); original = Convert.FromHexString(entry.Key); Assert.Equal(originalUsed, ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(entry.Value)); }
            await AdvanceOriginalStoreEpochForTestAsync(2_100);
            account = ReopenAccount();
            if (originalUsed)
                using (var exclusion = await account.OpenMailboxEpochExclusionAsync(original, Source(account)))
                    await exclusion.RetireIdleMailboxCounterFloorAsync();
            var issuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
            _ = await account.RenewOwnPermanentContactRetrieveGrantAsync(original, Source(account), issuer);
            byte[] replacement;
            using (var grants = await ReadPeerGrantsAsync(own: true))
            { Assert.Equal(2, grants.Entries.Count); replacement = Convert.FromHexString(Assert.Single(grants.Selections).Value.Current!); }
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            // Installation alone cannot retire the old holder; this first real
            // read establishes independent positive replacement coverage.
            Assert.Equal(0, (await SynchronizeNativeSender(issuer, terminal)).ProcessedEnvelopes);
            using (var grants = await ReadPeerGrantsAsync(own: true))
            {
                Assert.Equal(2, grants.Entries.Count);
                Assert.Equal(originalUsed, ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(grants.Entries[Convert.ToHexString(original)]));
                Assert.True(ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(grants.Entries[Convert.ToHexString(replacement)]));
            }
            using (var read = await ReadPeerMailboxReads(own: true)) Assert.Single(read.Counters);
            Assert.Equal(1, originalIssuer.Calls); Assert.Equal(originalUsed ? 1 : 0, originalTerminal.RetrieveCalls);
            return (original, replacement, issuer, terminal);
        }

        internal Task ResumeOwnUnusedRetrievePlanAsync() => SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);

        internal async Task AssertUnusedRetrieveOriginalRemovedAsync(byte[] original, byte[] replacement)
        {
            using var grants = await ReadPeerGrantsAsync(own: true);
            var remaining = Assert.Single(grants.Entries);
            Assert.Equal(Convert.ToHexString(replacement), remaining.Key); Assert.DoesNotContain(Convert.ToHexString(original), grants.Entries.Keys);
            Assert.True(ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(remaining.Value));
            using var reads = await ReadPeerMailboxReads(own: true);
            Assert.Equal(0, reads.Phase); Assert.Null(reads.Active); Assert.Single(reads.Traversals); Assert.Single(reads.Counters);
            using var publications = await RouteState(); Assert.Single(publications.Entries);
        }

        internal async Task<byte[]> OwnUnusedRetrieveGuardsAsync(bool includeGrantAndPlan = false)
        {
            var roots = await ArchivedPathRootSnapshot();
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var root in roots.Skip(includeGrantAndPlan ? 0 : 1)) hash.AppendData(root);
            var account = ReopenAccount(); var accountId = (await account.GetCurrentAsync())!.AccountId.ToArray();
            var sql = await ArchivedPathSqlProjection(accountId, Bytes(32, 0x44)); hash.AppendData(sql);
            hash.AppendData((await account.ReadOwnMailboxReplayFenceAsync()).Digest.Span);
            if (includeGrantAndPlan)
            { using var plan = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException(); hash.AppendData(plan.Use(bytes => SHA256.HashData(bytes))); }
            CryptographicOperations.ZeroMemory(accountId); CryptographicOperations.ZeroMemory(sql);
            foreach (var root in roots) CryptographicOperations.ZeroMemory(root);
            return hash.GetHashAndReset();
        }

        internal async Task DeleteUsedOriginalRetrieveTransportAsync(byte[] original)
        {
            using var grants = await ReadPeerGrantsAsync(own: true);
            var entry = grants.Entries[Convert.ToHexString(original)]; Assert.True(ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(entry));
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span);
            var account = ReopenAccount(); var accountId = (await account.GetCurrentAsync())!.AccountId.ToArray();
            await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
            {
                using var command = sql.CreateCommand();
                command.CommandText = "DELETE FROM transport_outbox_items WHERE account_scope=$holder;";
                command.Parameters.AddWithValue("$holder", VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span).Value.ToArray());
                Assert.Equal(1, command.ExecuteNonQuery());
            });
            CryptographicOperations.ZeroMemory(accountId);
        }

        internal async Task AssertOriginalReadBodyAsync(byte[] original)
        {
            var account = ReopenAccount(); var accountId = (await account.GetCurrentAsync())!.AccountId.ToArray();
            await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
            {
                using var command = sql.CreateCommand(); command.CommandText = "SELECT ciphertext_bundle FROM transport_outbox_items;";
                using var reader = command.ExecuteReader(); Assert.True(reader.Read());
                var exact = reader.GetFieldValue<byte[]>(0);
                try { Assert.Equal(original, MailboxAuthenticatedClientRequestCodec.Decode(exact).Binding.CanonicalRequest.ToArray()); }
                finally { CryptographicOperations.ZeroMemory(exact); }
                Assert.False(reader.Read());
            });
            CryptographicOperations.ZeroMemory(accountId);
        }

        internal async Task ClearReadIntentInDisposableGrantAsync()
        {
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            var before = raw.Use(bytes => bytes.ToArray());
            using var grants = ProtectedDid2MailboxGrantJournal.Decode(before, Network, before.AsSpan(28, 32), before.AsSpan(60, 32));
            var entry = Assert.Single(grants.Entries).Value; Assert.True(ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(entry));
            // Deliberate isolated protected dependency loss, not a runtime
            // transition or an authority/repair input.
            entry[97] = 0; grants.Revision++;
            var after = ProtectedDid2MailboxGrantJournal.Encode(grants, Network, before.AsSpan(28, 32), before.AsSpan(60, 32));
            try { Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, before, after)); }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }
    }
}
