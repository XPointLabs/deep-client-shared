using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("ordinary", "none")] [InlineData("ordinary", "AfterStage")] [InlineData("ordinary", "AfterHistoryAdopted")]
    [InlineData("accept", "none")] [InlineData("accept", "AfterStage")] [InlineData("accept", "AfterHistoryAdopted")]
    [InlineData("ordinary", "GrantAfterStage")] [InlineData("accept", "GrantAfterStage")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2AutomaticNamespaceRetirement_NewAuthoringRetiresExcludedHoldersAndColdPlans(string kind, string fault)
    {
        // Normal owned authoring, actual namespace/floor/holder plans and
        // native PQ/SQLCipher; in-process signed Store is not physical E2E.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareUsedDepositAttemptCase(kind);
        var stored = await fixture.DeliverCompletedCaseWithExactRetry(test);
        fixture.AdvanceSyntheticMailboxClockPast(test.Transport.DurableTimeForFixture);
        await fixture.CleanupSettledStoreCase(test, kind);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var originalSource = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        var issuerCalls = test.Grants.Calls; var ingressCalls = test.Transport.Calls;
        byte[]? operation = null;
        async Task Prepare()
        {
            using var text = operation is null
                ? await fixture.CreateOwnedText(test.Scope, "automatic namespace maintenance preserves original Store")
                : await fixture.RetryOwnedText(test.Scope, operation, "automatic namespace maintenance preserves original Store");
            operation ??= text.OperationId.ToArray();
            Assert.True(operation.AsSpan().SequenceEqual(text.OperationId.Span));
        }
        try
        {
            if (fault != "none")
            {
                var hit = false; var cleared = 0;
                var point = fault == "GrantAfterStage" ? Did2CompactionFailpoint.AfterStage : Enum.Parse<Did2CompactionFailpoint>(fault);
                using (Did2CompactionTestHooks.Push(actual =>
                    {
                        if (actual == Did2CompactionFailpoint.AfterPlanCleared) cleared++;
                        if (!hit && actual == point && (fault != "GrantAfterStage" || cleared >= 1))
                        { hit = true; throw new IOException("Interrupted automatic namespace transition."); }
                    }))
                    await Assert.ThrowsAsync<IOException>(Prepare);
                Assert.True(hit);
                Assert.Null(operation);
                using (var ordinary = await fixture.ReadAuthoredTextJournalAsync(test.Scope))
                { Assert.Empty(ordinary.Entries); Assert.Null(ordinary.Pending); }
                Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
                fixture.ColdReopenStoreSettlement(test.Scope);
            }
            await Prepare();
            fixture.ColdReopenStoreSettlement(test.Scope);
            await Prepare(); // Exact authoring retry cannot acquire/delete anything else.
            using (var grants = await fixture.ReadPeerGrantsAsync(own: test.Scope.IsInitiator))
            { Assert.Empty(grants.Entries); Assert.Empty(grants.Selections); }
            using (var sends = await fixture.ReadMailboxSends(own: test.Scope.IsInitiator))
            { Assert.Empty(sends.Entries); Assert.Empty(sends.Floors); }
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Equal(originalSource, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
            var cached = await test.Deliver();
            Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
            Assert.Equal(issuerCalls, test.Grants.Calls); Assert.Equal(ingressCalls, test.Transport.Calls);
        }
        finally { CryptographicOperations.ZeroMemory(native); CryptographicOperations.ZeroMemory(originalSource); }
    }

    [Theory]
    [InlineData("ordinary", false)] [InlineData("ordinary", true)]
    [InlineData("accept", false)] [InlineData("accept", true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2AutomaticNamespaceRetirement_ExpiryAloneAndUnknownWorkKeepOriginalCustody(string kind, bool unknown)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareUsedDepositAttemptCase(kind);
        test.Grants.MaximumFixtureGrantLifetimeSeconds = 120; test.Transport.LoseReply = unknown;
        if (unknown) await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        else
        {
            await fixture.DeliverCompletedCaseWithExactRetry(test);
            fixture.AdvanceSyntheticMailboxClockPast(test.Transport.DurableTimeForFixture);
            await fixture.CleanupSettledStoreCase(test, kind);
        }
        if (unknown) await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        else
        {
            using var grants = await fixture.ReadPeerGrantsAsync(own: test.Scope.IsInitiator);
            fixture.AdvanceStoreSettlementClock(grants.Entries.Values.Max(entry => MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span).ExpiresAtUnixSeconds) + 6);
        }
        var secure = fixture.CompletedContactSendStorage(test.Scope.IsInitiator);
        using var originalGrant = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
        using var originalSend = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var issuerCalls = test.Grants.Calls; var ingressCalls = test.Transport.Calls;
        using var prepared = await fixture.CreateOwnedText(test.Scope, "pinned namespaces must not be evicted");
        using var actualGrant = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
        using var actualSend = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        Assert.Equal(originalGrant.Use(bytes => bytes.ToArray()), actualGrant.Use(bytes => bytes.ToArray()));
        Assert.Equal(originalSend.Use(bytes => bytes.ToArray()), actualSend.Use(bytes => bytes.ToArray()));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        Assert.Equal(issuerCalls, test.Grants.Calls); Assert.Equal(ingressCalls, test.Transport.Calls);
        CryptographicOperations.ZeroMemory(native);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2AutomaticNamespaceRetirement_IdleReaderKeepsLastHolderUntilReplacementReadCompletes()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        _ = await fixture.PrepareRetainedPublicationAsync(elapsed: false);
        fixture.TrackMailboxDispatchClock();
        var issuer = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: true);
        var terminal = new OwnedReadTerminal(fixture, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
        Assert.Equal(0, (await fixture.SynchronizeNativeSender(issuer, terminal)).ProcessedEnvelopes);
        byte[] acquisition;
        using (var grants = await fixture.ReadPeerGrantsAsync(own: true))
            acquisition = Convert.FromHexString(Assert.Single(grants.Entries).Key);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        var account = fixture.ReopenAccount();
        var replacementIssuer = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: true);
        _ = await account.RenewOwnPermanentContactRetrieveGrantAsync(acquisition, fixture.Source(account), replacementIssuer);
        byte[] replacement, exactReplacement;
        using (var grants = await fixture.ReadPeerGrantsAsync(own: true))
        {
            Assert.Equal(2, grants.Entries.Count);
            var current = Assert.Single(grants.Selections).Value.Current!;
            replacement = Convert.FromHexString(current);
            exactReplacement = ProtectedDid2MailboxGrantJournal.Response(grants.Entries[current]).ToArray();
        }
        var replacementTerminal = new OwnedReadTerminal(fixture, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
        Assert.Equal(0, (await fixture.SynchronizeNativeSender(issuer, replacementTerminal)).ProcessedEnvelopes);
        using (var grants = await fixture.ReadPeerGrantsAsync(own: true)) Assert.Equal(2, grants.Entries.Count);
        fixture.ColdReopenCompactionStorage();
        Assert.Equal(0, (await fixture.SynchronizeNativeSender(issuer, replacementTerminal)).ProcessedEnvelopes);
        using (var grants = await fixture.ReadPeerGrantsAsync(own: true))
        {
            var remaining = Assert.Single(grants.Entries);
            Assert.Equal(Convert.ToHexString(replacement), remaining.Key);
            Assert.Equal(exactReplacement, ProtectedDid2MailboxGrantJournal.Response(remaining.Value).ToArray());
            var selection = Assert.Single(grants.Selections).Value;
            Assert.Equal(remaining.Key, selection.Current); Assert.Equal(selection.Current, selection.RetainedTail);
        }
        Assert.Equal(1, issuer.Calls); Assert.Equal(1, replacementIssuer.Calls);
        Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(2, replacementTerminal.RetrieveCalls);
        foreach (var bytes in new[] { acquisition, replacement, exactReplacement }) CryptographicOperations.ZeroMemory(bytes);
    }
}
