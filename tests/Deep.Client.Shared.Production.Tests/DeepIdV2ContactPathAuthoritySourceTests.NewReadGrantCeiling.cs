using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2NewReadGrantCeiling_ColdReadsReuseExactWinnerAndExpiredWinnerStillRenews(bool pendingSuccessor)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckNewReadGrantCeilingAsync(pendingSuccessor);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2NewReadGrantCeiling_ShorterGrantStillRenewsAtRetryOrExpiryBoundary(bool expired)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckNewReadBelowGrantCeilingAsync(expired);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2NewReadGrantCeiling_CurrentPolicyFloorRenewsButCorruptSignatureCannotIssueAnotherHolder(bool corruptSignature)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckNewReadGrantCeilingTransitionAsync(corruptSignature);
    }

    [Fact]
    public async Task Did2NewReadGrantCeiling_CapturedFinalAckKeepsIndependentRenewalOfDueCurrentWinner()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var intent = Bytes(32, 0xc1);
        var (complete, _, _, _, _) = await fixture.PrepareNativeHelloCompletion(intent, verifyDraftRecovery: true);
        byte[] initial;
        using (var sent = await complete(fixture.Accounts)) initial = sent.ExactDph2.ToArray();
        var store = new OwnedStoreFixture(fixture, null, ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent), initial);
        _ = await fixture.StartNativeContact(intent, new OwnedGrantTransport(fixture, ownerOnPrimary: true), store);
        var first = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false)
            { MaximumFixtureGrantLifetimeSeconds = 120 };
        var terminal = new OwnedReadTerminal(fixture, initial) { RetainedEnvelope = store.StoredEnvelope };
        using (ClientMailboxRetrieveTestHooks.Push(point =>
            { if (point == ClientMailboxRetrieveFailpoint.AfterPageCommit) throw new IOException("Captured final page before ACK."); }))
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SynchronizeNativeReceiver(first, terminal));

        // A different current holder already exists while the captured page
        // retains its original grant. Later that current holder is due at its
        // fixed cap; captured ACK must keep ordinary independent renewal.
        var owner = fixture.ReopenGrantReader();
        var currentIssuer = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var current = await owner.RenewOwnPermanentContactRetrieveGrantAsync(
            SHA256.HashData(first.OriginalRequest.Span), fixture.GrantReaderSource(owner), currentIssuer);
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(current.ExactGrant.Span);
        Assert.Equal(2_000UL, grant.ExpiresAtUnixSeconds);
        fixture.AdvanceStoreSettlementClock(ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(
            grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds) - 5);
        fixture.ColdReopenReceiverStoreStorage();
        terminal.IndependentAck = true; terminal.ExpectedAckCounter = 1;
        var replacement = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var result = await fixture.SynchronizeNativeReceiver(replacement, terminal);
        Assert.Equal(1, result.ProcessedEnvelopes); Assert.Equal(1, result.DurableTombstones);
        Assert.Equal(1, replacement.Calls); Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
        Assert.NotEqual(currentIssuer.OriginalRequest.ToArray(), replacement.OriginalRequest.ToArray());
        using var reads = await fixture.ReadPeerMailboxReads();
        Assert.Null(reads.Active); Assert.Equal(0, reads.Phase);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckNewReadGrantCeilingTransitionAsync(bool corruptSignature)
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            var first = new OwnedGrantTransport(this, selfRetrieve: true);
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            Assert.Equal(0, (await SynchronizeNativeSender(first, terminal)).ProcessedEnvelopes);
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                ContactCodec.Decode("XMC2", first.OriginalResponse.Span).Field(8).Span);
            if (corruptSignature)
            {
                // Disposable protected corruption fixture: retain all canonical
                // metadata and framing while breaking only issuer authenticity.
                using var key = await innerStorage.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidDataException();
                using var root = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                var scope = key.Use(bytes => bytes.Slice(24, 64).ToArray());
                var before = root.Use(bytes => bytes.ToArray());
                try
                {
                    using var state = ProtectedDid2MailboxGrantJournal.Decode(before, Network, scope.AsSpan(0, 32), scope.AsSpan(32));
                    var entry = Assert.Single(state.Entries).Value;
                    var response = ProtectedDid2MailboxGrantJournal.Response(entry).ToArray();
                    var offset = entry.AsSpan().IndexOf(response);
                    Assert.True(offset >= 0); entry[offset + response.Length - 1] ^= 1;
                    state.Revision++;
                    var changed = ProtectedDid2MailboxGrantJournal.Encode(state, Network, scope.AsSpan(0, 32), scope.AsSpan(32));
                    try { Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, before, changed)); }
                    finally { CryptographicOperations.ZeroMemory(changed); }
                }
                finally { CryptographicOperations.ZeroMemory(scope); CryptographicOperations.ZeroMemory(before); }
            }
            else
            {
                // A real root-signed successor raises its grant floor without
                // extending the ceiling. The old authentic holder needs renewal.
                await AdvanceNetworkAsync(expiry: grant.ExpiresAtUnixSeconds);
                var exact = successor!.ExactPma2.ToArray();
                BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(FieldOffset(exact, 7)), checked(grant.Generation + 1));
                var candidate = ContactCodec.Decode("PMA2", exact);
                var rows = candidate.Field(16).ToArray();
                for (var offset = 0; offset < rows.Length; offset += 96)
                    root.SignCommit(candidate.SignatureInput).CopyTo(rows, offset + 32);
                rows.CopyTo(exact, FieldOffset(exact, 16));
                rotatedIssuerPma = ContactCodec.Decode("PMA2", exact).CanonicalBytes.ToArray();
                AuthorSignedEpochAdvance();
            }
            AdvanceStoreSettlementClock(ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(
                grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds) - 5);
            ColdReopenCompactionStorage();
            var replacement = new OwnedGrantTransport(this, selfRetrieve: true);
            using var frozen = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            if (corruptSignature)
            {
                await Assert.ThrowsAsync<CryptographicException>(() => SynchronizeNativeSender(replacement, terminal));
                Assert.Equal(0, replacement.Calls); Assert.Equal(1, terminal.RetrieveCalls);
                using var after = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(frozen.Use(bytes => bytes.ToArray()), after.Use(bytes => bytes.ToArray()));
            }
            else
            {
                Assert.Equal(0, (await SynchronizeNativeSender(replacement, terminal)).ProcessedEnvelopes);
                Assert.Equal(1, replacement.Calls);
                var next = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                    ContactCodec.Decode("XMC2", replacement.OriginalResponse.Span).Field(8).Span);
                Assert.Equal(grant.ExpiresAtUnixSeconds, next.ExpiresAtUnixSeconds);
                Assert.True(next.Generation > grant.Generation);
            }
        }

        internal async Task CheckNewReadGrantCeilingAsync(bool pendingSuccessor)
        {
            var route = await PrepareRetainedPublicationAsync(elapsed: false);
            var firstIssuer = new OwnedGrantTransport(this, selfRetrieve: true);
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            Assert.Equal(0, (await SynchronizeNativeSender(firstIssuer, terminal)).ProcessedEnvelopes);
            Assert.Equal(1, firstIssuer.Calls);
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                ContactCodec.Decode("XMC2", firstIssuer.OriginalResponse.Span).Field(8).Span);
            Assert.Equal(2_000UL, grant.ExpiresAtUnixSeconds);
            Assert.True(OriginalAdmissionEnd(route.Route) < grant.ExpiresAtUnixSeconds);
            var grantHash = Convert.ToHexString(SHA256.HashData(
                ContactCodec.Decode("XMC2", firstIssuer.OriginalResponse.Span).Field(8).Span));
            byte[] original;
            using (var state = await ReadPeerGrantsAsync(own: true)) original = Assert.Single(state.Entries).Value.ToArray();
            try
            {
                // The authenticated upper reaches the proactive margin after
                // original route admission ended. Each call starts a new real
                // read; no captured cycle or issuer callback supplies reuse.
                var refresh = ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds);
                AdvanceStoreSettlementClock(refresh - 5);
                for (var cold = 0; cold < 2; cold++)
                {
                    ColdReopenCompactionStorage();
                    var unused = new OwnedGrantTransport(this, selfRetrieve: true);
                    Assert.Equal(0, (await SynchronizeNativeSender(unused, terminal)).ProcessedEnvelopes);
                    Assert.Equal(0, unused.Calls);
                    using var state = await ReadPeerGrantsAsync(own: true);
                    Assert.Equal(original, Assert.Single(state.Entries).Value);
                    Assert.Null(Assert.Single(state.Selections).Value.Pending);
                    using var reads = await ReadPeerMailboxReads(own: true);
                    Assert.Null(reads.Active); Assert.Equal(0, reads.Phase);
                    Assert.Equal(checked((ulong)cold + 2), Assert.Single(reads.Counters).Value);
                    Assert.True(reads.Counters.ContainsKey(grantHash));
                }
                Assert.Equal(3, terminal.RetrieveCalls);

                if (pendingSuccessor)
                {
                    // Explicit renewal already owns a pending successor at the
                    // same ceiling. Ordinary new-work scheduling must resume it.
                    var pending = new OwnedGrantTransport(this, selfRetrieve: true) { LoseResponse = true };
                    var owner = ReopenAccount();
                    await Assert.ThrowsAsync<IOException>(() => owner.RenewOwnPermanentContactRetrieveGrantAsync(
                        SHA256.HashData(firstIssuer.OriginalRequest.Span), Source(owner), pending));
                    Assert.Equal(1, pending.Calls);
                    pending.LoseResponse = false;
                    ColdReopenCompactionStorage();
                    Assert.Equal(0, (await SynchronizeNativeSender(pending, terminal)).ProcessedEnvelopes);
                    Assert.Equal(2, pending.Calls); Assert.True(pending.ExactRetry);
                    using var resumed = await ReadPeerGrantsAsync(own: true);
                    Assert.Equal(2, resumed.Entries.Count);
                    Assert.Null(Assert.Single(resumed.Selections).Value.Pending);
                    Assert.Equal(Convert.ToHexString(SHA256.HashData(pending.OriginalRequest.Span)),
                        Assert.Single(resumed.Selections).Value.Current);
                    return;
                }

                // The same exact winner becomes expired; independently signed
                // current carriage now permits a replacement beyond its cap.
                await AdvanceOriginalStoreEpochForTestAsync(grant.ExpiresAtUnixSeconds + 6);
                ColdReopenCompactionStorage();
                var replacement = new OwnedGrantTransport(this, selfRetrieve: true);
                Assert.Equal(0, (await SynchronizeNativeSender(replacement, terminal)).ProcessedEnvelopes);
                Assert.Equal(1, replacement.Calls);
                var next = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                    ContactCodec.Decode("XMC2", replacement.OriginalResponse.Span).Field(8).Span);
                Assert.True(next.ExpiresAtUnixSeconds > grant.ExpiresAtUnixSeconds);
                using (var state = await ReadPeerGrantsAsync(own: true))
                {
                    Assert.Equal(2, state.Entries.Count);
                    Assert.Equal(original, state.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(original)]);
                }
                using var finalRead = await ReadPeerMailboxReads(own: true);
                Assert.Equal(2, finalRead.Counters.Count);
                Assert.Equal(3UL, finalRead.Counters[grantHash]);
            }
            finally { CryptographicOperations.ZeroMemory(original); }
        }

        internal async Task CheckNewReadBelowGrantCeilingAsync(bool expired)
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            var first = new OwnedGrantTransport(this, selfRetrieve: true) { MaximumFixtureGrantLifetimeSeconds = 40 };
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            Assert.Equal(0, (await SynchronizeNativeSender(first, terminal)).ProcessedEnvelopes);
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                ContactCodec.Decode("XMC2", first.OriginalResponse.Span).Field(8).Span);
            Assert.True(grant.ExpiresAtUnixSeconds < 2_000);
            // Retrieve's real request deadline plus five-second uncertainty is
            // 15 seconds. At the boundary the old grant still covers current
            // time, but a fresh holder can extend it under the signed policy.
            AdvanceStoreSettlementClock(expired ? grant.ExpiresAtUnixSeconds + 6 : grant.ExpiresAtUnixSeconds - 20);
            ColdReopenCompactionStorage();
            var replacement = new OwnedGrantTransport(this, selfRetrieve: true);
            Assert.Equal(0, (await SynchronizeNativeSender(replacement, terminal)).ProcessedEnvelopes);
            Assert.Equal(1, first.Calls); Assert.Equal(1, replacement.Calls);
            Assert.NotEqual(first.OriginalRequest.ToArray(), replacement.OriginalRequest.ToArray());
            var next = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                ContactCodec.Decode("XMC2", replacement.OriginalResponse.Span).Field(8).Span);
            Assert.True(next.ExpiresAtUnixSeconds > grant.ExpiresAtUnixSeconds);
            using var state = await ReadPeerGrantsAsync(own: true);
            Assert.Equal(2, state.Entries.Count);
        }
    }
}
