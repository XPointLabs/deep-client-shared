using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")] [InlineData("conflict-root")] [InlineData("conflict-slot")]
    [InlineData("corrupt-copy")] [InlineData("corrupt-reference")] [InlineData("foreign-instance")]
    public async Task Did2AcquisitionRetention_ExactCodecAndAtomicProtectedMove(string fault)
    {
        // Codec/storage contract only, not an authority to archive by expiry.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckAutomaticDepositRenewalAsync("none", fault);
    }

    [Theory]
    [InlineData("none")] [InlineData("BeforeSeal")] [InlineData("AfterSeal")]
    public async Task Did2AcquisitionRetention_ActualPressureKeepsOriginalsFloorsAndColdHandoff(string fault)
    {
        // Actual producer, signed requests, native account and encrypted disk.
        // In-process courier is not physical network/release evidence.
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 1_200);
        await fixture.CheckAcquisitionRetentionPressureAsync(fault);
    }

    [Theory]
    [InlineData("batch-none")] [InlineData("batch-conflict-root")]
    [InlineData("batch-conflict-slot")] [InlineData("batch-cancelled")]
    public async Task Did2AcquisitionRetention_EightOriginalsCommitTogetherOrLeaveExactPredecessor(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 1_200);
        await fixture.CheckAcquisitionRetentionPressureAsync(fault);
    }

    [Theory]
    [InlineData("epoch-none")] [InlineData("epoch-BeforeRestore")] [InlineData("epoch-AfterRestore")]
    [InlineData("epoch-BeforeDelete")] [InlineData("epoch-AfterDelete")]
    public async Task Did2AcquisitionRetention_SealedCustodyRetiresOnlyThroughGenuineEpochAndColdHandoffs(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 1_200);
        await fixture.CheckAcquisitionRetentionPressureAsync(fault);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckRetainedAcquisitionCodecAsync(byte[] original, string fault)
        {
            using var raw = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            var before = raw.Use(bytes => bytes.ToArray());
            using var state = await ReadPeerGrantsAsync();
            var name = ProtectedDid2MailboxGrantJournal.Acquisition(original);
            var selected = Assert.Single(state.Selections).Value.Current;
            var account = before.AsSpan(28, 32).ToArray(); var instance = before.AsSpan(60, 32).ToArray();
            var (working, retained) = ProtectedDid2MailboxGrantJournal.SealOldest(state, Convert.FromHexString(name), Network, account, instance);
            var slot = ProtectedDid2MailboxGrantJournal.RetainedSlot(Convert.FromHexString(name));
            try
            {
                using var cold = ProtectedDid2MailboxGrantJournal.Decode(working, Network, account, instance);
                Assert.Single(cold.Entries); Assert.Single(cold.Retained);
                Assert.Equal(selected, Assert.Single(cold.Selections).Value.Current);
                Assert.Throws<IOException>(() => ProtectedDid2MailboxGrantJournal.AcquisitionForRenewal(cold,
                    Assert.Single(cold.Selections).Key, Convert.FromHexString(name), MailboxCapabilityDomain.Deposit));
                if (fault is "corrupt-copy" or "foreign-instance")
                {
                    if (fault == "corrupt-copy") retained[^1] ^= 1; else instance[0] ^= 1;
                    var error = Record.Exception(() => ProtectedDid2MailboxGrantJournal.DecodeRetained(cold, name, retained, Network, account, instance));
                    Assert.True(error is CryptographicException or InvalidDataException or FormatException);
                    return;
                }
                if (fault == "corrupt-reference")
                {
                    cold.Retained[name].EntryHash[0] ^= 1;
                    Assert.Throws<CryptographicException>(() => ProtectedDid2MailboxGrantJournal.DecodeRetained(cold, name, retained, Network, account, instance));
                    return;
                }
                using var exact = ProtectedDid2MailboxGrantJournal.DecodeRetained(cold, name, retained, Network, account, instance);
                Assert.Equal(original, Assert.Single(exact.Entries).Value);
                var restore = ProtectedDid2MailboxGrantJournal.RestoreRetainedOldest(cold, name, original, Network, account, instance);
                try
                {
                    using var restored = ProtectedDid2MailboxGrantJournal.Decode(restore, Network, account, instance);
                    Assert.Equal(2, restored.Entries.Count); Assert.Equal(2, restored.Retained[name].Phase);
                    Assert.Equal(selected, Assert.Single(restored.Selections).Value.Current);
                    Assert.Equal(original, restored.Entries[name]);
                }
                finally { CryptographicOperations.ZeroMemory(restore); }
                if (fault == "conflict-slot") await peerStorage.WriteBatchAsync([new(slot, retained)]);
                var expected = before.ToArray();
                if (fault == "conflict-root") expected[4] ^= 1;
                try
                {
                    var applied = await peerStorage.CompareExchangeAndInsertAsync(ProtectedDid2MailboxGrantJournal.Slot,
                        expected, working, [new(slot, retained)]);
                    Assert.Equal(fault == "none", applied);
                    using var actual = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                    Assert.Equal(applied ? working : before, actual.Use(bytes => bytes.ToArray()));
                    using var sealedRaw = await peerStorage.ReadOwnedAsync(slot);
                    if (applied || fault == "conflict-slot") Assert.Equal(retained, sealedRaw!.Use(bytes => bytes.ToArray()));
                    else Assert.Null(sealedRaw);
                    if (applied)
                    {
                        ColdReopenReceiverStoreStorage();
                        using var reopened = await ReadPeerGrantsAsync();
                        Assert.Single(reopened.Retained); Assert.Single(reopened.Entries);
                    }
                }
                finally { CryptographicOperations.ZeroMemory(expected); }
            }
            finally { foreach (var bytes in new[] { before, working, retained, account, instance }) CryptographicOperations.ZeroMemory(bytes); }
        }

        internal async Task CheckAcquisitionRetentionPressureAsync(string fault)
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            await AdvanceOriginalStoreEpochForTestAsync(1_206);
            TrackMailboxDispatchClock();
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            var originals = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var hit = false; ulong expiry = 0;
            try
            {
                for (var ordinal = 0; ordinal < 20; ordinal++)
                {
                    if (expiry != 0)
                    { var delta = checked(expiry + 6 - CurrentProofTime); ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta); }
                    var issuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true) { MaximumFixtureGrantLifetimeSeconds = 34 };
                    using var beforeReads = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
                    var before = beforeReads.Use(bytes => bytes.ToArray());
                    try
                    {
                        if (ordinal == 17 && fault is "BeforeSeal" or "AfterSeal")
                        {
                            using (Did2AcquisitionRetentionTestHooks.Push(point =>
                                { if (!hit && point.ToString() == fault) { hit = true; throw new IOException("Interrupted exact acquisition move."); } }))
                                await Assert.ThrowsAsync<IOException>(() => SynchronizeNativeSender(issuer, terminal));
                            Assert.True(hit); Assert.Equal(0, issuer.Calls);
                            using var afterReads = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
                            Assert.Equal(before, afterReads.Use(bytes => bytes.ToArray()));
                            ColdReopenCompactionStorage();
                        }
                        Assert.Equal(0, (await SynchronizeNativeSender(issuer, terminal)).ProcessedEnvelopes);
                    }
                    finally { CryptographicOperations.ZeroMemory(before); }
                    Assert.Equal(1, issuer.Calls);
                    using var grants = await ReadPeerGrantsAsync(own: true);
                    var name = Convert.ToHexString(SHA256.HashData(issuer.OriginalRequest.Span));
                    var captured = grants.Entries[name].ToArray(); captured.AsSpan(1045, 32).Clear();
                    originals.Add(name, captured);
                    expiry = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", issuer.OriginalResponse.Span).Field(8).Span).ExpiresAtUnixSeconds;
                    Assert.Equal(ordinal + 1, grants.Entries.Count + grants.Retained.Count);
                    using var reads = await ReadPeerMailboxReads(own: true);
                    Assert.Equal(ordinal + 1, reads.Counters.Count); Assert.Null(reads.Active); Assert.Equal(0, reads.Phase);
                    foreach (var entry in originals.Values)
                        Assert.True(reads.Counters[Convert.ToHexString(SHA256.HashData(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span))] > 0);
                    foreach (var pair in grants.Retained)
                    {
                        Assert.Equal(1, pair.Value.Phase);
                        using var sealedRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.RetainedSlot(Convert.FromHexString(pair.Key))) ?? throw new InvalidDataException();
                        using var retained = sealedRaw.Use(bytes => ProtectedDid2MailboxGrantJournal.DecodeRetained(grants, pair.Key,
                            bytes, Network, bytes.Slice(28, 32), bytes.Slice(60, 32)));
                        Assert.Equal(originals[pair.Key], Assert.Single(retained.Entries).Value);
                    }
                }
                ColdReopenCompactionStorage();
                using var final = await ReadPeerGrantsAsync(own: true);
                Assert.NotEmpty(final.Retained); Assert.Equal(20, final.Entries.Count + final.Retained.Count);
                Assert.Equal(20, terminal.RetrieveCalls);
                if (fault.StartsWith("epoch-", StringComparison.Ordinal))
                    await CheckRetainedAcquisitionEpochCleanupAsync(terminal, fault[6..]);
                if (fault.StartsWith("batch-", StringComparison.Ordinal))
                    await CheckAcquisitionBatchStorageAsync(fault[6..]);
            }
            finally { foreach (var original in originals.Values) CryptographicOperations.ZeroMemory(original); }
        }

        private async Task CheckAcquisitionBatchStorageAsync(string fault)
        {
            // Codec/storage contract on eight real signed predecessors. This
            // does not manufacture a business permission to archive a holder.
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            using var readRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
            var before = raw.Use(bytes => bytes.ToArray()); var account = before.AsSpan(28, 32).ToArray();
            var instance = before.AsSpan(60, 32).ToArray(); byte[] replacement = [];
            var copies = new List<(string Slot, byte[] Bytes)>();
            try
            {
                using var state = ProtectedDid2MailboxGrantJournal.Decode(before, Network, account, instance);
                var originalCount = state.Entries.Count; var retainedCount = state.Retained.Count;
                for (var index = 0; index < 8; index++)
                {
                    string? name = null;
                    foreach (var candidate in state.Entries.Keys)
                    {
                        try { _ = ProtectedDid2MailboxGrantJournal.RequireSealableOldest(state, Convert.FromHexString(candidate)); name = candidate; break; }
                        catch (IOException) { }
                    }
                    Assert.NotNull(name);
                    var acquisition = Convert.FromHexString(name);
                    copies.Add((ProtectedDid2MailboxGrantJournal.RetainedSlot(acquisition),
                        ProtectedDid2MailboxGrantJournal.StageSealedOldest(state, acquisition, Network, account, instance)));
                }
                replacement = ProtectedDid2MailboxGrantJournal.Encode(state, Network, account, instance);
                var writes = copies.Select(copy => new DeepSecureStorageWrite(copy.Slot, copy.Bytes)).ToArray();
                if (fault == "conflict-slot") await storage.WriteBatchAsync([writes[^1]]);
                var expected = before.ToArray();
                using var cancelled = new CancellationTokenSource();
                if (fault == "conflict-root") expected[4] ^= 1;
                if (fault == "cancelled") cancelled.Cancel();
                try
                {
                    if (fault == "cancelled")
                        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => storage.CompareExchangeAndInsertAsync(
                            ProtectedDid2MailboxGrantJournal.Slot, expected, replacement, writes, cancelled.Token));
                    else Assert.Equal(fault == "none", await storage.CompareExchangeAndInsertAsync(
                        ProtectedDid2MailboxGrantJournal.Slot, expected, replacement, writes));
                }
                finally { CryptographicOperations.ZeroMemory(expected); }
                ColdReopenCompactionStorage();
                using var after = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(fault == "none" ? replacement : before, after.Use(bytes => bytes.ToArray()));
                using var cold = await ReadPeerGrantsAsync(own: true);
                Assert.Equal(originalCount - (fault == "none" ? 8 : 0), cold.Entries.Count);
                Assert.Equal(retainedCount + (fault == "none" ? 8 : 0), cold.Retained.Count);
                foreach (var copy in copies)
                {
                    using var actual = await storage.ReadOwnedAsync(copy.Slot);
                    if (fault == "none" || fault == "conflict-slot" && copy.Slot == copies[^1].Slot)
                        Assert.Equal(copy.Bytes, actual!.Use(bytes => bytes.ToArray()));
                    else Assert.Null(actual);
                }
                using var afterReads = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(readRoot.Use(bytes => bytes.ToArray()), afterReads.Use(bytes => bytes.ToArray()));
            }
            finally
            {
                foreach (var bytes in new[] { before, account, instance, replacement }) CryptographicOperations.ZeroMemory(bytes);
                foreach (var copy in copies) CryptographicOperations.ZeroMemory(copy.Bytes);
            }
        }

        private async Task CheckRetainedAcquisitionEpochCleanupAsync(OwnedReadTerminal terminal, string fault)
        {
            string[] names;
            using (var before = await ReadPeerGrantsAsync(own: true)) names = before.Retained.Keys.ToArray();
            await AdvanceCurrentRoutingAuthorityAsync(6_006);
            ColdReopenCompactionStorage();
            var hit = false; var issuances = 0;
            for (var step = 0; step < 48; step++)
            {
                var issuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true)
                    { MaximumFixtureGrantLifetimeSeconds = 120 };
                using (Did2AcquisitionRetentionTestHooks.Push(point =>
                    { if (!hit && point.ToString() == fault) { hit = true; throw new IOException("Interrupted retained custody epoch handoff."); } }))
                {
                    var error = await Record.ExceptionAsync(() => SynchronizeNativeSender(issuer, terminal));
                    issuances += issuer.Calls;
                    if (error is not null)
                    {
                        Assert.IsType<IOException>(error); Assert.True(hit);
                        ColdReopenCompactionStorage();
                    }
                }
                using var after = await ReadPeerGrantsAsync(own: true);
                if (after.Retained.Count != 0) continue;
                foreach (var name in names)
                {
                    using var deleted = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.RetainedSlot(Convert.FromHexString(name)));
                    Assert.Null(deleted);
                }
                Assert.Equal(1, issuances); // Restoration never reissues an original XMG.
                Assert.Equal(fault != "none", hit);
                ColdReopenCompactionStorage();
                using var cold = await ReadPeerGrantsAsync(own: true);
                Assert.Empty(cold.Retained);
                using var reads = await ReadPeerMailboxReads(own: true);
                Assert.Null(reads.Active); Assert.Equal(0, reads.Phase);
                return;
            }
            Assert.Fail("Genuine epoch closure did not finish bounded sealed custody cleanup.");
        }
    }
}
