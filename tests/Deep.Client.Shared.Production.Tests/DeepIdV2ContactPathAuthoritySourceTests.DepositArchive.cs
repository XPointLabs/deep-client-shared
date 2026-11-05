using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")] [InlineData("BeforeSeal")] [InlineData("AfterSeal")]
    [InlineData("pending-send")] [InlineData("closed-acquisition")] [InlineData("guard")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2DepositArchive_FullWorkingJournalPreservesExactStoreAndColdRecovery(string fault)
    {
        // Genuine native Initial, signed MAU/quorum, encrypted SQL and actual
        // pressure producer/consumers. Occupancy uses127 individually signed
        // fixture acquisitions inserted through the codec in one batch: this
        // is not128 network deliveries or physical-runtime qualification.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckReferencedDepositArchiveAsync(fault);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2DepositArchive_OrdinaryNativePeerAndArchivedStoreStayExactAtFullWorkingCapacity()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckReferencedDepositArchiveAsync("none", "ordinary");
    }

    private sealed partial class Fixture
    {
        internal async Task CheckReferencedDepositArchiveAsync(string fault, string kind = "initial")
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            var test = await PrepareStoreMonotonicityCase(kind);
            test.Grants.MaximumFixtureGrantLifetimeSeconds = 120;
            test.Transport.LoseReply = true;
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
            var reply = test.Transport.CopyOriginalQuorumForFixture();
            var native = (await ReadMessagingFloor(test.Scope)).Exact.ToArray();
            var originalRequest = test.Transport.ExactRequest!.ToArray();
            byte[] original, full, sendRoot;
            using (var grants = await ReadPeerGrantsAsync(own: true)) original = Assert.Single(grants.Entries).Value.ToArray();
            using (var sends = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException())
                sendRoot = sends.Use(bytes => bytes.ToArray());
            var name = ProtectedDid2MailboxGrantJournal.Acquisition(original);
            var slot = ProtectedDid2MailboxGrantJournal.RetainedSlot(Convert.FromHexString(name));
            full = await FillSignedDepositWorkingSetAsync(test, original, fault == "closed-acquisition");
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2",
                ProtectedDid2MailboxGrantJournal.Response(original).Span).Field(8).Span);
            AdvanceStoreSettlementClock(grant.ExpiresAtUnixSeconds + 6);
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            var reader = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
            var hit = false;
            try
            {
                if (fault == "pending-send")
                {
                    using var sends = ProtectedDid2MailboxSendJournal.Decode(sendRoot, Network, test.Scope.LocalAccount, test.Scope.Instance);
                    var send = Assert.Single(sends.Entries).Value;
                    var bytes = send.Exact.ToArray(); bytes[296] = 1; bytes.AsSpan(256, 40).Clear();
                    sends.Entries[send.Name] = ProtectedDid2MailboxSendJournal.Entry.Decode(bytes); send.Dispose(); sends.Revision++;
                    var pending = ProtectedDid2MailboxSendJournal.Encode(sends, Network, test.Scope.LocalAccount, test.Scope.Instance);
                    try { Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, sendRoot, pending)); }
                    finally { CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(pending); }
                }
                using (Did2AcquisitionRetentionTestHooks.Push(point =>
                {
                    if (fault == point.ToString()) { hit = true; throw new IOException("Interrupted exact Deposit archival."); }
                    if (fault == "guard" && point == Did2AcquisitionRetentionFailpoint.BeforeSeal)
                    {
                        hit = true;
                        using var sends = ProtectedDid2MailboxSendJournal.Decode(sendRoot, Network, test.Scope.LocalAccount, test.Scope.Instance);
                        sends.Revision++;
                        var changed = ProtectedDid2MailboxSendJournal.Encode(sends, Network, test.Scope.LocalAccount, test.Scope.Instance);
                        try { Assert.True(storage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, sendRoot, changed).GetAwaiter().GetResult()); }
                        finally { CryptographicOperations.ZeroMemory(changed); }
                    }
                }))
                {
                    if (fault == "none") Assert.Equal(0, (await SynchronizeNativeSender(reader, terminal)).ProcessedEnvelopes);
                    else if (fault == "guard") await Assert.ThrowsAsync<CryptographicException>(() => SynchronizeNativeSender(reader, terminal));
                    else await Assert.ThrowsAsync<IOException>(() => SynchronizeNativeSender(reader, terminal));
                }
                if (fault is "pending-send" or "closed-acquisition" or "guard")
                {
                    Assert.Equal(fault == "guard", hit); Assert.Equal(0, reader.Calls); Assert.Equal(0, terminal.RetrieveCalls);
                    using var actual = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                    Assert.Equal(full, actual.Use(bytes => bytes.ToArray()));
                    using var absent = await storage.ReadOwnedAsync(slot); Assert.Null(absent);
                    Assert.Equal(1, test.Grants.Calls); Assert.Equal(1, test.Transport.Calls);
                    return;
                }
                if (fault != "none")
                {
                    Assert.True(hit); Assert.Equal(0, reader.Calls); Assert.Equal(0, terminal.RetrieveCalls);
                    ColdReopenCompactionStorage();
                    Assert.Equal(0, (await SynchronizeNativeSender(reader, terminal)).ProcessedEnvelopes);
                }
                ColdReopenCompactionStorage();
                using (var grants = await ReadPeerGrantsAsync(own: true))
                {
                    Assert.Equal(128, grants.Entries.Count); Assert.Single(grants.Retained);
                    Assert.False(grants.Entries.ContainsKey(name)); Assert.Equal(1, grants.Retained[name].Phase);
                    using var raw = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                    using var retained = raw.Use(bytes => ProtectedDid2MailboxGrantJournal.DecodeRetained(grants, name, bytes,
                        Network, test.Scope.LocalAccount, test.Scope.Instance));
                    Assert.Equal(original, Assert.Single(retained.Entries).Value);
                }
                using (var actual = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException())
                    Assert.Equal(sendRoot, actual.Use(bytes => bytes.ToArray()));
                // Existing retry reopens the expired archived original before
                // closure; stop before any successor or new transport effect.
                var closureHit = false;
                using (Did2MailboxSendTestHooks.Push(point =>
                    { if (point == Did2MailboxSendFailpoint.BeforeClosureRoot) { closureHit = true; throw new IOException("Stop before replacement work."); } }))
                    await Assert.ThrowsAsync<IOException>(test.Deliver);
                Assert.True(closureHit); Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
                if (fault == "none") await CheckDepositArchiveNegativesAsync(test, reply, slot, name);
                var settled = await AdoptStoreSettlement(test, reply);
                Assert.NotNull(settled.Cursor); Assert.False(settled.IngressDispatched);
                ColdReopenCompactionStorage();
                var cached = await test.Deliver();
                Assert.Equal(settled.Cursor, cached.Cursor); Assert.False(cached.IngressDispatched);
                Assert.Equal(originalRequest, test.Transport.ExactRequest);
                Assert.Equal(native, (await ReadMessagingFloor(test.Scope)).Exact.ToArray());
                Assert.Equal(1, test.Grants.Calls); Assert.Equal(1, test.Transport.Calls);
                Assert.Equal(1, reader.Calls); Assert.Equal(1, terminal.RetrieveCalls);
                // The original dependency-closed cleanup consumes the archived
                // source, removes only the send row, and keeps its replay floor.
                await CleanupSettledStoreCase(test, kind);
                ColdReopenCompactionStorage();
                using (var sends = await ReadMailboxSends(own: true)) { Assert.Empty(sends.Entries); Assert.Single(sends.Floors); }
                Assert.Equal(settled.Cursor, (await test.Deliver()).Cursor);
                using var stillRetained = await storage.ReadOwnedAsync(slot); Assert.NotNull(stillRetained);
            }
            finally
            {
                foreach (var bytes in new[] { reply, native, originalRequest, original, full, sendRoot }) CryptographicOperations.ZeroMemory(bytes);
            }
        }

        private async Task<byte[]> FillSignedDepositWorkingSetAsync(CompletedContactSendCase test, byte[] original, bool closedLast)
        {
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            var before = raw.Use(bytes => bytes.ToArray());
            try
            {
                using var grants = ProtectedDid2MailboxGrantJournal.Decode(before, Network, test.Scope.LocalAccount, test.Scope.Instance);
                var route = test.Grants.Route ?? throw new InvalidDataException();
                var prior = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(original).Span);
                var policy = await CurrentGrantPolicyAsync(route);
                var scope = Convert.ToHexString(original.AsSpan(0, 32));
                while (grants.Entries.Count < ProtectedDid2MailboxGrantJournal.MaximumEntries)
                {
                    var seed = RandomNumberGenerator.GetBytes(32);
                    try
                    {
                        using var holder = ReachabilityMailboxHolderAuthority.OpenRetained(route, prior.Field(3), prior.Field(4), MailboxCapabilityDomain.Deposit, seed);
                        var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, prior.Field(3), holder);
                        var pending = ProtectedDid2MailboxGrantJournal.Pending(seed, route, request, policy,
                            ContactCodec.Decode("PMT2", operational.ExactPmt2.Span), Network);
                        ProtectedDid2MailboxGrantJournal.AddPending(grants, pending);
                        if (closedLast && grants.Entries.Count == 128)
                        {
                            // Genuine signed request, structurally closed but no
                            // result: all older holders in this chain stay pinned.
                            var closed = ProtectedDid2MailboxGrantJournal.WithClosedUnresolved(pending,
                                ProtectedDid2MailboxGrantJournal.RequestExpiry(pending), Network);
                            grants.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(pending)] = closed;
                            CryptographicOperations.ZeroMemory(pending); ProtectedDid2MailboxGrantJournal.ClosePending(grants, scope);
                        }
                        else
                        {
                            var response = await IssueOwnedGrantAsync(request, route, retrieve: false, default);
                            try
                            {
                                _ = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(route, request, response, policy.ExactPma2);
                                grants.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(pending)] = ProtectedDid2MailboxGrantJournal.WithWinner(pending, response, Network);
                            }
                            finally { CryptographicOperations.ZeroMemory(response); CryptographicOperations.ZeroMemory(pending); }
                            ProtectedDid2MailboxGrantJournal.PromoteWinner(grants, scope);
                        }
                        grants.Revision++;
                    }
                    finally { CryptographicOperations.ZeroMemory(seed); }
                }
                var full = ProtectedDid2MailboxGrantJournal.Encode(grants, Network, test.Scope.LocalAccount, test.Scope.Instance);
                Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, before, full));
                return full;
            }
            finally { CryptographicOperations.ZeroMemory(before); }
        }

        private async Task CheckDepositArchiveNegativesAsync(CompletedContactSendCase test, byte[] reply, string slot, string name)
        {
            using var raw = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
            var exact = raw.Use(bytes => bytes.ToArray());
            try
            {
                foreach (var fault in new[] { "missing", "tamper", "wrong-hash", "foreign", "foreign-reference", "wrong-grant" })
                {
                    byte[] rootBefore = [], sendBefore = [];
                    if (fault is "missing" or "tamper" or "foreign")
                    {
                        if (fault == "missing") await storage.DeleteBatchAsync([slot]);
                        else
                        {
                            var corrupt = exact.ToArray();
                            if (fault == "foreign") corrupt[60] ^= 1; else corrupt[^1] ^= 1;
                            try { Assert.True(await storage.CompareExchangeAsync(slot, exact, corrupt)); }
                            finally { CryptographicOperations.ZeroMemory(corrupt); }
                        }
                    }
                    else if (fault == "wrong-grant")
                    {
                        using var send = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                        sendBefore = send.Use(bytes => bytes.ToArray());
                        using var sends = ProtectedDid2MailboxSendJournal.Decode(sendBefore, Network, test.Scope.LocalAccount, test.Scope.Instance);
                        using var grants = await ReadPeerGrantsAsync(own: true);
                        var other = grants.Entries.Values.First(entry => ContactCodec.Decode("XMG2",
                            ProtectedDid2MailboxGrantJournal.Request(entry).Span).Field(6).Span[0] == (byte)MailboxCapabilityDomain.Deposit);
                        var otherBytes = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(other).Span).Field(8);
                        var otherGrant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(otherBytes.Span);
                        var original = Assert.Single(sends.Entries).Value; var bytes = original.Exact.ToArray();
                        SHA256.HashData(otherBytes.Span).CopyTo(bytes, 96);
                        sends.EnrollGrant(otherGrant); sends.AdvanceCounter(SHA256.HashData(otherBytes.Span), original.Counter);
                        sends.Entries[original.Name] = ProtectedDid2MailboxSendJournal.Entry.Decode(bytes); original.Dispose(); sends.Revision++;
                        var changed = ProtectedDid2MailboxSendJournal.Encode(sends, Network, test.Scope.LocalAccount, test.Scope.Instance);
                        try { Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, sendBefore, changed)); }
                        finally { CryptographicOperations.ZeroMemory(changed); CryptographicOperations.ZeroMemory(bytes); }
                    }
                    else
                    {
                        using var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                        rootBefore = root.Use(bytes => bytes.ToArray());
                        using var grants = ProtectedDid2MailboxGrantJournal.Decode(rootBefore, Network, test.Scope.LocalAccount, test.Scope.Instance);
                        if (fault == "wrong-hash") grants.Retained[name].EntryHash[0] ^= 1;
                        else
                        {
                            var entry = grants.Retained[name]; grants.Retained.Remove(name);
                            grants.Retained.Add(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)), entry);
                        }
                        var changed = ProtectedDid2MailboxGrantJournal.Encode(grants, Network, test.Scope.LocalAccount, test.Scope.Instance);
                        try { Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, rootBefore, changed)); }
                        finally { CryptographicOperations.ZeroMemory(changed); }
                    }
                    try
                    {
                        ColdReopenCompactionStorage();
                        var error = await Record.ExceptionAsync(() => AdoptStoreSettlement(test, reply));
                        Assert.True(error is CryptographicException or InvalidDataException or FormatException, error?.GetType().Name ?? "Unexpected archive acceptance");
                        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
                    }
                    finally
                    {
                        // Disposable corruption fixture restoration only.
                        if (rootBefore.Length != 0) await Restore(ProtectedDid2MailboxGrantJournal.Slot, rootBefore);
                        else if (sendBefore.Length != 0) await Restore(ProtectedDid2MailboxSendJournal.Slot, sendBefore);
                        else if (fault == "missing") await storage.WriteBatchAsync([new(slot, exact)]);
                        else await Restore(slot, exact);
                        CryptographicOperations.ZeroMemory(rootBefore); CryptographicOperations.ZeroMemory(sendBefore);
                        ColdReopenCompactionStorage();
                    }
                }
                async Task Restore(string target, byte[] expected)
                {
                    using var current = await storage.ReadOwnedAsync(target) ?? throw new InvalidDataException();
                    var before = current.Use(bytes => bytes.ToArray());
                    try { Assert.True(await storage.CompareExchangeAsync(target, before, expected)); }
                    finally { CryptographicOperations.ZeroMemory(before); }
                }
            }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }
    }
}
