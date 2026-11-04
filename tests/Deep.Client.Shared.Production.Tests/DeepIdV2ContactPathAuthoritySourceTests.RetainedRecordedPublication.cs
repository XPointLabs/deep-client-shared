using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("missing")]
    [InlineData("tampered")]
    [InlineData("foreign-instance")]
    [InlineData("changed-after-proof")]
    public async Task Did2RetainedRead_RecordedPromotionRequiresExactProtectedArchiveLineageAfterColdReopen(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true, objectHorizonWindow: true);
        await fixture.CheckRetainedRecordedPublicationAsync(defect);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2RetainedRead_TwoRecordedLinksRequireExactProposalAdjacencyAfterPromotion(bool corruptAdjacency)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true, objectHorizonWindow: true);
        await fixture.CheckStagedRecordedChainAsync(2, false, retainedReadDefect: corruptAdjacency ? "adjacency" : "none");
    }

    private sealed partial class Fixture
    {
        internal async Task CheckRetainedRecordedPublicationAsync(string defect)
        {
            // Genuine lost threshold reply, expiry, recorded-winner recovery and
            // permanent promotion; no synthetic committed publication/authority.
            var seeded = await SeedRecordedRenewalAsync();
            try
            {
                _ = await EnsureRecordedReopenedAsync(seeded.Backend);
                Assert.Equal(1, seeded.Backend.RecoveryReads); Assert.Equal(1, seeded.Backend.RecoveryIssues);
                await CheckRetainedRecordedPublicationAfterPromotionAsync(seeded.Permanent, seeded.Original, seeded.Pending, defect);
            }
            finally
            {
                foreach (var bytes in new[] { seeded.Permanent, seeded.Original, seeded.Pending }) CryptographicOperations.ZeroMemory(bytes);
            }
        }

        private async Task CheckRetainedRecordedPublicationAfterPromotionAsync(byte[] permanent, byte[] original, byte[] pending, string defect)
        {
            byte[] originalRoute = [], currentRoute = [], publicationBefore = [], readBeforeExact = [];
            try
            {
                using (var state = await RouteState())
                {
                    var current = state.Entries[Convert.ToHexString(permanent)];
                    var archived = Assert.Single(state.Entries.Values, entry => entry.Phase == 7 &&
                        !entry.Exact[..32].SequenceEqual(permanent));
                    Assert.NotEqual(pending.AsSpan(0, 32).ToArray(), archived.Exact[..32].ToArray());
                    Assert.Equal(original.AsSpan(32).ToArray(), archived.Exact[32..].ToArray());
                    originalRoute = ContactRouteClosureCodec.Decode(archived.Record(6).Span).ExactHash.ToArray();
                    currentRoute = ContactRouteClosureCodec.Decode(current.Record(6).Span).ExactHash.ToArray();
                    Assert.NotEqual(originalRoute, currentRoute);
                }
                var slot = ProtectedDid2ContactRenewalClosure.ClosedSlot(pending.AsSpan(0, 32));
                using (var raw = await storage.ReadOwnedAsync(slot))
                {
                    Assert.NotNull(raw);
                    if (defect is not ("none" or "changed-after-proof"))
                    {
                        var exact = raw!.Use(bytes => bytes.ToArray());
                        try
                        {
                            if (defect == "missing")
                                Assert.True(await storage.CompareAndDeleteAsync(slot, exact, [slot]));
                            else
                            {
                                var changed = exact.ToArray();
                                // Disposable fixture corruption only: the actual
                                // closure codec/owner must reject it without repair.
                                changed[defect == "foreign-instance" ? 56 : defect == "adjacency" ? 216 : 184] ^= 1;
                                try
                                {
                                    if (defect == "adjacency")
                                    {
                                        byte[] instance;
                                        using (var generation = await storage.ReadOwnedAsync("deep.store.v2.sql-generation"))
                                            instance = generation!.Use(bytes => bytes.Slice(56, 32).ToArray());
                                        try
                                        {
                                            using var canonical = ProtectedDid2ContactRenewalClosure.Decode(changed, Network,
                                                checkpoint.Directory.Record.DeepAccountId.Span, instance);
                                            Assert.Equal(changed, canonical.Exact.ToArray());
                                        }
                                        finally { CryptographicOperations.ZeroMemory(instance); }
                                    }
                                    Assert.True(await storage.CompareExchangeAsync(slot, exact, changed));
                                }
                                finally { CryptographicOperations.ZeroMemory(changed); }
                            }
                        }
                        finally { CryptographicOperations.ZeroMemory(exact); }
                    }
                }
                ColdReopenCompactionStorage();
                publicationBefore = await RouteSnapshot();
                using (var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot))
                    readBeforeExact = raw!.Use(bytes => bytes.ToArray());
                using var readBefore = await ReadPeerMailboxReads(own: true);
                var issuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
                var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
                var callbackHit = false;
                if (defect == "changed-after-proof") issuer.BeforeReturn = async () =>
                {
                    using var raw = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                    var exact = raw.Use(bytes => bytes.ToArray());
                    try { Assert.True(await storage.CompareAndDeleteAsync(slot, exact, [slot])); callbackHit = true; }
                    finally { CryptographicOperations.ZeroMemory(exact); }
                };
                if (defect == "none")
                {
                    Assert.Equal(0, (await SynchronizeNativeSender(issuer, terminal)).ProcessedEnvelopes);
                    Assert.Equal(currentRoute, Assert.Single(terminal.RetrievedOriginalRoutes));
                    ColdReopenCompactionStorage();
                    var archivedIssuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
                    var archivedTerminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
                    Assert.Equal(0, (await SynchronizeNativeSender(archivedIssuer, archivedTerminal)).ProcessedEnvelopes);
                    Assert.Equal(originalRoute, Assert.Single(archivedTerminal.RetrievedOriginalRoutes));
                    Assert.Equal(1, issuer.Calls); Assert.Equal(1, archivedIssuer.Calls);
                    Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(1, archivedTerminal.RetrieveCalls);
                    using var readAfter = await ReadPeerMailboxReads(own: true);
                    Assert.Equal(0, readAfter.Phase); Assert.Equal(2, readAfter.Traversals.Count);
                }
                else
                {
                    var error = await Record.ExceptionAsync(() => SynchronizeNativeSender(issuer, terminal));
                    if (defect == "adjacency")
                        Assert.Equal("Retained recorded publication changed its exact proposal adjacency.",
                            Assert.IsType<CryptographicException>(error).Message);
                    Assert.True(error is CryptographicException or InvalidDataException,
                        "Invalid recorded archive custody must fail before Retrieve or retained-read advancement.");
                    Assert.Equal(defect == "changed-after-proof", callbackHit);
                    Assert.Equal(callbackHit ? 1 : 0, issuer.Calls); Assert.Equal(0, terminal.RetrieveCalls); Assert.Equal(0, terminal.AckCalls);
                    using var readAfter = await ReadPeerMailboxReads(own: true);
                    Assert.Equal(readBefore.Revision, readAfter.Revision); Assert.Equal(readBefore.Phase, readAfter.Phase);
                    Assert.Equal(readBefore.Traversals.Count, readAfter.Traversals.Count);
                    using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot);
                    Assert.Equal(readBeforeExact, raw!.Use(bytes => bytes.ToArray()));
                }
                Assert.Equal(publicationBefore, await RouteSnapshot());
            }
            finally
            {
                foreach (var bytes in new[] { originalRoute, currentRoute, publicationBefore, readBeforeExact })
                    CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }
}
