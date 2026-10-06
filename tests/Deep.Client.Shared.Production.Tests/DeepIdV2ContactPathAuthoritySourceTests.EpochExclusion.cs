using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2EpochExclusion_ActualClosedCustodyAndSignedAdvanceSurviveColdReopenWithoutDeletion(bool unresolved)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckEpochExclusionAsync(unresolved, advanceEpoch: true, fault: -1);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2EpochExclusion_OriginalCeilingAndOperationalRenewalAloneCannotExcludeNamespace(bool unresolved)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckEpochExclusionAsync(unresolved, advanceEpoch: false, fault: -1);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Did2EpochExclusion_ConsumerRejectsChangedRootAnchorClockOrExpiredProof(int fault)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckEpochExclusionAsync(unresolved: true, advanceEpoch: true, fault);
    }

    private sealed partial class Fixture
    {
        private ReadOnlyMemory<byte>? epochSuccessorPmt;

        // A genuinely threshold-signed fixture transition, not an operational
        // deployment/handover implementation or unsigned epoch override.
        private void AuthorSignedEpochAdvance()
        {
            var exact = successor!.ExactPmt2.ToArray();
            var prior = ContactCodec.Decode("PMT2", operational.ExactPmt2.Span);
            var offset = 12;
            for (var tag = 1; tag <= 16; tag++)
            {
                var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(offset + 4, 4)));
                offset += 8;
                if (tag == 6)
                    BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(offset, length),
                        checked(BinaryPrimitives.ReadUInt64BigEndian(prior.Field(6).Span) + 1));
                offset += length;
            }
            var candidate = ContactCodec.Decode("PMT2", exact);
            var input = candidate.SignatureInput;
            offset = exact.Length - candidate.Field(16).Length;
            for (var row = 0; row < candidate.Field(16).Length; row += 96)
            {
                var id = exact.AsSpan(offset + row, 32).ToArray();
                var signer = witnesses.Single(value => value.SignerId.Span.SequenceEqual(id));
                signer.SignCommit(input).CopyTo(exact, offset + row + 32);
            }
            epochSuccessorPmt = ContactCodec.Decode("PMT2", exact).CanonicalBytes;
        }

        internal async Task CheckEpochExclusionAsync(bool unresolved, bool advanceEpoch, int fault)
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this) { ShorterSignedExpiry = 1_200 };
            var route = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold,
                new OwnedPublicationSource(this, route), new OwnedPublicationReplica(this, route));
            var transport = new OwnedGrantTransport(this, selfRetrieve: true) { LoseResponse = unresolved };
            if (unresolved)
                await Assert.ThrowsAsync<IOException>(() => accounts.AcquireOwnPermanentContactRetrieveGrantAsync(Source(), transport));
            else _ = await accounts.AcquireOwnPermanentContactRetrieveGrantAsync(Source(), transport);
            byte[] selector;
            ulong ceiling, originalEpoch;
            using (var state = await ReadPeerGrantsAsync(own: true))
            {
                var entry = Assert.Single(state.Entries).Value;
                selector = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(entry));
                ceiling = ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(entry);
                Assert.Equal(1_200UL, ceiling);
                originalEpoch = BinaryPrimitives.ReadUInt64BigEndian(
                    ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span).Projection.Field(6).Span);
            }
            await Assert.ThrowsAsync<CryptographicException>(() => accounts.OpenMailboxEpochExclusionAsync(selector, Source()));
            await AdvanceNetworkAsync();
            if (advanceEpoch) AuthorSignedEpochAdvance();
            Sample += 85; ProofTime += 85; // Current successor, still before original ceiling.
            await Assert.ThrowsAsync<CryptographicException>(() => accounts.OpenMailboxEpochExclusionAsync(selector, Source()));
            if (!unresolved)
            {
                var straddling = checked(ceiling + 4); // Upper passed ceiling; lower has not.
                Sample = checked(Sample + straddling - ProofTime); ProofTime = straddling;
                await Assert.ThrowsAsync<CryptographicException>(() => accounts.OpenMailboxEpochExclusionAsync(selector, Source()));
            }
            var nextTime = checked(ceiling + 5); // Authenticated lower reaches ceiling exactly.
            Sample = checked(Sample + nextTime - ProofTime); ProofTime = nextTime;
            if (unresolved) Assert.Equal(1, await accounts.CloseExpiredMailboxAcquisitionsAsync(Source()));
            var reopened = ReopenAccount();
            using var before = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            var exactRoot = before.Use(bytes => bytes.ToArray());
            if (!advanceEpoch)
            {
                await Assert.ThrowsAsync<CryptographicException>(() => reopened.OpenMailboxEpochExclusionAsync(selector, Source(reopened)));
            }
            else
            {
                using var exclusion = await reopened.OpenMailboxEpochExclusionAsync(selector, Source(reopened));
                Assert.Equal(originalEpoch, exclusion.OriginalSelectionEpoch);
                Assert.Equal(checked(originalEpoch + 1), exclusion.ExcludingSelectionEpoch);
                Assert.Equal(unresolved, exclusion.IsUnresolvedAcquisition);
                Assert.Equal(selector, exclusion.AcquisitionHash.ToArray());
                Assert.Equal(SHA256.HashData(exactRoot), exclusion.OriginalGrantRootHash.ToArray());
                await exclusion.RecheckAsync();
                if (fault == 0) await storage.DeleteBatchAsync([ProtectedDid2MailboxGrantJournal.Slot]);
                if (fault == 1) await storage.DeleteBatchAsync([storage.LastHistoryAnchorSlot!]);
                if (fault == 2) Sample--;
                if (fault == 3) Sample += AccountDirectoryCurrentProofVerifier.RevocationFreshnessTtlSeconds;
                if (fault >= 0) await Assert.ThrowsAsync<CryptographicException>(() => exclusion.RecheckAsync());
                else
                {
                    using var canceled = new CancellationTokenSource(); canceled.Cancel();
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => exclusion.RecheckAsync(canceled.Token));
                    await exclusion.RecheckAsync();
                    exclusion.Dispose();
                    await Assert.ThrowsAsync<ObjectDisposedException>(() => exclusion.RecheckAsync());
                }
            }
            if (fault < 0 && advanceEpoch)
            {
                reopened = ReopenAccount();
                using var restored = await reopened.OpenMailboxEpochExclusionAsync(selector, Source(reopened));
                await restored.RecheckAsync(); // Restored from actual DNH2 + original journal, not cached proof.
            }
            if (fault != 0)
            {
                using var after = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(exactRoot, after.Use(bytes => bytes.ToArray()));
            }
            Assert.Equal(1, transport.Calls); // No retirement, deletion, reissuance or old-route callback.
            CryptographicOperations.ZeroMemory(exactRoot); CryptographicOperations.ZeroMemory(selector);
        }
    }
}
