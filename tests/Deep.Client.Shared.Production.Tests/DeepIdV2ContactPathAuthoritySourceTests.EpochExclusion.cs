using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task Did2RetirementDependencies_ChangedOrMissingRootRejectsWithoutGrantMutation(int dependencyFault)
    {
        await using var fixture = await Fixture.CreateAsync(shortMailboxAuthority: true);
        await fixture.CheckEpochExclusionAsync(unresolved: true, advanceEpoch: true, fault: -1, dependencyFault);
    }

    [Fact]
    public async Task Did2ReplayFence_MissingNativeFloorRejectsWithoutInitialization()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckMissingReplayFenceAsync();
    }

    [Theory]
    [InlineData(3)]
    [InlineData(7)]
    public async Task Did2ReplayFence_FractionalNativeRevisionRejectsWithoutRepair(int rootKind)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckFractionalReplayFenceAsync(rootKind);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2EpochExclusion_ActualClosedCustodyAndSignedAdvanceSurviveColdReopenWithoutDeletion(bool unresolved)
    {
        await using var fixture = await Fixture.CreateAsync(shortMailboxAuthority: true);
        await fixture.CheckEpochExclusionAsync(unresolved, advanceEpoch: true, fault: -1);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2EpochExclusion_OriginalCeilingAndOperationalRenewalAloneCannotExcludeNamespace(bool unresolved)
    {
        await using var fixture = await Fixture.CreateAsync(shortMailboxAuthority: true);
        await fixture.CheckEpochExclusionAsync(unresolved, advanceEpoch: false, fault: -1);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Did2EpochExclusion_ConsumerRejectsChangedRootAnchorClockOrExpiredProof(int fault)
    {
        await using var fixture = await Fixture.CreateAsync(shortMailboxAuthority: true);
        await fixture.CheckEpochExclusionAsync(unresolved: true, advanceEpoch: true, fault);
    }

    private sealed partial class Fixture
    {
        private ReadOnlyMemory<byte>? epochSuccessorPmt;

        internal async Task CheckMissingReplayFenceAsync()
        {
            Assert.Null(await NetworkStore.ReadAsync(default));
            await Assert.ThrowsAsync<InvalidDataException>(() => accounts.ReadOwnMailboxReplayFenceAsync());
            Assert.Null(await NetworkStore.ReadAsync(default));
        }

        internal async Task CheckFractionalReplayFenceAsync(int rootKind)
        {
            _ = await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            using var before = await storage.ReadOwnedAsync(storage.LastHistoryAnchorSlot!) ?? throw new InvalidDataException();
            var anchor = before.Use(bytes => bytes.ToArray());
            await using var sql = await OpenSqlAsync();
            using var command = sql.CreateCommand();
            command.CommandText = "UPDATE protected_lkg_root SET revision=revision+0.5 WHERE root_kind=$kind;";
            command.Parameters.AddWithValue("$kind", rootKind);
            Assert.Equal(1, command.ExecuteNonQuery());
            await Assert.ThrowsAsync<InvalidDataException>(() => ReopenAccount().ReadOwnMailboxReplayFenceAsync());
            await Assert.ThrowsAsync<InvalidDataException>(async () => await NetworkStore.ReadAsync(default));
            command.CommandText = "SELECT typeof(revision) FROM protected_lkg_root WHERE root_kind=$kind;";
            Assert.Equal("real", command.ExecuteScalar());
            using var after = await storage.ReadOwnedAsync(storage.LastHistoryAnchorSlot!) ?? throw new InvalidDataException();
            Assert.Equal(anchor, after.Use(bytes => bytes.ToArray()));
            CryptographicOperations.ZeroMemory(anchor);
        }

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
                if (tag == 4 && rotatedIssuerPma is not null)
                    ContactCodec.Decode("PMA2", rotatedIssuerPma).CoreHash.Span.CopyTo(exact.AsSpan(offset + 6, 32));
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

        internal async Task CheckEpochExclusionAsync(bool unresolved, bool advanceEpoch, int fault, int dependencyFault = -1)
        {
            Assert.Equal(1_200UL, BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("PMA2", operational.ExactPma2.Span).Field(12).Span));
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
            Did2CompactionPlan.Root? capturedFence = null;
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
                capturedFence = await exclusion.CaptureDurableReplayFenceAsync();
                Assert.Equal(Did2CompactionPlan.RootKind.NativeFence, capturedFence.Value.Kind);
                Assert.True(capturedFence.Value.Guard);
                Assert.Empty(capturedFence.Value.Successor.ToArray());
                Assert.Equal(capturedFence.Value.Before.ToArray(), capturedFence.Value.After.ToArray());
                var dependencies = await exclusion.CaptureRetirementDependenciesAsync();
                Assert.Equal(new[] { Did2CompactionPlan.RootKind.Ordinary, Did2CompactionPlan.RootKind.Send,
                    Did2CompactionPlan.RootKind.Grant, Did2CompactionPlan.RootKind.Read, Did2CompactionPlan.RootKind.SessionCatalog,
                    Did2CompactionPlan.RootKind.Attachment, Did2CompactionPlan.RootKind.AccountRegistration, Did2CompactionPlan.RootKind.NativeFence },
                    dependencies.Guards.Select(guard => guard.Kind));
                Assert.Equal(SHA256.HashData(exactRoot), dependencies.Guards[2].Digest.ToArray());
                Assert.Equal(Did2CompactionPlan.RootKind.NativeFence, dependencies.Guards[^1].Kind);
                Assert.Equal(capturedFence.Value.Before.ToArray(), dependencies.Guards[^1].Digest.ToArray());
                Assert.True(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.RetainedRetrievePath));
                // This acquisition has never polled: a Retrieve domain alone
                // must not invent a protected traversal dependency.
                Assert.False(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.ReadTraversal));
                Assert.Equal(!unresolved, dependencies.Dependencies.HasFlag(
                    ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.UnresolvedReceiptOrObject));
                await dependencies.RecheckAsync();
                using (var planBefore = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException())
                {
                    // Both known and unresolved Retrieve custody remain pinned.
                    // A fresh exclusion alone must never stage deletion of that path.
                    await Assert.ThrowsAsync<IOException>(() => exclusion.RetireUnusedClosedDepositAcquisitionAsync());
                    if (unresolved)
                        await Assert.ThrowsAsync<IOException>(() => exclusion.RetireIdleMailboxCounterFloorAsync());
                    using var planAfter = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                    Assert.Equal(planBefore.Use(bytes => SHA256.HashData(bytes)), planAfter.Use(bytes => SHA256.HashData(bytes)));
                    using var grantAfter = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                    Assert.Equal(SHA256.HashData(exactRoot), grantAfter.Use(bytes => SHA256.HashData(bytes)));
                }
                var callerCopy = dependencies.Guards;
                Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(callerCopy[0].Digest, out var exposed));
                Array.Clear(exposed.Array!, exposed.Offset, exposed.Count); // Never writes the captured guard.
                await dependencies.RecheckAsync();
                if (dependencyFault >= 0)
                {
                    using var originalSend = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                    if (dependencyFault == 0)
                    {
                        using var state = originalSend.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, Network, exactRoot.AsSpan(28, 32), exactRoot.AsSpan(60, 32)));
                        state.Revision++;
                        var changed = ProtectedDid2MailboxSendJournal.Encode(state, Network, exactRoot.AsSpan(28, 32), exactRoot.AsSpan(60, 32));
                        var originalBytesForCas = originalSend.Use(bytes => bytes.ToArray());
                        try { Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, originalBytesForCas, changed)); }
                        finally { CryptographicOperations.ZeroMemory(changed); CryptographicOperations.ZeroMemory(originalBytesForCas); }
                        await Assert.ThrowsAsync<CryptographicException>(() => dependencies.RecheckAsync());
                        var reselected = await exclusion.CaptureRetirementDependenciesAsync();
                        Assert.NotEqual(dependencies.Guards[1].Digest.ToArray(), reselected.Guards[1].Digest.ToArray());
                    }
                    else
                    {
                        await storage.DeleteBatchAsync([ProtectedDid2MailboxSendJournal.Slot]);
                        await Assert.ThrowsAsync<InvalidDataException>(() => dependencies.RecheckAsync());
                        await Assert.ThrowsAsync<InvalidDataException>(() => exclusion.CaptureRetirementDependenciesAsync());
                    }
                    // Restore only this injected fixture fault; not a runtime repair/recovery assertion.
                    var originalBytes = originalSend.Use(bytes => bytes.ToArray());
                    try
                    {
                        using var currentSend = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot);
                        if (currentSend is null) await storage.WriteBatchAsync([new(ProtectedDid2MailboxSendJournal.Slot, originalBytes)]);
                        else
                        {
                            var expected = currentSend.Use(bytes => bytes.ToArray());
                            try { Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, expected, originalBytes)); }
                            finally { CryptographicOperations.ZeroMemory(expected); }
                        }
                    }
                    finally { CryptographicOperations.ZeroMemory(originalBytes); }
                    await dependencies.RecheckAsync();
                }
                if (fault == 0) await storage.DeleteBatchAsync([ProtectedDid2MailboxGrantJournal.Slot]);
                if (fault == 1) await storage.DeleteBatchAsync([storage.LastHistoryAnchorSlot!]);
                if (fault == 2) Sample--;
                if (fault == 3) Sample += AccountDirectoryCurrentProofVerifier.RevocationFreshnessTtlSeconds;
                if (fault >= 0)
                {
                    await Assert.ThrowsAsync<CryptographicException>(() => exclusion.RecheckAsync());
                    await Assert.ThrowsAsync<CryptographicException>(() => exclusion.CaptureDurableReplayFenceAsync());
                    await Assert.ThrowsAsync<CryptographicException>(() => dependencies.RecheckAsync());
                }
                else
                {
                    using var canceled = new CancellationTokenSource(); canceled.Cancel();
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => exclusion.RecheckAsync(canceled.Token));
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => exclusion.CaptureDurableReplayFenceAsync(canceled.Token));
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => dependencies.RecheckAsync(canceled.Token));
                    await exclusion.RecheckAsync();
                    exclusion.Dispose();
                    await Assert.ThrowsAsync<ObjectDisposedException>(() => exclusion.RecheckAsync());
                    await Assert.ThrowsAsync<ObjectDisposedException>(() => exclusion.CaptureDurableReplayFenceAsync());
                    await Assert.ThrowsAsync<ObjectDisposedException>(() => dependencies.RecheckAsync());
                }
            }
            if (fault == 1 && advanceEpoch)
                await Assert.ThrowsAsync<CryptographicException>(() => reopened.ReadOwnMailboxReplayFenceAsync());
            if (fault < 0 && advanceEpoch)
            {
                reopened = ReopenAccount();
                var cold = await reopened.ReadOwnMailboxReplayFenceAsync();
                var captured = capturedFence ?? throw new InvalidDataException();
                Assert.Equal(captured.Selector.ToArray(), cold.Selector.ToArray());
                Assert.Equal(captured.Before.ToArray(), cold.Digest.ToArray());
                var sampleBefore = Sample;
                Sample += AccountDirectoryCurrentProofVerifier.RevocationFreshnessTtlSeconds;
                var offline = await ReopenAccount().ReadOwnMailboxReplayFenceAsync();
                Assert.Equal(cold.Digest.ToArray(), offline.Digest.ToArray()); // No fresh directory proof required.
                Sample = sampleBefore;
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
