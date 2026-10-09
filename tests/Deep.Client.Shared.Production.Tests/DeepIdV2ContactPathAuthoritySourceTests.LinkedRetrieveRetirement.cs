using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2LinkedRetrieveRetirement_ActualReadAckAndEveryColdHandoverKeepOriginal(bool nonempty)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        if (nonempty) await fixture.CheckCompletedAckFloorRetirementAsync(retireClosedRenewal: true);
        else await fixture.PrepareLinkedRetrieveRetirementAsync(abandon: false, active: false);
    }

    [Fact]
    public async Task Did2LinkedRetrieveRetirement_CancellationAbandonsOnlyBeforeCommit()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        await fixture.PrepareLinkedRetrieveRetirementAsync(abandon: true, active: false);
    }

    [Fact]
    public async Task Did2LinkedRetrieveRetirement_ActualCapturedReadPinsWithoutStaging()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        await fixture.PrepareLinkedRetrieveRetirementAsync(abandon: false, active: true);
    }

    private sealed partial class Fixture
    {
        internal async Task PrepareLinkedRetrieveRetirementAsync(bool abandon, bool active)
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            TrackMailboxDispatchClock();
            var issuer = new OwnedGrantTransport(this, selfRetrieve: true);
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            if (active)
            {
                using (ClientMailboxRetrieveTestHooks.Push(point =>
                    { if (point == ClientMailboxRetrieveFailpoint.AfterPageCommit) throw new IOException("Injected original read handover."); }))
                    await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => SynchronizeNativeSender(issuer, terminal));
                using var read = await ReadPeerMailboxReads(own: true); Assert.NotNull(read.Active);
            }
            else Assert.Equal(0, (await SynchronizeNativeSender(issuer, terminal)).ProcessedEnvelopes);
            await CheckLinkedUnusedRetrieveRetirementAsync(own: true, abandon, active);
        }

        internal async Task CheckLinkedUnusedRetrieveRetirementAsync(bool own, bool abandon = false, bool active = false)
        {
            var secure = own ? (IDeepSecureStorage)storage : peerStorage;
            DeepIdV2AccountService Account() => own ? ReopenAccount() : ReopenGrantReader();
            Deep.Client.Shared.Services.ContactV2.DeepIdV2ContactPathAuthoritySource SourceFor(DeepIdV2AccountService account) =>
                own ? Source(account) : GrantReaderSource(account);
            byte[] originalEntry, originalSelector;
            using (var state = await ReadPeerGrantsAsync(own))
            {
                originalEntry = Assert.Single(state.Entries).Value.ToArray();
                originalSelector = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(originalEntry));
            }
            var lost = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: own) { LoseResponse = true };
            var renewing = Account();
            await Assert.ThrowsAsync<IOException>(() => renewing.RenewOwnPermanentContactRetrieveGrantAsync(originalSelector, SourceFor(renewing), lost));
            var candidate = SHA256.HashData(lost.OriginalRequest.Span);
            // The same owner closes only after the authenticated lower bound
            // passes the request window. This is not a negative issuer outcome.
            var expiry = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XMG2", lost.OriginalRequest.Span).Field(10).Span);
            var delta = checked(expiry + 31 - CurrentProofTime); Sample += delta; ProofTime += delta;
            var closing = Account(); Assert.Equal(1, await closing.CloseExpiredMailboxAcquisitionsAsync(SourceFor(closing)));
            var pinned = Account(); var noIssue = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: own);
            await Assert.ThrowsAsync<IOException>(() => pinned.RenewOwnPermanentContactRetrieveGrantAsync(originalSelector, SourceFor(pinned), noIssue));
            Assert.Equal(0, noIssue.Calls);
            var notExcluded = Account();
            await Assert.ThrowsAsync<CryptographicException>(() => notExcluded.OpenMailboxEpochExclusionAsync(candidate, SourceFor(notExcluded)));
            await AdvanceOriginalStoreEpochForTestAsync(2_100);
            // Import and read back the genuinely signed higher epoch before
            // taking the unchanged local-fence snapshot. Selection must not be
            // blamed for the source owner's required pre-selection import.
            var capturing = Account();
            _ = await SourceFor(capturing).VerifyForOwnPreKeyAuthoringAsync(capturing, default);
            if (active)
            {
                using var before = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                var account = Account();
                using var exclusion = await account.OpenMailboxEpochExclusionAsync(candidate, SourceFor(account));
                await Assert.ThrowsAsync<IOException>(() => exclusion.RetireUnusedClosedRetrieveAcquisitionAsync());
                using var after = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(before.Use(bytes => bytes.ToArray()), after.Use(bytes => bytes.ToArray()));
                using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException(); Assert.Equal(0, plan.Use(bytes => bytes[1]));
                Assert.Equal(1, lost.Calls); return;
            }
            using var root = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            var originalRoot = root.Use(bytes => bytes.ToArray());
            var accountId = (await Account().GetCurrentAsync())!.AccountId.ToArray();
            async Task<byte[]> SqlState()
            {
                byte[] state = [];
                await WithOwnedApplicationConnectionAsync(own, Network, accountId, sql =>
                    state = SqliteDeepMailboxStore.ReadCompleteLocalSqlProjection(sql, SHA256.HashData(candidate), default));
                return state;
            }
            var application = await SqlState();
            var slots = new[] { ProtectedDid2ContactRouteJournal.Slot, ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2MailboxSendJournal.Slot,
                ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot,
                SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot };
            var hashes = new List<byte[]>();
            foreach (var slot in slots)
            { using var raw = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); hashes.Add(raw.Use(bytes => SHA256.HashData(bytes))); }
            var native = await Account().ReadOwnMailboxReplayFenceAsync();
            var points = new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSqlRecorded,
                Did2CompactionFailpoint.AfterHistoryAdopted, Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
            for (var index = 0; index < (abandon ? 2 : points.Length); index++)
            {
                if (index != 0)
                {
                    using var now = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                    Assert.True(await secure.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, now.Use(bytes => bytes.ToArray()), originalRoot));
                }
                var account = Account(); using var cancellation = new CancellationTokenSource();
                using (var exclusion = await account.OpenMailboxEpochExclusionAsync(candidate, SourceFor(account)))
                using (Did2CompactionTestHooks.Push(point =>
                    { if (point == points[index]) { if (abandon) cancellation.Cancel(); else throw new IOException("Injected linked closed Retrieve handover."); } }))
                {
                    if (abandon) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => exclusion.RetireUnusedClosedRetrieveAcquisitionAsync(cancellation.Token));
                    else await Assert.ThrowsAsync<IOException>(() => exclusion.RetireUnusedClosedRetrieveAcquisitionAsync());
                }
                if (own) ColdReopenCompactionStorage(); else ColdReopenReceiverStoreStorage();
                var recovery = own ? SenderCompactionOwner() : PeerRetirementOwner();
                if (index == 0 && !abandon)
                {
                    using var staged = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                    byte[] accountScope = [], logical = [], beforeBody = [];
                    await WithOwnedApplicationConnectionAsync(own, Network, accountId, sql =>
                    {
                        using var query = sql.CreateCommand(); query.CommandText = "SELECT account_scope,logical_id,ciphertext_bundle FROM transport_outbox_items ORDER BY account_scope,logical_id LIMIT 1;";
                        using var rows = query.ExecuteReader(); Assert.True(rows.Read());
                        accountScope = (byte[])rows.GetValue(0); logical = (byte[])rows.GetValue(1); beforeBody = (byte[])rows.GetValue(2);
                    });
                    async Task ReplaceBody(byte[] body) => await WithOwnedApplicationConnectionAsync(own, Network, accountId, sql =>
                    {
                        using var query = sql.CreateCommand(); query.CommandText = "UPDATE transport_outbox_items SET ciphertext_bundle=$body WHERE account_scope=$account AND logical_id=$logical;";
                        query.Parameters.AddWithValue("$body", body); query.Parameters.AddWithValue("$account", accountScope); query.Parameters.AddWithValue("$logical", logical);
                        Assert.Equal(1, query.ExecuteNonQuery());
                    });
                    var corrupt = beforeBody.Append((byte)0).ToArray();
                    try
                    {
                        await ReplaceBody(corrupt);
                        // ObserveReadback rejects a changed guarded root as a
                        // noncanonical plan read-back before any adoption.
                        await Assert.ThrowsAsync<InvalidDataException>(() => recovery.ResumeOwnedLocalCompactionAsync(default));
                        using var unchanged = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                        using var samePlan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                        Assert.Equal(originalRoot, unchanged.Use(bytes => bytes.ToArray()));
                        Assert.Equal(staged.Use(bytes => bytes.ToArray()), samePlan.Use(bytes => bytes.ToArray()));
                    }
                    finally
                    { await ReplaceBody(beforeBody); CryptographicOperations.ZeroMemory(accountScope); CryptographicOperations.ZeroMemory(logical); CryptographicOperations.ZeroMemory(beforeBody); CryptographicOperations.ZeroMemory(corrupt); }
                }
                if (abandon && index == 0) await recovery.AbandonUncommittedMailboxRetirementAsync(default);
                else
                {
                    if (index > 0) await Assert.ThrowsAsync<InvalidOperationException>(() => recovery.AbandonUncommittedMailboxRetirementAsync(default));
                    await recovery.ResumeOwnedLocalCompactionAsync(default);
                }
                using var state = await ReadPeerGrantsAsync(own);
                Assert.Equal(originalEntry, state.Entries[Convert.ToHexString(originalSelector)]);
                Assert.Equal(abandon && index == 0 ? 2 : 1, state.Entries.Count);
                var selection = Assert.Single(state.Selections).Value;
                Assert.Equal(Convert.ToHexString(originalSelector), selection.Current); Assert.Null(selection.Pending);
                Assert.Equal(Convert.ToHexString(abandon && index == 0 ? candidate : originalSelector), selection.RetainedTail);
                Assert.Equal(application, await SqlState());
                Assert.Equal(native.Digest.ToArray(), (await Account().ReadOwnMailboxReplayFenceAsync()).Digest.ToArray());
                for (var slot = 0; slot < slots.Length; slot++)
                { using var raw = await secure.ReadOwnedAsync(slots[slot]) ?? throw new InvalidDataException(); Assert.Equal(hashes[slot], raw.Use(bytes => SHA256.HashData(bytes))); }
                using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException(); Assert.Equal(0, plan.Use(bytes => bytes[1]));
                Assert.Equal(1, lost.Calls);
            }
            // The discarded unknown candidate does not restore its response.
            // A new current issuer creates a different request on the same path.
            var resumed = Account(); var freshIssuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: own);
            var winner = await resumed.RenewOwnPermanentContactRetrieveGrantAsync(originalSelector, SourceFor(resumed), freshIssuer);
            Assert.Equal(1, freshIssuer.Calls); Assert.True(freshIssuer.BuiltHeldFrame);
            Assert.NotEqual(lost.OriginalRequest.ToArray(), winner.ExactXmg2.ToArray());
            using (var state = await ReadPeerGrantsAsync(own))
            { Assert.Equal(2, state.Entries.Count); Assert.Equal(originalEntry, state.Entries[Convert.ToHexString(originalSelector)]); Assert.False(state.Entries.ContainsKey(Convert.ToHexString(candidate))); }
            foreach (var value in new[] { originalEntry, originalSelector, candidate, originalRoot, application, accountId }) CryptographicOperations.ZeroMemory(value);
        }
    }
}
