using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OriginalStore_IssuerRotationKeepsHistoricalOutcomeAndRejectsCurrentPolicySubstitution(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        var stored = await fixture.DeliverCompletedCaseWithExactRetry(test);
        var dispatches = test.Transport.Calls;
        await fixture.AdvanceOriginalStoreIssuerForTestAsync(2_100);
        if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
        var account = fixture.UsedDepositAccount(initial);
        var source = initial ? fixture.Source(account) : fixture.GrantReaderSource(account);
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(account, default);
        Assert.Equal(PublicKey(0x35), fresh.MailboxAuthority.ResolveIssuer(MailboxCapabilityDomain.Deposit).PublicKey.ToArray());
        Assert.Equal(PublicKey(0x36), fresh.MailboxAuthority.ResolveIssuer(MailboxCapabilityDomain.Retrieve).PublicKey.ToArray());

        await fixture.RetireCompletedContactSend(test);
        byte[] acquisition;
        using (var grants = await fixture.ReadPeerGrantsAsync(own: initial))
            acquisition = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(Assert.Single(grants.Entries).Value));
        using (var exclusion = await account.OpenMailboxEpochExclusionAsync(acquisition, source))
            await exclusion.RetireIdleMailboxCounterFloorAsync();
        var secure = fixture.CompletedContactSendStorage(initial);
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var retained = await fixture.ReadUsedDepositRetainedRoots(test.Scope);
        var sourceSql = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        byte[] originalPma = [];
        try
        {
            // The actual current root-signed policy is valid, but it is not
            // evidence for a Store accepted under the original issuer key.
            originalPma = await fixture.ReplaceOriginalStorePolicyForTest(test.Scope, test.Operation, fresh.MailboxAuthority.ExactPma2);
            Assert.NotEqual(originalPma, fresh.MailboxAuthority.ExactPma2.ToArray());
            try
            {
                using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                using var grants = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                await Assert.ThrowsAsync<CryptographicException>(() => account.RetireUsedDepositAcquisitionAsync(acquisition, source));
                using var actualPlan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                using var actualGrants = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(plan.Use(bytes => bytes.ToArray()), actualPlan.Use(bytes => bytes.ToArray()));
                Assert.Equal(grants.Use(bytes => bytes.ToArray()), actualGrants.Use(bytes => bytes.ToArray()));
                Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
                Assert.Equal(retained, await fixture.ReadUsedDepositRetainedRoots(test.Scope));
                Assert.Equal(dispatches, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
            }
            finally
            {
                // Restore only the exact original evidence in this disposable
                // corruption fixture. Production never repairs missing proof.
                var substituted = await fixture.ReplaceOriginalStorePolicyForTest(test.Scope, test.Operation, originalPma);
                Assert.Equal(fresh.MailboxAuthority.ExactPma2.ToArray(), substituted);
                CryptographicOperations.ZeroMemory(substituted);
            }
            Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            using (Did2CompactionTestHooks.Push(point =>
                { if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Injected issuer-rotation handover."); }))
                await Assert.ThrowsAsync<IOException>(() => account.RetireUsedDepositAcquisitionAsync(acquisition, source));
            if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
            await fixture.CompletedContactSendRecoveryOwner(initial).ResumeOwnedLocalCompactionAsync(default);
            using (var grants = await fixture.ReadPeerGrantsAsync(own: initial))
            { Assert.Empty(grants.Entries); Assert.Empty(grants.Selections); }
            var cached = await test.Deliver();
            Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor); Assert.Equal(stored.Disposition, cached.Disposition);
            Assert.Equal(dispatches, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
            Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Equal(retained, await fixture.ReadUsedDepositRetainedRoots(test.Scope));
            Assert.Equal(sourceSql, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
            Assert.True(test.Transport.StoredEnvelope!.ExpiresAtUnixSeconds > 2_100);
        }
        finally
        {
            foreach (var bytes in new[] { acquisition, application, native, retained, sourceSql, originalPma })
                CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private sealed partial class Fixture
    {
        internal async Task AdvanceOriginalStoreIssuerForTestAsync(ulong unixSeconds)
        {
            await AdvanceNetworkAsync(expiry: 6_000);
            var exact = successor!.ExactPma2.ToArray();
            PublicKey(0x35).CopyTo(exact, FieldOffset(exact, 5));
            PublicKey(0x36).CopyTo(exact, FieldOffset(exact, 6));
            var provisional = ContactCodec.Decode("PMA2", exact);
            var rows = provisional.Field(16).ToArray();
            for (var offset = 0; offset < rows.Length; offset += 96)
            {
                Assert.Equal(root.RootKeyId.ToArray(), rows.AsSpan(offset, 32).ToArray());
                root.SignCommit(provisional.SignatureInput).CopyTo(rows, offset + 32);
            }
            rows.CopyTo(exact, FieldOffset(exact, 16));
            rotatedIssuerPma = ContactCodec.Decode("PMA2", exact).CanonicalBytes.ToArray();
            AuthorSignedEpochAdvance(); // Rebind and threshold-sign the actual PMT2 successor.
            Sample = checked(Sample + unixSeconds - ProofTime); ProofTime = unixSeconds;
        }

        internal async Task<byte[]> ReplaceOriginalStorePolicyForTest(Did2MessagingSessionScope scope,
            byte[] operation, ReadOnlyMemory<byte> exactPma)
        {
            byte[] original = [];
            await WithAuthoredApplicationConnectionAsync(scope, sql =>
            {
                using var read = sql.CreateCommand();
                read.CommandText = "SELECT exact_pma FROM mailbox_store_public_evidence WHERE scope_hash=$scope AND operation_id=$op;";
                read.Parameters.AddWithValue("$scope", scope.Hash.ToArray()); read.Parameters.AddWithValue("$op", operation);
                original = Assert.IsType<byte[]>(read.ExecuteScalar());
                using var change = sql.CreateCommand();
                change.CommandText = "UPDATE mailbox_store_public_evidence SET exact_pma=$pma WHERE scope_hash=$scope AND operation_id=$op;";
                change.Parameters.AddWithValue("$pma", exactPma.ToArray());
                change.Parameters.AddWithValue("$scope", scope.Hash.ToArray()); change.Parameters.AddWithValue("$op", operation);
                Assert.Equal(1, change.ExecuteNonQuery());
            });
            return original;
        }
    }
}
