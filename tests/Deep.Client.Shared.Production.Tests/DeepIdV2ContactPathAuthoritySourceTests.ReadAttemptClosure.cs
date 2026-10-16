using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("before")]
    [InlineData("after")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ExpiredActiveRetrieve_ClosesUnknownAndColdReadsWithIndependentGrant(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckExpiredActiveRetrieveAsync(fault);
    }

    [Theory]
    [InlineData("upper-only")]
    [InlineData("missing-sql")]
    [InlineData("changed-sql")]
    [InlineData("cancelled")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ExpiredActiveRetrieve_RefusesClosureWithoutOriginalCustodyAndLowerTime(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckRefusedActiveRetrieveClosureAsync(defect);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckRefusedActiveRetrieveClosureAsync(string defect)
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            TrackMailboxDispatchClock();
            var issuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true)
                { MaximumFixtureGrantLifetimeSeconds = 120 };
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true, LoseRetrieveReply = true };
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => SynchronizeNativeSender(issuer, terminal));
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", issuer.OriginalResponse.Span).Field(8).Span);
            // Hold the signed fixture's monotonic clock at the overlap point,
            // so test scheduling cannot turn upper-only expiry into lower expiry.
            if (defect == "upper-only") mailboxClockStarted = null;
            var target = defect == "upper-only" ? checked(grant.ExpiresAtUnixSeconds - 1) : checked(grant.ExpiresAtUnixSeconds + 31);
            Assert.True(target > CurrentProofTime);
            var delta = target - CurrentProofTime; ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
            if (defect is "missing-sql" or "changed-sql")
            {
                var frame = MailboxAuthenticatedClientRequestCodec.Decode(Assert.Single(terminal.ExactRetrieveRequests));
                var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(frame.Binding.CanonicalRequest.Span);
                var account = (await ReopenAccount().GetCurrentAsync())!.AccountId.ToArray();
                await WithOwnedApplicationConnectionAsync(true, Network, account, sql =>
                {
                    using var command = sql.CreateCommand();
                    // Deliberately damage only the disposable native fixture. A
                    // protected phase2 cannot interpret this as non-dispatch.
                    command.CommandText = defect == "missing-sql"
                        ? "DELETE FROM transport_outbox_attempts WHERE account_scope=$scope AND logical_id=$op; DELETE FROM transport_outbox_items WHERE account_scope=$scope AND logical_id=$op;"
                        : "UPDATE transport_outbox_items SET ciphertext_bundle=zeroblob(length(ciphertext_bundle)) WHERE account_scope=$scope AND logical_id=$op;";
                    command.Parameters.AddWithValue("$scope", VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span).ToArray());
                    command.Parameters.AddWithValue("$op", request.OperationId.ToArray());
                    Assert.True(command.ExecuteNonQuery() > 0);
                });
            }
            ColdReopenCompactionStorage();
            using var beforeRead = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
            using var beforeGrants = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            var replacement = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
            var reopened = ReopenAccount();
            if (defect == "upper-only")
            {
                var authority = await Source(reopened).VerifyForOwnPreKeyAuthoringAsync(reopened, default);
                Assert.True(authority.Proof.TrustedLowerUnixSeconds < grant.ExpiresAtUnixSeconds);
                Assert.True(authority.Proof.TrustedUpperUnixSeconds >= grant.ExpiresAtUnixSeconds);
                await Assert.ThrowsAsync<CryptographicException>(() => reopened.SynchronizeOwnMailboxAsync(Source(reopened), replacement, terminal));
            }
            else if (defect == "changed-sql")
                await Assert.ThrowsAsync<MailboxAuthenticatedCapabilityException>(() => reopened.SynchronizeOwnMailboxAsync(Source(reopened), replacement, terminal));
            else if (defect == "cancelled")
            {
                using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reopened.SynchronizeOwnMailboxAsync(Source(reopened), replacement, terminal, cancellation.Token));
            }
            else await Assert.ThrowsAnyAsync<CryptographicException>(() => reopened.SynchronizeOwnMailboxAsync(Source(reopened), replacement, terminal));
            Assert.Equal(0, replacement.Calls); Assert.Equal(1, terminal.RetrieveCalls);
            using var afterRead = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
            using var afterGrants = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            Assert.Equal(beforeRead.Use(bytes => bytes.ToArray()), afterRead.Use(bytes => bytes.ToArray()));
            Assert.Equal(beforeGrants.Use(bytes => bytes.ToArray()), afterGrants.Use(bytes => bytes.ToArray()));
            using var read = await ReadPeerMailboxReads(own: true);
            Assert.Equal(2, read.Phase); Assert.NotNull(read.Active); Assert.Empty(read.Closed);
        }

        internal async Task CheckExpiredActiveRetrieveAsync(string fault)
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            TrackMailboxDispatchClock();
            var originalIssuer = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true)
                { MaximumFixtureGrantLifetimeSeconds = 120 };
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true, LoseRetrieveReply = true };
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => SynchronizeNativeSender(originalIssuer, terminal));
            Assert.Equal(1, terminal.RetrieveCalls);
            using (var active = await ReadPeerMailboxReads(own: true))
            { Assert.Equal(2, active.Phase); Assert.NotNull(active.Active); Assert.Empty(active.Closed); }
            byte[] original;
            using (var grants = await ReadPeerGrantsAsync(own: true)) original = Assert.Single(grants.Entries).Value.ToArray();
            var oldMau = Assert.Single(terminal.ExactRetrieveRequests).ToArray();
            try
            {
                var oldGrant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", originalIssuer.OriginalResponse.Span).Field(8).Span);
                var target = Math.Max(checked(oldGrant.ExpiresAtUnixSeconds + 31), checked(CurrentProofTime + 1));
                var delta = checked(target - CurrentProofTime); ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
                ColdReopenCompactionStorage(); terminal.LoseRetrieveReply = false;
                var replacement = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
                if (fault != "none")
                {
                    var expected = fault == "before" ? Did2MailboxInstallationFailpoint.BeforeReadClosure : Did2MailboxInstallationFailpoint.AfterReadClosure;
                    var hit = false;
                    using (Did2MailboxInstallationTestHooks.Push(point =>
                    { if (point == expected) { hit = true; throw new IOException("Injected protected read-closure interruption."); } }))
                        await Assert.ThrowsAsync<IOException>(() => SynchronizeNativeSender(replacement, terminal));
                    Assert.True(hit); Assert.Equal(0, replacement.Calls); Assert.Equal(1, terminal.RetrieveCalls);
                    ColdReopenCompactionStorage();
                }
                Assert.Equal(0, (await SynchronizeNativeSender(replacement, terminal)).ProcessedEnvelopes);
                Assert.Equal(1, replacement.Calls); Assert.Equal(2, terminal.RetrieveCalls); Assert.Equal(0, terminal.AckCalls);
                Assert.False(terminal.ExactRetrieveRequests[1].AsSpan().SequenceEqual(oldMau));
                using (var read = await ReadPeerMailboxReads(own: true))
                {
                    Assert.Equal(0, read.Phase); Assert.Null(read.Active);
                    var closed = Assert.Single(read.Closed).Value;
                    Assert.Equal(oldMau, closed.ExactMau); Assert.Equal(2, closed.Phase);
                    Assert.True(closed.ClosedAtLower >= oldGrant.ExpiresAtUnixSeconds);
                    Assert.Equal(MailboxAuthenticatedClientRequestCodec.Decode(oldMau).Presentation.ReplayCounter,
                        read.Counters[Convert.ToHexString(closed.Grant)]);
                }
                using (var grants = await ReadPeerGrantsAsync(own: true))
                {
                    Assert.Equal(2, grants.Entries.Count);
                    Assert.Equal(original, grants.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(original)]);
                }
                ColdReopenCompactionStorage();
                Assert.Equal(0, (await SynchronizeNativeSender(replacement, terminal)).ProcessedEnvelopes);
                Assert.Equal(1, replacement.Calls); Assert.Equal(3, terminal.RetrieveCalls);
                Assert.Single(terminal.ExactRetrieveRequests, request => request.AsSpan().SequenceEqual(oldMau));
                using (var final = await ReadPeerMailboxReads(own: true)) Assert.Single(final.Closed);
                if (fault == "none")
                {
                    await AdvanceOriginalStoreEpochForTestAsync(2_100);
                    var account = ReopenAccount();
                    using var exclusion = await account.OpenMailboxEpochExclusionAsync(
                        Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(original)), Source(account));
                    var dependencies = await exclusion.CaptureRetirementDependenciesAsync();
                    Assert.True(dependencies.Dependencies.HasFlag(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.ReadWork));
                    await Assert.ThrowsAsync<IOException>(() => exclusion.RetireIdleMailboxCounterFloorAsync());
                    using var retained = await ReadPeerMailboxReads(own: true); Assert.Single(retained.Closed);
                }
            }
            finally { CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(oldMau); }
        }
    }
}
