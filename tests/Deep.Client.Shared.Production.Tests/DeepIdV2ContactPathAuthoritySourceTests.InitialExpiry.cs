using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("draft", false)] [InlineData("unknown-claim", false)] [InlineData("completed-source", false)]
    [InlineData("draft", true)] [InlineData("unknown-claim", true)] [InlineData("completed-source", true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionExpiry_LowerDeadlineAndLostStopReplyKeepTheOriginalIntent(string stage, bool lostReply)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        var intent = Bytes(32, 0xb2);
        var prepared = await fixture.PrepareNativeHelloCompletion(intent, preSessionCut: stage == "completed-source" ? null : stage);
        if (stage == "completed-source") using (var completed = await prepared.Complete(fixture.ReopenAccount())) { }
        var deadline = Did2ControlWorkStop.ProvenExpirySecond(prepared.Init.ExpiresAtUnixMilliseconds);
        await fixture.AdvanceInitialExpiryToLowerBoundary(deadline - 1);
        var proof = await fixture.ReadPreSessionExpiryProof();
        Assert.Equal(deadline - 1, proof.Lower); Assert.True(proof.Upper >= deadline);
        var before = await fixture.ReadInitialStopGuardDigest();
        try
        {
            await Assert.ThrowsAsync<IOException>(() => fixture.ExpirePreSessionInitial(intent));
            var afterRefusal = await fixture.ReadInitialStopGuardDigest();
            try { Assert.True(CryptographicOperations.FixedTimeEquals(before, afterRefusal)); }
            finally { CryptographicOperations.ZeroMemory(afterRefusal); }
            fixture.ProofTime++; fixture.Sample++;
            Assert.Equal(deadline, (await fixture.ReadPreSessionExpiryProof()).Lower);
            var hit = false;
            using (Did2MailboxSendTestHooks.Push(point =>
            {
                if (lostReply && point == Did2MailboxSendFailpoint.AfterWorkStopRoot)
                { hit = true; throw new IOException("Lost proven Initial expiry reply."); }
            }))
            {
                if (lostReply) await Assert.ThrowsAsync<IOException>(() => fixture.ExpirePreSessionInitial(intent));
                else await fixture.ExpirePreSessionInitial(intent);
            }
            Assert.Equal(lostReply, hit); fixture.ColdReopenCompactionStorage();
            var requests = fixture.ProofRequests;
            await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
            Assert.Equal(requests, fixture.ProofRequests);
            await fixture.ExpirePreSessionInitial(intent);
            await fixture.AssertPreSessionCancelled(intent, reason: ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired);
            await Assert.ThrowsAsync<IOException>(() => fixture.BeginPreClaimAsync(intent));
            var stoppedAt = await fixture.PreSessionStopTime(intent);
            await fixture.CancelPreSessionInitial(intent);
            Assert.Equal(stoppedAt, await fixture.PreSessionStopTime(intent));
            await fixture.AssertPreSessionCancelled(intent, reason: ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired);
        }
        finally { CryptographicOperations.ZeroMemory(before); }
    }

    [Theory]
    [InlineData("AfterStage")] [InlineData("AfterSql")] [InlineData("AfterSqlRecorded")]
    [InlineData("AfterHistoryAdopted")] [InlineData("AfterPartsDeleted")] [InlineData("AfterPlanCleared")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionExpiry_AuditDeletionColdRecoversEveryHandoverWithoutFreshProof(string interruption)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var intent = Bytes(32, 0xb3); _ = await fixture.PrepareNativeHelloCompletion(intent, preSessionCut: "unknown-claim");
        await fixture.CancelPreSessionInitial(intent);
        var deadline = checked(await fixture.PreSessionStopTime(intent) + SqliteDeepMailboxStore.StoppedAuditSeconds);
        await fixture.AdvanceControlAuditToLowerBoundary(deadline);
        var selected = Enum.Parse<Did2CompactionFailpoint>(interruption); var hit = false;
        using (Did2CompactionTestHooks.Push(point =>
        {
            if (point == selected) { hit = true; throw new IOException("Interrupted proven pre-session audit expiry."); }
        }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CancelPreSessionInitial(intent));
        Assert.True(hit); fixture.ColdReopenCompactionStorage();
        var requests = fixture.ProofRequests;
        await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        Assert.Equal(requests, fixture.ProofRequests);
        await fixture.AssertPreSessionCancelled(intent, auditExpired: true);
        await Assert.ThrowsAsync<IOException>(() => fixture.BeginPreClaimAsync(intent));
    }

    [Theory]
    [InlineData("AfterAbandonRecorded")] [InlineData("AfterPartsDeleted")] [InlineData("AfterPlanCleared")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreSessionExpiry_UncommittedAuditAbortKeepsOriginalAuditAndCannotReverseStop(string interruption)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        var intent = Bytes(32, 0xb4); _ = await fixture.PrepareNativeHelloCompletion(intent, preSessionCut: "unknown-claim");
        await fixture.CancelPreSessionInitial(intent);
        var stopTime = await fixture.PreSessionStopTime(intent);
        var before = await fixture.ReadPreSessionApplication(intent);
        try
        {
            await fixture.AdvanceControlAuditToLowerBoundary(checked(stopTime + SqliteDeepMailboxStore.StoppedAuditSeconds));
            using (Did2CompactionTestHooks.Push(point =>
            {
                if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Prepared pre-session audit expiry.");
            }))
                await Assert.ThrowsAsync<IOException>(() => fixture.CancelPreSessionInitial(intent));
            var selected = Enum.Parse<Did2CompactionFailpoint>(interruption); var hit = false;
            using (Did2CompactionTestHooks.Push(point =>
            {
                if (point == selected) { hit = true; throw new IOException("Interrupted pre-session audit expiry abort."); }
            }))
                await Assert.ThrowsAsync<IOException>(() => fixture.SenderCompactionOwner().AbandonUncommittedControlAuditAsync(default));
            Assert.True(hit); fixture.ColdReopenCompactionStorage();
            var requests = fixture.ProofRequests;
            await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
            Assert.Equal(requests, fixture.ProofRequests);
            await fixture.AssertPreSessionCancelled(intent);
            Assert.Equal(stopTime, await fixture.PreSessionStopTime(intent));
            Assert.Equal(before, await fixture.ReadPreSessionApplication(intent));
            await Assert.ThrowsAsync<IOException>(() => fixture.BeginPreClaimAsync(intent));
            await fixture.CancelPreSessionInitial(intent); await fixture.AssertPreSessionCancelled(intent, auditExpired: true);
        }
        finally { CryptographicOperations.ZeroMemory(before); }
    }

    private sealed partial class Fixture
    {
        internal async Task AdvanceInitialExpiryToLowerBoundary(ulong lower)
        {
            // Initial's short deadline fits the real bootstrap DTS/head window.
            // The audit's future root renewal is not yet valid at this boundary.
            var elapsed = MailboxElapsedSeconds;
            ProofTime = checked(ProofTime + elapsed); Sample = checked(Sample + elapsed); mailboxClockStarted = null;
            await AdvanceOriginalStoreEpochForTestAsync(2_100);
            var delta = checked(lower + 5 - CurrentProofTime);
            ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
        }
        internal Task ExpirePreSessionInitial(byte[] intent)
        {
            var account = ReopenAccount(); return account.ExpireOwnInitialContactAsync(intent, Source(account));
        }
        internal async Task<(ulong Lower, ulong Upper)> ReadPreSessionExpiryProof()
        {
            var account = ReopenAccount(); var source = Source(account);
            var own = await source.VerifyForOwnPreKeyAuthoringAsync(account, default);
            return (own.Proof.TrustedLowerUnixSeconds, own.Proof.TrustedUpperUnixSeconds);
        }
        internal async Task<byte[]> ReadInitialStopGuardDigest()
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var slot in new[] { ProtectedDid2ContactStartJournal.Slot, ProtectedDph2PreClaimJournal.Slot,
                ProtectedInitialKeyRetirementJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot,
                SqliteDeepIdV2AccountGeneration.ApplicationStateSlot, Did2CompactionPlan.Slot })
            {
                using var raw = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                raw.Use(bytes => { hash.AppendData(bytes); return true; });
            }
            return hash.GetHashAndReset(); // Diagnostic equality, not authority.
        }
    }
}
