using System.Security.Cryptography;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.MessagingV1;

public sealed class Msg01CorrectiveTests
{
    public static TheoryData<string> Backends => new() { "memory", "sqlite" };

    [Theory, MemberData(nameof(Backends))]
    public async Task ExactFiveHundredTargetsAndIndependentAttemptBindings(string backend)
    {
        await using var h=MessageStoreHarness.Create(backend);var seed=MessagingV1Fixture.Seed(scope:h.Scope);
        var head=(await h.Store.BeginOutboundAsync(MessagingV1Fixture.Operation(1),Claim(seed),seed,default)).Snapshot!;
        var targets=Enumerable.Range(1,500).Select(i=>MessagingV1Fixture.Target(50,i+1000)).ToArray();
        var fanout=targets.Select((t,i)=>MessagingV1Fixture.Fanout(t,i+1)).ToArray();
        head=(await h.Store.ApplyAsync(PreparedMessageMutation.PrepareFanout(head,MessagingV1Fixture.Operation(2),fanout,At(2)),default)).Snapshot!;
        Assert.Equal(500,head.Targets.Count);
        Assert.Throws<ArgumentOutOfRangeException>(()=>PreparedMessageMutation.PrepareFanout(head,MessagingV1Fixture.Operation(3),fanout.Append(MessagingV1Fixture.Fanout(MessagingV1Fixture.Target(50,9999),999)),At(3)));
        var plans=head.Targets.Take(2).Select((t,i)=>MessagingV1Fixture.AttemptPlan(head,t.Target,MessagingV1Fixture.Attempt(20+i),20+i)).ToArray();
        var sent=await h.Store.ApplyAsync(PreparedMessageMutation.StartSending(head,MessagingV1Fixture.Operation(4),plans,At(4)),default);
        Assert.Equal(MessageCommitResult.Applied,sent.CommitResult);
        Assert.Equal(2,sent.Snapshot!.Targets.Count(t=>t.ActiveAttemptId is not null));
        Assert.Throws<ArgumentOutOfRangeException>(()=>PreparedMessageMutation.StartSending(head,MessagingV1Fixture.Operation(5),[plans[0],new TargetAttemptPlan(plans[1].Target,plans[0].AttemptId,plans[1].RequestHash,plans[1].RatchetBeforeHash,plans[1].RatchetTransitionHash,plans[1].DirectoryHeadHash,plans[1].OperationId,plans[1].BindingHash,plans[1].Ciphertext.Span)],At(5)));
    }

    [Theory, MemberData(nameof(Backends))]
    public async Task InboundRatchetReceiptDedupDeviceEvidenceAndLeaseSurviveReopen(string backend)
    {
        await using var h=MessageStoreHarness.Create(backend);var body=MessagingV1Fixture.Bytes(128,71);var sealedState=MessagingV1Fixture.Bytes(96,72);var receipt=MessagingV1Fixture.Bytes(80,73);
        var claim=new SemanticClaimCandidate(MessagingV1Fixture.Account(80),MessagingV1Fixture.Device(81),MessagingV1Fixture.Conversation(82),MessagingV1Fixture.Semantic(83),MessageEventHash32.FromBytes(SHA256.HashData(body)));
        var request=Inbound(h.Capabilities,h.Scope,claim,body,sealedState,receipt);
        var first=await h.Store.MaterializeInboundAsync(request,default);Assert.Single(first!.ObservedAuthorDevices);
        var secondClaim=new SemanticClaimCandidate(claim.AuthorAccountId,MessagingV1Fixture.Device(84),claim.Key.ConversationId,claim.Key.SemanticMessageId,claim.EventHash);
        var duplicate=await h.Store.MaterializeInboundAsync(Inbound(h.Capabilities,h.Scope,secondClaim,body,sealedState,receipt),default);
        Assert.Equal(2,duplicate!.ObservedAuthorDevices.Count);
        await h.ReopenAsync();
        var owner=MessageRecoveryOwnerId16.FromBytes(MessagingV1Fixture.Bytes(16,85));
        var pending=await h.Store.ClaimPendingReceiptsAsync(owner,At(20),10,default);Assert.Equal(2,pending.Count);Assert.All(pending,item=>Assert.NotNull(item.Lease));
        foreach(var item in pending)
            Assert.Equal(MessageCommitResult.Applied,await h.Store.CompletePendingReceiptAsync(item.ReceiptId,owner,At(21),default));
        Assert.Empty(await h.Store.ClaimPendingReceiptsAsync(owner,At(22),10,default));
    }

    [Theory, MemberData(nameof(Backends))]
    public async Task ForkLatchPersistsAndDisposedWrongScopeParity(string backend)
    {
        await using var h=MessageStoreHarness.Create(backend);var first=MessagingV1Fixture.Claim();
        Assert.Equal(SemanticClaimResult.First,await h.Store.ClaimSemanticAsync(first,default));
        var conflict=new SemanticClaimCandidate(first.AuthorAccountId,MessagingV1Fixture.Device(99),first.Key.ConversationId,first.Key.SemanticMessageId,MessagingV1Fixture.EventHash(100));
        Assert.Equal(SemanticClaimResult.ForkLatched,await h.Store.ClaimSemanticAsync(conflict,default));
        await h.ReopenAsync();Assert.Equal(SemanticClaimResult.ForkLatched,await h.Store.ClaimSemanticAsync(first,default));
        var seed=MessagingV1Fixture.Seed(semantic:222,scope:h.Scope);var head=(await h.Store.BeginOutboundAsync(MessagingV1Fixture.Operation(222),Claim(seed),seed,default)).Snapshot!;
        var other=MessagingV1Fixture.Scope(account:222);var wrong=new LogicalOutboxSnapshot(other,head.ClaimKey,head.AuthorDeviceId,head.EventHash,head.CanonicalPayload,head.CreatedAt,head.ExpiresAt,head.State,head.Revision,head.Targets);
        Assert.Equal(MessageCommitResult.Conflict,(await h.Store.ApplyAsync(PreparedMessageMutation.Cancel(wrong,MessagingV1Fixture.Operation(223),At(23)),default)).CommitResult);
        await h.Store.DisposeAsync();using var cancelled=new CancellationTokenSource();cancelled.Cancel();
        await Assert.ThrowsAsync<ObjectDisposedException>(()=>h.Store.ReadAsync(first.Key,cancelled.Token).AsTask());
    }

    [Theory, MemberData(nameof(Backends))]
    public async Task AttemptReplayConflictRecoveryLeaseAndLateCancellationParity(string backend)
    {
        await using var h=MessageStoreHarness.Create(backend);var seed=MessagingV1Fixture.Seed(semantic:240,scope:h.Scope);
        var head=(await h.Store.BeginOutboundAsync(MessagingV1Fixture.Operation(240),Claim(seed),seed,default)).Snapshot!;var target=MessagingV1Fixture.Target(240,241);
        head=(await h.Store.ApplyAsync(PreparedMessageMutation.PrepareFanout(head,MessagingV1Fixture.Operation(241),[MessagingV1Fixture.Fanout(target,240)],At(1)),default)).Snapshot!;
        var attempt=MessagingV1Fixture.Attempt(24);var plan=PreparedMessageMutation.StartSending(head,MessagingV1Fixture.Operation(242),[MessagingV1Fixture.AttemptPlan(head,target,attempt,240)],At(2));
        var sent=await h.Store.ApplyAsync(plan,default);Assert.Equal(MessageCommitResult.Applied,sent.CommitResult);Assert.Equal(MessageCommitResult.Idempotent,(await h.Store.ApplyAsync(plan,default)).CommitResult);
        head=(await h.Store.ApplyAsync(PreparedMessageMutation.FromVerifiedOutcome(sent.Snapshot!,MessagingV1Fixture.Outcome(h.Capabilities,sent.Snapshot!,target,attempt,VerifiedTargetOutcomeKind.Accepted),At(3)),default)).Snapshot!;
        head=(await h.Store.ApplyAsync(PreparedMessageMutation.Cancel(head,MessagingV1Fixture.Operation(243),At(4)),default)).Snapshot!;Assert.Equal(LogicalOutboxState.Cancelled,head.State);
        head=(await h.Store.ApplyAsync(PreparedMessageMutation.ApplyLateReceipt(head,MessagingV1Fixture.LateReceipt(h.Capabilities,head,target,attempt),At(5)),default)).Snapshot!;
        Assert.Equal(LogicalOutboxState.Cancelled,head.State);Assert.Equal(LogicalTargetState.Materialized,Assert.Single(head.Targets).State);

        var recoverSeed=MessagingV1Fixture.Seed(semantic:250,scope:h.Scope);await h.Store.BeginOutboundAsync(MessagingV1Fixture.Operation(250),Claim(recoverSeed),recoverSeed,default);
        var firstOwner=MessageRecoveryOwnerId16.FromBytes(MessagingV1Fixture.Bytes(16,251));var secondOwner=MessageRecoveryOwnerId16.FromBytes(MessagingV1Fixture.Bytes(16,252));
        Assert.Single(await h.Store.ClaimRecoveryAsync(firstOwner,At(10),10,default));await h.ReopenAsync();
        Assert.Empty(await h.Store.ClaimRecoveryAsync(secondOwner,At(11),10,default));
        Assert.Single(await h.Store.ClaimRecoveryAsync(secondOwner,At(11)+MessagingV1Limits.MaxRecoveryLease+TimeSpan.FromMilliseconds(1),10,default));

        var otherSeed=MessagingV1Fixture.Seed(semantic:260,scope:h.Scope);var other=(await h.Store.BeginOutboundAsync(MessagingV1Fixture.Operation(260),Claim(otherSeed),otherSeed,default)).Snapshot!;var otherTarget=MessagingV1Fixture.Target(260,261);
        other=(await h.Store.ApplyAsync(PreparedMessageMutation.PrepareFanout(other,MessagingV1Fixture.Operation(261),[MessagingV1Fixture.Fanout(otherTarget,260)],At(12)),default)).Snapshot!;
        var reused=PreparedMessageMutation.StartSending(other,MessagingV1Fixture.Operation(262),[MessagingV1Fixture.AttemptPlan(other,otherTarget,attempt,260)],At(13));
        Assert.Equal(MessageCommitResult.Conflict,(await h.Store.ApplyAsync(reused,default)).CommitResult);
    }

    [Theory, MemberData(nameof(Backends))]
    public async Task OutboundSemanticIdentityNeverReturnsAnotherAuthorDevice(string backend)
    {
        await using var h = MessageStoreHarness.Create(backend);
        var first = MessagingV1Fixture.Seed(semantic: 270, eventHash: 271, authorDevice: 272, scope: h.Scope);
        var created = await h.Store.BeginOutboundAsync(MessagingV1Fixture.Operation(270), Claim(first), first, default);
        Assert.Equal(MessageCommitResult.Applied, created.CommitResult);

        var other = MessagingV1Fixture.Seed(semantic: 270, eventHash: 271, authorDevice: 273, scope: h.Scope);
        var conflict = await h.Store.BeginOutboundAsync(MessagingV1Fixture.Operation(271), Claim(other), other, default);
        Assert.Equal(MessageCommitResult.Conflict, conflict.CommitResult);
        Assert.Null(conflict.Snapshot);

        var replay = await h.Store.BeginOutboundAsync(MessagingV1Fixture.Operation(270), Claim(first), first, default);
        Assert.Equal(MessageCommitResult.Idempotent, replay.CommitResult);
        Assert.Equal(first.AuthorDeviceId, replay.Snapshot!.AuthorDeviceId);
    }

    [Theory, MemberData(nameof(Backends))]
    public async Task CapabilityAndFingerprintBindingsRejectHostileSubstitutionAcrossBackends(string backend)
    {
        await using var h = MessageStoreHarness.Create(backend);
        var seed = MessagingV1Fixture.Seed(semantic: 280, scope: h.Scope);
        var head = (await h.Store.BeginOutboundAsync(MessagingV1Fixture.Operation(280), Claim(seed), seed, default)).Snapshot!;
        var queued = head;
        var target = MessagingV1Fixture.Target(280, 281);
        var fanout = PreparedMessageMutation.PrepareFanout(head, MessagingV1Fixture.Operation(281),
            [MessagingV1Fixture.Fanout(target, 280)], At(1));
        head = (await h.Store.ApplyAsync(fanout, default)).Snapshot!;

        var alteredFanout = PreparedMessageMutation.PrepareFanout(queued, MessagingV1Fixture.Operation(281),
            [new FanoutTargetSeed(target, MessagingV1Fixture.Directory(381), MessagingV1Fixture.TargetOperation(481), MessagingV1Fixture.Binding(581))], At(1));
        Assert.Equal(MessageCommitResult.Conflict, (await h.Store.ApplyAsync(alteredFanout, default)).CommitResult);

        var attempt = MessagingV1Fixture.Attempt(280);
        var start = PreparedMessageMutation.StartSending(head, MessagingV1Fixture.Operation(282),
            [MessagingV1Fixture.AttemptPlan(head, target, attempt, 280)], At(2));
        head = (await h.Store.ApplyAsync(start, default)).Snapshot!;
        var alteredStart = PreparedMessageMutation.StartSending(head, MessagingV1Fixture.Operation(282),
            [new TargetAttemptPlan(target, attempt, MessagingV1Fixture.Request(680), MessagingV1Fixture.RatchetHash(730), MessagingV1Fixture.Transition(780),
                head.Targets.Single().DirectoryHeadHash, head.Targets.Single().OperationId!, MessagingV1Fixture.Binding(880), MessagingV1Fixture.Bytes(256, 980))], At(2));
        Assert.Equal(MessageCommitResult.Conflict, (await h.Store.ApplyAsync(alteredStart, default)).CommitResult);
        var storedTarget = Assert.Single(head.Targets);
        var hostileContext = new MessageCapabilityTrustedContext(MessageEvidencePurpose.TargetOutcome,
            head.StoreScope, head.ClaimKey, target, attempt, VerifiedTargetOutcomeKind.Accepted,
            targetOperationId: MessagingV1Fixture.TargetOperation(999), bindingHash: storedTarget.BindingHash,
            requestHash: storedTarget.RequestHash!.ToArray(), envelopeHash: head.EventHash.ToArray(),
            ratchetBeforeHash: storedTarget.RatchetBeforeHash!.ToArray(),
            ratchetAfterHash: storedTarget.RatchetTransitionHash!.ToArray(), replayCounter: 1,
            replayNonce: MessagingV1Fixture.Bytes(32, 990));
        var hostileEvidence = MessagingV1Fixture.Authenticate(
            hostileContext, MessagingV1Fixture.Bytes(32, 999));
        var expectedContext = new MessageCapabilityTrustedContext(MessageEvidencePurpose.TargetOutcome,
            head.StoreScope, head.ClaimKey, target, attempt, VerifiedTargetOutcomeKind.Accepted,
            targetOperationId: storedTarget.OperationId, bindingHash: storedTarget.BindingHash,
            requestHash: storedTarget.RequestHash!.ToArray(), envelopeHash: head.EventHash.ToArray(),
            ratchetBeforeHash: storedTarget.RatchetBeforeHash!.ToArray(),
            ratchetAfterHash: storedTarget.RatchetTransitionHash!.ToArray(), replayCounter: 1,
            replayNonce: MessagingV1Fixture.Bytes(32, 990));
        Assert.Throws<CryptographicException>(() =>
            h.Capabilities.VerifyTargetOutcome(expectedContext, hostileEvidence));
        var hostileOutcome = h.Capabilities.VerifyTargetOutcome(hostileContext, hostileEvidence);
        Assert.Throws<InvalidOperationException>(() => PreparedMessageMutation.FromVerifiedOutcome(head, hostileOutcome, At(3)));

        var accepted = MessagingV1Fixture.Outcome(h.Capabilities,head, target, attempt, VerifiedTargetOutcomeKind.Accepted);
        head = (await h.Store.ApplyAsync(PreparedMessageMutation.FromVerifiedOutcome(head, accepted, At(3)), default)).Snapshot!;
        var hostileLateContext = new MessageCapabilityTrustedContext(MessageEvidencePurpose.LateMaterialization,
            head.StoreScope, head.ClaimKey, target, attempt, VerifiedTargetOutcomeKind.Materialized,
            MessagingV1Fixture.Receipt(881), storedTarget.OperationId, MessagingV1Fixture.Binding(882),
            storedTarget.RequestHash!.ToArray(), head.EventHash.ToArray(),
            storedTarget.DirectoryHeadHash.ToArray(), storedTarget.RatchetTransitionHash!.ToArray(),
            2, MessagingV1Fixture.Bytes(32, 991));
        var hostileLate = h.Capabilities.VerifyLateReceipt(hostileLateContext,
            MessagingV1Fixture.Authenticate(
                hostileLateContext, MessagingV1Fixture.Bytes(32, 883)));
        Assert.Throws<InvalidOperationException>(() => PreparedMessageMutation.ApplyLateReceipt(head, hostileLate, At(4)));
    }

    [Fact]
    public async Task SqlCipherRejectsWrongKeyPlaintextAndDetectsAbruptCommitWindows()
    {
        var dir=Path.Combine(Path.GetTempPath(),$"deep-msg-corrective-{Guid.NewGuid():N}");Directory.CreateDirectory(dir);var path=Path.Combine(dir,"msg.db");var key=MessagingV1Fixture.Bytes(32,301);var scope=MessagingV1Fixture.Scope(instance:301);
        try
        {
            var before=new SqliteMessageStoreOptions(path,key,scope,MessagingV1Fixture.CreateEvidenceAuthority(),failpoint:new SelectiveFailpoint("begin.before-commit"));
            await using(var store=SqliteMessageStoreBootstrap.Open(before)){var seed=MessagingV1Fixture.Seed(semantic:301,scope:scope);await Assert.ThrowsAsync<InjectedExit>(()=>store.BeginOutboundAsync(MessagingV1Fixture.Operation(301),Claim(seed),seed,default).AsTask());}
            await using(var reopened=SqliteMessageStoreBootstrap.Open(new(path,key,scope,MessagingV1Fixture.CreateEvidenceAuthority(),false))){Assert.Null(await reopened.ReadAsync(new(scope.LocalAccountId,MessagingV1Fixture.Conversation(),MessagingV1Fixture.Semantic(301)),default));}
            var after=new SqliteMessageStoreOptions(path,key,scope,MessagingV1Fixture.CreateEvidenceAuthority(),false,new SelectiveFailpoint("begin.after-commit-before-return"));
            var seed2=MessagingV1Fixture.Seed(semantic:302,scope:scope);await using(var store=SqliteMessageStoreBootstrap.Open(after)){await Assert.ThrowsAsync<InjectedExit>(()=>store.BeginOutboundAsync(MessagingV1Fixture.Operation(302),Claim(seed2),seed2,default).AsTask());}
            await using(var reopened=SqliteMessageStoreBootstrap.Open(new(path,key,scope,MessagingV1Fixture.CreateEvidenceAuthority(),false))){Assert.NotNull(await reopened.ReadAsync(seed2.ClaimKey,default));}
            Assert.False(File.ReadAllBytes(path).AsSpan(0,16).SequenceEqual("SQLite format 3\0"u8));
            Assert.Throws<MessageStoreResetRequiredException>(()=>SqliteMessageStoreBootstrap.Open(new(path,MessagingV1Fixture.Bytes(32,999),scope,MessagingV1Fixture.CreateEvidenceAuthority(),false)));
            var plain=Path.Combine(dir,"plain.db");using(var c=new SqliteConnection($"Data Source={plain};Pooling=False")){c.Open();using var q=c.CreateCommand();q.CommandText="CREATE TABLE x(v INTEGER);";q.ExecuteNonQuery();}
            Assert.Throws<MessageStoreResetRequiredException>(()=>SqliteMessageStoreBootstrap.Open(new(plain,key,scope,MessagingV1Fixture.CreateEvidenceAuthority(),false)));
        }
        finally { await SqliteMessageStoreBootstrap.ResetAsync(path);var plain=Path.Combine(dir,"plain.db");if(File.Exists(plain))File.Delete(plain);if(Directory.Exists(dir))Directory.Delete(dir,false);CryptographicOperations.ZeroMemory(key); }
    }

    [Fact]
    public async Task SqlCipherWalAndSidecarsAreVerifiedAcrossCheckpointAndZeroByteStates()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"deep-msg-sidecars-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "msg.db");
        var key = MessagingV1Fixture.Bytes(32, 401);
        var scope = MessagingV1Fixture.Scope(instance: 401);
        try
        {
            await using (var store = SqliteMessageStoreBootstrap.Open(new(
                path, key, scope, MessagingV1Fixture.CreateEvidenceAuthority())))
            {
                var seed = MessagingV1Fixture.Seed(semantic: 401, scope: scope);
                await store.BeginOutboundAsync(MessagingV1Fixture.Operation(401), Claim(seed), seed, default);
                store.ValidateEncryptedFilesForTesting();
                using var raw = new SqliteConnection($"Data Source={path};Pooling=False");
                raw.Open();
                Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(raw.Handle, key));
                using var journal = raw.CreateCommand();
                journal.CommandText = "PRAGMA journal_mode;";
                Assert.Equal("wal", Convert.ToString(journal.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture), StringComparer.OrdinalIgnoreCase);
            }
            File.WriteAllBytes(path + "-wal", []);
            File.WriteAllBytes(path + "-shm", []);
            await using (var reopened = SqliteMessageStoreBootstrap.Open(new(
                path, key, scope, MessagingV1Fixture.CreateEvidenceAuthority(), allowCreate: false)))
            {
                reopened.ValidateEncryptedFilesForTesting();
            }
            File.WriteAllBytes(path + "-wal", [0x01]);
            Assert.Throws<MessageStoreResetRequiredException>(() => SqliteMessageStoreBootstrap.Open(new(
                path, key, scope, MessagingV1Fixture.CreateEvidenceAuthority(), allowCreate: false)));
        }
        finally
        {
            await SqliteMessageStoreBootstrap.ResetAsync(path);
            if (Directory.Exists(dir)) Directory.Delete(dir, false);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static SemanticClaimCandidate Claim(LogicalOutboxSeed seed)=>new(seed.AuthorAccountId,seed.AuthorDeviceId,seed.ConversationId,seed.SemanticMessageId,seed.EventHash);
    private static DateTimeOffset At(int seconds)=>MessagingV1Fixture.CreatedAt.AddSeconds(seconds);
    private static InboxMaterializationRequest Inbound(IMessageVerifiedTransportHandoff capabilities,MessageStoreScope scope,SemanticClaimCandidate claim,byte[] body,byte[] state,byte[] receipt)
    {
        var context = new MessageCapabilityTrustedContext(MessageEvidencePurpose.InboundMaterialization,
            scope, claim.Key, receiptId: MessagingV1Fixture.Receipt(claim.AuthorDeviceId.Span[0] + 92),
            requestHash: SHA256.HashData(body), envelopeHash: claim.EventHash.ToArray(),
            ratchetBeforeHash: MessagingV1Fixture.Bytes(32, 91),
            ratchetAfterHash: SHA256.HashData(state),
            replayCounter: checked((ulong)claim.AuthorDeviceId.Span[0] + 1),
            replayNonce: SHA256.HashData(claim.AuthorDeviceId.Span),
            ratchetSessionId: RatchetSessionId32.FromBytes(MessagingV1Fixture.Bytes(32,90)));
        var sealedEvidence = MessagingV1Fixture.Authenticate(context, receipt);
        return capabilities.VerifyInbound(context, claim, body,
            RatchetSessionId32.FromBytes(MessagingV1Fixture.Bytes(32,90)),
            RatchetStateHash32.FromBytes(MessagingV1Fixture.Bytes(32,91)),
            RatchetStateHash32.FromBytes(SHA256.HashData(state)), state, At(10), sealedEvidence);
    }
    private sealed class SelectiveFailpoint(string window):IMessageStoreFailpoint{public void Hit(string actual){if(actual==window)throw new InjectedExit();}}
    private sealed class InjectedExit:Exception;
}
