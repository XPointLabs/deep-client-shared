using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence.MessagingV1;

namespace Deep.Client.Shared.Tests.MessagingV1;

public sealed class Msg01V2Tests
{
    public static TheoryData<string> Backends => new() { "memory", "sqlite" };

    [Theory, MemberData(nameof(Backends))]
    public async Task IndependentTargetAttemptsAndLateReceiptSurviveReopen(string backend)
    {
        await using var h=MessageStoreHarness.Create(backend); var seed=MessagingV1Fixture.Seed(scope:h.Scope);
        var begin=await h.Store.BeginOutboundAsync(MessagingV1Fixture.Operation(1),new(seed.AuthorAccountId,seed.AuthorDeviceId,seed.ConversationId,seed.SemanticMessageId,seed.EventHash),seed,default);
        var head=begin.Snapshot!; var a=MessagingV1Fixture.Target(30,31); var b=MessagingV1Fixture.Target(30,32);
        head=(await h.Store.ApplyAsync(PreparedMessageMutation.PrepareFanout(head,MessagingV1Fixture.Operation(2),[MessagingV1Fixture.Fanout(a,1),MessagingV1Fixture.Fanout(b,2)],MessagingV1Fixture.CreatedAt.AddSeconds(2)),default)).Snapshot!;
        var aa=MessagingV1Fixture.Attempt(41); var ab=MessagingV1Fixture.Attempt(42);
        head=(await h.Store.ApplyAsync(PreparedMessageMutation.StartSending(head,MessagingV1Fixture.Operation(3),[MessagingV1Fixture.AttemptPlan(head,a,aa,1),MessagingV1Fixture.AttemptPlan(head,b,ab,2)],MessagingV1Fixture.CreatedAt.AddSeconds(3)),default)).Snapshot!;
        Assert.NotEqual(head.Targets[0].ActiveAttemptId,head.Targets[1].ActiveAttemptId);
        head=(await h.Store.ApplyAsync(PreparedMessageMutation.FromVerifiedOutcome(head,MessagingV1Fixture.Outcome(h.Capabilities,head,a,aa,VerifiedTargetOutcomeKind.Accepted),MessagingV1Fixture.CreatedAt.AddSeconds(4)),default)).Snapshot!;
        head=(await h.Store.ApplyAsync(PreparedMessageMutation.FromVerifiedOutcome(head,MessagingV1Fixture.Outcome(h.Capabilities,head,b,ab,VerifiedTargetOutcomeKind.TerminalRejected),MessagingV1Fixture.CreatedAt.AddSeconds(5)),default)).Snapshot!;
        await h.ReopenAsync(); head=(await h.Store.ReadAsync(seed.ClaimKey,default))!;
        head=(await h.Store.ApplyAsync(PreparedMessageMutation.ApplyLateReceipt(head,MessagingV1Fixture.LateReceipt(h.Capabilities,head,a,aa),MessagingV1Fixture.CreatedAt.AddSeconds(6)),default)).Snapshot!;
        Assert.Equal(LogicalOutboxState.RecipientMaterialized,head.State);
    }

    [Fact]
    public async Task TenThousandPreCommitCrashWindowsLeaveNoPartialBegin()
    {
        for(var i=1;i<=10_000;i++)
        {
            var scope=MessagingV1Fixture.Scope(instance:i+10_000); var backing=new InMemoryMessageStoreBacking(scope);
            await using var crashing=new InMemoryMessageTransactionStore(backing,MessagingV1Fixture.CreateEvidenceAuthority(),new ThrowingFailpoint());
            var seed=MessagingV1Fixture.Seed(semantic:i+20_000,eventHash:i+30_000,scope:scope);
            await Assert.ThrowsAsync<InjectedCrash>(() => crashing.BeginOutboundAsync(MessagingV1Fixture.Operation(i+40_000),new(seed.AuthorAccountId,seed.AuthorDeviceId,seed.ConversationId,seed.SemanticMessageId,seed.EventHash),seed,default).AsTask());
            await using var reopened=new InMemoryMessageTransactionStore(backing,MessagingV1Fixture.CreateEvidenceAuthority());
            Assert.Null(await reopened.ReadAsync(seed.ClaimKey,default));
        }
    }

    private sealed class ThrowingFailpoint : IMessageStoreFailpoint
    { public void Hit(string window) => throw new InjectedCrash(); }
    private sealed class InjectedCrash : Exception;
}
