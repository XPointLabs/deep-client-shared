using Deep.Protocol.ApplicationCore;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedMailboxSend_AutomaticRecoveryReopensExactOriginalAndDoesNotDuplicateNativeSend()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(false);
        var account = test.Scope.IsInitiator ? fixture.ReopenAccount() : fixture.ReopenGrantReader();
        var source = test.Scope.IsInitiator ? fixture.Source(account) : fixture.GrantReaderSource(account);
        var caller = test.Operation.ToArray();
        test.Transport.LoseReply = true;
        test.Transport.OnLostReply = () =>
        {
            caller.AsSpan().Clear(); fixture.Sample += 40; fixture.ProofTime += 40;
            test.Transport.LoseReply = false;
        };
        var result = await account.DeliverOwnMessagingWithRecoveryAsync(test.Scope, caller, source, test.Grants, test.Transport, default);
        Assert.NotNull(result.Disposition); Assert.NotNull(result.Cursor);
        Assert.Equal(2, test.Transport.Calls); Assert.NotNull(test.Transport.ExactRequest);
        Assert.Equal(1, account.ExactStoreResumes); Assert.Equal(0, account.ExactRecoveryLeaseWaits);
        Assert.All(caller, value => Assert.Equal((byte)0, value));
        using var state = await fixture.ReadMailboxSends(own: test.Scope.IsInitiator);
        var entry = Assert.Single(state.Entries.Values, value => value.Operation.SequenceEqual(test.Operation) && !value.HasPredecessor);
        Assert.Equal(1UL, entry.Counter); Assert.True(entry.Prepared);
    }
}
