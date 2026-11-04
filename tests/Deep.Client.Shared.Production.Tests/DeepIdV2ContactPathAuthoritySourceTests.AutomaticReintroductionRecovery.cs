using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteReintroduction_AutomaticRecoveryKeepsExactPreparedOriginalWithoutAnotherNativeSend()
    {
        // Genuine signed in-process services, owned grants, SQLCipher and native
        // custody. This is not a socket, deployed-node or physical-device claim.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        fixture.TrackMailboxDispatchClock();
        await fixture.RenewNativeSenderPublicationPastExpiryAsync();
        using var command = await fixture.CreateOwnedRouteUpdate(sender);
        var operation = command.OperationId.ToArray(); byte[] ciphertext;
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, operation)) ciphertext = sent.ExactEnvelope.ToArray();
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        using var authoredBefore = await fixture.ReadAuthoredTextJournalAsync(sender);
        var account = fixture.ReopenAccount(); var caller = operation.ToArray();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var terminal = new OwnedStoreFixture(fixture, sender, operation, ciphertext) { LoseReply = true };
        byte[] originalMau = [];
        terminal.OnLostReply = () =>
        {
            originalMau = terminal.ExactRequest!.ToArray();
            var grant = MailboxAuthenticatedClientRequestCodec.Decode(originalMau).Presentation.Grant;
            Assert.True(checked(fixture.CurrentProofTime + 45) < grant.ExpiresAtUnixSeconds);
            caller.AsSpan().Clear(); fixture.Sample += 40; fixture.ProofTime += 40;
            terminal.LoseReply = false;
        };
        var result = await fixture.DeliverAutomaticReintroducedRoute(account, sender, caller, grants, terminal);
        Assert.NotNull(result.Cursor); Assert.NotNull(result.Disposition);
        Assert.Equal(2, terminal.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(originalMau, terminal.ExactRequest); // Includes body, grant, counter, nonce and operation.
        Assert.All(caller, value => Assert.Equal((byte)0, value));
        Assert.Equal(1, account.ExactStoreResumes); Assert.Equal(0, account.ExactRecoveryLeaseWaits);
        using (var sends = await fixture.ReadMailboxSends())
        {
            var attempt = Assert.Single(sends.Entries.Values, entry => entry.Operation.SequenceEqual(operation));
            Assert.False(attempt.HasPredecessor); Assert.False(attempt.HasSuccessor); Assert.True(attempt.Prepared);
            Assert.Equal(SHA256.HashData(originalMau), attempt.MauHash.ToArray());
            Assert.Equal(1UL, attempt.Counter);
        }
        using (var authoredAfter = await fixture.ReadAuthoredTextJournalAsync(sender))
        {
            Assert.Equal(authoredBefore.NextSequence(sender), authoredAfter.NextSequence(sender));
            Assert.Equal(authoredBefore.Entries.Count, authoredAfter.Entries.Count);
            Assert.Equal(authoredBefore.Entries[Convert.ToHexString(operation)].EventHash.ToArray(),
                authoredAfter.Entries[Convert.ToHexString(operation)].EventHash.ToArray());
        }
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        foreach (var bytes in new[] { operation, ciphertext, floor, caller, originalMau }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteReintroduction_AutomaticRecoveryStopsExpiredOriginalBeforeFreshRecipientOrDispatch()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        fixture.TrackMailboxDispatchClock();
        await fixture.RenewNativeSenderPublicationPastExpiryAsync();
        using var command = await fixture.CreateOwnedRouteUpdate(sender);
        var operation = command.OperationId.ToArray(); byte[] ciphertext;
        var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
        var deadline = message.ExpiresAtUnixMilliseconds / 1_000;
        Assert.True(deadline > fixture.CurrentProofTime);
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, operation)) ciphertext = sent.ExactEnvelope.ToArray();
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var account = fixture.ReopenAccount(); var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var terminal = new OwnedStoreFixture(fixture, sender, operation, ciphertext) { LoseReply = true };
        byte[] originalMau = [];
        terminal.OnLostReply = () =>
        {
            originalMau = terminal.ExactRequest!.ToArray();
            var delta = checked(deadline + 20 - fixture.CurrentProofTime);
            fixture.Sample = checked(fixture.Sample + delta); fixture.ProofTime = checked(fixture.ProofTime + delta);
            fixture.RejectContactRetryRecipient(initial: true);
        };
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() =>
            fixture.DeliverAutomaticReintroducedRoute(account, sender, operation, grants, terminal));
        Assert.Equal(1, terminal.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(originalMau, terminal.ExactRequest);
        Assert.Equal(0, fixture.RejectedContactRetryProofCalls); Assert.Equal(0, fixture.RejectedContactRetryReadCalls);
        Assert.Equal(ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired,
            await fixture.ReadStoppedWorkReason(sender, operation));
        using (var sends = await fixture.ReadMailboxSends())
        {
            var attempt = Assert.Single(sends.Entries.Values, entry => entry.Operation.SequenceEqual(operation));
            Assert.True(attempt.Closed); Assert.True(attempt.Prepared); Assert.False(attempt.HasSuccessor);
            Assert.Equal(deadline, attempt.RetryUntil); Assert.True(attempt.ClosedAtLower >= deadline);
            Assert.Equal(SHA256.HashData(originalMau), attempt.MauHash.ToArray());
        }
        Assert.Equal(1, account.ExactStoreResumes); Assert.Equal(0, account.ExactRecoveryLeaseWaits);
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        foreach (var bytes in new[] { operation, ciphertext, floor, originalMau }) CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed partial class Fixture
    {
        internal async Task<ClientMailboxStoreResult> DeliverAutomaticReintroducedRoute(DeepIdV2AccountService account,
            Did2MessagingSessionScope scope, byte[] operation, IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport)
        {
            var source = Source(account);
            var read = new SyntheticPermanentRead(this, source, nativeMessagingPublication);
            var address = nativeMessagingContact!.Candidate.Address;
            var contact = await account.ResolvePermanentContactAsync(address, source, read);
            var resolved = await source.VerifyPermanentContactAsync(contact.Candidate, default);
            return await account.DeliverOwnRouteReintroductionWithRecoveryAsync(scope, operation, address,
                resolved, source, grants, transport, default, read);
        }
    }
}
