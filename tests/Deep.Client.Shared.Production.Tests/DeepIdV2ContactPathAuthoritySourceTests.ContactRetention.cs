using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0, false)] [InlineData(1, false)] [InlineData(2, false)]
    [InlineData(0, true)] [InlineData(1, true)] [InlineData(2, true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CompletedContactSend_PreCommitAbandonKeepsBothPredecessorsAcrossColdHandover(int handover, bool initial)
    {
        // Real native/SQLCipher/owned Store; synthetic authenticated services,
        // not a physical client or socket/deployed-network qualification.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        _ = await test.Deliver();
        var secure = fixture.CompletedContactSendStorage(initial);
        var payloadSlot = initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var send = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        using var consent = await secure.ReadOwnedAsync(payloadSlot) ?? throw new InvalidDataException();
        var originalSend = send.Use(bytes => bytes.ToArray()); var originalConsent = consent.Use(bytes => bytes.ToArray());
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var roots = await fixture.ReadCompletedContactSendRetainedRoots(test.Scope);
        using (Did2CompactionTestHooks.Push(point =>
            { if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Interrupted prepared contact retirement."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.RetireCompletedContactSend(test));
        if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
        var owner = fixture.CompletedContactSendRecoveryOwner(initial);
        // The first stage is the current SQL-bound terminal control audit,
        // before the separate protected send-chain retirement. Abandon that
        // actual profile; the protected-only acquisition owner cannot own it.
        if (handover == 0)
        {
            using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
            using var part = await secure.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(0)) ?? throw new InvalidDataException();
            var original = part.Use(bytes => bytes.ToArray()); var changed = original.ToArray(); changed[^1] ^= 1;
            try
            {
                Assert.True(await secure.CompareExchangeAsync(ProtectedDid2CompactionPlan.PartSlot(0), original, changed));
                await Assert.ThrowsAsync<InvalidDataException>(() => owner.AbandonUncommittedControlAuditAsync(default));
                using var unchanged = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                var digest = plan.Use(bytes => SHA256.HashData(bytes));
                Assert.True(unchanged.Use(bytes => CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), digest)));
                Assert.True(await secure.CompareExchangeAsync(ProtectedDid2CompactionPlan.PartSlot(0), changed, original));
            }
            finally { CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(changed); }
            await owner.AbandonUncommittedControlAuditAsync(default);
        }
        else
        {
            var point = handover == 1 ? Did2CompactionFailpoint.AfterPartsDeleted : Did2CompactionFailpoint.AfterPlanCleared;
            using (Did2CompactionTestHooks.Push(actual =>
                { if (actual == point) throw new IOException("Interrupted contact abandonment."); }))
                await Assert.ThrowsAsync<IOException>(() => owner.AbandonUncommittedControlAuditAsync(default));
            if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
            await fixture.CompletedContactSendRecoveryOwner(initial).ResumeOwnedLocalCompactionAsync(default);
        }
        using var sendAfter = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        using var consentAfter = await secure.ReadOwnedAsync(payloadSlot) ?? throw new InvalidDataException();
        Assert.True(sendAfter.Use(bytes => bytes.SequenceEqual(originalSend)));
        Assert.True(consentAfter.Use(bytes => bytes.SequenceEqual(originalConsent)));
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        Assert.Equal(roots, await fixture.ReadCompletedContactSendRetainedRoots(test.Scope));
        using var idle = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
        Assert.Equal(0, idle.Use(bytes => bytes[1]));
        for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
            Assert.Null(await secure.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index)));
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        await fixture.RetireCompletedContactSend(test);
        using var marker = await secure.ReadOwnedAsync(payloadSlot) ?? throw new InvalidDataException();
        if (initial)
        { using var commands = marker.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance)); Assert.True(commands.Entries[Convert.ToHexString(test.Intent)].PayloadRetired); }
        else
        { using var commands = marker.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance)); Assert.True(commands.FindScope(test.Scope)!.PayloadRetired); }
        foreach (var bytes in new[] { originalSend, originalConsent, application, native, roots }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CompletedContactSend_SameOwnerColdRetryFinishesInterruptedAuditAndSendClosure(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        var stored = await test.Deliver();
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var retained = await fixture.ReadCompletedContactSendRetainedRoots(test.Scope);
        var hit = false;
        using (Did2CompactionTestHooks.Push(point =>
        {
            if (point != Did2CompactionFailpoint.AfterStage) return;
            hit = true; throw new IOException("Interrupted actual terminal control audit.");
        }))
            await Assert.ThrowsAsync<IOException>(() => fixture.RetireCompletedContactSend(test));
        Assert.True(hit);
        if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
        // Retry the same business owner, not a fixture-only recovery shortcut.
        await fixture.RetireCompletedContactSend(test);
        using (var sends = await fixture.ReadMailboxSends(own: initial))
        { Assert.Empty(sends.Entries); Assert.Equal(1UL, Assert.Single(sends.Floors).Value.HighestCounter); }
        var secure = fixture.CompletedContactSendStorage(initial);
        using (var idle = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException())
            Assert.Equal(0, idle.Use(bytes => bytes[1]));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        Assert.Equal(retained, await fixture.ReadCompletedContactSendRetainedRoots(test.Scope));
        var cached = await test.Deliver();
        Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
        Assert.Equal(stored.Disposition, cached.Disposition);
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        foreach (var bytes in new[] { native, retained }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CompletedContactSend_ConsentOnlyColdAccountCanReplayAcceptanceAndSendFreshUserText()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(false);
        _ = await test.Deliver();
        var peer = test.PeerScope ?? throw new InvalidDataException();
        var acceptedEnvelope = test.Transport.StoredEnvelope!.Ciphertext.ToArray();
        using (var received = await fixture.ReceiveOwnedMessage(peer, acceptedEnvelope)) { }
        await fixture.RetireCompletedContactSend(test);
        fixture.ColdReopenReceiverStoreStorage(); fixture.ColdReopenCompactionStorage();
        Assert.Equal(Did2ContactAcceptanceState.LocalAcceptanceRetained, await fixture.ReadOwnedContactState(test.Scope));
        Assert.Equal(Did2ContactAcceptanceState.PeerAcceptanceRetained, await fixture.ReadOwnedContactState(peer));
        var floor = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        using (var accept = await fixture.PrepareOwnedContactAccept(test.Scope, Bytes(32, 0x64)))
        {
            Assert.True(accept.Operation.SequenceEqual(test.Operation));
            using var cached = await fixture.SendOwnedMessage(test.Scope, test.Operation, ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2));
            Assert.True(cached.ExactEnvelope.SequenceEqual(acceptedEnvelope));
        }
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        const string text = "Fresh user text after consent payload retirement";
        using var draft = await fixture.CreateOwnedText(test.Scope, text);
        var operation = draft.OperationId.ToArray();
        Assert.Equal(4UL, draft.SenderSequence);
        using var sent = await fixture.SendOwnedMessage(test.Scope, operation, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
        var transport = new OwnedStoreFixture(fixture, test.Scope, operation, null);
        var stored = await fixture.DeliverNativeMessage(test.Scope, operation, test.Grants, transport);
        Assert.True(stored.IngressDispatched); Assert.Equal(1, transport.Calls);
        var envelope = transport.StoredEnvelope!.Ciphertext.ToArray();
        Assert.True(sent.ExactEnvelope.SequenceEqual(envelope));
        using (var received = await fixture.ReceiveOwnedMessage(peer, envelope)) { }
        var receivedFloor = (await fixture.ReadMessagingFloor(peer)).Exact.ToArray();
        using (var duplicate = await fixture.ReceiveOwnedMessage(peer, envelope)) { Assert.Equal(2, duplicate.Direction); }
        Assert.Equal(receivedFloor, (await fixture.ReadMessagingFloor(peer)).Exact.ToArray());
        var remote = Assert.Single(await fixture.ListOwnedMessages(peer)); Assert.Equal(text, remote.Text); Assert.False(remote.IsLocalAuthor);
        var local = Assert.Single(await fixture.ListOwnedMessages(test.Scope)); Assert.Equal(text, local.Text); Assert.True(local.IsLocalAuthor);
        Assert.Single(await fixture.ListOwnedReceiptObligations(peer));
        using var raw = await fixture.CompletedContactSendStorage(false).ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot) ?? throw new InvalidDataException();
        using var commands = raw.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes,
            test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance));
        Assert.True(commands.FindScope(test.Scope)!.PayloadRetired);
        Assert.Equal(ProtectedDid2ContactAcceptJournal.PrefixBytes, commands.FindScope(test.Scope)!.Exact.Length);
        foreach (var bytes in new[] { acceptedEnvelope, floor, operation, envelope, receivedFloor }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CompletedContactSend_InitialMarkerColdRetryKeepsHandshakeAndFreshOwnedText()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(true);
        var stored = await test.Deliver();
        var initialEnvelope = test.Transport.StoredEnvelope!.Ciphertext.ToArray();
        await fixture.RetireCompletedContactSend(test);
        fixture.ColdReopenCompactionStorage();
        var cached = await test.Deliver();
        Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
        Assert.Equal(1, test.Transport.Calls); Assert.Equal(1, test.Grants.Calls);
        using (var received = await fixture.CompleteReceiver(initialEnvelope)) { }
        var receiver = await fixture.EnsureReceiverMessaging(initialEnvelope);
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x66)))
        using (var sentAccept = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(test.Scope, sentAccept.ExactEnvelope.ToArray())) { }
        Assert.Equal(Did2ContactAcceptanceState.PeerAcceptanceRetained, await fixture.ReadOwnedContactState(test.Scope));
        const string text = "Fresh user text after Initial working payload retirement";
        using var draft = await fixture.CreateOwnedText(test.Scope, text);
        var operation = draft.OperationId.ToArray();
        using var sent = await fixture.SendOwnedMessage(test.Scope, operation, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
        var transport = new OwnedStoreFixture(fixture, test.Scope, operation, null);
        var next = await fixture.DeliverNativeMessage(test.Scope, operation, test.Grants, transport);
        Assert.True(next.IngressDispatched); Assert.Equal(1, transport.Calls);
        var envelope = transport.StoredEnvelope!.Ciphertext.ToArray(); Assert.True(sent.ExactEnvelope.SequenceEqual(envelope));
        using (var received = await fixture.ReceiveOwnedMessage(receiver, envelope)) { }
        var floor = (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray();
        using (var duplicate = await fixture.ReceiveOwnedMessage(receiver, envelope)) { Assert.Equal(2, duplicate.Direction); }
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        var remote = Assert.Single(await fixture.ListOwnedMessages(receiver)); Assert.Equal(text, remote.Text); Assert.False(remote.IsLocalAuthor);
        var local = Assert.Single(await fixture.ListOwnedMessages(test.Scope)); Assert.Equal(text, local.Text); Assert.True(local.IsLocalAuthor);
        Assert.Single(await fixture.ListOwnedReceiptObligations(receiver));
        using var raw = await fixture.CompletedContactSendStorage(true).ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot) ?? throw new InvalidDataException();
        using var commands = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance));
        var marker = commands.Entries[Convert.ToHexString(test.Intent)]; Assert.True(marker.PayloadRetired);
        Assert.Equal(ProtectedDid2ContactStartJournal.PrefixBytes, marker.Exact.Length);
        foreach (var bytes in new[] { initialEnvelope, operation, envelope, floor }) CryptographicOperations.ZeroMemory(bytes);
    }
}
