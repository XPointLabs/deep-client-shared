using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2InitialAttempt_ExpiredApplicationClosesOriginalUnknownWithoutIssuingOrDispatchingSuccessor()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(true);
        test.Grants.MaximumFixtureGrantLifetimeSeconds = 120;
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == Did2MailboxSendFailpoint.AfterPreparedRoot) throw new IOException("Interrupted initial request."); }))
            await Assert.ThrowsAsync<IOException>(test.Deliver);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var source = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        byte[] original;
        using (var sends = await fixture.ReadMailboxSends())
        {
            var entry = Assert.Single(sends.Entries).Value; original = entry.Exact.ToArray();
            Assert.True(entry.RetryUntil < entry.Expires);
            var delta = checked(entry.RetryUntil + 6 - fixture.CurrentProofTime);
            fixture.Sample = checked(fixture.Sample + delta); fixture.ProofTime = checked(fixture.ProofTime + delta);
        }
        fixture.ColdReopenCompactionStorage();
        var issuer = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeInitial(test.Intent, issuer, test.Transport));
        using (var sends = await fixture.ReadMailboxSends())
        {
            var entry = Assert.Single(sends.Entries).Value;
            Assert.True(entry.Closed); Assert.False(entry.HasSuccessor); Assert.True(entry.Prepared);
            Assert.Equal(original[..296], entry.Exact[..296].ToArray());
            Assert.True(entry.ClosedAtLower >= entry.AdmissionUntil);
            Assert.Equal(2UL, sends.MinimumCounter(entry.GrantHash));
        }
        Assert.Equal(0, issuer.Calls); Assert.Equal(0, test.Transport.Calls);
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        Assert.Equal(source, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
        foreach (var bytes in new[] { original, source, native }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2InitialAttempt_ChangedOriginalDraftRecipientRejectsBeforeIssuerAndSendMutation()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(true);
        var secure = fixture.CompletedContactSendStorage(true);
        using var draft = await secure.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot) ?? throw new InvalidDataException();
        var original = draft.Use(bytes => bytes.ToArray()); var hostile = original.ToArray();
        // One disposable fixture draft, canonical framing; only its original
        // recipient DCR digest is changed, not a public signature or native event.
        hostile[ProtectedDid2ContactStartJournal.HeaderBytes + 4 + 192] ^= 1;
        Assert.True(await secure.CompareExchangeAsync(ProtectedDid2ContactStartJournal.Slot, original, hostile));
        using var before = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        try
        {
            await Assert.ThrowsAsync<CryptographicException>(test.Deliver);
            using var after = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
            Assert.Equal(before.Use(bytes => bytes.ToArray()), after.Use(bytes => bytes.ToArray()));
            Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
            Assert.Equal(0, test.Grants.Calls); Assert.Equal(0, test.Transport.Calls);
        }
        finally
        {
            Assert.True(await secure.CompareExchangeAsync(ProtectedDid2ContactStartJournal.Slot, hostile, original));
            foreach (var bytes in new[] { original, hostile, native }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [Theory]
    [InlineData("BeforeSuccessorRoot")] [InlineData("AfterSuccessorRoot")] [InlineData("AfterSql")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2InitialAttempt_CurrentGrantColdSuccessorPreservesDraftRecipientDphAndApplicationDeadline(string fault)
    {
        // Genuine native PQ/SQLCipher source, signatures and owned orchestration;
        // an in-process issuer chooses a shorter, signed policy-compliant grant.
        // This is not socket/device E2E or changed-recipient-route qualification.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var test = await fixture.PrepareCompletedContactSendCase(true);
        test.Grants.MaximumFixtureGrantLifetimeSeconds = 120;
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == Did2MailboxSendFailpoint.AfterPreparedRoot) throw new IOException("Interrupted original initial preparation."); }))
            await Assert.ThrowsAsync<IOException>(test.Deliver);
        Assert.Equal(1, test.Grants.Calls); Assert.Equal(0, test.Transport.Calls);
        var source = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var authored = await fixture.ReadAuthoredRootDigestAsync();
        ulong applicationDeadline;
        var secure = fixture.CompletedContactSendStorage(true);
        using (var raw = await secure.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot) ?? throw new InvalidDataException())
        using (var drafts = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes,
            test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance)))
        {
            var draft = Assert.Single(drafts.Entries).Value;
            applicationDeadline = Math.Min(ApplicationCoreCodec.DecodeDmc2(draft.Init).ExpiresAtUnixMilliseconds,
                ApplicationCoreCodec.DecodeDmc2(draft.Hello).ExpiresAtUnixMilliseconds) / 1_000;
        }
        byte[] original;
        using (var sends = await fixture.ReadMailboxSends())
        {
            var parent = Assert.Single(sends.Entries).Value;
            Assert.Equal(applicationDeadline, parent.RetryUntil); Assert.True(parent.RetryUntil < parent.Expires);
            original = parent.Exact.ToArray();
            var center = checked(parent.AdmissionUntil + 6);
            Assert.True(center + 5 < parent.RetryUntil);
            var delta = checked(center - fixture.CurrentProofTime);
            fixture.ProofTime = checked(fixture.ProofTime + delta); fixture.Sample = checked(fixture.Sample + delta);
        }
        fixture.ColdReopenCompactionStorage();
        var issuer = new OwnedGrantTransport(fixture, ownerOnPrimary: true) { MaximumFixtureGrantLifetimeSeconds = 120 };
        var transport = new OwnedStoreFixture(fixture, test.Scope, test.Operation, null);
        var failpoint = Enum.Parse<Did2MailboxSendFailpoint>(fault); var hit = false;
        using (Did2MailboxSendTestHooks.Push(point =>
            { if (point == failpoint) { hit = true; throw new IOException("Interrupted initial successor handover."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeInitial(test.Intent, issuer, transport));
        Assert.True(hit); Assert.Equal(1, issuer.Calls); Assert.Equal(0, transport.Calls);
        fixture.ColdReopenCompactionStorage();
        var unused = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var stored = await fixture.DeliverNativeInitial(test.Intent, unused, transport);
        Assert.NotNull(stored.Cursor); Assert.Equal(0, unused.Calls); Assert.Equal(1, transport.Calls);
        using (var sends = await fixture.ReadMailboxSends())
        {
            var chain = sends.Chain(test.Scope.Hash, test.Operation);
            Assert.Equal(2, chain.Count);
            var parent = chain[0]; var child = chain[1];
            Assert.Equal(original[..296], parent.Exact[..296].ToArray());
            Assert.True(parent.Closed); Assert.True(child.Prepared); Assert.False(child.Closed);
            Assert.Equal(child.Attempt.ToArray(), parent.Successor.ToArray());
            Assert.Equal(parent.Attempt.ToArray(), child.Predecessor.ToArray());
            Assert.Equal(parent.EnvelopeHash.ToArray(), child.EnvelopeHash.ToArray());
            Assert.Equal(parent.Expires, child.Expires); Assert.Equal(applicationDeadline, child.RetryUntil);
            var granted = MailboxAuthenticatedClientRequestCodec.Decode(transport.ExactRequest!).Presentation.Grant;
            Assert.Equal(Math.Min(child.RetryUntil, granted.ExpiresAtUnixSeconds), child.AdmissionUntil);
            Assert.NotEqual(parent.MailboxOperation.ToArray(), child.MailboxOperation.ToArray());
            Assert.NotEqual(parent.GrantHash.ToArray(), child.GrantHash.ToArray());
            Assert.Equal(2UL, sends.MinimumCounter(parent.GrantHash)); Assert.Equal(2UL, sends.MinimumCounter(child.GrantHash));
        }
        fixture.AdvanceSyntheticMailboxClockPast(transport.DurableTimeForFixture);
        fixture.ColdReopenCompactionStorage();
        var cached = await fixture.DeliverNativeInitial(test.Intent, unused, transport);
        Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
        using var sendsBefore = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        await Assert.ThrowsAsync<IOException>(() => fixture.RetireCompletedContactSend(test));
        using var sendsAfter = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        Assert.Equal(sendsBefore.Use(bytes => bytes.ToArray()), sendsAfter.Use(bytes => bytes.ToArray()));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        Assert.Equal(source, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(0, unused.Calls); Assert.Equal(1, transport.Calls);
        foreach (var bytes in new[] { source, native, authored, original }) CryptographicOperations.ZeroMemory(bytes);
    }
}
