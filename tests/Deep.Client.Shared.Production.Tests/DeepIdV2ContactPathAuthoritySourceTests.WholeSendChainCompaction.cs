using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true)] [InlineData(false)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CompletedContactSend_LateParentStoreCannotRemovePendingOrUnknownChild(bool initial)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        test.Grants.MaximumFixtureGrantLifetimeSeconds = 120;
        var stored = await fixture.DeliverCompletedCaseWithExactRetry(test);
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        var secure = fixture.CompletedContactSendStorage(initial);
        using var originalRaw = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        var original = originalRaw.Use(bytes => bytes.ToArray());
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var retained = await fixture.ReadCompletedContactSendRetainedRoots(test.Scope);
        var source = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        using var idle = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
        var idleBytes = idle.Use(bytes => bytes.ToArray());
        try
        {
            foreach (var preparedChild in new[] { false, true })
            {
                // Hostile, canonical protected metadata, not a legitimate
                // issued successor or positive successor-dispatch fixture.
                var attack = fixture.BuildUnresolvedCompletedContactTail(test, original, preparedChild);
                try
                {
                    Assert.True(await secure.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, original, attack));
                    var cached = await test.Deliver();
                    Assert.False(cached.IngressDispatched); Assert.Equal(stored.Cursor, cached.Cursor);
                    Assert.Equal(stored.Disposition, cached.Disposition);
                    await Assert.ThrowsAsync<IOException>(() => fixture.RetireCompletedContactSend(test));
                    using var after = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                    Assert.True(after.Use(bytes => bytes.SequenceEqual(attack)));
                    using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                    Assert.True(plan.Use(bytes => bytes.SequenceEqual(idleBytes)));
                    Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
                    Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
                    Assert.Equal(retained, await fixture.ReadCompletedContactSendRetainedRoots(test.Scope));
                    Assert.Equal(source, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
                    Assert.Equal(1, test.Grants.Calls); Assert.Equal(1, test.Transport.Calls);
                }
                finally
                {
                    Assert.True(await secure.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, attack, original));
                    CryptographicOperations.ZeroMemory(attack);
                }
            }
            if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
            await fixture.RetireCompletedContactSend(test);
            using var root = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
            using var sends = root.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes,
                test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance));
            Assert.Empty(sends.Entries); Assert.Single(sends.Floors);
            Assert.Equal(1, test.Grants.Calls); Assert.Equal(1, test.Transport.Calls);
        }
        finally
        {
            foreach (var bytes in new[] { original, application, native, retained, source, idleBytes, test.Operation, test.Intent })
                CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private sealed partial class Fixture
    {
        internal byte[] BuildUnresolvedCompletedContactTail(CompletedContactSendCase test, byte[] original, bool preparedChild)
        {
            using var sends = ProtectedDid2MailboxSendJournal.Decode(original, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance);
            var parent = sends.Entries[Convert.ToHexString(ProtectedDid2MailboxSendJournal.Key(test.Scope.Hash, test.Operation))];
            var closed = parent.CloseUnknown(parent.AdmissionUntil);
            sends.Entries[parent.Name] = closed; parent.Dispose(); sends.Revision++;
            var request = MailboxAuthenticatedClientRequestCodec.Decode(test.Transport.ExactRequest ?? throw new InvalidDataException());
            var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Binding.CanonicalRequest.Span);
            var attempt = Bytes(32, preparedChild ? (byte)0xe2 : (byte)0xe1);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData("Deep/Local/DID2/MailboxStoreOperation/1"u8); hash.AppendData([0]);
            hash.AppendData(test.Scope.Network); hash.AppendData(test.Scope.LocalAccount); hash.AppendData(test.Scope.Hash);
            hash.AppendData(attempt); hash.AppendData(SHA256.HashData(body.Ciphertext.Span));
            var logical = hash.GetHashAndReset()[..16];
            using var child = ProtectedDid2MailboxSendJournal.Entry.SuccessorOf(closed, attempt,
                Bytes(32, 0xe3), closed.RouteHash, new()
                {
                    Epoch = body.Epoch, MailboxId = body.MailboxId, PlacementId = body.PlacementId,
                    OperationId = logical, DeduplicationDigest = SHA256.HashData(body.Ciphertext.Span),
                    CreatedAtUnixSeconds = closed.ClosedAtLower, ExpiresAtUnixSeconds = closed.Expires,
                    Ciphertext = body.Ciphertext.ToArray()
                }, Math.Min(closed.Expires, checked(closed.ClosedAtLower + 60)));
            sends.EnrollScope(child.GrantHash, Bytes(32, 0xe4)); sends.LinkSuccessor(closed, child);
            if (preparedChild)
            {
                var pending = sends.Entries[child.Name]; var prepared = pending.WithPrepared(Bytes(64, 0xe5), 1);
                sends.Entries[pending.Name] = prepared; pending.Dispose(); sends.AdvanceCounter(prepared.GrantHash, 1); sends.Revision++;
            }
            CryptographicOperations.ZeroMemory(attempt); CryptographicOperations.ZeroMemory(logical);
            return ProtectedDid2MailboxSendJournal.Encode(sends, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance);
        }
    }
}
