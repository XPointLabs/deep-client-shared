using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("reply")]
    [InlineData("selection")]
    [InlineData("before-sql")]
    [InlineData("after-sql")]
    [InlineData("cancel")]
    [InlineData("expired")]
    public async Task Did2RetrieveRenewal_ActualOwnerPreservesOriginalAndColdResumesExactSuccessor(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckOwnedRetrieveRenewalAsync(fault);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckOwnedRetrieveRenewalAsync(string fault)
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            var firstTransport = new OwnedGrantTransport(this, selfRetrieve: true);
            var first = await accounts.AcquireOwnPermanentContactRetrieveGrantAsync(Source(), firstTransport);
            var originalSelector = SHA256.HashData(first.ExactXmg2.Span);
            byte[] originalEntry;
            using (var state = await ReadPeerGrantsAsync(own: true)) originalEntry = Assert.Single(state.Entries).Value.ToArray();
            var slots = new[] { ProtectedDid2ContactRouteJournal.Slot, ProtectedDid2MailboxReadJournal.Slot,
                ProtectedDid2MailboxSendJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot };
            var hashes = new List<byte[]>();
            foreach (var slot in slots)
            { using var raw = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); hashes.Add(raw.Use(bytes => SHA256.HashData(bytes))); }
            await AdvanceOriginalStoreEpochForTestAsync(2_100);
            var transport = new OwnedGrantTransport(this, selfRetrieve: true) { LoseResponse = fault is "reply" or "expired" };
            using var cancellation = new CancellationTokenSource();
            if (fault == "cancel") transport.BeforeReturn = () => { cancellation.Cancel(); return Task.CompletedTask; };
            var owner = ReopenAccount();
            // An absent selector cannot supply original route/holder custody.
            await Assert.ThrowsAsync<IOException>(() => owner.RenewOwnPermanentContactRetrieveGrantAsync(
                Bytes(32, 0xef), Source(owner), transport));
            Assert.Equal(0, transport.Calls);
            Did2MailboxInstallationFailpoint? point = fault switch
            {
                "selection" => Did2MailboxInstallationFailpoint.BeforeSelection,
                "before-sql" => Did2MailboxInstallationFailpoint.BeforeSql,
                "after-sql" => Did2MailboxInstallationFailpoint.AfterSql,
                _ => null
            };
            async Task Renew() => _ = await owner.RenewOwnPermanentContactRetrieveGrantAsync(
                originalSelector, Source(owner), transport, cancellation.Token);
            using (Did2MailboxInstallationTestHooks.Push(value =>
                { if (value == point) throw new IOException("Injected owned renewal handover."); }))
            {
                if (fault == "none") await Renew();
                else if (fault == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(Renew);
                else await Assert.ThrowsAsync<IOException>(Renew);
            }
            using (var state = await ReadPeerGrantsAsync(own: true))
            {
                Assert.Equal(2, state.Entries.Count);
                Assert.Equal(originalEntry, state.Entries[Convert.ToHexString(originalSelector)]);
                if (fault is "reply" or "expired" or "cancel" or "selection")
                {
                    var selection = Assert.Single(state.Selections).Value;
                    Assert.Equal(Convert.ToHexString(originalSelector), selection.Current);
                    Assert.NotNull(selection.Pending);
                    // Ordinary acquisition neither dispatches nor adopts a pending successor.
                    var ordinary = ReopenAccount();
                    await Assert.ThrowsAsync<CryptographicException>(() => ordinary.AcquireOwnPermanentContactRetrieveGrantAsync(Source(ordinary), transport));
                    Assert.Equal(1, transport.Calls);
                }
            }
            if (fault == "expired")
            {
                var request = ContactCodec.Decode("XMG2", transport.OriginalRequest.Span);
                var nextTime = checked(System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(request.Field(10).Span) + 31);
                Sample += nextTime - ProofTime; ProofTime = nextTime;
                var closing = ReopenAccount();
                Assert.Equal(1, await closing.CloseExpiredMailboxAcquisitionsAsync(Source(closing)));
                using var before = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                var pendingOwner = ReopenAccount();
                await Assert.ThrowsAsync<IOException>(() => pendingOwner.RenewOwnPermanentContactRetrieveGrantAsync(
                    originalSelector, Source(pendingOwner), transport));
                using var after = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(before.Use(bytes => bytes.ToArray()), after.Use(bytes => bytes.ToArray()));
                Assert.Equal(1, transport.Calls);
                using var closed = await ReadPeerGrantsAsync(own: true);
                Assert.Equal(2, closed.Entries.Count);
                Assert.Equal(originalEntry, closed.Entries[Convert.ToHexString(originalSelector)]);
                Assert.True(ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(closed.Entries[Convert.ToHexString(SHA256.HashData(transport.OriginalRequest.Span))]));
                Assert.Null(Assert.Single(closed.Selections).Value.Pending);
                Assert.Equal(Convert.ToHexString(originalSelector), Assert.Single(closed.Selections).Value.Current);
                for (var index = 0; index < slots.Length; index++)
                { using var raw = await storage.ReadOwnedAsync(slots[index]) ?? throw new InvalidDataException(); Assert.Equal(hashes[index], raw.Use(bytes => SHA256.HashData(bytes))); }
                CryptographicOperations.ZeroMemory(originalSelector); CryptographicOperations.ZeroMemory(originalEntry);
                return; // Closed unknown work is not a new acquisition or a successful renewal.
            }
            transport.LoseResponse = false; transport.BeforeReturn = null;
            var cold = ReopenAccount();
            var renewed = await cold.RenewOwnPermanentContactRetrieveGrantAsync(originalSelector, Source(cold), transport);
            Assert.Equal(fault is "reply" or "cancel" ? 2 : 1, transport.Calls);
            Assert.True(transport.ExactRetry); Assert.True(transport.BuiltHeldFrame);
            Assert.Equal(transport.OriginalRequest.ToArray(), renewed.ExactXmg2.ToArray());
            Assert.NotEqual(first.ExactXmg2.ToArray(), renewed.ExactXmg2.ToArray());
            var accountId = (await cold.GetCurrentAsync())!.AccountId.ToArray();
            await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
            {
                using var query = sql.CreateCommand();
                foreach (var table in new[] { "mailbox_credential_scopes", "mailbox_credential_epochs", "mailbox_credential_grants" })
                { query.CommandText = $"SELECT COUNT(*) FROM {table};"; Assert.Equal(2, Convert.ToInt32(query.ExecuteScalar())); }
                foreach (var table in new[] { "mailbox_prepared_batches", "mailbox_prepared_batch_targets", "transport_outbox_items" })
                { query.CommandText = $"SELECT COUNT(*) FROM {table};"; Assert.Equal(0, Convert.ToInt32(query.ExecuteScalar())); }
                query.CommandText = "SELECT canonical_grant FROM mailbox_credential_grants;";
                using var rows = query.ExecuteReader();
                var grants = new List<byte[]>(); while (rows.Read()) grants.Add((byte[])rows.GetValue(0));
                Assert.Equal(2, grants.Count);
                Assert.Contains(grants, value => value.AsSpan().SequenceEqual(first.ExactGrant.Span));
                Assert.Contains(grants, value => value.AsSpan().SequenceEqual(renewed.ExactGrant.Span));
            });
            var again = ReopenAccount();
            Assert.Equal(renewed.ExactXmc2.ToArray(), (await again.RenewOwnPermanentContactRetrieveGrantAsync(
                originalSelector, Source(again), transport)).ExactXmc2.ToArray());
            Assert.Equal(fault is "reply" or "cancel" ? 2 : 1, transport.Calls);
            using (var state = await ReadPeerGrantsAsync(own: true))
            {
                var scope = Assert.Single(state.Selections);
                Assert.Null(scope.Value.Pending);
                Assert.Equal(Convert.ToHexString(SHA256.HashData(renewed.ExactXmg2.Span)), scope.Value.Current);
                Assert.Equal(originalEntry, ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(state, scope.Key, SHA256.HashData(first.ExactGrant.Span)));
                Assert.Equal(2, state.Entries.Count);
            }
            for (var index = 0; index < slots.Length; index++)
            { using var raw = await storage.ReadOwnedAsync(slots[index]) ?? throw new InvalidDataException(); Assert.Equal(hashes[index], raw.Use(bytes => SHA256.HashData(bytes))); }
            if (fault == "none")
            {
                var nextSelector = SHA256.HashData(renewed.ExactXmg2.Span);
                var nextOwner = ReopenAccount(); var nextTransport = new OwnedGrantTransport(this, selfRetrieve: true);
                _ = await nextOwner.RenewOwnPermanentContactRetrieveGrantAsync(nextSelector, Source(nextOwner), nextTransport);
                Assert.Equal(1, nextTransport.Calls);
                using var before = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                var staleOwner = ReopenAccount(); var staleTransport = new OwnedGrantTransport(this, selfRetrieve: true);
                await Assert.ThrowsAsync<IOException>(() => staleOwner.RenewOwnPermanentContactRetrieveGrantAsync(
                    originalSelector, Source(staleOwner), staleTransport));
                Assert.Equal(0, staleTransport.Calls);
                using var after = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                Assert.Equal(before.Use(bytes => bytes.ToArray()), after.Use(bytes => bytes.ToArray()));
                CryptographicOperations.ZeroMemory(nextSelector);
            }
            CryptographicOperations.ZeroMemory(originalSelector); CryptographicOperations.ZeroMemory(originalEntry);
        }
    }
}
