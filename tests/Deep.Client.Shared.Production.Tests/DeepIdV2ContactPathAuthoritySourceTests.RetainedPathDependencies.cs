using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    private sealed partial class Fixture
    {
        // Hostile writes into disposable protected storage only. A structurally
        // valid reduced journal is not proof of settlement or a repair input.
        private async Task CheckArchivedPathProtectedDependenciesAsync(DeepIdV2AccountService account,
            byte[] acquisition, byte[] accountId, ParsedContactRouteClosure route,
            ClientMailboxScope scope, ReadOnlyMemory<byte> currentIntent)
        {
            var baselineSql = await ArchivedPathSqlProjection(accountId, route.ExactHash);
            var baselineRoots = await ArchivedPathRootSnapshot();
            var native = (await account.ReadOwnMailboxReplayFenceAsync()).Digest.ToArray();
            try
            {
                foreach (var fault in new[] { "missing-traversal", "missing-replay-floor", "missing-current-path" })
                {
                    var slot = fault == "missing-current-path"
                        ? ProtectedDid2ContactRouteJournal.Slot : ProtectedDid2MailboxReadJournal.Slot;
                    using var raw = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
                    var before = raw.Use(bytes => bytes.ToArray());
                    byte[] after;
                    if (fault == "missing-current-path")
                    {
                        using var publications = ProtectedDid2ContactRouteJournal.Decode(before, Network, accountId, before.AsSpan(60, 32));
                        var name = Convert.ToHexString(currentIntent.Span);
                        Assert.True(publications.Entries.Remove(name, out var removed));
                        removed!.Dispose();
                        Assert.Single(publications.Entries); // The authentic archive, not an empty fake root.
                        after = ProtectedDid2ContactRouteJournal.Encode(publications, Network, accountId, before.AsSpan(60, 32));
                    }
                    else
                    {
                        using var read = ProtectedDid2MailboxReadJournal.Decode(before, Network, accountId, before.AsSpan(60, 32));
                        Assert.Equal(0, read.Phase); Assert.Null(read.Active);
                        if (fault == "missing-traversal")
                            Assert.True(read.Traversals.Remove(Convert.ToHexString(scope.Value)));
                        else
                        {
                            using var grants = await ReadPeerGrantsAsync(own: true);
                            var exactGrant = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(grants.Entries[Convert.ToHexString(acquisition)]).Span).Field(8);
                            Assert.True(read.Counters.Remove(Convert.ToHexString(SHA256.HashData(exactGrant.Span))));
                        }
                        read.Revision = checked(read.Revision + 1);
                        after = ProtectedDid2MailboxReadJournal.Encode(read, Network, accountId, before.AsSpan(60, 32));
                    }
                    var changed = false;
                    try
                    {
                        using (var exclusion = await account.OpenMailboxEpochExclusionAsync(acquisition, Source(account)))
                        {
                            Assert.True(await storage.CompareExchangeAsync(slot, before, after));
                            changed = true;
                            var damagedRoots = await ArchivedPathRootSnapshot();
                            using var idle = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                            var exactPlan = idle.Use(bytes => bytes.ToArray());
                            try
                            {
                                for (var attempt = 0; attempt < 2; attempt++)
                                {
                                    var rejected = await Assert.ThrowsAsync<IOException>(() => exclusion.RetireArchivedReadPathAsync());
                                    Assert.Contains(fault switch
                                    {
                                        "missing-traversal" => "Original completed traversal is required",
                                        "missing-replay-floor" => "Original read replay floor is absent",
                                        _ => "last current permanent route cannot be retired"
                                    }, rejected.Message, StringComparison.Ordinal);
                                    using var planAfter = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                                    Assert.Equal(exactPlan, planAfter.Use(bytes => bytes.ToArray()));
                                    var rootsAfter = await ArchivedPathRootSnapshot();
                                    for (var index = 0; index < damagedRoots.Length; index++) Assert.Equal(damagedRoots[index], rootsAfter[index]);
                                    await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
                                        Assert.Equal(baselineSql, SqliteDeepMailboxStore.ReadCompleteLocalSqlProjection(sql, route.ExactHash.Span, default)),
                                        acquireOwnerLease: false);
                                }
                            }
                            finally { CryptographicOperations.ZeroMemory(exactPlan); }
                        }
                    }
                    finally
                    {
                        // Restore only this fixture's deliberately removed
                        // dependency; production never repairs from these bytes.
                        if (changed) Assert.True(await storage.CompareExchangeAsync(slot, after, before));
                        CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after);
                    }
                    var restoredRoots = await ArchivedPathRootSnapshot();
                    for (var index = 0; index < baselineRoots.Length; index++) Assert.Equal(baselineRoots[index], restoredRoots[index]);
                    Assert.Equal(native, (await account.ReadOwnMailboxReplayFenceAsync()).Digest.ToArray());
                }
            }
            finally { CryptographicOperations.ZeroMemory(baselineSql); CryptographicOperations.ZeroMemory(native); }
        }
    }
}
