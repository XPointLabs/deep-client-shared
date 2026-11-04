using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true, "missing")]
    [InlineData(false, "missing")]
    [InlineData(true, "trs")]
    [InlineData(false, "trs")]
    [InlineData(true, "storage-type")]
    [InlineData(false, "storage-type")]
    [InlineData(true, "rooted-header")]
    [InlineData(false, "rooted-header")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2EstablishedNativeProvenance_ActualInitialCorruptionRejectsWithoutRepair(bool initiator, string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var pair = await fixture.PrepareArchiveEnrollmentPair(0);
        var scope = initiator ? pair.Sender : pair.Receiver;
        if (defect == "rooted-header") await fixture.CompactActiveNativePrefix(scope, 2);
        await fixture.CheckEstablishedNativeInitial(scope, defect);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckEstablishedNativeInitial(Did2MessagingSessionScope scope, string defect)
        {
            var secure = NativeStorage(scope); var floor = await ReadMessagingFloor(scope);
            var history = await ReadNativeHistory(scope); var archive = await ReadNativeArchive(scope);
            var retirements = await ProtectedInitialKeyRetirementJournal.ReadAsync(secure,
                scope.Network.ToArray(), scope.LocalAccount.ToArray(), default);
            var retirement = Assert.Single(retirements.Entries.Values, entry =>
                entry.ScopeHash.SequenceEqual(scope.Hash));
            var slots = new[] { scope.FloorSlot, Did2MessagingHistoryCheckpoint.Slot(scope),
                Did2MessagingArchiveRoot.Slot(scope), ProtectedInitialKeyRetirementJournal.Slot };
            using var before = await secure.ReadOwnedBatchAsync(slots);
            await WithArchiveFixtureSql(scope, connection =>
            {
                var sql = Did2MessagingSqlJournal.ForOrdinaryRuntime(connection, scope, history, archive);
                var proof = sql.RequireEstablishedNativeProvenance(floor, retirement);
                Assert.Equal(retirement.TrsHash.ToArray(), proof.OriginalTrsHash.ToArray());
                Assert.Equal(scope.InitialBasis.ToArray(), proof.InitialBasis.ToArray());
                Assert.Equal(retirement.SourceInstance.ToArray(), proof.SourceInstance.ToArray());
                Assert.Equal(retirement.Role, proof.Role);
                if (!scope.IsInitiator) Assert.Equal(retirement.Intent.ToArray(), proof.ClaimOperation.ToArray());
                byte[][] original;
                using (var read = connection.CreateCommand())
                {
                    read.CommandText = "SELECT envelope,session_init,hello,metadata FROM initial_events;";
                    using var row = read.ExecuteReader(); Assert.True(row.Read());
                    original = [row.GetFieldValue<byte[]>(0), row.GetFieldValue<byte[]>(1), row.GetFieldValue<byte[]>(2), row.GetFieldValue<byte[]>(3)];
                    Assert.False(row.Read());
                }
                var altered = original[3].ToArray(); altered[defect == "rooted-header" ? 591 : 236] ^= 1;
                if (defect == "rooted-header") Assert.True(archive.Basis.Ordinal >= 2);
                try
                {
                    using (var change = connection.CreateCommand())
                    {
                        change.CommandText = defect switch
                        {
                            "missing" => "DELETE FROM initial_events WHERE singleton=1;",
                            "trs" or "rooted-header" => "UPDATE initial_events SET metadata=$metadata WHERE singleton=1;",
                            "storage-type" => "PRAGMA ignore_check_constraints=ON; UPDATE initial_events SET metadata=CAST(metadata AS TEXT) WHERE singleton=1; PRAGMA ignore_check_constraints=OFF;",
                            _ => throw new ArgumentOutOfRangeException(nameof(defect))
                        };
                        if (defect is "trs" or "rooted-header") change.Parameters.AddWithValue("$metadata", altered);
                        change.ExecuteNonQuery();
                    }
                    var importError = Record.Exception(() => sql.RequireEstablishedNativeImport(retirement));
                    Assert.True(importError is InvalidDataException or CryptographicException,
                        "The actual corrupted Initial row entered the established import seam.");
                    var floorError = Record.Exception(() => sql.RequireEstablishedNativeProvenance(floor, retirement));
                    Assert.True(floorError is InvalidDataException or CryptographicException,
                        "The actual corrupted Initial row entered established floor admission.");
                    using var unchanged = connection.CreateCommand();
                    unchanged.CommandText = "SELECT typeof(metadata),CAST(metadata AS BLOB) FROM initial_events;";
                    using var row = unchanged.ExecuteReader();
                    Assert.Equal(defect != "missing", row.Read());
                    if (defect != "missing")
                    {
                        Assert.Equal(defect == "storage-type" ? "text" : "blob", row.GetString(0));
                        Assert.Equal(defect is "trs" or "rooted-header" ? altered : original[3], row.GetFieldValue<byte[]>(1));
                        Assert.False(row.Read());
                    }
                }
                finally
                {
                    using var restore = connection.CreateCommand();
                    restore.CommandText = "INSERT OR REPLACE INTO initial_events(singleton,envelope,session_init,hello,metadata) VALUES(1,$envelope,$init,$hello,$metadata);";
                    restore.Parameters.AddWithValue("$envelope", original[0]); restore.Parameters.AddWithValue("$init", original[1]);
                    restore.Parameters.AddWithValue("$hello", original[2]); restore.Parameters.AddWithValue("$metadata", original[3]);
                    Assert.Equal(1, restore.ExecuteNonQuery());
                    foreach (var bytes in original) CryptographicOperations.ZeroMemory(bytes);
                    CryptographicOperations.ZeroMemory(altered);
                }
                Assert.Equal(proof.InitialHeaderHash.ToArray(), sql.RequireEstablishedNativeProvenance(floor, retirement).InitialHeaderHash.ToArray());
            });
            using var after = await secure.ReadOwnedBatchAsync(slots);
            for (var index = 0; index < slots.Length; index++)
                Assert.Equal(before[index]!.Use(bytes => SHA256.HashData(bytes)), after[index]!.Use(bytes => SHA256.HashData(bytes)));
        }
    }
}
