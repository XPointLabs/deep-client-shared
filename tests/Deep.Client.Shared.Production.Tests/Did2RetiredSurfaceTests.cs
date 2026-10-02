using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2RetiredSurfaceTests
{
    [Fact]
    public void InitialInboxCanBeMintedOnlyFromOwnedDid2Custody()
    {
        var methods = typeof(AuthenticatedInitialDmc2Batch).GetMethods(
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic);
        Assert.DoesNotContain(methods, method => method.Name == "FromCommittedStageAsync");
        Assert.Contains(methods, method => method.Name == "FromOwnedDid2Async" && !method.IsPublic);
    }

    [Fact]
    public void BoundedPublicationHasNoLegacyPlacementFactoryOrGenericDecoder()
    {
        Assert.Null(typeof(ContactResolveCanonicalPathRequest).GetMethod("FromBoundedPublication"));
        Assert.Throws<ContactResolvePathException>(() => ContactResolveCanonicalPathRequest.Decode("XPP1"u8));
        Assert.NotNull(typeof(ContactResolveCanonicalPathRequest).GetMethod("FromDid2BoundedPublication"));
    }

    [Theory]
    [InlineData("Deep.Client.Shared.Services.DeepAccountService")]
    [InlineData("Deep.Client.Shared.Services.MessagingV1.DeepDirectMessagingStorageOwner")]
    [InlineData("Deep.Client.Shared.Services.ContactV1.ContactResolverClient")]
    [InlineData("Deep.Client.Shared.Services.ContactV1.ProductionPreKeyV1InventoryOwner")]
    [InlineData("Deep.Client.Shared.Services.GroupV1.DeepGroupV1Runtime")]
    [InlineData("Deep.Client.Shared.Persistence.ContactV1.SqliteContactStateStore")]
    [InlineData("Deep.Client.Shared.Persistence.ContactV1.SqliteXpk1ClaimJournal")]
    [InlineData("Deep.Client.Shared.Persistence.MessagingCryptoV1.InitiatorInitialSessionVerifiedScope")]
    public void RetiredOwnersAreAbsentFromShippingAssembly(string name) =>
        Assert.Null(typeof(DeepIdV2AccountService).Assembly.GetType(name, throwOnError: false));

    [Fact]
    public void RawNetworkClosureBoundsRejectEmptyAndOversizedCollections()
    {
        Assert.Throws<ArgumentNullException>(() => DeepIdV2NetworkClosureBounds.ValidateChain(null!, "chain", 4096));
        Assert.Throws<ArgumentException>(() => DeepIdV2NetworkClosureBounds.ValidateChain([], "chain", 4096));
        Assert.Throws<ArgumentException>(() => DeepIdV2NetworkClosureBounds.ValidateChain([ReadOnlyMemory<byte>.Empty], "chain", 4096));
        Assert.Throws<ArgumentException>(() => DeepIdV2NetworkClosureBounds.ValidateChain(
            Enumerable.Repeat<ReadOnlyMemory<byte>>(new byte[] { 1 }, 4097).ToArray(), "chain", 4096));
        Assert.Equal(3L, DeepIdV2NetworkClosureBounds.ValidateChain([new byte[] { 1 }, new byte[] { 2, 3 }], "chain", 4096));
    }

    [Fact]
    public async Task RatchetSchemaRejectsOldGenerationWithoutMigrationOrMutation()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-did2-schema-cutover", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "ratchet.db");
        var key = Enumerable.Repeat((byte)0x91, 32).ToArray();
        static byte[] Id(byte value) => Enumerable.Repeat(value, 32).ToArray();
        var scope = new MessagingCryptoV1StoreScope(Id(1), 1, Id(2), 1, Id(3), Id(4), 1);
        try
        {
            using (var options = new MessagingCryptoV1StoreOptions(path, key, scope))
            await using (var created = new SqliteMessagingCryptoV1Store(options)) { }
            using (var observer = new SqliteConnection(new SqliteConnectionStringBuilder
                   { DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString()))
            {
                observer.Open();
                Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(observer.Handle, key));
                using var command = observer.CreateCommand();
                command.CommandText = "PRAGMA user_version;";
                Assert.Equal(9L, (long)command.ExecuteScalar()!);
                command.CommandText = "SELECT count(*) FROM sqlite_schema WHERE name LIKE 'initiator_initial_session_%';";
                Assert.Equal(0L, (long)command.ExecuteScalar()!);
                command.CommandText = "PRAGMA user_version=8;";
                command.ExecuteNonQuery();
            }
            var before = SHA256.HashData(File.ReadAllBytes(path));
            using (var options = new MessagingCryptoV1StoreOptions(path, key, scope, allowCreate: false))
            {
                var failure = Assert.Throws<MessagingCryptoV1StoreOpenException>(() => new SqliteMessagingCryptoV1Store(options));
                Assert.Equal(MessagingCryptoV1StoreOpenFailure.UnsupportedGeneration, failure.Reason);
            }
            Assert.Equal(before, SHA256.HashData(File.ReadAllBytes(path)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            Directory.Delete(directory, recursive: true);
        }
    }
}
