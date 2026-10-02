using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

/// <summary>Codec/storage-only fixtures. Manually written protected metadata is
/// not a real account/endpoint, initial import, retirement or physical E2E.</summary>
public sealed class Did2MessagingCatalogTests
{
    private static readonly byte[] Network = Bytes(16, 1), Account = Bytes(32, 2), Instance = Bytes(32, 3);

    [Fact]
    public void OrdinaryIncomingServiceHasOneOwnerSelectedEntryAndNoCallerScopedAlternative()
    {
        var entries = typeof(DeepIdV2AccountService).GetMethods(
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic)
            .Where(method => method.Name.StartsWith("ReceiveOwnMessaging", StringComparison.Ordinal)).ToArray();
        var entry = Assert.Single(entries);
        Assert.Equal("ReceiveOwnMessagingEnvelopeAsync", entry.Name);
        Assert.False(entry.IsPublic);
        Assert.Equal([typeof(ReadOnlyMemory<byte>), typeof(DeepIdV2ContactPathAuthoritySource), typeof(CancellationToken)],
            entry.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
    }

    [Fact]
    public async Task PeerBootstrapRequiresExactRegistrationAndSurvivesReopenWithoutRepairingMissingValue()
    {
        using var storage = new InMemoryDeepSecureStorage();
        var exact = Catalog(1);
        using var decoded = ProtectedDid2MessagingSessionCatalog.Decode(exact, Network, Account, Instance);
        var scope = decoded.Scope(0);
        var credential = DeepIdV2Codec.AuthorDid2(Bytes(32, 0x41), Bytes(1952, 0x51), Bytes(16, 0x61));
        var bootstrap = new byte[ProtectedDid2MessagingPeerBootstrap.Bytes]; bootstrap[0] = 1;
        scope.Hash.CopyTo(bootstrap.AsSpan(4)); credential.CanonicalBytes.Span.CopyTo(bootstrap.AsSpan(68));
        SHA256.HashData(bootstrap.AsSpan(68)).CopyTo(bootstrap.AsSpan(36));
        try
        {
            var catalog = new ProtectedDid2MessagingSessionCatalog(storage, Network, Account, Instance);
            await storage.WriteBatchAsync([new(ProtectedDid2MessagingSessionCatalog.Slot, exact)]);
            await Assert.ThrowsAsync<InvalidDataException>(() => catalog.ReadPeerCredentialAsync(scope, default));
            using (var absent = await storage.ReadOwnedAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope))) Assert.Null(absent);
            await storage.WriteBatchAsync([new(ProtectedDid2MessagingPeerBootstrap.Slot(scope), bootstrap)]);
            var reopened = new ProtectedDid2MessagingSessionCatalog(storage, Network, Account, Instance);
            Assert.Equal(credential.CanonicalBytes.ToArray(), (await reopened.ReadPeerCredentialAsync(scope, default)).CanonicalBytes.ToArray());
            foreach (var offset in new[] { 0, 1, 4, 36, 68 })
            {
                var damaged = bootstrap.ToArray(); damaged[offset] ^= 1;
                Assert.Throws<CryptographicException>(() => ProtectedDid2MessagingPeerBootstrap.Restore(damaged, scope));
            }
            Assert.Throws<CryptographicException>(() => ProtectedDid2MessagingPeerBootstrap.Restore(bootstrap[..^1], scope));
            var foreign = scope.Exact.ToArray(); foreign[212] ^= 1;
            var foreignScope = Did2MessagingSessionScope.RestoreMetadata(foreign);
            await Assert.ThrowsAsync<CryptographicException>(() => reopened.ReadPeerCredentialAsync(foreignScope, default));
            await storage.DeleteBatchAsync([ProtectedDid2MessagingPeerBootstrap.Slot(scope)]);
            await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadPeerCredentialAsync(scope, default));
            using var stillAbsent = await storage.ReadOwnedAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope));
            Assert.Null(stillAbsent);
        }
        finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(bootstrap); }
    }

    [Fact]
    public void CatalogRoundTrips512BoundedUniqueKeysWithoutAnExportableSecretConstructor()
    {
        var exact = Catalog(512);
        using var decoded = ProtectedDid2MessagingSessionCatalog.Decode(exact, Network, Account, Instance);
        Assert.Equal(512, decoded.Count); Assert.True(decoded.Exact.Span.SequenceEqual(exact));
        using var key = decoded.ReadKey(0); Assert.Equal(32, key.Length);
        decoded.Dispose(); Assert.Throws<ObjectDisposedException>(() => decoded.ReadKey(0));
        Assert.Empty(typeof(OwnedInitialMessagingSeed).GetConstructors());
        CryptographicOperations.ZeroMemory(exact);
    }

    [Theory]
    [InlineData(0, 2)]
    [InlineData(1, 1)]
    [InlineData(3, 0)]
    [InlineData(11, 9)]
    [InlineData(12, 7)]
    [InlineData(28, 7)]
    [InlineData(60, 7)]
    [InlineData(92, 0)]
    [InlineData(92, 3)]
    [InlineData(93, 1)]
    public void UnknownOrForeignCatalogRejectsBeforeReleasingKeys(int offset, byte value)
    {
        var exact = Catalog(1); exact[offset] = value;
        Assert.ThrowsAny<Exception>(() => ProtectedDid2MessagingSessionCatalog.Decode(exact, Network, Account, Instance));
        CryptographicOperations.ZeroMemory(exact);
    }

    [Fact]
    public void SourceLookupIsExactAndCannotAliasAnExistingSessionOrBasis()
    {
        var exact = Catalog(2);
        try
        {
            using var decoded = ProtectedDid2MessagingSessionCatalog.Decode(exact, Network, Account, Instance);
            var scope = decoded.Scope(0);
            Assert.Same(scope, decoded.FindSource(scope.Session, scope.InitialBasis));
            Assert.Null(decoded.FindSource(Bytes(32, 0xf1), Bytes(32, 0xf2)));
            Assert.Throws<CryptographicException>(() => decoded.FindSource(scope.Session, Bytes(32, 0xf2)));
            Assert.Throws<CryptographicException>(() => decoded.FindSource(Bytes(32, 0xf1), scope.InitialBasis));
            decoded.Dispose();
            Assert.Throws<ObjectDisposedException>(() => decoded.FindSource(Bytes(32, 0xf1), Bytes(32, 0xf2)));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Fact]
    public void IncomingLookupRequiresInitializedExactNetworkSessionAndBothEndpoints()
    {
        var exact = Catalog(2);
        try
        {
            using (var pending = ProtectedDid2MessagingSessionCatalog.Decode(exact, Network, Account, Instance))
            {
                var selected = pending.Scope(0);
                Assert.Throws<InvalidOperationException>(() => pending.FindIncoming(Network, selected.Session, selected.RemoteDevice, selected.LocalDevice));
            }
            exact[92] = 2; exact[532] = 2;
            BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4), 5);
            using var ready = ProtectedDid2MessagingSessionCatalog.Decode(exact, Network, Account, Instance);
            foreach (var index in new[] { 0, 1 })
            {
                var selected = ready.Scope(index);
                Assert.Same(selected, ready.FindIncoming(Network, selected.Session, selected.RemoteDevice, selected.LocalDevice));
                Assert.Throws<CryptographicException>(() => ready.FindIncoming(Bytes(16, 9), selected.Session, selected.RemoteDevice, selected.LocalDevice));
                Assert.Throws<CryptographicException>(() => ready.FindIncoming(Network, selected.Session, Bytes(32, 9), selected.LocalDevice));
                Assert.Throws<CryptographicException>(() => ready.FindIncoming(Network, selected.Session, selected.RemoteDevice, Bytes(32, 9)));
                Assert.Throws<InvalidDataException>(() => ready.FindIncoming(Network, selected.Session[..31], selected.RemoteDevice, selected.LocalDevice));
            }
            Assert.Null(ready.FindIncoming(Network, Bytes(32, 9), Bytes(32, 10), Bytes(32, 11)));
            ready.Dispose();
            Assert.Throws<ObjectDisposedException>(() => ready.FindIncoming(Network, Bytes(32, 9), Bytes(32, 10), Bytes(32, 11)));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Fact]
    public void OrderingDuplicateKeySessionBasisTrailingTruncationAndCapacityAreClosed()
    {
        var exact = Catalog(2);
        var swapped = exact.ToArray(); exact.AsSpan(92, 440).CopyTo(swapped.AsSpan(532)); exact.AsSpan(532, 440).CopyTo(swapped.AsSpan(92));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MessagingSessionCatalog.Decode(swapped, Network, Account, Instance));
        foreach (var field in new[] { 408, 4 + 212, 4 + 308 })
        {
            var repeated = exact.ToArray(); exact.AsSpan(92 + field, 32).CopyTo(repeated.AsSpan(532 + field));
            Assert.Throws<InvalidDataException>(() => ProtectedDid2MessagingSessionCatalog.Decode(repeated, Network, Account, Instance));
            CryptographicOperations.ZeroMemory(repeated);
        }
        var zeroKey = exact.ToArray(); zeroKey.AsSpan(500, 32).Clear();
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MessagingSessionCatalog.Decode(zeroKey, Network, Account, Instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MessagingSessionCatalog.Decode(exact[..^1], Network, Account, Instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MessagingSessionCatalog.Decode([.. exact, 0], Network, Account, Instance));
        Assert.Throws<CryptographicException>(() => ProtectedDid2MessagingSessionCatalog.Decode(new byte[92 + 513 * 440], Network, Account, Instance));
        using var before = ProtectedDid2MessagingSessionCatalog.Decode(exact, Network, Account, Instance);
        var changedScope = before.Scope(0).Exact.ToArray(); changedScope[372] ^= 1;
        Assert.Throws<CryptographicException>(() => before.FindExact(Did2MessagingSessionScope.RestoreMetadata(changedScope)));
        foreach (var bytes in new[] { exact, swapped, zeroKey }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    public async Task RegisteredSqlCreationIsRestartSafeAndInitializedMissingSqlOrFloorCannotReimport()
    {
        var directory = Path.Combine(Path.GetTempPath(), "did2-catalog-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        var accountPath = Path.Combine(directory, "account.db");
        using var storage = new InMemoryDeepSecureStorage();
        var exact = Catalog(1); var keyRecord = KeyRecord();
        using var initial = ProtectedDid2MessagingSessionCatalog.Decode(exact, Network, Account, Instance);
        var scope = initial.Scope(0);
        try
        {
            await storage.WriteBatchAsync([new("deep.store.v2.sql-generation", keyRecord), new(ProtectedDid2MessagingSessionCatalog.Slot, exact), new(scope.FloorSlot, Did2MessagingFloor.Empty(scope).Exact)]);
            for (var iteration = 0; iteration < 2; iteration++)
            {
                using var opened = await SqliteDeepIdV2AccountGeneration.OpenRegisteredMessagingUnderLeaseAsync(storage, accountPath, Network, Account, scope, default);
                Assert.Equal(0UL, (await opened.Custody.ReconcileAsync(default)).Ordinal);
                await Assert.ThrowsAsync<InvalidOperationException>(() => opened.Custody.ReadActiveStateAsync(default));
            }
            using var registered = await new ProtectedDid2MessagingSessionCatalog(storage, Network, Account, Instance).ReadAsync(default);
            Assert.Equal(2, registered.Phase(0));
            var file = Path.Combine(accountPath + ".messaging", Convert.ToHexStringLower(scope.Hash) + ".dms2");
            Assert.False(File.ReadAllBytes(file).AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
            File.Delete(file);
            await Assert.ThrowsAsync<InvalidDataException>(() => SqliteDeepIdV2AccountGeneration.OpenRegisteredMessagingUnderLeaseAsync(storage, accountPath, Network, Account, scope, default));
            Assert.False(File.Exists(file));
            await storage.DeleteBatchAsync([scope.FloorSlot]);
            await Assert.ThrowsAsync<InvalidDataException>(() => SqliteDeepIdV2AccountGeneration.OpenRegisteredMessagingUnderLeaseAsync(storage, accountPath, Network, Account, scope, default));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(keyRecord);
            SqliteDeepIdV2AccountGeneration.DeleteMessagingAfterExplicitReset(accountPath);
            Directory.Delete(directory);
        }
    }

    [Fact]
    public async Task Phase1RejectsInvalidSqlAndResetPreservesUnknownFiles()
    {
        var directory = Path.Combine(Path.GetTempPath(), "did2-catalog-invalid-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        var accountPath = Path.Combine(directory, "account.db"); using var storage = new InMemoryDeepSecureStorage();
        var exact = Catalog(1); var record = KeyRecord();
        using var catalog = ProtectedDid2MessagingSessionCatalog.Decode(exact, Network, Account, Instance); var scope = catalog.Scope(0);
        var messageDir = accountPath + ".messaging"; Directory.CreateDirectory(messageDir);
        var path = Path.Combine(messageDir, Convert.ToHexStringLower(scope.Hash) + ".dms2");
        var foreign = Path.Combine(messageDir, "keep-unrelated.txt");
        try
        {
            await storage.WriteBatchAsync([new("deep.store.v2.sql-generation", record), new(ProtectedDid2MessagingSessionCatalog.Slot, exact), new(scope.FloorSlot, Did2MessagingFloor.Empty(scope).Exact)]);
            using (var sql = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(path, Bytes(32, 9), true))
            { using var cmd = sql.CreateCommand(); cmd.CommandText = "CREATE TABLE unexpected(x);"; cmd.ExecuteNonQuery(); }
            await Assert.ThrowsAnyAsync<Exception>(() => SqliteDeepIdV2AccountGeneration.OpenRegisteredMessagingUnderLeaseAsync(storage, accountPath, Network, Account, scope, default));
            using var unchanged = await new ProtectedDid2MessagingSessionCatalog(storage, Network, Account, Instance).ReadAsync(default); Assert.Equal(1, unchanged.Phase(0));
            // Test-only foreign sentinel; runtime reset must preserve it.
            File.WriteAllText(foreign, "unrelated");
            SqliteDeepIdV2AccountGeneration.DeleteMessagingAfterExplicitReset(accountPath);
            Assert.False(File.Exists(path)); Assert.True(File.Exists(foreign));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(record);
            foreach (var file in Directory.EnumerateFiles(messageDir)) File.Delete(file);
            Directory.Delete(messageDir); Directory.Delete(directory);
        }
    }

    [Fact]
    public void ActiveSourceRequiresExactStableRetirementNotJustAnyProtectedManifest()
    {
        var scope = Scope(1);
        Assert.Throws<CryptographicException>(() => Did2MessagingSourceScope.RequireRetirement(null, scope, true, false));
        var raw = new byte[236]; raw[0] = 1; raw[1] = 1;
        foreach (var offset in new[] { 4, 44, 76, 108, 140, 172, 204 }) raw.AsSpan(offset, 32).Fill(9);
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(36), 1);
        scope.Hash.CopyTo(raw.AsSpan(76)); scope.InitialBasis.CopyTo(raw.AsSpan(108));
        var pending = new ProtectedInitialKeyRetirementJournal.Entry(raw);
        Assert.Throws<CryptographicException>(() => Did2MessagingSourceScope.RequireRetirement(pending, scope, true, false));
        var stable = pending.Stable();
        Did2MessagingSourceScope.RequireRetirement(stable, scope, true, false);
        Assert.Throws<CryptographicException>(() => Did2MessagingSourceScope.RequireRetirement(stable, scope, true, true));
        raw[1] = 2; raw[76] ^= 1;
        Assert.Throws<CryptographicException>(() => Did2MessagingSourceScope.RequireRetirement(new(raw), scope, false, false));
    }

    private static byte[] Catalog(int count)
    {
        var raw = ProtectedDid2MessagingSessionCatalog.Empty(Network, Account, Instance);
        var entries = Enumerable.Range(1, count).Select(index =>
        {
            var scope = Scope(index); var entry = new byte[440]; entry[0] = 1; scope.Exact.CopyTo(entry.AsSpan(4));
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(408), index); entry[439] = 9;
            return (Scope: scope, Entry: entry);
        }).OrderBy(item => Convert.ToHexString(item.Scope.Hash), StringComparer.Ordinal).ToArray();
        var output = new byte[92 + count * 440]; raw.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(2), checked((ushort)count));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(4), checked(1UL + (ulong)count));
        for (var index = 0; index < count; index++) { entries[index].Entry.CopyTo(output, 92 + index * 440); CryptographicOperations.ZeroMemory(entries[index].Entry); }
        return output;
    }
    private static Did2MessagingSessionScope Scope(int index)
    {
        var raw = new byte[404]; raw[0] = 1; raw[1] = 1; Network.CopyTo(raw, 4); Instance.CopyTo(raw, 20); Account.CopyTo(raw, 52);
        foreach (var offset in new[] { 92, 132, 172, 212, 244, 276, 308, 340, 372 }) raw.AsSpan(offset, 32).Fill(checked((byte)(offset % 251 + 1)));
        foreach (var offset in new[] { 84, 124, 164, 204 }) BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(offset), 1);
        BinaryPrimitives.WriteInt32BigEndian(raw.AsSpan(212), index); BinaryPrimitives.WriteInt32BigEndian(raw.AsSpan(308), index);
        return Did2MessagingSessionScope.RestoreMetadata(raw);
    }
    private static byte[] KeyRecord()
    {
        var record = new byte[120]; "DSK2"u8.CopyTo(record); BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(4), 3);
        Network.CopyTo(record, 8); Account.CopyTo(record, 24); Instance.CopyTo(record, 56); record.AsSpan(88, 32).Fill(9); return record;
    }
    private static byte[] Bytes(int size, byte value) => Enumerable.Repeat(value, size).ToArray();
}
