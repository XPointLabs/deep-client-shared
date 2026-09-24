using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Production.Tests;

public sealed class SqliteDeepIdV2AccountGenerationTests
{
    [Fact]
    public async Task CreatesEncryptedGenerationAndReopensExactDID2Projection()
    {
        if (!SupportedProvider()) return;
        var directory = NewDirectory();
        var sqlPath = Path.Combine(directory, "account.dsv2");
        try
        {
            using var storage = new InMemoryDeepSecureStorage();
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var created = await CreateGenesisAsync(storage, network,
                verifier);
            await SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath,
                storage, network, created.AccountId, "Alice",
                created.Verified, allowCreate: true, default);
            Assert.True(File.Exists(sqlPath));
            Assert.False(File.ReadAllBytes(sqlPath).AsSpan(0, 16)
                .SequenceEqual("SQLite format 3\0"u8));
            using var keyRecord = await storage.ReadOwnedAsync(
                "deep.store.v2.sql-generation");
            Assert.NotNull(keyRecord);
            File.Move(sqlPath, sqlPath + ".pending");
            File.WriteAllBytes(sqlPath + ".pending", [1, 2, 3]);
            File.WriteAllBytes(sqlPath + ".pending-journal", [4, 5, 6]);
            await SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath,
                storage, network, created.AccountId, "Alice",
                created.Verified, allowCreate: true, default);
            Assert.True(File.Exists(sqlPath));
            Assert.False(File.Exists(sqlPath + ".pending-journal"));
            using var current = await new ProtectedDeepIdV2CurrentAccountIndex(
                storage, network, 1).PublishVerifiedAsync("Alice",
                created.AccountId, 1_900_000_000, verifier, default);
            await SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath,
                storage, network, current.AccountId, current.DisplayName,
                current.Verified, allowCreate: false, default);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath, storage,
                    network, current.AccountId, current.DisplayName,
                    current.Verified, allowCreate: true, default));
            var wrongNetwork = network.ToArray();
            wrongNetwork[0] ^= 0x55;
            await Assert.ThrowsAsync<CryptographicException>(() =>
                SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath, storage,
                    wrongNetwork, current.AccountId, current.DisplayName,
                    current.Verified, allowCreate: false, default));
        }
        finally { DeleteGeneratedDirectory(directory); }
    }

    [Fact]
    public async Task ExistingGenerationCannotBeSilentlyRecreatedAfterDatabaseLoss()
    {
        if (!SupportedProvider()) return;
        var directory = NewDirectory();
        var sqlPath = Path.Combine(directory, "account.dsv2");
        try
        {
            using var storage = new InMemoryDeepSecureStorage();
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var created = await CreateGenesisAsync(storage, network,
                verifier);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath, storage,
                    network, created.AccountId, "Alice",
                    created.Verified, allowCreate: false, default));
            await SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath,
                storage, network, created.AccountId, "Alice",
                created.Verified, allowCreate: true, default);
            using var current = await new ProtectedDeepIdV2CurrentAccountIndex(
                storage, network, 1).PublishVerifiedAsync("Alice",
                created.AccountId, 1_900_000_000, verifier, default);
            File.Delete(sqlPath);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath, storage,
                    network, current.AccountId, current.DisplayName,
                    current.Verified, allowCreate: false, default));
        }
        finally { DeleteGeneratedDirectory(directory); }
    }

    [Fact]
    public async Task DatabaseWithoutProtectedKeyAndEmptyDatabaseFailClosed()
    {
        if (!SupportedProvider()) return;
        var directory = NewDirectory();
        var sqlPath = Path.Combine(directory, "account.dsv2");
        try
        {
            using var storage = new InMemoryDeepSecureStorage();
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var created = await CreateGenesisAsync(storage, network,
                verifier);
            File.WriteAllBytes(sqlPath, []);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath, storage,
                    network, created.AccountId, "Alice",
                    created.Verified, allowCreate: true, default));
            File.Delete(sqlPath);
            await SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath,
                storage, network, created.AccountId, "Alice",
                created.Verified, allowCreate: true, default);
            using var current = await new ProtectedDeepIdV2CurrentAccountIndex(
                storage, network, 1).PublishVerifiedAsync("Alice",
                created.AccountId, 1_900_000_000, verifier, default);
            File.WriteAllBytes(sqlPath, []);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath, storage,
                    network, current.AccountId, current.DisplayName,
                    current.Verified, allowCreate: false, default));
        }
        finally { DeleteGeneratedDirectory(directory); }
    }

    [Fact]
    public async Task JournaledKeyAndSqlReopenExactAccountAfterProcessBoundary()
    {
        if (!SupportedProvider()) return;
        var directory = NewDirectory();
        var statePath = Path.Combine(directory, "secure.bin");
        var sqlPath = Path.Combine(directory, "account.dsv2");
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            byte[] exactDab2;
            using (var first = new JournaledDeepSecureStorage(statePath,
                       new TestAeadProtector(key)))
            {
                using var created = await CreateGenesisAsync(first, network,
                    verifier);
                exactDab2 = created.Verified.PublicEvidence.Binding.Record
                    .CanonicalBytes.ToArray();
                await SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath,
                    first, network, created.AccountId, "Alice",
                    created.Verified, allowCreate: true, default);
                using var current = await new ProtectedDeepIdV2CurrentAccountIndex(
                    first, network, 1).PublishVerifiedAsync("Alice",
                    created.AccountId, 1_900_000_000, verifier, default);
            }
            using (var reopened = new JournaledDeepSecureStorage(statePath,
                       new TestAeadProtector(key)))
            {
                using var current = await new ProtectedDeepIdV2CurrentAccountIndex(
                    reopened, network, 1).ReadVerifiedAsync(1_900_000_000,
                    verifier, default);
                Assert.NotNull(current);
                Assert.Equal(exactDab2, current!.Verified.PublicEvidence.Binding
                    .Record.CanonicalBytes.ToArray());
                await SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath,
                    reopened, network, current.AccountId, current.DisplayName,
                    current.Verified, allowCreate: false, default);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            DeleteGeneratedDirectory(directory);
        }
    }

    [Fact]
    public async Task WrongSqlGenerationIsRejectedWithoutMutation()
    {
        if (!SupportedProvider()) return;
        var directory = NewDirectory();
        var sqlPath = Path.Combine(directory, "account.dsv2");
        try
        {
            using var storage = new InMemoryDeepSecureStorage();
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var created = await CreateGenesisAsync(storage, network,
                verifier);
            await SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath,
                storage, network, created.AccountId, "Alice",
                created.Verified, allowCreate: true, default);
            byte[] key;
            using (var protectedKey = await storage.ReadOwnedAsync(
                       "deep.store.v2.sql-generation"))
            {
                Assert.NotNull(protectedKey);
                key = protectedKey!.Use(value => value.Slice(88, 32).ToArray());
            }
            try
            {
                SQLitePCL.Batteries_V2.Init();
                using var connection = new SqliteConnection(
                    new SqliteConnectionStringBuilder
                    {
                        DataSource = sqlPath,
                        Mode = SqliteOpenMode.ReadWrite,
                        Pooling = false
                    }.ToString());
                connection.Open();
                Assert.Equal(SQLitePCL.raw.SQLITE_OK,
                    SQLitePCL.raw.sqlite3_key(connection.Handle, key));
                using var command = connection.CreateCommand();
                command.CommandText = "PRAGMA user_version=1;";
                command.ExecuteNonQuery();
            }
            finally { CryptographicOperations.ZeroMemory(key); }
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                SqliteDeepIdV2AccountGeneration.EnsureAsync(sqlPath, storage,
                    network, created.AccountId, "Alice", created.Verified,
                    allowCreate: true, default));
        }
        finally { DeleteGeneratedDirectory(directory); }
    }

    private static async Task<CreatedDeepIdV2OfflineGenesis>
        CreateGenesisAsync(IDeepSecureStorage storage, byte[] network,
            IDeepMlDsa65Verifier verifier)
    {
        using var phrase = Deep.Protocol.Identity.DeepRecoveryV1.Generate();
        return await new DeepIdV2OfflineGenesisIssuer(storage, network, 1)
            .CreateAsync(phrase, 1_900_000_000, verifier, default);
    }

    private static string NewDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(),
            "deep-did2-sql-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void DeleteGeneratedDirectory(string directory)
    {
        foreach (var name in new[] { "account.lock", "account.dsv2",
                     "account.dsv2.bootstrap.lock", "account.dsv2.pending",
                     "account.dsv2-journal", "account.dsv2-wal",
                     "account.dsv2-shm", "account.dsv2.pending-journal",
                     "secure.bin", "secure.bin.pending", "secure.bin.backup",
                     "secure.bin.lock" })
            File.Delete(Path.Combine(directory, name));
        Directory.Delete(directory);
    }

    private static bool SupportedProvider() =>
        OperatingSystem.IsWindows() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is
            (System.Runtime.InteropServices.Architecture.X64 or
             System.Runtime.InteropServices.Architecture.Arm64) ||
        OperatingSystem.IsLinux() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
            System.Runtime.InteropServices.Architecture.X64;

    private sealed class TestAeadProtector : IDeepSecretProtector, IDisposable
    {
        private readonly byte[] key;

        internal TestAeadProtector(ReadOnlySpan<byte> key) =>
            this.key = key.ToArray();

        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            var output = new byte[32 + plaintext.Length];
            "TSP2"u8.CopyTo(output);
            RandomNumberGenerator.Fill(output.AsSpan(4, 12));
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(output.AsSpan(4, 12), plaintext,
                output.AsSpan(32), output.AsSpan(16, 16),
                "Deep/Test/DID2SqlStorage"u8);
            return output;
        }

        public byte[] Unprotect(ReadOnlySpan<byte> protectedBytes)
        {
            if (protectedBytes.Length < 32 ||
                !protectedBytes[..4].SequenceEqual("TSP2"u8))
                throw new CryptographicException("Invalid test envelope.");
            var plaintext = new byte[protectedBytes.Length - 32];
            try
            {
                using var aes = new AesGcm(key, 16);
                aes.Decrypt(protectedBytes.Slice(4, 12),
                    protectedBytes[32..], protectedBytes.Slice(16, 16),
                    plaintext, "Deep/Test/DID2SqlStorage"u8);
                return plaintext;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw;
            }
        }

        public void Dispose() => CryptographicOperations.ZeroMemory(key);
    }
}
