using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2DirectoryLkgStoreTests
{
    [Fact]
    public async Task SignedEmptyV2FloorSurvivesAccountReopenAndRejectsCorruption()
    {
        if (!SupportedProvider()) return;
        var directory = Path.Combine(Path.GetTempPath(),
            "deep-did2-lkg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var storage = new InMemoryDeepSecureStorage();
            var network = Bytes(16, 0x20);
            var authority = await SignedV2Genesis.CreateAsync(network);
            var clock = new FrozenClock(
                DateTimeOffset.FromUnixTimeSeconds(1_900_000_000));
            var account = NewAccount(storage, directory, network, clock);
            _ = await account.CreateAsync("Alice");
            var first = await account.OpenDirectoryLkgStoreAsync(
                authority.Verified, authority.ExactHead, authority.HeadHash);
            var initial = await first.RestoreAsync(authority.Verified, default);
            Assert.Equal(0UL, initial.LogGeneration);
            Assert.Equal(authority.ExactHead, initial.ExactAdh1.ToArray());

            var reopened = NewAccount(storage, directory, network, clock);
            var second = await reopened.OpenDirectoryLkgStoreAsync(
                authority.Verified, authority.ExactHead, authority.HeadHash);
            var restored = await second.RestoreAsync(authority.Verified, default);
            Assert.Equal(initial.CoreHash.ToArray(), restored.CoreHash.ToArray());
            var successor = authority.CreateEmptySuccessor(restored);
            await SqliteDeepIdV2AccountGeneration.CommitDirectoryLkgForTestsAsync(
                second, restored, successor);
            var advanced = await second.RestoreAsync(authority.Verified, default);
            Assert.Equal(1UL, advanced.LogGeneration);
            Assert.Equal(successor.ExactAdh1.ToArray(),
                advanced.ExactAdh1.ToArray());
            await SqliteDeepIdV2AccountGeneration.CommitDirectoryLkgForTestsAsync(
                second, advanced, successor);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await SqliteDeepIdV2AccountGeneration
                    .CommitDirectoryLkgForTestsAsync(second, restored, successor));
            var wrongHash = authority.HeadHash.ToArray();
            wrongHash[0] ^= 1;
            await Assert.ThrowsAnyAsync<CryptographicException>(() =>
                reopened.OpenDirectoryLkgStoreAsync(
                    authority.Verified, authority.ExactHead, wrongHash));

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
                using var connection = new Microsoft.Data.Sqlite.SqliteConnection(
                    new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
                    {
                        DataSource = Path.Combine(directory,
                            "deep-store-v2-account.dsv2"),
                        Mode = Microsoft.Data.Sqlite.SqliteOpenMode.ReadWrite,
                        Pooling = false
                    }.ToString());
                connection.Open();
                Assert.Equal(SQLitePCL.raw.SQLITE_OK,
                    SQLitePCL.raw.sqlite3_key(connection.Handle, key));
                byte[] advancedPayload;
                using (var read = connection.CreateCommand())
                {
                    read.CommandText = "SELECT payload FROM protected_lkg_root WHERE root_kind=2;";
                    advancedPayload = Assert.IsType<byte[]>(read.ExecuteScalar());
                }
                var initialPayload = new byte[44 + initial.ExactAdh1.Length];
                "DLK2"u8.CopyTo(initialPayload);
                initialPayload[4] = 2;
                initial.CoreHash.Span.CopyTo(initialPayload.AsSpan(8, 32));
                BinaryPrimitives.WriteUInt32BigEndian(
                    initialPayload.AsSpan(40, 4),
                    checked((uint)initial.ExactAdh1.Length));
                initial.ExactAdh1.Span.CopyTo(initialPayload.AsSpan(44));
                using (var rollback = connection.CreateCommand())
                {
                    rollback.CommandText = "UPDATE protected_lkg_root SET revision=1,payload=$old WHERE root_kind=2;";
                    rollback.Parameters.AddWithValue("$old", initialPayload);
                    Assert.Equal(1, rollback.ExecuteNonQuery());
                }
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await second.RestoreAsync(authority.Verified, default));
                using (var restore = connection.CreateCommand())
                {
                    restore.CommandText = "UPDATE protected_lkg_root SET revision=2,payload=$current WHERE root_kind=2;";
                    restore.Parameters.AddWithValue("$current", advancedPayload);
                    Assert.Equal(1, restore.ExecuteNonQuery());
                }
                Assert.Equal(1UL, (await second.RestoreAsync(
                    authority.Verified, default)).LogGeneration);
                using var mutation = connection.CreateCommand();
                mutation.CommandText = "UPDATE protected_lkg_root SET payload=x'01' WHERE root_kind=2;";
                Assert.Equal(1, mutation.ExecuteNonQuery());
                await Assert.ThrowsAsync<InvalidDataException>(async () =>
                    await second.RestoreAsync(authority.Verified, default));
                using var deletion = connection.CreateCommand();
                deletion.CommandText = "DELETE FROM protected_lkg_root WHERE root_kind=2;";
                Assert.Equal(1, deletion.ExecuteNonQuery());
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await second.RestoreAsync(authority.Verified, default));
            }
            finally { CryptographicOperations.ZeroMemory(key); }
            await reopened.ResetExplicitlyAsync();
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await second.RestoreAsync(authority.Verified, default));
        }
        finally
        {
            foreach (var path in Directory.EnumerateFiles(directory))
                File.Delete(path);
            Directory.Delete(directory);
        }
    }

    private static DeepIdV2AccountService NewAccount(
        IDeepSecureStorage storage, string directory, byte[] network,
        IClock clock) => new(storage, directory, network, 1, clock,
            DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);

    private static bool SupportedProvider() =>
        OperatingSystem.IsWindows() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is
            (System.Runtime.InteropServices.Architecture.X64 or
             System.Runtime.InteropServices.Architecture.Arm64) ||
        OperatingSystem.IsLinux() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
            System.Runtime.InteropServices.Architecture.X64;

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed record SignedV2Genesis(
        VerifiedXPointNetworkAuthority Verified, byte[] ExactHead,
        byte[] HeadHash, byte[] Network, KeyPair[] Witnesses,
        byte[][] WitnessIds)
    {
        internal AccountDirectoryProtectedLkg CreateEmptySuccessor(
            AccountDirectoryProtectedLkg predecessor)
        {
            var (exact, hash) = AuthorHead(Verified, Network, 1,
                predecessor.CoreHash.Span, Witnesses, WitnessIds);
            return AccountDirectoryProtectedLkgFactory.Restore(Verified,
                exact, hash);
        }

        internal static async Task<SignedV2Genesis> CreateAsync(byte[] network)
        {
            var roots = new[]
            {
                PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x31)),
                PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x32))
            };
            var witnesses = Enumerable.Range(0, 3).Select(index =>
                PublicKeyAuth.GenerateKeyPair(
                    Bytes(32, checked((byte)(0x51 + index))))).ToArray();
            var rootKeys = roots.Select((pair, index) =>
                new XPointNetworkBootstrapRootKey(
                    Bytes(32, checked((byte)(0x40 + index))), 0,
                    pair.PublicKey, Bytes(32, checked((byte)(0x70 + index)))))
                .ToArray();
            var witnessKeys = witnesses.Select((pair, index) =>
                new XPointNetworkBootstrapWitnessKey(
                    Bytes(32, checked((byte)(0x60 + index))), 0,
                    pair.PublicKey, Bytes(32, checked((byte)(0x80 + index)))))
                .ToArray();
            var sources = new[]
            {
                new AccountDirectoryDts1Source(Bytes(32, 0x91), Bytes(32, 0xa1),
                    1, "time-a.example", 443, Bytes(32, 0xb1), 5),
                new AccountDirectoryDts1Source(Bytes(32, 0x92), Bytes(32, 0xa2),
                    1, "time-b.example", 443, Bytes(32, 0xb2), 5)
            };
            var request = new XPointNetworkGenesisAuthoringRequest(
                Bytes(32, 0x11), network, rootKeys, 2, witnessKeys, 2,
                sources, 10, 10, 1_900_000_000, 1_900_000_000,
                1_900_100_000, 1_900_000_000, 1_900_030_000, 2, 1);
            var signers = roots.Select((pair, index) =>
                new RootSigner(rootKeys[index], pair)).ToArray();
            var bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                request, signers);
            var authority = bootstrap.Authority;
            var ids = witnessKeys.Select(value => value.WitnessId.ToArray())
                .ToArray();
            var (exact, hash) = AuthorHead(authority, network, 0,
                new byte[32], witnesses, ids);
            _ = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(
                authority, exact, hash);
            return new SignedV2Genesis(authority, exact, hash, network,
                witnesses, ids);
        }

        private static (byte[] Exact, byte[] Hash) AuthorHead(
            VerifiedXPointNetworkAuthority authority, byte[] network,
            ulong generation, ReadOnlySpan<byte> predecessor,
            KeyPair[] witnesses, byte[][] ids)
        {
            var predecessorBytes = predecessor.ToArray();
            var placeholders = ids.Select(id =>
                new AccountDirectoryAdh1WitnessEntry(id, Bytes(64, 0x01)))
                .ToArray();
            AccountDirectoryAdh1 Head(
                IReadOnlyList<AccountDirectoryAdh1WitnessEntry> receipts) =>
                new(network, generation, predecessorBytes, 0,
                    AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
                    DeepIdV2DirectorySparseMap.EmptyMapRoot.Span,
                    authority.AuthorityCoreReference.Span,
                    authority.DirectoryWitnessPolicyHash.Span,
                    1_900_000_000, 1_900_010_000, 2, receipts);
            var unsigned = AccountDirectoryAdh1Codec.EncodeUnsigned(Head(placeholders));
            var input = SignatureInput(
                "Deep/AccountDirectory/V1/ADH1/witness",
                AccountDirectoryAdh1Codec.Suite, unsigned);
            var receipts = witnesses.Select((pair, index) =>
                new AccountDirectoryAdh1WitnessEntry(ids[index],
                    PublicKeyAuth.SignDetached(input, pair.PrivateKey))).ToArray();
            var head = Head(receipts);
            var exact = AccountDirectoryAdh1Codec.Encode(head);
            var hash = DomainHash("Deep/AccountDirectory/V1/ADH1/core",
                AccountDirectoryAdh1Codec.EncodeUnsigned(head));
            return (exact, hash);
        }

        private static byte[] SignatureInput(string domain, ushort suite,
            ReadOnlySpan<byte> canonical)
        {
            var label = Encoding.ASCII.GetBytes(domain);
            var input = new byte[label.Length + 7 + canonical.Length];
            label.CopyTo(input, 0);
            BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(label.Length + 1), suite);
            BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(label.Length + 3),
                checked((uint)canonical.Length));
            canonical.CopyTo(input.AsSpan(label.Length + 7));
            return input;
        }

        private static byte[] DomainHash(string domain, ReadOnlySpan<byte> value)
        {
            var label = Encoding.ASCII.GetBytes(domain);
            var input = new byte[label.Length + 5 + value.Length];
            label.CopyTo(input, 0);
            BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(label.Length + 1),
                checked((uint)value.Length));
            value.CopyTo(input.AsSpan(label.Length + 5));
            return SHA256.HashData(input);
        }
    }

    private sealed class RootSigner(
        XPointNetworkBootstrapRootKey key, KeyPair pair)
        : IXPointNetworkBootstrapRootSigner
    {
        public ReadOnlyMemory<byte> RootKeyId => key.RootKeyId;
        public ulong KeyGeneration => key.KeyGeneration;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.Ed25519PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => key.CustodyDomainHash;

        public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request,
            Memory<byte> signature64, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var signature = PublicKeyAuth.SignDetached(
                request.SigningInput.ToArray(), pair.PrivateKey);
            signature.CopyTo(signature64);
            return ValueTask.FromResult(64);
        }
    }
}
