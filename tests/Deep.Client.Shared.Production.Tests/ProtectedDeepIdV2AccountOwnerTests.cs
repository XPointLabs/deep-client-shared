using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ProtectedDeepIdV2AccountOwnerTests
{
    [Fact]
    public async Task CreateReadAndExplicitResetNeverTouchV1()
    {
        if (!SupportedProvider()) return;
        var lockPath = NewLockPath();
        try
        {
            using var storage = new InMemoryDeepSecureStorage();
            await storage.WriteBatchAsync(
                [new DeepSecureStorageWrite("deep.store.v1.keep",
                    new byte[] { 7 })]);
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            var owner = NewOwner(storage, network, lockPath);
            Assert.Null(await owner.ReadCurrentAsync(1_900_000_000,
                verifier, default));
            using var created = await owner.CreateFreshAsync(" Alice ",
                1_900_000_000, verifier, default);
            Assert.Equal("Alice", created.DisplayName);
            var exactDid2 = created.Verified.PublicEvidence.Binding.DeepId
                .CanonicalBytes.ToArray();
            var nextOwner = NewOwner(storage, network, lockPath);
            using var restored = await nextOwner.ReadCurrentAsync(
                1_900_000_000, verifier, default);
            Assert.Equal(exactDid2, restored!.Verified.PublicEvidence.Binding
                .DeepId.CanonicalBytes.ToArray());
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => nextOwner.CreateFreshAsync("Second", 1_900_000_000,
                    verifier, default).AsTask());
            await nextOwner.ResetExplicitlyAsync(default);
            Assert.Null(await nextOwner.ReadCurrentAsync(1_900_000_000,
                verifier, default));
            using var v1 = await storage.ReadOwnedAsync("deep.store.v1.keep");
            Assert.NotNull(v1);
        }
        finally { File.Delete(lockPath); }
    }

    [Fact]
    public async Task InterruptedUnpublishedCreationRequiresExplicitReset()
    {
        if (!SupportedProvider()) return;
        var lockPath = NewLockPath();
        try
        {
            using var inner = new InMemoryDeepSecureStorage();
            var storage = new FailFirstIndexWriteStorage(inner);
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            var owner = NewOwner(storage, network, lockPath);
            await Assert.ThrowsAsync<IOException>(
                () => owner.CreateFreshAsync("Alice", 1_900_000_000,
                    verifier, default).AsTask());
            var restartedOwner = NewOwner(storage, network, lockPath);
            await Assert.ThrowsAsync<DeepIdV2CreationInterruptedException>(
                () => restartedOwner.ReadCurrentAsync(1_900_000_000,
                    verifier, default).AsTask());
            await Assert.ThrowsAsync<DeepIdV2CreationInterruptedException>(
                () => restartedOwner.CreateFreshAsync("Alice", 1_900_000_000,
                    verifier, default).AsTask());
            using (var pending = await inner.ReadOwnedAsync(
                       "deep.store.v2.creation-intent"))
                Assert.NotNull(pending);
            await restartedOwner.ResetExplicitlyAsync(default);
            Assert.Null(await inner.ReadOwnedAsync(
                "deep.store.v2.creation-intent"));
            using var created = await restartedOwner.CreateFreshAsync(
                "Alice", 1_900_000_000, verifier, default);
            Assert.Equal("Alice", created.DisplayName);
        }
        finally { File.Delete(lockPath); }
    }

    [Fact]
    public async Task FileLeaseSerializesSeparateOwners()
    {
        var lockPath = NewLockPath();
        try
        {
            var first = new DeepIdV2AccountFileLease(lockPath);
            var second = new DeepIdV2AccountFileLease(lockPath);
            using (var held = await first.AcquireAsync(default))
            {
                using var cancelled = new CancellationTokenSource(
                    TimeSpan.FromMilliseconds(200));
                await Assert.ThrowsAnyAsync<OperationCanceledException>(
                    () => second.AcquireAsync(cancelled.Token).AsTask());
            }
            using var acquired = await second.AcquireAsync(default);
            Assert.NotNull(acquired);
        }
        finally { File.Delete(lockPath); }
    }

    [Fact]
    public async Task JournaledStoreReopensExactCurrentAccountAfterProcessBoundary()
    {
        if (!SupportedProvider()) return;
        var directory = Path.Combine(Path.GetTempPath(),
            "deep-did2-journal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var statePath = Path.Combine(directory, "secure.bin");
        var lockPath = Path.Combine(directory, "account.lock");
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            byte[] exactDab2;
            byte[] accountId;
            using (var first = new JournaledDeepSecureStorage(statePath,
                       new TestAeadProtector(key)))
            {
                var owner = NewOwner(first, network, lockPath);
                using var created = await owner.CreateFreshAsync("Alice",
                    1_900_000_000, verifier, default);
                accountId = created.AccountId.ToArray();
                exactDab2 = created.Verified.PublicEvidence.Binding.Record
                    .CanonicalBytes.ToArray();
            }
            using (var reopened = new JournaledDeepSecureStorage(statePath,
                       new TestAeadProtector(key)))
            {
                var owner = NewOwner(reopened, network, lockPath);
                using var current = await owner.ReadCurrentAsync(
                    1_900_000_000, verifier, default);
                Assert.Equal("Alice", current!.DisplayName);
                Assert.Equal(accountId, current.AccountId.ToArray());
                Assert.Equal(exactDab2, current.Verified.PublicEvidence.Binding
                    .Record.CanonicalBytes.ToArray());
                using var retained = await owner.ReadRetainedRecoveryPhraseAsync(
                    1_900_000_000, verifier, default);
                Assert.NotNull(retained);
                await owner.DeleteRetainedRecoveryPhraseAsync(
                    1_900_000_000, verifier, default);
                Assert.Null(await owner.ReadRetainedRecoveryPhraseAsync(
                    1_900_000_000, verifier, default));
            }
            using (var reopenedAfterDeletion = new JournaledDeepSecureStorage(
                       statePath, new TestAeadProtector(key)))
            {
                var owner = NewOwner(reopenedAfterDeletion, network, lockPath);
                using var current = await owner.ReadCurrentAsync(
                    1_900_000_000, verifier, default);
                Assert.Equal(exactDab2, current!.Verified.PublicEvidence.Binding
                    .Record.CanonicalBytes.ToArray());
                Assert.Null(await owner.ReadRetainedRecoveryPhraseAsync(
                    1_900_000_000, verifier, default));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            foreach (var path in new[] { statePath, statePath + ".pending",
                         statePath + ".backup", statePath + ".lock", lockPath })
                File.Delete(path);
            Directory.Delete(directory);
        }
    }

    private static ProtectedDeepIdV2AccountOwner NewOwner(
        IDeepSecureStorage storage, byte[] network, string lockPath) =>
        new(storage, new DeepIdV2AccountFileLease(lockPath), network, 1);

    private static string NewLockPath() => Path.Combine(Path.GetTempPath(),
        "deep-did2-owner-" + Guid.NewGuid().ToString("N") + ".lock");

    private static bool SupportedProvider() =>
        OperatingSystem.IsWindows() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is
            (System.Runtime.InteropServices.Architecture.X64 or
             System.Runtime.InteropServices.Architecture.Arm64) ||
        OperatingSystem.IsLinux() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
            System.Runtime.InteropServices.Architecture.X64;

    private sealed class FailFirstIndexWriteStorage(IDeepSecureStorage inner) :
        IDeepSecureStorage
    {
        private int fail = 1;

        public Task<OwnedDeepSecret?> ReadOwnedAsync(string slot,
            CancellationToken cancellationToken = default) =>
            inner.ReadOwnedAsync(slot, cancellationToken);

        public Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes,
            CancellationToken cancellationToken = default)
        {
            if (writes.Any(static item =>
                    item.Slot == "deep.store.v2.current-account") &&
                Interlocked.Exchange(ref fail, 0) == 1)
                throw new IOException("Injected index write failure.");
            return inner.WriteBatchAsync(writes, cancellationToken);
        }

        public Task DeleteBatchAsync(IReadOnlyList<string> slots,
            CancellationToken cancellationToken = default) =>
            inner.DeleteBatchAsync(slots, cancellationToken);

        public Task PurgeStoreV1NamespaceAsync(
            CancellationToken cancellationToken = default) =>
            inner.PurgeStoreV1NamespaceAsync(cancellationToken);

        public Task PurgeStoreV2NamespaceAsync(
            CancellationToken cancellationToken = default) =>
            inner.PurgeStoreV2NamespaceAsync(cancellationToken);
    }

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
                "Deep/Test/DID2Storage"u8);
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
                    plaintext, "Deep/Test/DID2Storage"u8);
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
