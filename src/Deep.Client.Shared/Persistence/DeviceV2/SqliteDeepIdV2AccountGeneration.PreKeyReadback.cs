using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    // A conservative stored-plan guard, not a source verifier. Selection must
    // independently authenticate the original source. Recovery compares the
    // exact encrypted file without opening/repairing PKV2 or obtaining a proof.
    internal static async Task<byte[]> ReadExistingPreKeySourceReadbackUnderLeaseAsync(IDeepSecureStorage storage,
        string accountPath, ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        ct.ThrowIfCancellationRequested();
        var path = PreKeyStatePath(accountPath);
        RequireOrdinaryDirectory(Path.GetDirectoryName(path) ?? throw new InvalidDataException("An owned source directory is required."));
        RequireApplicationFileFamily(path);
        RequireNoPreKeyReadbackSidecars(path);
        using var checkpoint = await storage.ReadOwnedAsync(ResponderInitialSessionCheckpoint.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Responder source lost its registered checkpoint.");
        using var state = checkpoint.Use(bytes => ResponderInitialSessionCheckpoint.Decode(bytes, instance.Span, account.Span, network.Span));
        if (state.Phase != 1) throw new IOException("Pending responder work pins local cleanup.");
        using var installed = await storage.ReadOwnedAsync(PreKeyInstallMarkerSlot, ct).ConfigureAwait(false);
        using var inventory = await storage.ReadOwnedAsync(PreKeyInventoryMarkerSlot, ct).ConfigureAwait(false);
        using var committed = await storage.ReadOwnedAsync(PreKeyCommitMarkerSlot, ct).ConfigureAwait(false);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/mailbox-prekey-source-state"u8); hash.AppendData([0]);
        hash.AppendData(network.Span); hash.AppendData(account.Span); hash.AppendData(instance.Span);
        checkpoint.Use(bytes => { hash.AppendData(SHA256.HashData(bytes)); return true; });
        if (installed is null)
        {
            if (inventory is not null || committed is not null || File.Exists(path) || state.Sequence != 0)
                throw new InvalidDataException("Responder source lost its protected install marker.");
            hash.AppendData([0]); held.RequireOwner(lease); ct.ThrowIfCancellationRequested(); return hash.GetHashAndReset();
        }
        if (!installed.Use(bytes => bytes.Length == 32 && bytes.IndexOfAnyExcept((byte)0) >= 0) || !File.Exists(path))
            throw new InvalidDataException("Installed responder source lost its existing custody.");
        var installedDigest = installed.Use(bytes => SHA256.HashData(bytes));
        if (inventory is not null && !inventory.Use(bytes => bytes.Length == 64 &&
            Fixed(installedDigest, SHA256.HashData(bytes[..32])) && bytes[32..].IndexOfAnyExcept((byte)0) >= 0))
            throw new CryptographicException("Responder inventory marker is foreign or malformed.");
        if (committed is not null)
        {
            var inventoryDigest = inventory?.Use(bytes => SHA256.HashData(bytes));
            if (inventory is null || !committed.Use(bytes => bytes.Length == PreKeyCommitMarkerLength &&
                Fixed(inventoryDigest!, SHA256.HashData(bytes[..64]))))
                throw new CryptographicException("Responder commit marker differs from its inventory.");
            committed.Use(bytes =>
            {
                var first = DeepIdV2PreKeyCommitReceiptCodec.Decode(bytes.Slice(64, DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength));
                var second = DeepIdV2PreKeyCommitReceiptCodec.Decode(bytes.Slice(64 + DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength));
                if (!Fixed(first.Field(1).Span, network.Span) || !Fixed(second.Field(1).Span, network.Span) ||
                    Fixed(first.Field(5).Span, second.Field(5).Span))
                    throw new CryptographicException("Responder commit marker has a foreign or repeated replica.");
                return true;
            });
        }
        hash.AppendData([1]); installed.Use(bytes => { hash.AppendData(bytes); return true; });
        hash.AppendData([inventory is null ? (byte)0 : (byte)1]);
        inventory?.Use(bytes => { hash.AppendData(bytes); return true; });
        hash.AppendData([committed is null ? (byte)0 : (byte)1]);
        committed?.Use(bytes => { hash.AppendData(bytes); return true; });
        // Fixed memory; no allocation from file length or secret inventory cell
        // sizes. FileShare.Read excludes writes/deletion while the held reader
        // streams all ciphertext. Even a harmless ciphertext rewrite pins the
        // stored plan; recovery never assumes logical equivalence or repairs it.
        await using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            65_536, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var length = file.Length;
        if (length <= 0) throw new InvalidDataException("Responder source is empty.");
        var encodedLength = new byte[8]; BinaryPrimitives.WriteInt64BigEndian(encodedLength, length); hash.AppendData(encodedLength);
        var buffer = new byte[65_536];
        try
        {
            long read = 0;
            for (int count; (count = await file.ReadAsync(buffer, ct).ConfigureAwait(false)) != 0;)
            {
                held.RequireOwner(lease); read = checked(read + count); hash.AppendData(buffer.AsSpan(0, count));
            }
            RequireApplicationFileFamily(path); RequireNoPreKeyReadbackSidecars(path);
            if (read != length || file.Length != length) throw new IOException("Responder source changed during readback.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return hash.GetHashAndReset();
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    private static void RequireNoPreKeyReadbackSidecars(string path)
    {
        if (new[] { "-journal", "-wal", "-shm" }.Any(suffix => File.Exists(path + suffix)))
            throw new IOException("Unfinished responder-source IO pins local cleanup.");
    }
}
