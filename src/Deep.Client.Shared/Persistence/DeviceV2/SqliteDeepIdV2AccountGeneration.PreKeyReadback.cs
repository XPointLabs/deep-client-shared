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
            if (inventory is null || !committed.Use(bytes => bytes.Length == PreKeyCommitMarkerLength &&
                Fixed(installedDigest, SHA256.HashData(bytes[..32]))))
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
        if (committed is not null)
        {
            var scope = installed.Use(value => value.ToArray());
            var initialHash = committed.Use(value => value.Slice(32, 32).ToArray());
            try
            {
                using var successors = await ProtectedPreKeyInventoryChain.ReadAsync(storage, scope, initialHash, ct).ConfigureAwait(false);
                if (!inventory!.Use(value => Fixed(value, successors.Tip)))
                    throw new CryptographicException("Responder successor pointer changed during source readback.");
                // Preserve the exact existing initial-only readback. New data
                // is framed only when a real successor chain exists.
                if (successors.Entries.Count > 0)
                {
                    hash.AppendData([2]); var count = new byte[4];
                    BinaryPrimitives.WriteUInt32BigEndian(count, checked((uint)successors.Entries.Count)); hash.AppendData(count);
                    foreach (var entry in successors.Entries)
                    {
                        var record = entry.CopyExact();
                        try { hash.AppendData(SHA256.HashData(record)); }
                        finally { CryptographicOperations.ZeroMemory(record); }
                        using var pair = await storage.ReadOwnedAsync(ProtectedPreKeyInventoryChain.CommitSlot(entry.PublicationHash), ct).ConfigureAwait(false) ??
                            throw new IOException("Pending prekey publication pins source cleanup.");
                        var publication = DeepIdV2PreKeyPublicationCodec.Decode(entry.CopyPublication());
                        pair.Use(value =>
                        {
                            if (value.Length != PreKeyCommitMarkerLength || !Fixed(value[..32], scope) || !Fixed(value.Slice(32, 32), entry.PublicationHash))
                                throw new CryptographicException("Responder successor commit readback differs from its exact inventory.");
                            var first = DeepIdV2PreKeyCommitReceiptCodec.Decode(value.Slice(64, DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength));
                            var second = DeepIdV2PreKeyCommitReceiptCodec.Decode(value.Slice(64 + DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength));
                            ValidatePreKeyCommitPair(publication, first, second);
                            hash.AppendData(SHA256.HashData(value)); return true;
                        });
                    }
                }
            }
            finally { CryptographicOperations.ZeroMemory(scope); }
        }
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
