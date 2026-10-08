using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Client.Shared.Persistence;

/// <summary>
/// Platform-owned authenticated protection for one mutable binary buffer.
/// Implementations must return a fresh array and must reject modified ciphertext.
/// </summary>
public interface IDeepSecretProtector
{
    byte[] Protect(ReadOnlySpan<byte> plaintext);

    byte[] Unprotect(ReadOnlySpan<byte> protectedBytes);
}

/// <summary>
/// Stores the complete secure-storage inventory as one authenticated, atomically
/// replaced binary aggregate. Secret values never pass through JSON or managed strings.
/// </summary>
public sealed class JournaledDeepSecureStorage : IDeepSecureStorage, IDisposable
{
    private const ushort FormatVersion = 1;
    private const int HeaderSize = 8;
    private const int MaximumEntries = DeepSecureStorageRegistration.MaximumEntries;
    private const int MaximumSlotBytes = 512;
    private const int MaximumValueBytes = 1024 * 1024;
    private const int MaximumPlaintextBytes = 8 * 1024 * 1024;
    private const uint MoveFileReplaceExisting = 0x1;
    private const uint MoveFileWriteThrough = 0x8;
    private static readonly byte[] Magic = "DSS1"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private readonly string statePath;
    private readonly string pendingPath;
    private readonly string backupPath;
    private readonly string leasePath;
    private readonly IDeepSecretProtector protector;
    private readonly SemaphoreSlim gate = new(1, 1);
    private int disposed;

    public JournaledDeepSecureStorage(string statePath, IDeepSecretProtector protector)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        this.protector = protector ?? throw new ArgumentNullException(nameof(protector));
        this.statePath = Path.GetFullPath(statePath);
        pendingPath = this.statePath + ".pending";
        backupPath = this.statePath + ".backup";
        leasePath = this.statePath + ".lock";

        var directory = Path.GetDirectoryName(this.statePath);
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new ArgumentException("Secure-storage path has no parent directory.", nameof(statePath));
        }

        Directory.CreateDirectory(directory);
    }

    public async Task<OwnedDeepSecret?> ReadOwnedAsync(
        string slot,
        CancellationToken cancellationToken = default)
    {
        ValidateSlot(slot);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Dictionary<string, byte[]>? values = null;
        try
        {
            ThrowIfDisposed();
            using var processLease = await AcquireProcessLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            values = Load();
            return values.TryGetValue(slot, out var value)
                ? new OwnedDeepSecret(value)
                : null;
        }
        finally
        {
            ZeroValues(values);
            gate.Release();
        }
    }

    public async Task WriteBatchAsync(
        IReadOnlyList<DeepSecureStorageWrite> writes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(writes);
        _ = DeepSecureStorageRegistration.ValidateWrites(writes);
        if (writes.Count == 0 || writes.Count > MaximumEntries)
        {
            throw new ArgumentException("Secure-storage batch is empty or too large.", nameof(writes));
        }

        var additions = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            foreach (var write in writes)
            {
                ValidateSlot(write.Slot);
                if (write.Value.IsEmpty || write.Value.Length > MaximumValueBytes
                    || additions.ContainsKey(write.Slot))
                {
                    throw new ArgumentException("Secure-storage batch is malformed.", nameof(writes));
                }
                additions.Add(write.Slot, write.Value.ToArray());
            }

            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            Dictionary<string, byte[]>? values = null;
            try
            {
                ThrowIfDisposed();
                using var processLease = await AcquireProcessLeaseAsync(cancellationToken)
                    .ConfigureAwait(false);
                values = Load();
                if (values.Count + additions.Count > MaximumEntries
                    || additions.Keys.Any(values.ContainsKey))
                {
                    throw new InvalidOperationException(
                        "Secure-storage slot already exists or capacity was exceeded.");
                }

                foreach (var addition in additions)
                {
                    values.Add(addition.Key, addition.Value);
                }
                additions.Clear();
                await CommitAsync(values, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                ZeroValues(values);
                gate.Release();
            }
        }
        finally
        {
            ZeroValues(additions);
        }
    }

    public async Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected,
        ReadOnlyMemory<byte> replacement, CancellationToken cancellationToken = default)
    {
        ValidateSlot(slot);
        if (expected.IsEmpty || replacement.IsEmpty || expected.Length > MaximumValueBytes || replacement.Length > MaximumValueBytes)
            throw new ArgumentException("Secure-storage replacement is outside its byte bound.");
        var expectedCopy = expected.ToArray();
        var replacementCopy = replacement.ToArray();
        var matched = false;
        try
        {
            await MutateAsync(values =>
            {
                if (!values.TryGetValue(slot, out var current) ||
                    !CryptographicOperations.FixedTimeEquals(current, expectedCopy)) return false;
                values[slot] = replacementCopy;
                CryptographicOperations.ZeroMemory(current);
                matched = true;
                return true;
            }, cancellationToken).ConfigureAwait(false);
            return matched;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedCopy);
            CryptographicOperations.ZeroMemory(replacementCopy);
        }
    }

    public async Task<bool> CompareExchangeAndInsertAsync(string slot, ReadOnlyMemory<byte> expected,
        ReadOnlyMemory<byte> replacement, IReadOnlyList<DeepSecureStorageWrite> insertions,
        CancellationToken cancellationToken = default)
    {
        using var batch = new DeepSecureStorageRegistration(slot, expected, replacement, insertions);
        var matched = false;
        await MutateAsync(values =>
        {
            if (!values.TryGetValue(slot, out var current) ||
                !CryptographicOperations.FixedTimeEquals(current, batch.Expected) ||
                batch.Insertions.Keys.Any(values.ContainsKey)) return false;
            batch.ValidateCapacity(values);
            var successor = batch.CopySuccessor();
            values[slot] = successor[slot];
            foreach (var item in successor) if (item.Key != slot) values.Add(item.Key, item.Value);
            CryptographicOperations.ZeroMemory(current);
            matched = true;
            return true;
        }, cancellationToken).ConfigureAwait(false);
        return matched;
    }

    public async Task DeleteBatchAsync(
        IReadOnlyList<string> slots,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(slots);
        var requested = new HashSet<string>(StringComparer.Ordinal);
        foreach (var slot in slots)
        {
            ValidateSlot(slot);
            requested.Add(slot);
        }

        await MutateAsync(
            values =>
            {
                var changed = false;
                foreach (var slot in requested)
                {
                    if (values.Remove(slot, out var value))
                    {
                        CryptographicOperations.ZeroMemory(value);
                        changed = true;
                    }
                }
                return changed;
            },
            cancellationToken).ConfigureAwait(false);
    }

    public Task PurgeStoreV1NamespaceAsync(CancellationToken cancellationToken = default) =>
        MutateAsync(
            values =>
            {
                var changed = false;
                foreach (var slot in values.Keys.Where(static key =>
                             key.StartsWith("deep.store.v1.", StringComparison.Ordinal)).ToArray())
                {
                    if (values.Remove(slot, out var value))
                    {
                        CryptographicOperations.ZeroMemory(value);
                        changed = true;
                    }
                }
                return changed;
            },
            cancellationToken);

    public Task PurgeStoreV2NamespaceAsync(CancellationToken cancellationToken = default) =>
        MutateAsync(
            values =>
            {
                var changed = false;
                foreach (var slot in values.Keys.Where(static key =>
                             key.StartsWith("deep.store.v2.", StringComparison.Ordinal)).ToArray())
                {
                    if (values.Remove(slot, out var value))
                    {
                        CryptographicOperations.ZeroMemory(value);
                        changed = true;
                    }
                }
                return changed;
            },
            cancellationToken);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        gate.Wait();
        gate.Release();
        (protector as IDisposable)?.Dispose();
    }

    private async Task MutateAsync(
        Func<Dictionary<string, byte[]>, bool> mutation,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Dictionary<string, byte[]>? values = null;
        try
        {
            ThrowIfDisposed();
            using var processLease = await AcquireProcessLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            values = Load();
            if (mutation(values))
            {
                await CommitAsync(values, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ZeroValues(values);
            gate.Release();
        }
    }

    private Dictionary<string, byte[]> Load()
    {
        RecoverFileSet();
        if (!File.Exists(statePath))
        {
            return new Dictionary<string, byte[]>(StringComparer.Ordinal);
        }

        var fileLength = new FileInfo(statePath).Length;
        if (fileLength is <= 0 or > MaximumPlaintextBytes * 2)
            throw new CryptographicException("Protected secure-storage aggregate has an invalid size.");
        var protectedBytes = File.ReadAllBytes(statePath);
        byte[]? plaintext = null;
        try
        {
            if (protectedBytes.Length == 0 || protectedBytes.Length > MaximumPlaintextBytes * 2)
            {
                throw new InvalidDataException("Protected secure-storage aggregate has an invalid size.");
            }
            plaintext = protector.Unprotect(protectedBytes);
            return Decode(plaintext);
        }
        catch (CryptographicException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not IOException)
        {
            throw new CryptographicException(
                "Secure-storage aggregate authentication or decoding failed.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private async Task CommitAsync(
        IReadOnlyDictionary<string, byte[]> values,
        CancellationToken cancellationToken)
    {
        var plaintext = Encode(values);
        byte[]? protectedBytes = null;
        try
        {
            protectedBytes = protector.Protect(plaintext);
            if (protectedBytes.Length == 0 || protectedBytes.Length > MaximumPlaintextBytes * 2)
            {
                throw new CryptographicException(
                    "Platform protection returned an invalid aggregate.");
            }

            TryDelete(pendingPath);
            using (var stream = new FileStream(
                       pendingPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 16 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(protectedBytes);
                stream.Flush(flushToDisk: true);
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (File.Exists(statePath))
            {
                TryDelete(backupPath);
            }
            await ReplaceDurablyAsync(pendingPath, statePath, cancellationToken).ConfigureAwait(false);

            // The new aggregate is authoritative after the rename. No previous
            // aggregate is retained, so deletion cannot later roll back secrets.
            TryDelete(backupPath);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
    }

    private void RecoverFileSet()
    {
        // A pending file has never crossed the commit rename and is never promoted.
        TryDelete(pendingPath);
        // A backup is never a valid recovery source because it could resurrect a
        // deleted key. Current writes do not create one; remove leftovers from an
        // interrupted older implementation before reading the authoritative state.
        TryDelete(backupPath);
    }

    private async Task<FileStream> AcquireProcessLeaseAsync(
        CancellationToken cancellationToken)
    {
        var elapsed = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    leasePath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1,
                    FileOptions.WriteThrough);
            }
            catch (IOException exception)
            {
                if (elapsed.Elapsed >= TimeSpan.FromSeconds(30))
                {
                    throw new IOException(
                        "Timed out acquiring the secure-storage process lease.", exception);
                }
                await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }

    private static byte[] Encode(IReadOnlyDictionary<string, byte[]> values)
    {
        if (values.Count > MaximumEntries)
        {
            throw new InvalidOperationException("Secure-storage aggregate exceeds its entry limit.");
        }

        var entries = values
            .OrderBy(static pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => (Slot: StrictUtf8.GetBytes(pair.Key), pair.Value))
            .ToArray();
        try
        {
            var length = HeaderSize;
            foreach (var entry in entries)
            {
                if (entry.Slot.Length == 0 || entry.Slot.Length > MaximumSlotBytes
                    || entry.Value.Length == 0 || entry.Value.Length > MaximumValueBytes)
                {
                    throw new InvalidOperationException("Secure-storage aggregate contains an invalid entry.");
                }
                length = checked(length + 2 + 4 + entry.Slot.Length + entry.Value.Length);
            }
            if (length > MaximumPlaintextBytes)
            {
                throw new InvalidOperationException("Secure-storage aggregate exceeds its size limit.");
            }

            var output = new byte[length];
            Magic.CopyTo(output, 0);
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), FormatVersion);
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), checked((ushort)entries.Length));
            var offset = HeaderSize;
            foreach (var entry in entries)
            {
                BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)entry.Slot.Length));
                BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 2), checked((uint)entry.Value.Length));
                offset += 6;
                entry.Slot.CopyTo(output, offset);
                offset += entry.Slot.Length;
                entry.Value.CopyTo(output, offset);
                offset += entry.Value.Length;
            }
            return output;
        }
        finally
        {
            foreach (var entry in entries)
            {
                CryptographicOperations.ZeroMemory(entry.Slot);
            }
        }
    }

    private static Dictionary<string, byte[]> Decode(ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.Length < HeaderSize || plaintext.Length > MaximumPlaintextBytes
            || !plaintext[..4].SequenceEqual(Magic)
            || BinaryPrimitives.ReadUInt16BigEndian(plaintext[4..]) != FormatVersion)
        {
            throw new InvalidDataException("Secure-storage aggregate header is invalid.");
        }

        var count = BinaryPrimitives.ReadUInt16BigEndian(plaintext[6..]);
        if (count > MaximumEntries)
        {
            throw new InvalidDataException("Secure-storage aggregate has too many entries.");
        }

        var values = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            var offset = HeaderSize;
            string? previous = null;
            for (var index = 0; index < count; index++)
            {
                if (plaintext.Length - offset < 6)
                {
                    throw new InvalidDataException("Secure-storage aggregate is truncated.");
                }
                var slotLength = BinaryPrimitives.ReadUInt16BigEndian(plaintext[offset..]);
                var valueLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(plaintext[(offset + 2)..]));
                offset += 6;
                if (slotLength == 0 || slotLength > MaximumSlotBytes
                    || valueLength <= 0 || valueLength > MaximumValueBytes
                    || plaintext.Length - offset < slotLength + valueLength)
                {
                    throw new InvalidDataException("Secure-storage aggregate entry is invalid.");
                }

                var slot = StrictUtf8.GetString(plaintext.Slice(offset, slotLength));
                ValidateSlot(slot);
                offset += slotLength;
                if (previous is not null && StringComparer.Ordinal.Compare(previous, slot) >= 0)
                {
                    throw new InvalidDataException("Secure-storage aggregate is not strictly ordered.");
                }
                previous = slot;
                if (!values.TryAdd(slot, plaintext.Slice(offset, valueLength).ToArray()))
                {
                    throw new InvalidDataException("Secure-storage aggregate contains duplicate slots.");
                }
                offset += valueLength;
            }

            if (offset != plaintext.Length)
            {
                throw new InvalidDataException("Secure-storage aggregate contains trailing bytes.");
            }
            return values;
        }
        catch
        {
            ZeroValues(values);
            throw;
        }
    }

    private static void ValidateSlot(string slot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slot);
        var byteCount = StrictUtf8.GetByteCount(slot);
        if (byteCount == 0 || byteCount > MaximumSlotBytes
            || slot.Any(static character => char.IsControl(character) || char.IsSurrogate(character)))
        {
            throw new ArgumentException("Secure-storage slot name is invalid.", nameof(slot));
        }
    }

    private static void ZeroValues(Dictionary<string, byte[]>? values)
    {
        if (values is null)
        {
            return;
        }
        foreach (var value in values.Values)
        {
            CryptographicOperations.ZeroMemory(value);
        }
        values.Clear();
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (FileNotFoundException)
        {
        }
        catch (DirectoryNotFoundException)
        {
        }
    }

    private static async Task ReplaceDurablyAsync(string temporaryPath, string finalPath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (OperatingSystem.IsWindows())
        {
            var deadline = TimeSpan.FromSeconds(2);
            var elapsed = Stopwatch.StartNew();
            var delayMilliseconds = 25;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (MoveFileEx(
                        temporaryPath,
                        finalPath,
                        MoveFileReplaceExisting | MoveFileWriteThrough))
                {
                    return;
                }

                var error = Marshal.GetLastPInvokeError();
                var remaining = deadline - elapsed.Elapsed;
                if (!IsTransientWindowsReplaceError(error)
                    || remaining <= TimeSpan.Zero)
                {
                    throw new Win32Exception(error);
                }

                // An external handle can deny replacement longer than127ms.
                // Keep both writer leases while asynchronously waiting; never
                // delete/copy the authoritative file or alter its permissions.
                // Cancellation before rename leaves only uncommitted pending data.
                await Task.Delay(TimeSpan.FromMilliseconds(
                    Math.Min(delayMilliseconds, remaining.TotalMilliseconds)), cancellationToken)
                    .ConfigureAwait(false);
                if (elapsed.Elapsed >= deadline) throw new Win32Exception(error);
                delayMilliseconds = Math.Min(delayMilliseconds * 2, 100);
            }
        }

        File.Move(temporaryPath, finalPath, overwrite: true);
        FlushUnixDirectory(Path.GetDirectoryName(finalPath)
            ?? throw new InvalidOperationException("Secure-storage state has no parent directory."));
    }

    private static bool IsTransientWindowsReplaceError(int error) =>
        error is 5 or 32 or 33; // ACCESS_DENIED, SHARING_VIOLATION, LOCK_VIOLATION

    private static void FlushUnixDirectory(string directory)
    {
        var descriptor = Open(directory, 0);
        if (descriptor < 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        try
        {
            if (Fsync(descriptor) != 0)
            {
                var error = Marshal.GetLastPInvokeError();
                if (error is not (22 or 95))
                {
                    throw new Win32Exception(error);
                }
            }
        }
        finally
        {
            _ = Close(descriptor);
        }
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int descriptor);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int Close(int descriptor);

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(
        string existingPath,
        string newPath,
        uint flags);

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed != 0, this);
}
