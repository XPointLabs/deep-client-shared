using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

public sealed partial class JournaledDeepSecureStorage
{
    public static async Task<JournaledDeepSecureStorage> CreateNewAsync(string statePath, IDeepSecretProtector protector,
        CancellationToken cancellationToken = default)
    {
        var owner = new JournaledDeepSecureStorage(statePath, protector);
        var success = false;
        await owner.gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            owner.CreateParentDirectory();
            using var process = await owner.AcquireProcessLeaseAsync(cancellationToken).ConfigureAwait(false);
            if (File.Exists(owner.statePath) || File.Exists(owner.pendingPath) || File.Exists(owner.backupPath) ||
                (Directory.Exists(owner.objectDirectory) && Directory.EnumerateFileSystemEntries(owner.objectDirectory).Any()))
                throw new InvalidOperationException("New secure storage requires an absent owned file family.");
            owner.CreateObjectDirectory();
            using var empty = new Inventory(Random32(), 1, new byte[32]);
            await owner.PublishAsync(new byte[32], empty, new Dictionary<string, byte[]>(), null, RootKind.Creation, cancellationToken).ConfigureAwait(false);
            using var audit = await owner.AdmitAsync(cancellationToken, forceAudit: true).ConfigureAwait(false);
            success = true; return owner;
        }
        finally
        {
            owner.gate.Release();
            // Ownership of the caller's protector transfers only on success.
            if (!success) Interlocked.Exchange(ref owner.disposed, 1);
        }
    }

    /// <summary>Explicit one-off authenticated DSS1 enrollment at the SAME path.
    /// This is never called by ordinary reads or missing-state recovery.</summary>
    public static async Task<JournaledDeepSecureStorage> EnrollAggregateAsync(string statePath, IDeepSecretProtector protector,
        CancellationToken cancellationToken = default)
    {
        var owner = new JournaledDeepSecureStorage(statePath, protector);
        var success = false;
        await owner.gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var process = await owner.AcquireProcessLeaseAsync(cancellationToken).ConfigureAwait(false);
            var source = owner.ReadAggregateSource(cancellationToken, allowManifest: true);
            try
            {
                if (source.IsManifest)
                {
                    source.Dispose();
                    using var current = await owner.AdmitAsync(cancellationToken, forceAudit: true).ConfigureAwait(false);
                    success = true; return owner; // Postcommit recovery uses only DSS2.
                }
                var sourceHash = source.Hash.ToArray();
                var lengths = source.Values.ToDictionary(p => p.Key, p => p.Value.Length, StringComparer.Ordinal);
                if (Directory.Exists(owner.objectDirectory) && !File.Exists(owner.pendingPath) &&
                    Directory.EnumerateFileSystemEntries(owner.objectDirectory).Any())
                    throw new CryptographicException("Untracked value-object state prevents aggregate enrollment.");
                owner.CreateObjectDirectory();
                if (File.Exists(owner.pendingPath))
                {
                    source.Dispose();
                    await owner.RecoverEnrollmentPendingAsync(sourceHash, lengths, cancellationToken).ConfigureAwait(false);
                    source = owner.ReadAggregateSource(cancellationToken);
                    if (!Fixed(source.Hash, sourceHash)) throw new CryptographicException("Aggregate source changed during explicit resume.");
                }
                if (File.Exists(owner.backupPath))
                {
                    source.Dispose();
                    await owner.RetirePathAsync(owner.backupPath, new(sourceHash, RootKind.Enrollment, null), null,
                        cancellationToken, manifest: true).ConfigureAwait(false);
                    source = owner.ReadAggregateSource(cancellationToken);
                    if (!Fixed(source.Hash, sourceHash)) throw new CryptographicException("Aggregate source changed during cleanup.");
                }
                if (Directory.EnumerateFileSystemEntries(owner.objectDirectory).Any())
                    throw new CryptographicException("Untracked value-object state remains after explicit enrollment recovery.");
                using var candidate = new Inventory(Random32(), 1, sourceHash.ToArray());
                var objects = new Dictionary<string, byte[]>(StringComparer.Ordinal);
                try
                {
                    foreach (var item in source.Values)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var (descriptor, file) = owner.EncryptObject(candidate, item.Key, item.Value);
                        candidate.Values.Add(item.Key, descriptor); objects.Add(descriptor.Name, file);
                    }
                    if (candidate.Values.Count != source.Values.Count || ValidateInventory(candidate) !=
                        8L + source.Values.Sum(p => 6L + StrictUtf8.GetByteCount(p.Key) + p.Value.Length))
                        throw new CryptographicException("Enrollment does not cover the complete source inventory.");
                    source.Dispose(); // Never carry the old value/key inventory through Protect.
                    await owner.PublishAsync(sourceHash, candidate, objects, null, RootKind.Enrollment, cancellationToken).ConfigureAwait(false);
                    using var audit = await owner.AdmitAsync(cancellationToken, forceAudit: true).ConfigureAwait(false);
                    success = true; return owner;
                }
                finally { ZeroValues(objects); }
            }
            finally { source.Dispose(); }
        }
        finally
        {
            owner.gate.Release(); if (!success) Interlocked.Exchange(ref owner.disposed, 1);
        }
    }

    private sealed class AggregateSource(byte[] exact, Dictionary<string, byte[]> values, bool isManifest) : IDisposable
    {
        internal byte[] Exact { get; } = exact;
        internal byte[] Hash { get; } = SHA256.HashData(exact);
        internal Dictionary<string, byte[]> Values { get; } = values;
        internal bool IsManifest { get; } = isManifest;
        public void Dispose() { ZeroValues(Values); Values.Clear(); CryptographicOperations.ZeroMemory(Exact); }
    }

    private AggregateSource ReadAggregateSource(CancellationToken ct, bool allowManifest = false)
    {
        ct.ThrowIfCancellationRequested();
        var exact = ReadBoundedFile(statePath, MaximumPlaintextBytes * 2, manifest: true);
        byte[]? plain = null; Dictionary<string, byte[]>? values = null;
        try
        {
            Interlocked.Increment(ref unprotectCalls); plain = protector.Unprotect(exact);
            if (ReferenceEquals(exact, plain)) throw new CryptographicException("Protector did not return owned plaintext.");
            Interlocked.Add(ref manifestPlaintext, plain.Length);
            var current = plain.Length >= 4 && plain.AsSpan(0, 4).SequenceEqual("DSS2"u8);
            if (current)
            {
                if (exact.Length > MaximumProtectedManifestBytes) throw new CryptographicException("Adopted manifest exceeds its protected byte bound.");
                if (!allowManifest) throw new CryptographicException("An adopted manifest is not a legacy aggregate predecessor.");
                using var validated = DecodeManifest(plain); values = new(StringComparer.Ordinal);
            }
            else values = Decode(plain, null);
            ct.ThrowIfCancellationRequested();
            var source = new AggregateSource(exact, values, current);
            try { RequireExactFile(statePath, source.Hash, MaximumPlaintextBytes * 2, manifest: true); return source; }
            catch { source.Dispose(); throw; }
        }
        catch (Exception error) when (error is ArgumentException or OverflowException or InvalidDataException)
        { ZeroValues(values); CryptographicOperations.ZeroMemory(exact); throw new CryptographicException("Explicit aggregate enrollment authentication failed.", error); }
        catch { ZeroValues(values); CryptographicOperations.ZeroMemory(exact); throw; }
        finally { if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
    }

    private async Task RecoverEnrollmentPendingAsync(byte[] sourceHash, Dictionary<string, int> lengths, CancellationToken ct)
    {
        var bytes = ReadBoundedFile(pendingPath, MaximumProtectedManifestBytes, manifest: true, allowEmpty: true);
        var authority = new ReplacementAuthority(sourceHash, RootKind.Enrollment, null);
        if (bytes.Length == 0)
        { await RetirePathAsync(pendingPath, authority, null, ct, manifest: true).ConfigureAwait(false); return; }
        var pendingHash = SHA256.HashData(bytes); byte[]? plain = null; string[] staged;
        try
        {
            Interlocked.Increment(ref unprotectCalls); plain = protector.Unprotect(bytes);
            if (ReferenceEquals(plain, bytes)) throw new CryptographicException("Protector did not return owned plaintext.");
            Interlocked.Add(ref manifestPlaintext, plain.Length);
            using var pending = DecodeManifest(plain);
            if (pending.Revision != 1 || !Fixed(pending.Predecessor, sourceHash) || pending.Cleanup.Count != 0 ||
                pending.Values.Count != lengths.Count || pending.Values.Any(p => !lengths.TryGetValue(p.Key, out var length) || length != p.Value.Length))
                throw new CryptographicException("Pending enrollment does not cover its exact aggregate source.");
            staged = pending.Values.Values.Select(v => v.Name).ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(bytes); if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
        Revalidate(authority, ct); RequireExactFile(pendingPath, pendingHash, MaximumProtectedManifestBytes, manifest: true);
        foreach (var name in staged)
        {
            await RetirePathAsync(ObjectPath(name), authority, name, ct, manifest: false, pendingHash: pendingHash).ConfigureAwait(false);
            if (File.Exists(ObjectPath(name, ".pending")))
                await RetirePathAsync(ObjectPath(name, ".pending"), authority, name, ct, manifest: false, pendingHash: pendingHash).ConfigureAwait(false);
        }
        await RetirePathAsync(pendingPath, authority, null, ct, manifest: true).ConfigureAwait(false);
    }

    private void CreateParentDirectory()
    {
        var directory = Path.GetDirectoryName(statePath)!; RequireNoRedirectedAncestors(directory);
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(directory);
        else Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        RequireNoRedirectedAncestors(directory);
    }

    // Deliberately confined to explicit enrollment. Ordinary storage has exactly
    // one DSS2 reader and never calls this decoder or repairs absent state.
    private static Dictionary<string, byte[]> Decode(ReadOnlySpan<byte> plaintext, IReadOnlySet<string>? selectedSlots)
    {
        if (plaintext.Length is < 8 or > MaximumPlaintextBytes || !plaintext[..4].SequenceEqual("DSS1"u8) ||
            BinaryPrimitives.ReadUInt16BigEndian(plaintext[4..]) != 1)
            throw new CryptographicException("Explicit enrollment requires the canonical DSS1 source.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(plaintext[6..]);
        if (count > MaximumEntries) throw new CryptographicException("Aggregate enrollment count exceeds capacity.");
        var values = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            var offset = 8; string? previous = null;
            for (var index = 0; index < count; index++)
            {
                if (plaintext.Length - offset < 6) throw new CryptographicException("Aggregate enrollment entry is truncated.");
                var nameLength = BinaryPrimitives.ReadUInt16BigEndian(plaintext[offset..]);
                var valueLength = BinaryPrimitives.ReadUInt32BigEndian(plaintext[(offset + 2)..]); offset += 6;
                if (nameLength is < 1 or > MaximumSlotBytes || valueLength is < 1 ||
                    valueLength > DeviceV2.ProtectedDid2GroupJournal.MaximumBytes || plaintext.Length - offset < nameLength + (long)valueLength)
                    throw new CryptographicException("Aggregate enrollment entry exceeds its bound.");
                var slot = StrictUtf8.GetString(plaintext.Slice(offset, nameLength)); offset += nameLength; ValidateSlot(slot);
                if (valueLength > DeepSecureStorageRegistration.MaximumBytesForSlot(slot) ||
                    (previous is not null && StringComparer.Ordinal.Compare(previous, slot) >= 0))
                    throw new CryptographicException("Aggregate enrollment inventory is not canonical.");
                previous = slot;
                if (selectedSlots is null || selectedSlots.Contains(slot)) values.Add(slot, plaintext.Slice(offset, checked((int)valueLength)).ToArray());
                offset += checked((int)valueLength);
            }
            if (offset != plaintext.Length) throw new CryptographicException("Aggregate enrollment has trailing bytes.");
            return values;
        }
        catch { ZeroValues(values); throw; }
    }
}
