using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Deep.Client.Shared.Persistence;

public sealed partial class JournaledDeepSecureStorage
{
    private enum RootKind { Current, Creation, Enrollment }
    private sealed record ReplacementAuthority(byte[] Hash, RootKind Kind, Guard? Guard,
        byte[]? CreationProtected = null, byte[]? CreationPlaintextHash = null);

    private string ObjectPath(string name, string extension = ".dvo")
    {
        if (!ValidObjectName(name)) throw new CryptographicException("Value object name is invalid.");
        return Path.Combine(objectDirectory, name + extension);
    }

    private (ValueDescriptor Descriptor, byte[] File) EncryptObject(Inventory inventory, string slot, ReadOnlySpan<byte> value)
    {
        byte[]? id = null;
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var proposed = Random32(); var name = Convert.ToHexStringLower(proposed);
            if (!inventory.Values.Values.Any(v => Fixed(v.Id, proposed)) && !inventory.Cleanup.Contains(name) &&
                !File.Exists(ObjectPath(name)) && !File.Exists(ObjectPath(name, ".pending"))) { id = proposed; break; }
        }
        if (id is null) throw new CryptographicException("Unable to allocate a fresh value-object identity.");
        var key = Random32(); var file = new byte[checked(value.Length + ObjectOverheadBytes)];
        try
        {
            "DVO2"u8.CopyTo(file); BinaryPrimitives.WriteUInt16BigEndian(file.AsSpan(4), 2);
            inventory.StoreId.CopyTo(file, 8); id.CopyTo(file, 40);
            BinaryPrimitives.WriteUInt64BigEndian(file.AsSpan(72), inventory.Revision);
            BinaryPrimitives.WriteUInt32BigEndian(file.AsSpan(80), checked((uint)value.Length));
            RandomNumberGenerator.Fill(file.AsSpan(84, 12));
            var aad = ObjectAad(file.AsSpan(0, ObjectHeaderBytes), slot);
            try
            {
                using var aes = new AesGcm(key, 16);
                aes.Encrypt(file.AsSpan(84, 12), value, file.AsSpan(ObjectHeaderBytes, value.Length), file.AsSpan(ObjectHeaderBytes + value.Length, 16), aad);
            }
            finally { CryptographicOperations.ZeroMemory(aad); }
            return (new(slot, id, inventory.Revision, value.Length, SHA256.HashData(file), key), file);
        }
        catch { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(file); throw; }
    }

    private byte[] ReadObject(Inventory inventory, ValueDescriptor descriptor)
    {
        var file = ReadBoundedFile(ObjectPath(descriptor.Name), descriptor.FileLength, manifest: false, exactLength: descriptor.FileLength);
        byte[]? plaintext = null;
        try
        {
            if (!Fixed(SHA256.HashData(file), descriptor.Hash) || !file.AsSpan(0, 4).SequenceEqual("DVO2"u8) ||
                BinaryPrimitives.ReadUInt16BigEndian(file.AsSpan(4)) != 2 || BinaryPrimitives.ReadUInt16BigEndian(file.AsSpan(6)) != 0 ||
                !Fixed(file.AsSpan(8, 32), inventory.StoreId) || !Fixed(file.AsSpan(40, 32), descriptor.Id) ||
                BinaryPrimitives.ReadUInt64BigEndian(file.AsSpan(72)) != descriptor.Birth ||
                BinaryPrimitives.ReadUInt32BigEndian(file.AsSpan(80)) != descriptor.Length)
                throw new CryptographicException("Selected value object differs from its authenticated inventory.");
            var aad = ObjectAad(file.AsSpan(0, ObjectHeaderBytes), descriptor.Slot);
            try
            {
                plaintext = new byte[descriptor.Length]; using var aes = new AesGcm(descriptor.Key, 16);
                aes.Decrypt(file.AsSpan(84, 12), file.AsSpan(ObjectHeaderBytes, descriptor.Length), file.AsSpan(ObjectHeaderBytes + descriptor.Length, 16), plaintext, aad);
                Interlocked.Add(ref objectPlaintext, plaintext.Length);
                var result = plaintext; plaintext = null; return result;
            }
            finally { CryptographicOperations.ZeroMemory(aad); }
        }
        finally { CryptographicOperations.ZeroMemory(file); if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static byte[] ObjectAad(ReadOnlySpan<byte> header, string slot)
    {
        var domain = "Deep/LocalStorage/DSS2/object"u8; var name = StrictUtf8.GetBytes(slot);
        var aad = new byte[domain.Length + 1 + ObjectHeaderBytes + 2 + name.Length];
        domain.CopyTo(aad); header.CopyTo(aad.AsSpan(domain.Length + 1));
        BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(domain.Length + 1 + ObjectHeaderBytes), checked((ushort)name.Length));
        name.CopyTo(aad, domain.Length + 1 + ObjectHeaderBytes + 2); return aad;
    }

    private Task PublishAsync(InventoryRead current, Inventory candidate, IReadOnlyDictionary<string, byte[]> objects,
        Guard? guard, RootKind kind, CancellationToken ct)
    {
        var hash = current.Hash.ToArray(); current.Dispose();
        return PublishAsync(hash, candidate, objects, guard, kind, ct);
    }

    private async Task PublishAsync(byte[] predecessorHash, Inventory candidate, IReadOnlyDictionary<string, byte[]> objects,
        Guard? guard, RootKind kind, CancellationToken ct)
    {
        var expectedPlaintext = EncodeManifest(candidate);
        var plaintextHash = SHA256.HashData(expectedPlaintext);
        var facts = objects.Keys.Select(name => candidate.Values.Values.Single(v => v.Name == name))
            .Select(v => new ObjectFact(v.Name, v.FileLength, v.Hash.ToArray())).ToArray();
        candidate.Dispose(); // No admitted key/guard loan crosses Protect or waits.
        var protectedBytes = ProtectManifest(expectedPlaintext);
        var authority = new ReplacementAuthority(predecessorHash, kind, guard,
            kind == RootKind.Creation ? protectedBytes : null, kind == RootKind.Creation ? plaintextHash : null);
        try
        {
            VerifyCandidate(protectedBytes, plaintextHash, facts, ct, verifyObjects: false);
            Revalidate(authority, ct);
            if (File.Exists(pendingPath)) throw new CryptographicException("An unresolved protected pending inventory already exists.");
            WriteBoundedFile(pendingPath, protectedBytes, manifest: true);
            FlushParent(pendingPath);
            Hit(JournaledDeepSecureStorageFailpoint.AfterPendingManifest);
            foreach (var item in objects)
            {
                ct.ThrowIfCancellationRequested(); Revalidate(authority, ct);
                WriteBoundedFile(ObjectPath(item.Key, ".pending"), item.Value, manifest: false);
                await ReplaceDurablyAsync(ObjectPath(item.Key, ".pending"), ObjectPath(item.Key), authority, ct, replace: false,
                    stagedObject: facts.Single(fact => fact.Name == item.Key)).ConfigureAwait(false);
                Hit(JournaledDeepSecureStorageFailpoint.AfterObjectStaged);
            }
            var protectedHash = SHA256.HashData(protectedBytes);
            Hit(JournaledDeepSecureStorageFailpoint.BeforeManifestReplace);
            // Pending authentication is data validation. It is disposed before
            // the fresh CURRENT policy admission that authorizes the commit.
            VerifyCandidate(protectedBytes, plaintextHash, facts, ct, verifyObjects: true);
            await ReplaceDurablyAsync(pendingPath, statePath, authority, ct, replace: kind != RootKind.Creation,
                pendingHash: protectedHash, newObjects: facts).ConfigureAwait(false);
            Hit(JournaledDeepSecureStorageFailpoint.AfterManifestReplace);
            using var readback = ReadCurrent(ct);
            if (!Fixed(readback.Hash, protectedHash)) throw new CryptographicException("Committed protected inventory readback differs.");
            foreach (var fact in facts)
            {
                var item = readback.Inventory.Values.Values.Single(v => v.Name == fact.Name);
                var value = ReadObject(readback.Inventory, item); CryptographicOperations.ZeroMemory(value);
            }
            ct.ThrowIfCancellationRequested(); RequireExactSource(readback.Hash);
        }
        finally { CryptographicOperations.ZeroMemory(protectedBytes); }
    }

    private void VerifyCandidate(byte[] expectedProtected, byte[] plaintextHash, ObjectFact[] objects, CancellationToken ct, bool verifyObjects)
    {
        var actual = verifyObjects ? ReadBoundedFile(pendingPath, MaximumProtectedManifestBytes, manifest: true) : expectedProtected.ToArray();
        byte[]? plain = null;
        try
        {
            if (!Fixed(actual, expectedProtected)) throw new CryptographicException("Prepared inventory changed before publication.");
            Interlocked.Increment(ref unprotectCalls); plain = protector.Unprotect(actual);
            if (ReferenceEquals(plain, actual)) throw new CryptographicException("Protector did not return owned plaintext.");
            Interlocked.Add(ref manifestPlaintext, plain.Length);
            if (!Fixed(SHA256.HashData(plain), plaintextHash)) throw new CryptographicException("Prepared inventory differs from the intended successor.");
            using var inventory = DecodeManifest(plain);
            if (verifyObjects) foreach (var fact in objects)
            {
                ct.ThrowIfCancellationRequested();
                var descriptor = inventory.Values.Values.Single(v => v.Name == fact.Name);
                var value = ReadObject(inventory, descriptor); CryptographicOperations.ZeroMemory(value);
            }
            ct.ThrowIfCancellationRequested();
            if (verifyObjects) RequireExactFile(pendingPath, SHA256.HashData(expectedProtected), MaximumProtectedManifestBytes, manifest: true);
        }
        finally { CryptographicOperations.ZeroMemory(actual); if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
    }

    private void Revalidate(ReplacementAuthority authority, CancellationToken ct, string? retiredName = null)
    {
        ct.ThrowIfCancellationRequested();
        if (authority.Kind == RootKind.Creation)
        {
            if (File.Exists(statePath) || File.Exists(backupPath)) throw new CryptographicException("Creation lost its absent predecessor.");
            if (authority.CreationProtected is null || authority.CreationPlaintextHash is null)
                throw new CryptographicException("Creation lacks its exact protected candidate.");
            VerifyCandidate(authority.CreationProtected, authority.CreationPlaintextHash, [], ct, verifyObjects: false);
            if (File.Exists(pendingPath))
                RequireExactFile(pendingPath, SHA256.HashData(authority.CreationProtected), MaximumProtectedManifestBytes, manifest: true);
            RequireObjectDirectory();
            if (Directory.EnumerateFileSystemEntries(objectDirectory).Any()) throw new CryptographicException("Creation gained unrelated object state.");
            if (File.Exists(statePath) || File.Exists(backupPath)) throw new CryptographicException("Creation gained a committed predecessor during admission.");
            RequireNoRedirectedAncestors(Path.GetDirectoryName(statePath)!); return;
        }
        if (authority.Kind == RootKind.Enrollment)
        { using var source = ReadAggregateSource(ct); if (!Fixed(source.Hash, authority.Hash)) throw new CryptographicException("Enrollment source changed."); return; }
        using var current = ReadCurrent(ct);
        if (!Fixed(current.Hash, authority.Hash)) throw new CryptographicException("Protected predecessor changed before effect.");
        if (retiredName is not null && current.Inventory.Values.Values.Any(v => v.Name == retiredName))
            throw new CryptographicException("Retirement selected an active object.");
        if (authority.Guard is { } guard)
        {
            if (!current.Inventory.Values.TryGetValue(guard.Slot, out var descriptor)) throw new CryptographicException("Protected mutation guard disappeared.");
            var value = ReadObject(current.Inventory, descriptor);
            try { if (!Fixed(value, guard.Expected)) throw new CryptographicException("Protected mutation guard changed."); }
            finally { CryptographicOperations.ZeroMemory(value); }
        }
        ct.ThrowIfCancellationRequested(); RequireExactSource(current.Hash);
    }

    private async Task CompleteCleanupAsync(InventoryRead current, CancellationToken ct)
    {
        var hash = current.Hash.ToArray(); var names = current.Inventory.Cleanup.ToArray();
        current.Dispose(); var authority = new ReplacementAuthority(hash, RootKind.Current, null);
        foreach (var name in names)
            await RetirePathAsync(ObjectPath(name), authority, name, ct, manifest: false).ConfigureAwait(false);
        Hit(JournaledDeepSecureStorageFailpoint.BeforeCleanupManifest);
        using var actual = ReadCurrent(ct);
        if (!Fixed(actual.Hash, hash)) throw new CryptographicException("Cleanup predecessor changed.");
        using var candidate = actual.Inventory.Successor(actual.Hash); candidate.Cleanup.Clear();
        await PublishAsync(actual, candidate, new Dictionary<string, byte[]>(), null, RootKind.Current, ct).ConfigureAwait(false);
        Hit(JournaledDeepSecureStorageFailpoint.AfterCleanupManifest);
    }

    private async Task RecoverPendingAsync(CancellationToken ct)
    {
        InventoryFact current;
        using (var read = ReadCurrent(ct)) current = Facts(read);
        var authority = new ReplacementAuthority(current.Hash, RootKind.Current, null);
        var bytes = ReadBoundedFile(pendingPath, MaximumProtectedManifestBytes, manifest: true, allowEmpty: true);
        if (bytes.Length == 0)
        { await RetirePathAsync(pendingPath, authority, null, ct, manifest: true).ConfigureAwait(false); return; }
        var pendingHash = SHA256.HashData(bytes); byte[]? plaintext = null; string[] staged;
        try
        {
            Interlocked.Increment(ref unprotectCalls); plaintext = protector.Unprotect(bytes);
            if (ReferenceEquals(plaintext, bytes)) throw new CryptographicException("Protector did not return owned plaintext.");
            Interlocked.Add(ref manifestPlaintext, plaintext.Length);
            using var pending = DecodeManifest(plaintext);
            staged = ValidatePendingSuccessor(current, pending);
        }
        catch (Exception error) when (error is ArgumentException or OverflowException or InvalidDataException)
        { throw new CryptographicException("Pending inventory is not an authenticated successor.", error); }
        finally { CryptographicOperations.ZeroMemory(bytes); if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext); }
        Revalidate(authority, ct); RequireExactFile(pendingPath, pendingHash, MaximumProtectedManifestBytes, manifest: true);
        foreach (var name in staged)
        {
            // The descriptor stays until EVERY new name and temporary name is
            // durably retired. It cannot be used as an alternative current root.
            await RetirePathAsync(ObjectPath(name), authority, name, ct, manifest: false, pendingHash: pendingHash).ConfigureAwait(false);
            if (File.Exists(ObjectPath(name, ".pending")))
                await RetirePathAsync(ObjectPath(name, ".pending"), authority, name, ct, manifest: false, pendingHash: pendingHash).ConfigureAwait(false);
        }
        await RetirePathAsync(pendingPath, authority, null, ct, manifest: true).ConfigureAwait(false);
    }

    private static string[] ValidatePendingSuccessor(InventoryFact current, Inventory pending)
    {
        if (!Fixed(current.StoreId, pending.StoreId) || current.Revision == ulong.MaxValue || pending.Revision != current.Revision + 1 || !Fixed(pending.Predecessor, current.Hash))
            throw new CryptographicException("Pending inventory does not join the exact current predecessor.");
        var newIds = new HashSet<string>(StringComparer.Ordinal);
        var retired = new HashSet<string>(current.Cleanup, StringComparer.Ordinal);
        var currentIds = current.Values.Values.Select(v => v.Name).ToHashSet(StringComparer.Ordinal);
        foreach (var old in current.Values.Values)
            if (!pending.Values.TryGetValue(old.Slot, out var item) || item.Name != old.Name) retired.Add(old.Name);
        foreach (var item in pending.Values.Values)
        {
            if (current.Values.TryGetValue(item.Slot, out var old) && item.Name == old.Name)
            {
                if (item.Birth != old.Birth || item.Length != old.Length || !Fixed(item.Hash, old.Hash) || !Fixed(SHA256.HashData(item.Key), old.KeyHash))
                    throw new CryptographicException("Pending inventory substituted an existing object.");
            }
            else
            {
                if (currentIds.Contains(item.Name) || current.Cleanup.Contains(item.Name) || item.Birth != pending.Revision)
                    throw new CryptographicException("Pending inventory reuses a current or retired object ID.");
                newIds.Add(item.Name);
            }
        }
        var metadataCleanup = newIds.Count == 0 && pending.Values.Count == current.Values.Count &&
            pending.Values.All(p => current.Values.TryGetValue(p.Key, out var prior) && prior.Name == p.Value.Name) && pending.Cleanup.Count == 0;
        if (!metadataCleanup && !retired.SetEquals(pending.Cleanup)) throw new CryptographicException("Pending retirement obligations are incomplete.");
        return newIds.Order(StringComparer.Ordinal).ToArray();
    }

    private async Task RetirePathAsync(string path, ReplacementAuthority authority, string? objectName, CancellationToken ct,
        bool manifest, byte[]? pendingHash = null)
    {
        var tombstone = path + ".tombstone";
        Revalidate(authority, ct, objectName);
        if (pendingHash is not null) RequireExactFile(pendingPath, pendingHash, MaximumProtectedManifestBytes, manifest: true);
        if (File.Exists(tombstone))
        {
            using var prior = OpenSecureFile(tombstone, write: false);
            if (prior.Length != 0) throw new CryptographicException("Retirement temporary file is not empty.");
            prior.Dispose(); File.Delete(tombstone); FlushParent(tombstone);
        }
        WriteBoundedFile(tombstone, [], manifest);
        await ReplaceDurablyAsync(tombstone, path, authority, ct, replace: true, retiredName: objectName, pendingHash: pendingHash, retirement: true).ConfigureAwait(false);
        Interlocked.Increment(ref cleanupTombstones); Hit(JournaledDeepSecureStorageFailpoint.AfterRetirementTombstone);
        Revalidate(authority, ct, objectName);
        var retired = ReadBoundedFile(path, 0, manifest, exactLength: 0, allowEmpty: true);
        if (retired.Length != 0) throw new CryptographicException("Retired name is no longer an empty tombstone.");
        File.Delete(path); FlushParent(path); Hit(JournaledDeepSecureStorageFailpoint.AfterRetirementUnlink);
    }

    private async Task ReplaceDurablyAsync(string temporary, string destination, ReplacementAuthority authority, CancellationToken ct,
        bool replace, string? retiredName = null, byte[]? pendingHash = null, ObjectFact[]? newObjects = null,
        ObjectFact? stagedObject = null, bool retirement = false)
    {
        var timer = Stopwatch.StartNew(); var milliseconds = 25;
        while (true)
        {
            ct.ThrowIfCancellationRequested(); Revalidate(authority, ct, retiredName);
            if (pendingHash is not null) RequireExactFile(pendingPath, pendingHash, MaximumProtectedManifestBytes, manifest: true);
            if (newObjects is not null) foreach (var item in newObjects)
                RequireExactFile(ObjectPath(item.Name), item.Hash, item.FileLength, manifest: false, exactLength: item.FileLength);
            if (stagedObject is not null)
                RequireExactFile(temporary, stagedObject.Hash, stagedObject.FileLength, manifest: false, exactLength: stagedObject.FileLength);
            if (retirement)
            {
                var empty = ReadBoundedFile(temporary, 0, manifest: false, exactLength: 0, allowEmpty: true);
                if (empty.Length != 0) throw new CryptographicException("Retirement source is not an exact empty tombstone.");
            }
            RequireNoRedirectedAncestors(Path.GetDirectoryName(destination)!);
            if (File.Exists(destination)) { using var existing = OpenSecureFile(destination, write: false); }
            if (!OperatingSystem.IsWindows())
            {
                File.Move(temporary, destination, overwrite: replace); FlushParent(destination); return;
            }
            if (MoveFileEx(temporary, destination, (replace ? 1U : 0U) | 8U)) return;
            var error = Marshal.GetLastPInvokeError(); var remaining = TimeSpan.FromSeconds(2) - timer.Elapsed;
            if (error is not (5 or 32 or 33) || remaining <= TimeSpan.Zero) throw new Win32Exception(error);
            // No admitted key is live here. Retry reopens and Unprotects CURRENT.
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(milliseconds, remaining.TotalMilliseconds)), ct).ConfigureAwait(false);
            milliseconds = Math.Min(milliseconds * 2, 100);
        }
    }

    private void RequireExactFile(string path, byte[] hash, int maximum, bool manifest, int? exactLength = null)
    {
        var bytes = ReadBoundedFile(path, maximum, manifest, exactLength);
        try { if (!Fixed(SHA256.HashData(bytes), hash)) throw new CryptographicException("Authenticated file changed before effect."); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private byte[] ReadBoundedFile(string path, int maximum, bool manifest, int? exactLength = null, bool allowEmpty = false)
    {
        try
        {
            using var stream = OpenSecureFile(path, write: false);
            if (manifest) Interlocked.Increment(ref manifestReads); else Interlocked.Increment(ref objectReads);
            var length = stream.Length;
            if (length < (allowEmpty ? 0 : 1) || length > maximum || (exactLength.HasValue && length != exactLength.Value))
                throw new CryptographicException("Authenticated file size is outside its exact bound.");
            var bytes = new byte[checked((int)length)]; var offset = 0;
            try
            {
                while (offset < bytes.Length)
                {
                    var read = stream.Read(bytes, offset, bytes.Length - offset);
                    if (manifest) Interlocked.Add(ref manifestProtectedRead, read); else Interlocked.Add(ref objectCiphertextRead, read);
                    if (read == 0) throw new CryptographicException("Authenticated file is truncated."); offset += read;
                }
                var extra = stream.ReadByte();
                if (extra != -1)
                {
                    if (manifest) Interlocked.Increment(ref manifestProtectedRead); else Interlocked.Increment(ref objectCiphertextRead);
                }
                if (extra != -1 || stream.Length != length) throw new CryptographicException("Authenticated file EOF changed.");
                RequireOpenedPath(stream.SafeFileHandle, path);
                RequireNoRedirectedAncestors(Path.GetDirectoryName(path)!); return bytes;
            }
            catch { CryptographicOperations.ZeroMemory(bytes); throw; }
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
        { throw new CryptographicException("Required authenticated storage file is absent.", error); }
    }

    private void WriteBoundedFile(string path, ReadOnlySpan<byte> bytes, bool manifest)
    {
        using var stream = OpenSecureFile(path, write: true);
        if (manifest) Interlocked.Increment(ref manifestWrites); else Interlocked.Increment(ref objectWrites);
        // Count only writes acknowledged by the managed I/O API.
        for (var offset = 0; offset < bytes.Length;)
        {
            var length = Math.Min(64 * 1024, bytes.Length - offset); stream.Write(bytes.Slice(offset, length)); offset += length;
            if (manifest) Interlocked.Add(ref manifestProtectedWritten, length); else Interlocked.Add(ref objectCiphertextWritten, length);
        }
        stream.Flush(flushToDisk: true);
        RequireOpenedPath(stream.SafeFileHandle, path);
    }

    private void RequireObjectDirectory()
    {
        if (!Directory.Exists(objectDirectory)) throw new CryptographicException("Adopted value-object directory is absent.");
        RequireNoRedirectedAncestors(objectDirectory);
    }

    private void CreateObjectDirectory()
    {
        RequireNoRedirectedAncestors(Path.GetDirectoryName(statePath)!);
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(objectDirectory);
        else Directory.CreateDirectory(objectDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        RequireObjectDirectory();
    }

    private async Task<FileStream> AcquireProcessLeaseAsync(CancellationToken ct)
    {
        if (!Directory.Exists(Path.GetDirectoryName(statePath))) throw new CryptographicException("Existing storage parent is absent.");
        var timer = Stopwatch.StartNew();
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try { return OpenSecureFile(leasePath, write: true, lease: true); }
            catch (IOException error)
            {
                if (timer.Elapsed >= TimeSpan.FromSeconds(30)) throw new IOException("Timed out acquiring the secure-storage process lease.", error);
                await Task.Delay(25, ct).ConfigureAwait(false);
            }
        }
    }

    private static void RequireNoRedirectedAncestors(string directory)
    {
        for (DirectoryInfo? node = new(directory); node is not null; node = node.Parent)
            if (node.Exists && (node.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException("Secure-storage directory redirection is forbidden.");
    }

    private static FileStream OpenSecureFile(string path, bool write, bool lease = false)
    {
        RequireNoRedirectedAncestors(Path.GetDirectoryName(path)!);
        SafeFileHandle handle;
        if (OperatingSystem.IsWindows())
        {
            handle = CreateFile(path, write ? 0xc0000000U : 0x80000000U, write ? 0U : 1U, IntPtr.Zero,
                write ? (lease ? 4U : 1U) : 3U, 0x00200000U | (write ? 0x80000000U : 0x08000000U), IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastPInvokeError(); handle.Dispose();
                if (error is 2 or 3) throw new FileNotFoundException("Secure-storage file is absent.", path);
                throw new IOException("Secure-storage file open failed.", new Win32Exception(error));
            }
            try
            {
                if (!GetFileInformationByHandle(handle, out var information) || information.NumberOfLinks != 1 ||
                    (information.FileAttributes & ((uint)FileAttributes.ReparsePoint | (uint)FileAttributes.Directory)) != 0)
                    throw new CryptographicException("Secure-storage file is redirected or linked.");
            }
            catch { handle.Dispose(); throw; }
        }
        else
        {
            var mac = OperatingSystem.IsMacOS() || OperatingSystem.IsMacCatalyst() || OperatingSystem.IsIOS();
            var noFollow = mac ? 0x100 : 0x20000; var closeExec = mac ? 0x1000000 : 0x80000;
            var create = mac ? 0x200 : 0x40; var exclusive = mac ? 0x800 : 0x80;
            var sync = mac ? 0x80 : 0x101000;
            var descriptor = Open(path, noFollow | closeExec | (write ? 2 | create | sync | (lease ? 0 : exclusive) : 0), 384);
            if (descriptor < 0)
            {
                var error = Marshal.GetLastPInvokeError();
                if (error is 2 or 20) throw new FileNotFoundException("Secure-storage file is absent.", path);
                if (error == 40) throw new CryptographicException("Secure-storage symbolic link is forbidden.");
                throw new IOException("Secure-storage file open failed.", new Win32Exception(error));
            }
            handle = new SafeFileHandle(descriptor, ownsHandle: true);
            var status = Marshal.AllocHGlobal(256);
            try
            {
                if (FStat(descriptor, status) != 0) throw new IOException("Secure-storage file identity is unavailable.");
                int mode; ulong links;
                if (mac) { mode = unchecked((ushort)Marshal.ReadInt16(status, 4)); links = unchecked((ushort)Marshal.ReadInt16(status, 6)); }
                else if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
                { mode = Marshal.ReadInt32(status, 16); links = unchecked((uint)Marshal.ReadInt32(status, 20)); }
                else if (RuntimeInformation.ProcessArchitecture == Architecture.X64)
                { mode = Marshal.ReadInt32(status, 24); links = unchecked((ulong)Marshal.ReadInt64(status, 16)); }
                else throw new PlatformNotSupportedException("Secure-storage file identity requires a supported 64-bit Unix ABI.");
                if ((mode & 0xf000) != 0x8000 || links != 1) throw new CryptographicException("Secure-storage file is not an unlinked regular file.");
                if (lease && Flock(descriptor, 2 | 4) != 0) throw new IOException("Secure-storage process lease is held.");
            }
            catch { handle.Dispose(); throw; }
            finally { Marshal.FreeHGlobal(status); }
        }
        try { RequireOpenedPath(handle, path); return new FileStream(handle, write ? FileAccess.ReadWrite : FileAccess.Read, 16 * 1024, isAsync: false); }
        catch { handle.Dispose(); throw; }
    }

    private static void RequireOpenedPath(SafeFileHandle handle, string expected)
    {
        string actual;
        if (OperatingSystem.IsWindows())
        {
            var requested = Path.GetFullPath(expected);
            var parent = Path.GetDirectoryName(requested) ?? throw new CryptographicException("Storage file has no owned parent.");
            RequireNoRedirectedAncestors(parent);
            // Packaged Windows hosts can virtualize LocalApplicationData without
            // a reparse point. Bind the actual directory handle selected by the
            // requested parent, then ONLY its exact requested leaf. Neither a
            // package-prefix whitelist nor suffix matching establishes ownership.
            using var parentHandle = CreateFile(parent, 0x80, 3, IntPtr.Zero, 3, 0x00200000 | 0x02000000, IntPtr.Zero);
            if (parentHandle.IsInvalid) throw new IOException("Owned storage parent cannot be opened.", new Win32Exception(Marshal.GetLastPInvokeError()));
            if (!GetFileInformationByHandle(parentHandle, out var parentIdentity) ||
                !GetFileInformationByHandle(handle, out var fileIdentity) ||
                (parentIdentity.FileAttributes & (uint)FileAttributes.Directory) == 0 ||
                (parentIdentity.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0 ||
                (fileIdentity.FileAttributes & ((uint)FileAttributes.Directory | (uint)FileAttributes.ReparsePoint)) != 0 ||
                fileIdentity.NumberOfLinks != 1 || parentIdentity.VolumeSerialNumber != fileIdentity.VolumeSerialNumber)
                throw new CryptographicException("Opened storage file or parent identity is redirected or linked.");
            var physicalParent = ReadWindowsHandlePath(parentHandle);
            RequireNoRedirectedAncestors(physicalParent);
            actual = ReadWindowsHandlePath(handle);
            var bound = Path.Combine(physicalParent, Path.GetFileName(requested));
            if (!string.Equals(actual, bound, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("Opened storage file escaped its exact owned path.");
            return;
        }
        var bytes = new byte[32768];
        if (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid())
        {
            var count = ReadLink("/proc/self/fd/" + handle.DangerousGetHandle().ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture), bytes, (nuint)bytes.Length);
            if (count <= 0 || count >= bytes.Length) throw new IOException("Opened storage path cannot be resolved.");
            actual = StrictUtf8.GetString(bytes.AsSpan(0, checked((int)count)));
        }
        else if (OperatingSystem.IsMacOS() || OperatingSystem.IsMacCatalyst() || OperatingSystem.IsIOS())
        {
            if (GetHandlePath(checked((int)handle.DangerousGetHandle()), 50, bytes) != 0) throw new IOException("Opened storage path cannot be resolved.");
            var length = Array.IndexOf(bytes, (byte)0);
            if (length < 1) throw new IOException("Opened storage path is not bounded.");
            actual = StrictUtf8.GetString(bytes.AsSpan(0, length));
        }
        else throw new PlatformNotSupportedException("Opened storage identity is unavailable on this platform.");
        if (!string.Equals(actual, Path.GetFullPath(expected), StringComparison.Ordinal))
            throw new CryptographicException("Opened storage file escaped its exact owned path.");
    }

    [SupportedOSPlatform("windows")]
    private static string ReadWindowsHandlePath(SafeFileHandle handle)
    {
        const int maximum = 32768;
        var capacity = 512;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buffer = new System.Text.StringBuilder(capacity);
            var length = GetFinalPathNameByHandle(handle, buffer, checked((uint)capacity), 0);
            if (length == 0 || length > maximum) throw new IOException("Opened storage path cannot be resolved within its bound.");
            if (length < capacity)
            {
                if (buffer.Length != length) throw new IOException("Opened storage path was truncated.");
                var path = buffer.ToString();
                if (path.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase)) return "\\\\" + path[8..];
                return path.StartsWith("\\\\?\\", StringComparison.Ordinal) ? path[4..] : path;
            }
            // Insufficient-buffer results report required capacity including
            // the terminator. Never use their possibly truncated path bytes.
            if (capacity == maximum) throw new IOException("Opened storage path exceeds its buffer bound.");
            capacity = checked((int)Math.Max(length, (uint)capacity + 1));
        }
        throw new IOException("Opened storage path did not stabilize within the bounded retries.");
    }

    private static void FlushParent(string path)
    {
        if (OperatingSystem.IsWindows()) return; // Named retirement uses write-through MoveFileEx before unlink.
        var directory = Path.GetDirectoryName(path)!; RequireNoRedirectedAncestors(directory);
        var descriptor = Open(directory, 0, 0);
        if (descriptor < 0) throw new IOException("Storage directory cannot be opened for durability.");
        try { if (Fsync(descriptor) != 0) throw new IOException("Storage directory durability is unavailable.", new Win32Exception(Marshal.GetLastPInvokeError())); }
        finally { _ = Close(descriptor); }
    }

    private static void Hit(JournaledDeepSecureStorageFailpoint point)
    {
#if DEEP_TEST_INTERNALS
        JournaledDeepSecureStorageTestHooks.Hit(point);
#endif
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal uint FileAttributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
        internal uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }
    [SupportedOSPlatform("windows"), DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [SupportedOSPlatform("windows"), DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
    [SupportedOSPlatform("windows"), DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, System.Text.StringBuilder path, uint length, uint flags);
    [SupportedOSPlatform("windows"), DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(string source, string destination, uint flags);
    [DllImport("libc", EntryPoint = "open", SetLastError = true)] private static extern int Open(string path, int flags, int mode);
    [DllImport("libc", EntryPoint = "fstat", SetLastError = true)] private static extern int FStat(int descriptor, IntPtr status);
    [DllImport("libc", EntryPoint = "flock", SetLastError = true)] private static extern int Flock(int descriptor, int operation);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)] private static extern int Fsync(int descriptor);
    [DllImport("libc", EntryPoint = "close")] private static extern int Close(int descriptor);
    [DllImport("libc", EntryPoint = "readlink", SetLastError = true)] private static extern nint ReadLink(string path, byte[] buffer, nuint length);
    [DllImport("libc", EntryPoint = "fcntl", SetLastError = true)] private static extern int GetHandlePath(int descriptor, int command, byte[] buffer);
}

internal enum JournaledDeepSecureStorageFailpoint
{
    AfterPendingManifest, AfterObjectStaged, BeforeManifestReplace, AfterManifestReplace,
    AfterRetirementTombstone, AfterRetirementUnlink, BeforeCleanupManifest, AfterCleanupManifest
}
#if DEEP_TEST_INTERNALS
internal static class JournaledDeepSecureStorageTestHooks
{
    private static readonly AsyncLocal<Action<JournaledDeepSecureStorageFailpoint>?> Current = new();
    internal static void Hit(JournaledDeepSecureStorageFailpoint point) => Current.Value?.Invoke(point);
    internal static IDisposable Push(Action<JournaledDeepSecureStorageFailpoint> callback)
    { var before = Current.Value; Current.Value = callback; return new Restore(before); }
    private sealed class Restore(Action<JournaledDeepSecureStorageFailpoint>? before) : IDisposable
    { public void Dispose() => Current.Value = before; }
}
#endif
