using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Services.AttachmentV1;

// This owned preparation must be adopted by account-scoped durable custody
// before upload. It is not a blob route, dispatch receipt or active runtime.
internal sealed class OwnedAttachmentPreparation : IDisposable
{
    private readonly OwnedDeepSecret manifest;
    private readonly byte[][] ciphertext;
    private readonly byte[] plaintextHash;
    private int disposed;
    internal OwnedAttachmentPreparation(ReadOnlySpan<byte> exactManifest, byte[][] ownedCiphertext, ReadOnlySpan<byte> plaintextHash)
    { manifest = new(exactManifest); ciphertext = ownedCiphertext; this.plaintextHash = plaintextHash.ToArray(); }
    internal ReadOnlySpan<byte> PlaintextHash { get { RequireAlive(); return plaintextHash; } }
    internal int ChunkCount { get { RequireAlive(); return ciphertext.Length; } }
    internal OwnedDeepSecret OwnManifest() { RequireAlive(); return manifest.Use(bytes => new OwnedDeepSecret(bytes)); }
    internal byte[] CopyCiphertext(uint index)
    {
        RequireAlive();
        if (index >= ciphertext.Length) throw new ArgumentOutOfRangeException(nameof(index));
        return ciphertext[index].ToArray();
    }
    private void RequireAlive() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        manifest.Dispose(); foreach (var bytes in ciphertext) CryptographicOperations.ZeroMemory(bytes);
        CryptographicOperations.ZeroMemory(plaintextHash);
        GC.SuppressFinalize(this);
    }
    ~OwnedAttachmentPreparation() => Dispose();
}

internal static class AttachmentObjectPreparation
{
    internal static async Task<OwnedAttachmentPreparation> PrepareAsync(Stream plaintext,
        long plaintextLength, ReadOnlyMemory<byte> networkId, string filename, string mediaType,
        ulong expiresAtUnixSeconds, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        if (!plaintext.CanRead) throw new ArgumentException("Attachment input must be readable.", nameof(plaintext));
        if (plaintextLength is < 1 or > 26_214_400) throw new ArgumentOutOfRangeException(nameof(plaintextLength));
        if (networkId.Length != 16) throw new ArgumentException("Attachment network must be exactly 16 bytes.", nameof(networkId));
        ct.ThrowIfCancellationRequested();
        var network = networkId.ToArray();
        var count = checked((int)((plaintextLength + 262143) / 262144));
        var chunks = new List<byte[]>(count);
        var entries = new List<Dam1ChunkEntry>(count);
        var id = RandomNumberGenerator.GetBytes(32); var key = RandomNumberGenerator.GetBytes(32);
        var capability = RandomNumberGenerator.GetBytes(32); var buffer = new byte[262144];
        byte[] exact = [];
        using var plaintextHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            // Validate all frozen metadata before touching the input stream.
            var bounds = Enumerable.Range(0, count).Select(i => new Dam1ChunkEntry((uint)i,
                checked((uint)(i == count - 1 ? plaintextLength - (long)i * 262144 : 262144) + 16), new byte[32])).ToArray();
            using var metadata = ApplicationCoreCodec.AuthorDam1(network, id, capability, key, (ulong)plaintextLength,
                bounds, expiresAtUnixSeconds, filename, mediaType);
            for (uint index = 0; index < count; index++)
            {
                ct.ThrowIfCancellationRequested();
                var length = checked((int)Math.Min(262144L, plaintextLength - (long)index * 262144));
                await plaintext.ReadExactlyAsync(buffer.AsMemory(0, length), ct).ConfigureAwait(false);
                plaintextHash.AppendData(buffer.AsSpan(0, length));
                var chunk = AttachmentChunkCipher.Encrypt(network, id, key, index, (ulong)plaintextLength, buffer.AsSpan(0, length));
                chunks.Add(chunk); entries.Add(new(index, checked((uint)chunk.Length), SHA256.HashData(chunk)));
                CryptographicOperations.ZeroMemory(buffer.AsSpan(0, length));
            }
            if (await plaintext.ReadAsync(buffer.AsMemory(0, 1), ct).ConfigureAwait(false) != 0)
                throw new InvalidDataException("Attachment input exceeds its declared exact length.");
            using var authored = ApplicationCoreCodec.AuthorDam1(network, id, capability, key, (ulong)plaintextLength,
                entries, expiresAtUnixSeconds, filename, mediaType);
            var canonical = authored.CanonicalBytes;
            // CanonicalBytes is already a defensive copy. Adopt that owned
            // array rather than leave another key-bearing copy for the GC.
            if (!System.Runtime.InteropServices.MemoryMarshal.TryGetArray(canonical, out ArraySegment<byte> owned) ||
                owned.Array is null || owned.Offset != 0 || owned.Count != owned.Array.Length)
                throw new InvalidOperationException("The manifest codec returned non-owned canonical storage.");
            exact = owned.Array;
            ct.ThrowIfCancellationRequested();
            var digest = plaintextHash.GetHashAndReset();
            try
            {
                var result = new OwnedAttachmentPreparation(exact, chunks.ToArray(), digest); chunks.Clear(); return result;
            }
            finally { CryptographicOperations.ZeroMemory(digest); }
        }
        finally
        {
            foreach (var bytes in new[] { network, id, key, capability, buffer, exact }) CryptographicOperations.ZeroMemory(bytes);
            foreach (var chunk in chunks) CryptographicOperations.ZeroMemory(chunk);
        }
    }
}
