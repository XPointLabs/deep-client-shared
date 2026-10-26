using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;
using Xunit.Abstractions;

namespace Deep.Client.Shared.Production.Tests;

public sealed class SqlCipherNativeOverflowIntegrityTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData("fresh", false)]
    [InlineData("fresh", true)]
    [InlineData("reused", false)]
    [InlineData("reused", true)]
    [InlineData("cached", false)]
    [InlineData("cached", true)]
    [InlineData("callback", false)]
    [InlineData("callback", true)]
    public async Task ActualNativeCipherScanAuthenticatesUnselectedOverflowPagesOnEveryHandle(
        string mode, bool corrupt)
    {
        using var fixture = new OverflowFixture();
        using var connection = fixture.Open();
        Assert.False(CipherScanRejects(connection));
        fixture.RequireMetadata(connection);
        if (mode == "cached") fixture.RequireArchive(connection);

        if (mode == "callback")
        {
            // A real external callback changes the actual encrypted file after
            // clean admission. The next scan must use this SAME open handle.
            await InvokeCallbackAsync(() => { if (corrupt) fixture.CorruptOverflowPage(); });
        }
        else if (corrupt) fixture.CorruptOverflowPage();

        var before = fixture.CiphertextHash();
        fixture.RequireMetadata(connection); // The unrelated small row still reads.
        bool rejected;
        if (mode == "fresh")
        {
            using var fresh = fixture.Open();
            fixture.RequireMetadata(fresh);
            rejected = CipherScanRejects(fresh);
        }
        else
        {
            // Do not reopen, clear the page cache or switch to a different
            // connection to make the reused/cached/callback cases pass.
            rejected = CipherScanRejects(connection);
        }
        Assert.Equal(corrupt, rejected);
        Assert.Equal(before, fixture.CiphertextHash());

        // Independent witness: the classified overflow page really belongs to
        // this payload. A fresh read avoids mistaking a cached old BLOB for the
        // actual corrupted bytes; it never substitutes for the scan above.
        using var witness = fixture.Open();
        if (corrupt)
        {
            var error = Assert.Throws<SqliteException>(() => fixture.RequireArchive(witness));
            Assert.Contains(error.SqliteErrorCode, new[] { 11, 26 });
        }
        else fixture.RequireArchive(witness);
        Assert.Equal(before, fixture.CiphertextHash());
        output.WriteLine(JsonSerializer.Serialize(new
        {
            schema = "deep.native-overflow-proof.v1", mode, corrupt,
            fixture.PageSize, fixture.ReservedBytes, fixture.OverflowPages,
            SameHandle = mode != "fresh", PayloadPrimed = mode == "cached",
            CallbackInvoked = mode == "callback", MetadataReadable = true,
            FullScanRejected = rejected, FreshArchiveWitnessRejected = corrupt, FileUnchanged = true
        }));
    }

    private static async Task InvokeCallbackAsync(Action callback)
    {
        await Task.Yield();
        callback();
    }

    private static bool CipherScanRejects(SqliteConnection connection)
    {
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA cipher_integrity_check;";
            using var rows = command.ExecuteReader();
            var reports = 0;
            while (rows.Read())
            {
                Assert.InRange(++reports, 1, 4096);
                Assert.False(rows.IsDBNull(0));
            }
            return reports != 0;
        }
        catch (SqliteException error) when (error.SqliteErrorCode is 11 or 26)
        {
            return true;
        }
    }

    private sealed class OverflowFixture : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "deep-native-overflow-" + Guid.NewGuid().ToString("N"));
        private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] metadata = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] payload = RandomNumberGenerator.GetBytes(256 * 1024);
        private readonly string path;
        private readonly long overflowOffset, length;
        internal int PageSize { get; }
        internal int ReservedBytes { get; }
        internal int OverflowPages { get; }

        internal OverflowFixture()
        {
            Directory.CreateDirectory(directory);
            path = Path.Combine(directory, "native.dms2");
            try
            {
                using var connection = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(path, key, create: true);
                using (var create = connection.CreateCommand())
                {
                    create.CommandText = "CREATE TABLE native_fixture_metadata (id INTEGER PRIMARY KEY, exact BLOB NOT NULL); CREATE TABLE native_fixture_archive (id INTEGER PRIMARY KEY, content BLOB NOT NULL);";
                    create.ExecuteNonQuery();
                }
                using (var insert = connection.CreateCommand())
                {
                    insert.CommandText = "INSERT INTO native_fixture_metadata VALUES(1,$metadata); INSERT INTO native_fixture_archive VALUES(1,$payload);";
                    insert.Parameters.AddWithValue("$metadata", metadata);
                    insert.Parameters.AddWithValue("$payload", payload);
                    insert.ExecuteNonQuery();
                }
                int pageSize;
                using (var size = connection.CreateCommand())
                {
                    size.CommandText = "PRAGMA page_size;";
                    pageSize = Convert.ToInt32(size.ExecuteScalar());
                }
                Assert.InRange(pageSize, 512, 65536);
                length = new FileInfo(path).Length;
                Assert.Equal(0, length % pageSize);
                var proof = ClassifyActualOverflowChain(connection, pageSize, length, payload);
                PageSize = pageSize; ReservedBytes = proof.Reserved; OverflowPages = proof.Pages;
                overflowOffset = proof.Offset;
                Assert.InRange(overflowOffset, pageSize, length - 1);
                Assert.False(CipherScanRejects(connection));
                RequireMetadata(connection);
            }
            catch { Dispose(); throw; }
        }

        // Test-only parsing of this SAME provider's actual serialized pager
        // image. Nothing is exported to disk. Physical page numbering, reserve
        // and overflow layout follow sqlite.org/c3ref/serialize.html and
        // sqlite.org/fileformat.html (table leaf cells / overflow pages).
        private static (int Reserved, int Pages, long Offset) ClassifyActualOverflowChain(
            SqliteConnection connection, int pageSize, long fileLength, byte[] expected)
        {
            const int maximumImage = 1024 * 1024;
            var pointer = SQLitePCL.raw.sqlite3_serialize(connection.Handle, "main", out var nativeLength, 0);
            Assert.NotEqual(IntPtr.Zero, pointer);
            byte[] image = [], record = [];
            try
            {
                Assert.InRange(nativeLength, 1, maximumImage);
                Assert.Equal(fileLength, nativeLength);
                image = new byte[checked((int)nativeLength)];
                Marshal.Copy(pointer, image, 0, image.Length);
                Assert.True(image.AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
                var encodedPageSize = BinaryPrimitives.ReadUInt16BigEndian(image.AsSpan(16));
                Assert.Equal(pageSize, encodedPageSize == 1 ? 65536 : encodedPageSize);
                var reserved = image[20]; var usable = pageSize - reserved;
                Assert.InRange(usable, 480, pageSize);
                var pageCount = image.Length / pageSize;
                using (var count = connection.CreateCommand())
                {
                    count.CommandText = "PRAGMA page_count;";
                    Assert.Equal(pageCount, Convert.ToInt32(count.ExecuteScalar()));
                }
                Assert.Equal(pageCount, checked((int)BinaryPrimitives.ReadUInt32BigEndian(image.AsSpan(28))));
                int root;
                using (var table = connection.CreateCommand())
                {
                    table.CommandText = "SELECT rootpage FROM sqlite_schema WHERE type='table' AND name='native_fixture_archive';";
                    root = Convert.ToInt32(table.ExecuteScalar());
                }
                Assert.InRange(root, 2, pageCount);
                var rootOffset = checked((root - 1) * pageSize);
                Assert.Equal(0x0d, image[rootOffset]); // Actual one-row table leaf.
                Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(image.AsSpan(rootOffset + 3)));
                var cell = BinaryPrimitives.ReadUInt16BigEndian(image.AsSpan(rootOffset + 8));
                Assert.InRange(cell, 10, usable - 1);
                var cursor = rootOffset + cell;
                var payloadBytes = checked((int)Varint(image, ref cursor));
                Assert.InRange(payloadBytes, expected.Length, expected.Length + 32);
                Assert.Equal(1UL, Varint(image, ref cursor)); // The exact inserted rowid.
                var minimum = (usable - 12) * 32 / 255 - 23;
                var local = minimum + (payloadBytes - minimum) % (usable - 4);
                if (local > usable - 35) local = minimum;
                Assert.True(payloadBytes > usable - 35);
                Assert.InRange(local, minimum, usable - 35);
                Assert.True(cursor + local + 4 <= rootOffset + usable);
                record = new byte[payloadBytes];
                image.AsSpan(cursor, local).CopyTo(record);
                var next = checked((int)BinaryPrimitives.ReadUInt32BigEndian(image.AsSpan(cursor + local)));
                var first = next;
                var written = local;
                var pages = new HashSet<int>();
                while (written < record.Length)
                {
                    Assert.InRange(next, 2, pageCount);
                    Assert.NotEqual(root, next);
                    Assert.True(pages.Add(next));
                    var offset = checked((next - 1) * pageSize);
                    next = checked((int)BinaryPrimitives.ReadUInt32BigEndian(image.AsSpan(offset)));
                    var take = Math.Min(usable - 4, record.Length - written);
                    image.AsSpan(offset + 4, take).CopyTo(record.AsSpan(written));
                    written += take;
                }
                Assert.Equal(0, next);
                Assert.Equal((payloadBytes - local + usable - 5) / (usable - 4), pages.Count);
                var headerCursor = 0;
                var headerBytes = checked((int)Varint(record, ref headerCursor));
                Assert.Equal(0UL, Varint(record, ref headerCursor)); // INTEGER PRIMARY KEY aliases rowid.
                Assert.Equal(checked((ulong)expected.Length * 2 + 12), Varint(record, ref headerCursor));
                Assert.Equal(headerBytes, headerCursor);
                Assert.Equal(record.Length, headerBytes + expected.Length);
                Assert.True(record.AsSpan(headerBytes).SequenceEqual(expected));
                // First chain page necessarily carries payload here; select a
                // real content byte rather than a pointer/reserved/padding byte.
                Assert.True(record.Length - local > 64);
                return (reserved, pages.Count, checked((long)(first - 1) * pageSize + 4 + 32));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(image);
                CryptographicOperations.ZeroMemory(record);
                var zeros = new byte[4096];
                for (long offset = 0; offset < Math.Min(nativeLength, maximumImage); offset += zeros.Length)
                    Marshal.Copy(zeros, 0, IntPtr.Add(pointer, checked((int)offset)),
                        checked((int)Math.Min(zeros.Length, nativeLength - offset)));
                SQLitePCL.raw.sqlite3_free(pointer);
            }
        }

        private static ulong Varint(byte[] bytes, ref int offset)
        {
            ulong value = 0;
            for (var index = 0; index < 9; index++)
            {
                Assert.InRange(offset, 0, bytes.Length - 1);
                var next = bytes[offset++];
                if (index == 8) return checked((value << 8) | next);
                value = (value << 7) | (uint)(next & 0x7f);
                if ((next & 0x80) == 0) return value;
            }
            throw new InvalidDataException("The synthetic pager image has an invalid varint.");
        }

        internal SqliteConnection Open() =>
            SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(path, key, create: false);

        internal void RequireMetadata(SqliteConnection connection) => RequireBytes(connection,
            "SELECT exact FROM native_fixture_metadata WHERE id=1;", metadata);

        internal void RequireArchive(SqliteConnection connection) => RequireBytes(connection,
            "SELECT content FROM native_fixture_archive WHERE id=1;", payload);

        private static void RequireBytes(SqliteConnection connection, string query, byte[] expected)
        {
            using var command = connection.CreateCommand();
            command.CommandText = query;
            var actual = Assert.IsType<byte[]>(command.ExecuteScalar());
            try { Assert.True(CryptographicOperations.FixedTimeEquals(expected, actual)); }
            finally { CryptographicOperations.ZeroMemory(actual); }
        }

        internal void CorruptOverflowPage()
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite,
                FileShare.ReadWrite | FileShare.Delete);
            Assert.Equal(length, stream.Length);
            stream.Position = overflowOffset;
            var original = stream.ReadByte();
            Assert.InRange(original, 0, 255);
            stream.Position = overflowOffset;
            stream.WriteByte((byte)(original ^ 0x80));
            stream.Flush(flushToDisk: true);
            Assert.Equal(length, stream.Length);
        }

        internal byte[] CiphertextHash()
        {
            Assert.Equal(length, new FileInfo(path).Length);
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            Assert.Equal(length, stream.Length);
            return SHA256.HashData(stream);
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(metadata);
            CryptographicOperations.ZeroMemory(payload);
            foreach (var suffix in new[] { "", "-journal", "-wal", "-shm" }) File.Delete(path + suffix);
            Directory.Delete(directory); // This test created a single flat fixture.
        }
    }
}
