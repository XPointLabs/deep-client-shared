using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.AttachmentV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

// Structural codec/SQL cases. Only the separate actual account-owner test
// exercises DID2 account custody; neither suite is transport/device evidence.
public sealed class Did2AttachmentCustodyTests
{
    [Fact]
    public async Task JournalRejectsUnknownShapeForeignScopeDuplicatesAndDisposal()
    {
        using var prepared = await Prepare(); using var owner = prepared.OwnManifest();
        var exact = owner.Use(bytes => bytes.ToArray()); var op = B(32, 2);
        try
        {
            using var state = new ProtectedDid2AttachmentJournal.State();
            var entry = ProtectedDid2AttachmentJournal.Entry.Prepare(op, exact, prepared.PlaintextHash);
            state.Entries.Add(Convert.ToHexString(op), entry);
            var frame = ProtectedDid2AttachmentJournal.Encode(state, Net, Account, Instance);
            using var decoded = ProtectedDid2AttachmentJournal.Decode(frame, Net, Account, Instance); Assert.True(decoded.Pending!.Pending);
            Assert.Throws<InvalidDataException>(() => ProtectedDid2AttachmentJournal.Decode(frame, B(16, 9), Account, Instance));
            foreach (var offset in new[] { 0, 1, 3, 11, 92 + 128, 92 + 129, 92 + 132, 92 + 136 })
            {
                var changed = frame.ToArray(); changed[offset] ^= 0x80;
                Assert.ThrowsAny<Exception>(() => ProtectedDid2AttachmentJournal.Decode(changed, Net, Account, Instance));
            }
            Assert.Throws<InvalidDataException>(() => ProtectedDid2AttachmentJournal.Decode(frame[..^1], Net, Account, Instance));
            Assert.Throws<InvalidDataException>(() => ProtectedDid2AttachmentJournal.Decode([.. frame, 0], Net, Account, Instance));
            var duplicate = ProtectedDid2AttachmentJournal.Entry.Prepare(B(32, 3), exact, prepared.PlaintextHash);
            state.Entries.Add(Convert.ToHexString(duplicate.Operation), duplicate);
            Assert.Throws<InvalidDataException>(() => ProtectedDid2AttachmentJournal.Encode(state, Net, Account, Instance));
            state.Dispose(); Assert.Throws<ObjectDisposedException>(() => entry.Exact.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Theory]
    [InlineData("DELETE FROM local_attachment_objects;")]
    [InlineData("DELETE FROM local_attachment_chunks;")]
    [InlineData("UPDATE local_attachment_chunks SET ciphertext=zeroblob(length(ciphertext));")]
    public async Task RegisteredSqlLossOrChangedCiphertextRejectsWithoutRecreation(string tamper)
    {
        using var fixture = new Fixture(); using var state = new ProtectedDid2AttachmentJournal.State();
        using var prepared = await Prepare(); var op = B(32, 2);
        using (var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key)))
        {
            using var empty = await Read(store, state, []);
            await store.InsertAttachmentCandidateAsync(op, prepared, default);
            using var manifest = prepared.OwnManifest(); var exact = manifest.Use(bytes => bytes.ToArray());
            try { state.Entries.Add(Convert.ToHexString(op), ProtectedDid2AttachmentJournal.Entry.Prepare(op, exact, prepared.PlaintextHash)); }
            finally { CryptographicOperations.ZeroMemory(exact); }
            using var first = await Read(store, state, op); Assert.NotNull(first);
            Assert.Equal(prepared.CopyCiphertext(0), first!.CopyCiphertext(0));
            var old = state.Entries[Convert.ToHexString(op)]; state.Entries[Convert.ToHexString(op)] = old.Stabilize(); old.Dispose();
        }
        fixture.Execute(tamper);
        using var reopened = SqliteDeepMailboxStore.OpenExisting(new(fixture.Path, fixture.Key));
        await Assert.ThrowsAsync<CryptographicException>(() => Read(reopened, state, op));
        Assert.Equal(tamper.Contains("DELETE FROM local_attachment_objects", StringComparison.Ordinal) ? 0 : 1,
            fixture.Scalar("SELECT count(*) FROM local_attachment_objects;"));
    }

    [Fact]
    public async Task UnregisteredCandidateIsInertAndDiscardedBeforeAdoption()
    {
        using var fixture = new Fixture(); using var state = new ProtectedDid2AttachmentJournal.State();
        using var prepared = await Prepare(); using var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key));
        using var empty = await Read(store, state, []);
        await store.InsertAttachmentCandidateAsync(B(32, 2), prepared, default);
        using var ignored = await Read(store, state, B(32, 2)); Assert.Null(ignored);
        Assert.Equal(0L, fixture.Scalar("SELECT count(*) FROM local_attachment_objects;"));
        Assert.Equal(0L, fixture.Scalar("SELECT count(*) FROM local_attachment_chunks;"));
    }
    private static readonly byte[] Net = B(16, 1), Account = B(32, 4), Instance = B(32, 5);
    private static byte[] B(int size, byte value) => Enumerable.Repeat(value, size).ToArray();
    private static Task<OwnedAttachmentPreparation> Prepare() => AttachmentObjectPreparation.PrepareAsync(
        new MemoryStream([1, 2, 3]), 3, Net, "file.bin", "application/octet-stream", 2_000_000_000, default);
    private static Task<OwnedAttachmentPreparation?> Read(SqliteDeepMailboxStore store, ProtectedDid2AttachmentJournal.State state, byte[] op) =>
        store.ReconcileOwnedAttachmentsAsync(state, Account, 1, Net, op, default);
    private sealed class Fixture : IDisposable
    {
        internal string Path { get; } = System.IO.Path.GetFullPath(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "deep-attachment-custody-" + Guid.NewGuid().ToString("N") + ".db"));
        internal byte[] Key { get; } = RandomNumberGenerator.GetBytes(32);
        private SqliteConnection Open()
        {
            var db = new SqliteConnection($"Data Source={Path};Pooling=False;Foreign Keys=True"); db.Open();
            Assert.Equal(SQLitePCL.raw.SQLITE_OK, MailboxRandomKeyTestEncoding.Apply(db, Key)); return db;
        }
        internal void Execute(string sql) { using var db = Open(); using var cmd = db.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery(); }
        internal long Scalar(string sql) { using var db = Open(); using var cmd = db.CreateCommand(); cmd.CommandText = sql; return (long)cmd.ExecuteScalar()!; }
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Key);
            foreach (var file in new[] { Path, Path + "-wal", Path + "-shm", Path + "-journal" }) File.Delete(file);
        }
    }
}
