using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Protocol.GroupV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.GroupV1;

public enum GroupStateStoreOpenFailure { UnreadableOrWrongKey = 1, UnsupportedGeneration = 2, ScopeMismatch = 3, Corrupt = 4 }

public sealed class GroupStateStoreOpenException : IOException
{
    internal GroupStateStoreOpenException(GroupStateStoreOpenFailure reason, string message, Exception? inner = null) : base(message, inner) => Reason = reason;
    public GroupStateStoreOpenFailure Reason { get; }
}

public sealed class SqliteGroupStateStoreOptions : IDisposable
{
    private readonly byte[] key;
    private readonly object gate = new();
    private bool disposed;
    public SqliteGroupStateStoreOptions(string statePath, ReadOnlySpan<byte> encryptionKey, GroupStoreScope scope, bool allowCreate = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath); ArgumentNullException.ThrowIfNull(scope);
        if (encryptionKey.Length != 32 || encryptionKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte SQLCipher key is required.", nameof(encryptionKey));
        StatePath = Path.GetFullPath(statePath); key = encryptionKey.ToArray(); Scope = scope; AllowCreate = allowCreate;
    }
    public string StatePath { get; }
    public GroupStoreScope Scope { get; }
    public bool AllowCreate { get; }
    internal void CopyKey(Span<byte> destination) { lock (gate) { ObjectDisposedException.ThrowIf(disposed, this); key.CopyTo(destination); } }
    public void Dispose() { lock (gate) { if (disposed) return; CryptographicOperations.ZeroMemory(key); disposed = true; } }
}

public sealed class SqliteGroupStateStore : IGroupStateStore, IDisposable
{
    private const int ApplicationId = 0x44475331; // DGS1
    private const int SchemaGeneration = 2;
    private const string Ddl = """
        CREATE TABLE group_store_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),account_id BLOB NOT NULL CHECK(length(account_id)=32),account_generation BLOB NOT NULL CHECK(length(account_generation)=8),store_generation INTEGER NOT NULL CHECK(store_generation=1));
        CREATE TABLE group_heads(group_id BLOB PRIMARY KEY CHECK(length(group_id)=32),network_id BLOB NOT NULL CHECK(length(network_id)=16),epoch BLOB NOT NULL CHECK(length(epoch)=8),revision BLOB NOT NULL CHECK(length(revision)=8),commit_hash BLOB NOT NULL CHECK(length(commit_hash)=32),package_hash BLOB NOT NULL CHECK(length(package_hash)=32),predecessor_hash BLOB NOT NULL CHECK(length(predecessor_hash)=32),canonical_commit BLOB NOT NULL CHECK(length(canonical_commit) BETWEEN 1 AND 93922),canonical_package BLOB NOT NULL CHECK(length(canonical_package) BETWEEN 1 AND 8388608),verified_gcp1_sha256 BLOB NOT NULL CHECK(length(verified_gcp1_sha256)=32),member_count INTEGER NOT NULL CHECK(member_count BETWEEN 1 AND 100),device_count INTEGER NOT NULL CHECK(device_count BETWEEN 1 AND 500),fork_latched INTEGER NOT NULL CHECK(fork_latched IN (0,1)));
        CREATE TABLE group_artifacts(group_id BLOB NOT NULL,magic TEXT NOT NULL CHECK(magic IN ('DGP1','GIV1','GIA1')),artifact_hash BLOB NOT NULL CHECK(length(artifact_hash)=32),canonical_bytes BLOB NOT NULL,PRIMARY KEY(group_id,magic,artifact_hash),FOREIGN KEY(group_id) REFERENCES group_heads(group_id) ON DELETE CASCADE);
        CREATE TABLE group_chunks(group_id BLOB NOT NULL,package_hash BLOB NOT NULL CHECK(length(package_hash)=32),chunk_index INTEGER NOT NULL CHECK(chunk_index>=0),chunk_count INTEGER NOT NULL CHECK(chunk_count>0),chunk_hash BLOB NOT NULL CHECK(length(chunk_hash)=32),canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes) BETWEEN 1 AND 24748),PRIMARY KEY(group_id,package_hash,chunk_index),FOREIGN KEY(group_id) REFERENCES group_heads(group_id) ON DELETE CASCADE);
        CREATE TABLE group_control_cursors(group_id BLOB NOT NULL,recipient_key BLOB NOT NULL CHECK(length(recipient_key)=32),package_hash BLOB NOT NULL CHECK(length(package_hash)=32),chunk_index INTEGER NOT NULL CHECK(chunk_index>=0),chunk_count INTEGER NOT NULL CHECK(chunk_count>0),PRIMARY KEY(group_id,recipient_key),FOREIGN KEY(group_id) REFERENCES group_heads(group_id) ON DELETE CASCADE);
        CREATE TABLE group_forks(group_id BLOB PRIMARY KEY,epoch BLOB NOT NULL CHECK(length(epoch)=8),predecessor_hash BLOB NOT NULL CHECK(length(predecessor_hash)=32),first_commit_hash BLOB NOT NULL CHECK(length(first_commit_hash)=32),first_commit BLOB NOT NULL,second_commit_hash BLOB NOT NULL CHECK(length(second_commit_hash)=32),second_commit BLOB NOT NULL,CHECK(first_commit_hash<>second_commit_hash),FOREIGN KEY(group_id) REFERENCES group_heads(group_id) ON DELETE CASCADE);
        CREATE TABLE group_operations(operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32),fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),group_id BLOB NOT NULL CHECK(length(group_id)=32),disposition INTEGER NOT NULL CHECK(disposition BETWEEN 1 AND 7),committed_revision BLOB NOT NULL CHECK(length(committed_revision)=8),FOREIGN KEY(group_id) REFERENCES group_heads(group_id) ON DELETE RESTRICT);
        CREATE INDEX group_operations_group ON group_operations(group_id,committed_revision);
        """;

    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly byte[] key = new byte[32];
    private readonly string path;
    private readonly string connectionString;
    private SqliteConnection? connection;
    private int disposed;

    static SqliteGroupStateStore() => SQLitePCL.Batteries_V2.Init();

    public SqliteGroupStateStore(SqliteGroupStateStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Scope.StoreGeneration != GroupStoreScope.CurrentStoreGeneration)
            throw Failure(GroupStateStoreOpenFailure.UnsupportedGeneration, "Unsupported GroupV1 store generation.");
        Scope = options.Scope; path = options.StatePath; options.CopyKey(key);
        var exists = File.Exists(path);
        if (!exists && !options.AllowCreate) { CryptographicOperations.ZeroMemory(key); throw Failure(GroupStateStoreOpenFailure.UnreadableOrWrongKey, "GroupV1 database does not exist."); }
        if (exists && new FileInfo(path).Length == 0) { CryptographicOperations.ZeroMemory(key); throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 database is empty."); }
        var parent = Path.GetDirectoryName(path); if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        connectionString = new SqliteConnectionStringBuilder { DataSource = path, Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite, Cache = SqliteCacheMode.Private, Pooling = false }.ToString();
        try
        {
            using (var opened = Open()) { if (exists) ValidateExisting(opened); else Create(opened); }
            ValidateEncryptedFile(); connection = Open(); ValidateAll(connection);
        }
        catch (GroupStateStoreOpenException) { FailedOpen(); throw; }
        catch (Exception ex) when (ex is SqliteException or FormatException or InvalidOperationException or ArgumentException)
        { FailedOpen(); throw Failure(GroupStateStoreOpenFailure.UnreadableOrWrongKey, "GroupV1 SQLCipher state cannot be opened.", ex); }
        catch { FailedOpen(); throw; }
    }

    public GroupStoreScope Scope { get; }

    public async ValueTask<GroupHeadSnapshot?> ReadHeadAsync(GroupId32 groupId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(groupId); await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { ThrowIfDisposed(); return ReadHead(GetConnection(), null, groupId)?.Copy(); }
        catch (GroupStateStoreOpenException) { throw; }
        catch (Exception ex) when (ex is SqliteException or FormatException or ArgumentException or InvalidOperationException)
        { throw Failure(GroupStateStoreOpenFailure.Corrupt, "Persisted GroupV1 head is invalid.", ex); }
        finally { gate.Release(); }
    }

    public async ValueTask<IReadOnlyList<GroupHeadSnapshot>> ReadHeadsAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); using var command = GetConnection().CreateCommand(); command.CommandText = "SELECT group_id FROM group_heads ORDER BY group_id;";
            using var reader = command.ExecuteReader(); var ids = new List<GroupId32>(); while (reader.Read()) ids.Add(GroupId32.FromBytes((byte[])reader[0])); reader.Close();
            return ids.Select(id => ReadHead(GetConnection(), null, id)?.Copy() ?? throw new FormatException("Group head vanished.")).ToArray();
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (Exception ex) when (ex is SqliteException or FormatException or ArgumentException or InvalidOperationException)
        { throw Failure(GroupStateStoreOpenFailure.Corrupt, "Persisted GroupV1 state is invalid.", ex); }
        finally { gate.Release(); }
    }

    public async ValueTask<GroupHeadReadLease> AcquireHeadReadLeaseAsync(
        GroupId32 groupId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(groupId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        SqliteTransaction? transaction = null;
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            transaction = GetConnection().BeginTransaction(deferred: false);
            var head = ReadHead(GetConnection(), transaction, groupId)?.Copy();
            var owned = transaction;
            transaction = null;
            return new GroupHeadReadLease(head, () =>
            {
                try { owned.Dispose(); }
                finally { gate.Release(); }
            });
        }
        catch (GroupStateStoreOpenException)
        {
            transaction?.Dispose();
            gate.Release();
            throw;
        }
        catch (Exception ex) when (ex is SqliteException or FormatException or ArgumentException
            or InvalidOperationException)
        {
            transaction?.Dispose();
            gate.Release();
            throw Failure(GroupStateStoreOpenFailure.Corrupt,
                "Persisted GroupV1 head lease is invalid.", ex);
        }
        catch
        {
            transaction?.Dispose();
            gate.Release();
            throw;
        }
    }

    public async ValueTask<GroupCommitResult> CommitVerifiedTransitionAsync(GroupTransitionCommitPlan plan, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!Scope.Equals(plan.Scope)) throw new ArgumentException("Transition belongs to another exact account scope.", nameof(plan));
        if (!plan.VerifiedTransition.BindsExactGcp1(plan.CanonicalPackage)
            || !CryptographicOperations.FixedTimeEquals(plan.VerifiedTransition.ExactVerifiedGcp1Sha256.Span,
                plan.ExactVerifiedGcp1Sha256))
            throw new ArgumentException("Transition plan contains unbound GCP1 evidence.", nameof(plan));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); cancellationToken.ThrowIfCancellationRequested(); var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            var replay = ReadOperation(db, tx, plan.OperationId);
            if (replay is not null)
            {
                var replayHead = ReadHead(db, tx, replay.GroupId) ?? throw new FormatException("Operation lost its group head."); tx.Commit();
                return CryptographicOperations.FixedTimeEquals(replay.Fingerprint, plan.Fingerprint)
                    ? new(replay.Disposition == GroupCommitDisposition.Applied ? GroupCommitDisposition.Idempotent : replay.Disposition, replayHead.Copy())
                    : new(GroupCommitDisposition.Conflict, replayHead.Copy());
            }

            var current = ReadHead(db, tx, plan.GroupId);
            if (current?.ForkLatched == true) { InsertOperation(db, tx, plan, GroupCommitDisposition.ForkLatched, current.Revision); tx.Commit(); return new(GroupCommitDisposition.ForkLatched, current.Copy()); }
            if (current is null)
            {
                if (plan.Epoch != 0 || plan.ExpectedRevision is not (null or 0) || plan.VerifiedTransition.Predecessor is not null)
                    return FinishWithoutJournal(tx, GroupCommitDisposition.NotFound, null);
                var created = Snapshot(plan, 1, false); InsertHead(db, tx, created); ReplaceArtifacts(db, tx, plan); UpsertCursors(db, tx, plan);
                InsertOperation(db, tx, plan, GroupCommitDisposition.Applied, 1); cancellationToken.ThrowIfCancellationRequested(); tx.Commit();
                return new(GroupCommitDisposition.Applied, ReadHead(db, null, plan.GroupId)!.Copy());
            }

            if (current.CommitHash.Span.SequenceEqual(plan.CommitHash) && current.PackageHash.Span.SequenceEqual(plan.PackageHash))
            { InsertOperation(db, tx, plan, GroupCommitDisposition.Idempotent, current.Revision); tx.Commit(); return new(GroupCommitDisposition.Idempotent, current.Copy()); }

            if (plan.Epoch == current.Epoch && plan.PredecessorHash.SequenceEqual(current.PredecessorHash.Span))
            {
                LatchFork(db, tx, current, plan); InsertOperation(db, tx, plan, GroupCommitDisposition.ForkLatched, current.Revision); tx.Commit();
                return new(GroupCommitDisposition.ForkLatched, ReadHead(db, null, plan.GroupId)!.Copy());
            }
            if (plan.ExpectedRevision != current.Revision) return FinishWithoutJournal(tx, GroupCommitDisposition.StaleRevision, current.Copy());
            if (current.Epoch == ulong.MaxValue || plan.Epoch != current.Epoch + 1 || plan.VerifiedTransition.Predecessor is null
                || !plan.VerifiedTransition.Predecessor.CanonicalBytes.Span.SequenceEqual(current.ExactCanonicalCommit.Span)
                || !plan.PredecessorHash.SequenceEqual(current.CommitHash.Span))
                return FinishWithoutJournal(tx, GroupCommitDisposition.InvalidTransition, current.Copy());

            var next = Snapshot(plan, checked(current.Revision + 1), false); UpdateHead(db, tx, next, current.Revision);
            ReplaceArtifacts(db, tx, plan); UpsertCursors(db, tx, plan); InsertOperation(db, tx, plan, GroupCommitDisposition.Applied, next.Revision);
            cancellationToken.ThrowIfCancellationRequested(); tx.Commit(); return new(GroupCommitDisposition.Applied, ReadHead(db, null, plan.GroupId)!.Copy());
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (Exception ex) when (ex is SqliteException or FormatException or InvalidOperationException or ArgumentException or OverflowException)
        { throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 transition transaction failed closed.", ex); }
        finally { gate.Release(); }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        gate.Wait(); try { connection?.Dispose(); connection = null; CryptographicOperations.ZeroMemory(key); } finally { gate.Release(); gate.Dispose(); }
    }

    private static GroupCommitResult FinishWithoutJournal(SqliteTransaction tx, GroupCommitDisposition disposition, GroupHeadSnapshot? head)
    { tx.Commit(); return new(disposition, head?.Copy()); }

    private static GroupHeadSnapshot Snapshot(GroupTransitionCommitPlan p, ulong revision, bool fork) => new(p.GroupId, p.NetworkId, p.Epoch, revision,
        p.CommitHash, p.PackageHash, p.PredecessorHash, p.CanonicalCommit, p.CanonicalPackage,
        p.ExactVerifiedGcp1Sha256, p.MemberCount, p.DeviceCount, fork, p.Artifacts, p.Cursors);

    private SqliteConnection Open()
    {
        var db = new SqliteConnection(connectionString); try { db.Open(); var rc = SQLitePCL.raw.sqlite3_key(db.Handle, key); if (rc != SQLitePCL.raw.SQLITE_OK) throw new SqliteException("SQLCipher rejected key.", rc); Execute(db, null, "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;"); return db; } catch { db.Dispose(); throw; }
    }
    private void Create(SqliteConnection db)
    {
        Execute(db, null, $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        using var tx = db.BeginTransaction(deferred: false); Execute(db, tx, Ddl); using var cmd = db.CreateCommand(); cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO group_store_meta VALUES(1,$account,$accountGeneration,$storeGeneration);";
        cmd.Parameters.AddWithValue("$account", Scope.AccountId.Bytes.ToArray()); cmd.Parameters.AddWithValue("$accountGeneration", U64(Scope.AccountGeneration)); cmd.Parameters.AddWithValue("$storeGeneration", Scope.StoreGeneration); cmd.ExecuteNonQuery(); tx.Commit(); ValidateCipher(db);
    }
    private void ValidateExisting(SqliteConnection db)
    {
        try
        {
            if (Scalar(db, "PRAGMA application_id;") != ApplicationId || Scalar(db, "PRAGMA user_version;") != SchemaGeneration)
                throw Failure(GroupStateStoreOpenFailure.UnsupportedGeneration, "Unsupported GroupV1 schema.");
            ValidateCipher(db); using var cmd = db.CreateCommand(); cmd.CommandText = "SELECT account_id,account_generation,store_generation FROM group_store_meta WHERE singleton=1;";
            using var reader = cmd.ExecuteReader(); if (!reader.Read()) throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 scope metadata is absent.");
            var account = (byte[])reader[0]; var generation = ReadU64((byte[])reader[1]); var storeGeneration = reader.GetInt32(2);
            if (reader.Read()) throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 scope metadata is duplicated.");
            if (!Scope.AccountId.Matches(account) || generation != Scope.AccountGeneration || storeGeneration != Scope.StoreGeneration)
                throw Failure(GroupStateStoreOpenFailure.ScopeMismatch, "GroupV1 database belongs to another account generation.");
            ValidateAll(db);
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (SqliteException ex) { throw Failure(GroupStateStoreOpenFailure.UnreadableOrWrongKey, "GroupV1 metadata is unreadable.", ex); }
        catch (Exception ex) when (ex is FormatException or ArgumentException or InvalidOperationException) { throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 state violates its sealed contract.", ex); }
    }
    private static void ValidateCipher(SqliteConnection db) { if (string.IsNullOrWhiteSpace(ScalarText(db, "PRAGMA cipher_version;"))) throw new InvalidOperationException("SQLCipher is unavailable."); if (!string.Equals(ScalarText(db, "PRAGMA integrity_check;"), "ok", StringComparison.OrdinalIgnoreCase)) throw new FormatException("GroupV1 integrity check failed."); }
    private void ValidateEncryptedFile() { using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); Span<byte> header = stackalloc byte[16]; if (stream.Read(header) == 16 && header.SequenceEqual("SQLite format 3\0"u8)) throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 database is plaintext."); }
    private void ValidateAll(SqliteConnection db)
    {
        using var cmd = db.CreateCommand(); cmd.CommandText = "SELECT group_id FROM group_heads ORDER BY group_id;"; using var reader = cmd.ExecuteReader(); var ids = new List<GroupId32>(); while (reader.Read()) ids.Add(GroupId32.FromBytes((byte[])reader[0])); reader.Close();
        var heads = ids.Select(id => ReadHead(db, null, id) ?? throw new FormatException("GroupV1 head is missing."))
            .ToDictionary(static head => Convert.ToHexString(head.GroupId.Bytes.Span), StringComparer.Ordinal);
        using var op = db.CreateCommand(); op.CommandText = "SELECT operation_id,fingerprint,group_id,disposition,committed_revision FROM group_operations;"; using var rows = op.ExecuteReader();
        while (rows.Read()) { _ = GroupOperationId32.FromBytes((byte[])rows[0]); if (((byte[])rows[1]).Length != 32) throw new FormatException("Invalid operation fingerprint."); var id = GroupId32.FromBytes((byte[])rows[2]); var disposition = (GroupCommitDisposition)rows.GetInt32(3); if (!Enum.IsDefined(disposition)) throw new FormatException("Invalid operation disposition."); var revision = ReadU64((byte[])rows[4]); if (!heads.TryGetValue(Convert.ToHexString(id.Bytes.Span), out var head)) throw new FormatException("Orphan operation."); if (revision == 0 || revision > head.Revision) throw new FormatException("Invalid operation revision."); }
    }

    private static GroupHeadSnapshot? ReadHead(SqliteConnection db, SqliteTransaction? tx, GroupId32 id)
    {
        using var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = "SELECT network_id,epoch,revision,commit_hash,package_hash,predecessor_hash,canonical_commit,canonical_package,verified_gcp1_sha256,member_count,device_count,fork_latched FROM group_heads WHERE group_id=$id;"; cmd.Parameters.AddWithValue("$id", id.ToArray());
        using var reader = cmd.ExecuteReader(); if (!reader.Read()) return null;
        var network = (byte[])reader[0]; var epoch = ReadU64((byte[])reader[1]); var revision = ReadU64((byte[])reader[2]); var commitHash = (byte[])reader[3]; var packageHash = (byte[])reader[4]; var predecessor = (byte[])reader[5]; var canonicalCommit = (byte[])reader[6]; var canonicalPackage = (byte[])reader[7]; var verifiedGcp1Sha256 = (byte[])reader[8]; var members = checked((ushort)reader.GetInt32(9)); var devices = checked((ushort)reader.GetInt32(10)); var fork = reader.GetInt32(11) == 1; if (reader.Read()) throw new FormatException("Duplicate GroupV1 head."); reader.Close();
        var commit = (GroupCommitRecord)GroupCodec.Decode("DGC1", canonicalCommit); var package = (GroupCommitPackageRecord)GroupCodec.Decode("GCP1", canonicalPackage);
        if (!commit.ArtifactHash.Span.SequenceEqual(commitHash) || !package.ArtifactHash.Span.SequenceEqual(packageHash)
            || !commit.Field(1).Span.SequenceEqual(network) || !commit.Field(2).Span.SequenceEqual(id.Span) || ReadU64(commit.Field(4).ToArray()) != epoch || !commit.Field(5).Span.SequenceEqual(predecessor)
            || !package.Field(1).Span.SequenceEqual(network) || !package.Field(2).Span.SequenceEqual(id.Span) || ReadU64(package.Field(3).ToArray()) != epoch
            || !ReadLp(package.Field(4).Span).SequenceEqual(canonicalCommit)) throw new FormatException("Persisted GroupV1 head binding is invalid.");
        var verifiedMembers = BinaryPrimitives.ReadUInt16BigEndian(commit.Field(11).Span);
        var verifiedDevices = CountDevices(commit.Field(12).Span, verifiedMembers);
        if (members != verifiedMembers || devices != verifiedDevices) throw new FormatException("Persisted GroupV1 member counts are not verified-commit facts.");
        var artifacts = ReadArtifacts(db, tx, id); ValidateArtifacts(package, commit, artifacts);
        var cursors = ReadCursors(db, tx, id); ValidateChunks(db, tx, id, packageHash, canonicalPackage, cursors);
        ValidateFork(db, tx, id, network, epoch, predecessor, commitHash, canonicalCommit, fork);
        return new(id, network, epoch, revision, commitHash, packageHash, predecessor, canonicalCommit,
            canonicalPackage, verifiedGcp1Sha256, members, devices, fork, artifacts, cursors);
    }

    private static List<GroupArtifactSnapshot> ReadArtifacts(SqliteConnection db, SqliteTransaction? tx, GroupId32 id)
    { using var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = "SELECT magic,artifact_hash,canonical_bytes FROM group_artifacts WHERE group_id=$id ORDER BY magic,artifact_hash;"; cmd.Parameters.AddWithValue("$id", id.ToArray()); using var r = cmd.ExecuteReader(); var list = new List<GroupArtifactSnapshot>(); while (r.Read()) { var magic = r.GetString(0); var hash = (byte[])r[1]; var canonical = (byte[])r[2]; var record = GroupCodec.Decode(magic, canonical); if (!record.ArtifactHash.Span.SequenceEqual(hash)) throw new FormatException("Persisted GroupV1 artifact hash mismatch."); list.Add(new(magic, hash, canonical)); } return list; }
    private static List<GroupRecipientControlCursorSnapshot> ReadCursors(SqliteConnection db, SqliteTransaction? tx, GroupId32 id)
    { using var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = "SELECT recipient_key,package_hash,chunk_index,chunk_count FROM group_control_cursors WHERE group_id=$id ORDER BY recipient_key;"; cmd.Parameters.AddWithValue("$id", id.ToArray()); using var r = cmd.ExecuteReader(); var list = new List<GroupRecipientControlCursorSnapshot>(); while (r.Read()) list.Add(new(GroupRecipientKey32.FromOpaqueBytes((byte[])r[0]), (byte[])r[1], checked((uint)r.GetInt64(2)), checked((uint)r.GetInt64(3)))); return list; }
    private static void ValidateChunks(SqliteConnection db, SqliteTransaction? tx, GroupId32 id, byte[] packageHash,
        byte[] canonicalPackage, IReadOnlyList<GroupRecipientControlCursorSnapshot> cursors)
    {
        using var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = "SELECT chunk_index,chunk_count,chunk_hash,canonical_bytes FROM group_chunks WHERE group_id=$id ORDER BY chunk_index;"; cmd.Parameters.AddWithValue("$id", id.ToArray()); using var r = cmd.ExecuteReader();
        var assembler = GroupCodec.NewChunkAssembler(); var count = 0; ReadOnlyMemory<byte> completed = default;
        while (r.Read()) { var chunk = (GroupCommitChunkRecord)GroupCodec.Decode("GCF1", (byte[])r[3]); if (!chunk.Field(1).Span.SequenceEqual(packageHash) || U32(chunk.Field(4).Span) != checked((uint)r.GetInt64(0)) || U32(chunk.Field(5).Span) != checked((uint)r.GetInt64(1)) || !chunk.Field(6).Span.SequenceEqual((byte[])r[2]) || !assembler.TryAdd(chunk, out completed)) throw new FormatException("Persisted GCF1 binding is invalid."); count++; }
        if (count != 0 && (completed.IsEmpty || !completed.Span.SequenceEqual(canonicalPackage))) throw new FormatException("Persisted GCF1 set is incomplete.");
        foreach (var cursor in cursors)
            if (count == 0 || !cursor.PackageHash.Span.SequenceEqual(packageHash) || cursor.ChunkCount != checked((uint)count) || cursor.ChunkIndex >= cursor.ChunkCount)
                throw new FormatException("Persisted GroupV1 control cursor has no exact GCF1 backing.");
    }

    private static void ValidateArtifacts(GroupCommitPackageRecord package, GroupCommitRecord commit, IReadOnlyList<GroupArtifactSnapshot> stored)
    {
        var expected = new List<(string Magic, byte[] Hash, byte[] Canonical)>(); var proposals = BinaryPrimitives.ReadUInt16BigEndian(package.Field(5).Span);
        var proposalBytes = package.Field(6).Span; var at = 0;
        for (var i = 0; i < proposals; i++) { var canonical = TakeLp(proposalBytes, ref at); var record = GroupCodec.Decode("DGP1", canonical); expected.Add(("DGP1", record.ArtifactHash.ToArray(), canonical.ToArray())); }
        if (at != proposalBytes.Length || proposals != BinaryPrimitives.ReadUInt16BigEndian(commit.Field(9).Span)
            || !expected.SelectMany(static x => x.Hash).ToArray().AsSpan().SequenceEqual(commit.Field(10).Span)) throw new FormatException("Persisted proposal set is not commit-bound.");
        var pairs = BinaryPrimitives.ReadUInt16BigEndian(package.Field(9).Span); var pairBytes = package.Field(10).Span; at = 0;
        for (var i = 0; i < pairs; i++)
        {
            Require(pairBytes, at, 38); var invitationHash = pairBytes.Slice(at + 6, 32).ToArray(); at += 38; var invitation = TakeLp(pairBytes, ref at);
            Require(pairBytes, at, 38); var acceptanceHash = pairBytes.Slice(at + 6, 32).ToArray(); at += 38; var acceptance = TakeLp(pairBytes, ref at);
            expected.Add(("GIV1", invitationHash, invitation.ToArray())); expected.Add(("GIA1", acceptanceHash, acceptance.ToArray()));
        }
        if (at != pairBytes.Length || expected.Count != stored.Count) throw new FormatException("Persisted invitation set is incomplete.");
        foreach (var item in expected)
            if (!stored.Any(value => value.Magic == item.Magic && value.Hash.Span.SequenceEqual(item.Hash) && value.ExactCanonicalBytes.Span.SequenceEqual(item.Canonical)))
                throw new FormatException("Persisted GroupV1 artifact set differs from exact GCP1.");
    }

    private static void ValidateFork(SqliteConnection db, SqliteTransaction? tx, GroupId32 id, byte[] network,
        ulong epoch, byte[] predecessor, byte[] commitHash, byte[] canonicalCommit, bool latched)
    {
        using var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = "SELECT epoch,predecessor_hash,first_commit_hash,first_commit,second_commit_hash,second_commit FROM group_forks WHERE group_id=$id;"; cmd.Parameters.AddWithValue("$id", id.ToArray()); using var r = cmd.ExecuteReader();
        if (!r.Read()) { if (latched) throw new FormatException("GroupV1 fork evidence is absent."); return; }
        if (!latched || ReadU64((byte[])r[0]) != epoch || !((byte[])r[1]).AsSpan().SequenceEqual(predecessor)
            || !((byte[])r[2]).AsSpan().SequenceEqual(commitHash) || !((byte[])r[3]).AsSpan().SequenceEqual(canonicalCommit)) throw new FormatException("GroupV1 fork evidence does not bind the retained head.");
        var secondHash = (byte[])r[4]; var secondCanonical = (byte[])r[5]; var second = (GroupCommitRecord)GroupCodec.Decode("DGC1", secondCanonical);
        if (!second.ArtifactHash.Span.SequenceEqual(secondHash) || secondHash.AsSpan().SequenceEqual(commitHash)
            || !second.Field(1).Span.SequenceEqual(network) || !second.Field(2).Span.SequenceEqual(id.Span)
            || ReadU64(second.Field(4).ToArray()) != epoch || !second.Field(5).Span.SequenceEqual(predecessor) || r.Read())
            throw new FormatException("GroupV1 sibling fork evidence is invalid.");
    }

    private static void InsertHead(SqliteConnection db, SqliteTransaction tx, GroupHeadSnapshot h) { using var cmd = HeadCommand(db, tx, h, false); if (cmd.ExecuteNonQuery() != 1) throw new InvalidOperationException("Group head insert failed."); }
    private static void UpdateHead(SqliteConnection db, SqliteTransaction tx, GroupHeadSnapshot h, ulong expectedRevision) { using var cmd = HeadCommand(db, tx, h, true); cmd.Parameters.AddWithValue("$expected", U64(expectedRevision)); if (cmd.ExecuteNonQuery() != 1) throw new InvalidOperationException("Group head CAS failed."); }
    private static SqliteCommand HeadCommand(SqliteConnection db, SqliteTransaction tx, GroupHeadSnapshot h, bool update)
    { var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = update ? "UPDATE group_heads SET network_id=$network,epoch=$epoch,revision=$revision,commit_hash=$commit,package_hash=$package,predecessor_hash=$predecessor,canonical_commit=$canonicalCommit,canonical_package=$canonicalPackage,verified_gcp1_sha256=$verifiedGcp1Sha256,member_count=$members,device_count=$devices,fork_latched=$fork WHERE group_id=$id AND revision=$expected;" : "INSERT INTO group_heads VALUES($id,$network,$epoch,$revision,$commit,$package,$predecessor,$canonicalCommit,$canonicalPackage,$verifiedGcp1Sha256,$members,$devices,$fork);"; cmd.Parameters.AddWithValue("$id", h.GroupId.ToArray()); cmd.Parameters.AddWithValue("$network", h.NetworkId.ToArray()); cmd.Parameters.AddWithValue("$epoch", U64(h.Epoch)); cmd.Parameters.AddWithValue("$revision", U64(h.Revision)); cmd.Parameters.AddWithValue("$commit", h.CommitHash.ToArray()); cmd.Parameters.AddWithValue("$package", h.PackageHash.ToArray()); cmd.Parameters.AddWithValue("$predecessor", h.PredecessorHash.ToArray()); cmd.Parameters.AddWithValue("$canonicalCommit", h.ExactCanonicalCommit.ToArray()); cmd.Parameters.AddWithValue("$canonicalPackage", h.ExactCanonicalPackage.ToArray()); cmd.Parameters.AddWithValue("$verifiedGcp1Sha256", h.ExactVerifiedGcp1Sha256.ToArray()); cmd.Parameters.AddWithValue("$members", h.MemberCount); cmd.Parameters.AddWithValue("$devices", h.DeviceCount); cmd.Parameters.AddWithValue("$fork", h.ForkLatched ? 1 : 0); return cmd; }

    private static void ReplaceArtifacts(SqliteConnection db, SqliteTransaction tx, GroupTransitionCommitPlan p)
    { using (var delete = db.CreateCommand()) { delete.Transaction = tx; delete.CommandText = "DELETE FROM group_artifacts WHERE group_id=$id; DELETE FROM group_chunks WHERE group_id=$id;"; delete.Parameters.AddWithValue("$id", p.GroupId.ToArray()); delete.ExecuteNonQuery(); } foreach (var a in p.Artifacts) { using var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = "INSERT INTO group_artifacts VALUES($id,$magic,$hash,$bytes);"; cmd.Parameters.AddWithValue("$id", p.GroupId.ToArray()); cmd.Parameters.AddWithValue("$magic", a.Magic); cmd.Parameters.AddWithValue("$hash", a.Hash.ToArray()); cmd.Parameters.AddWithValue("$bytes", a.ExactCanonicalBytes.ToArray()); cmd.ExecuteNonQuery(); } foreach (var c in p.Chunks) { using var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = "INSERT INTO group_chunks VALUES($id,$package,$index,$count,$hash,$bytes);"; cmd.Parameters.AddWithValue("$id", p.GroupId.ToArray()); cmd.Parameters.AddWithValue("$package", p.PackageHash.ToArray()); cmd.Parameters.AddWithValue("$index", c.Index); cmd.Parameters.AddWithValue("$count", c.Count); cmd.Parameters.AddWithValue("$hash", c.Hash.ToArray()); cmd.Parameters.AddWithValue("$bytes", c.ExactCanonicalBytes.ToArray()); cmd.ExecuteNonQuery(); } }
    private static void UpsertCursors(SqliteConnection db, SqliteTransaction tx, GroupTransitionCommitPlan p)
    { foreach (var c in p.Cursors) { using var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = "INSERT INTO group_control_cursors VALUES($id,$recipient,$package,$index,$count) ON CONFLICT(group_id,recipient_key) DO UPDATE SET package_hash=excluded.package_hash,chunk_index=excluded.chunk_index,chunk_count=excluded.chunk_count;"; cmd.Parameters.AddWithValue("$id", p.GroupId.ToArray()); cmd.Parameters.AddWithValue("$recipient", c.Recipient.Bytes.ToArray()); cmd.Parameters.AddWithValue("$package", c.PackageHash.ToArray()); cmd.Parameters.AddWithValue("$index", c.ChunkIndex); cmd.Parameters.AddWithValue("$count", c.ChunkCount); cmd.ExecuteNonQuery(); } }
    private static void LatchFork(SqliteConnection db, SqliteTransaction tx, GroupHeadSnapshot current, GroupTransitionCommitPlan p)
    { using (var cmd = db.CreateCommand()) { cmd.Transaction = tx; cmd.CommandText = "INSERT INTO group_forks VALUES($id,$epoch,$predecessor,$firstHash,$first,$secondHash,$second);"; cmd.Parameters.AddWithValue("$id", current.GroupId.ToArray()); cmd.Parameters.AddWithValue("$epoch", U64(current.Epoch)); cmd.Parameters.AddWithValue("$predecessor", current.PredecessorHash.ToArray()); cmd.Parameters.AddWithValue("$firstHash", current.CommitHash.ToArray()); cmd.Parameters.AddWithValue("$first", current.ExactCanonicalCommit.ToArray()); cmd.Parameters.AddWithValue("$secondHash", p.CommitHash.ToArray()); cmd.Parameters.AddWithValue("$second", p.CanonicalCommit.ToArray()); cmd.ExecuteNonQuery(); } using var update = db.CreateCommand(); update.Transaction = tx; update.CommandText = "UPDATE group_heads SET fork_latched=1 WHERE group_id=$id AND revision=$revision AND fork_latched=0;"; update.Parameters.AddWithValue("$id", current.GroupId.ToArray()); update.Parameters.AddWithValue("$revision", U64(current.Revision)); if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fork latch CAS failed."); }
    private static void InsertOperation(SqliteConnection db, SqliteTransaction tx, GroupTransitionCommitPlan p, GroupCommitDisposition disposition, ulong revision)
    { using var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = "INSERT INTO group_operations VALUES($operation,$fingerprint,$group,$disposition,$revision);"; cmd.Parameters.AddWithValue("$operation", p.OperationId.ToArray()); cmd.Parameters.AddWithValue("$fingerprint", p.Fingerprint.ToArray()); cmd.Parameters.AddWithValue("$group", p.GroupId.ToArray()); cmd.Parameters.AddWithValue("$disposition", (int)disposition); cmd.Parameters.AddWithValue("$revision", U64(revision)); cmd.ExecuteNonQuery(); }
    private static OperationRow? ReadOperation(SqliteConnection db, SqliteTransaction tx, GroupOperationId32 operation)
    { using var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = "SELECT fingerprint,group_id,disposition,committed_revision FROM group_operations WHERE operation_id=$id;"; cmd.Parameters.AddWithValue("$id", operation.ToArray()); using var r = cmd.ExecuteReader(); if (!r.Read()) return null; var result = new OperationRow((byte[])r[0], GroupId32.FromBytes((byte[])r[1]), (GroupCommitDisposition)r.GetInt32(2), ReadU64((byte[])r[3])); if (r.Read() || result.Fingerprint.Length != 32 || !Enum.IsDefined(result.Disposition) || result.Revision == 0) throw new FormatException("Invalid operation replay row."); return result; }

    private SqliteConnection GetConnection() => connection ?? throw new ObjectDisposedException(nameof(SqliteGroupStateStore));
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    private void FailedOpen() { connection?.Dispose(); connection = null; CryptographicOperations.ZeroMemory(key); }
    private static void Execute(SqliteConnection db, SqliteTransaction? tx, string sql) { using var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = sql; cmd.ExecuteNonQuery(); }
    private static long Scalar(SqliteConnection db, string sql) { using var cmd = db.CreateCommand(); cmd.CommandText = sql; return Convert.ToInt64(cmd.ExecuteScalar(), CultureInfo.InvariantCulture); }
    private static string ScalarText(SqliteConnection db, string sql) { using var cmd = db.CreateCommand(); cmd.CommandText = sql; return Convert.ToString(cmd.ExecuteScalar(), CultureInfo.InvariantCulture) ?? string.Empty; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
    private static ulong ReadU64(ReadOnlySpan<byte> value) { if (value.Length != 8) throw new FormatException("Invalid u64."); return BinaryPrimitives.ReadUInt64BigEndian(value); }
    private static uint U32(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt32BigEndian(value);
    private static ReadOnlySpan<byte> ReadLp(ReadOnlySpan<byte> value) { if (value.Length < 4) throw new FormatException("Invalid LP32."); var n = U32(value); if (n != value.Length - 4) throw new FormatException("Invalid LP32."); return value[4..]; }
    private static ReadOnlySpan<byte> TakeLp(ReadOnlySpan<byte> value, ref int at) { Require(value, at, 4); var n = U32(value[at..]); at += 4; if (n > int.MaxValue) throw new FormatException("LP32 is too large."); Require(value, at, checked((int)n)); var result = value.Slice(at, checked((int)n)); at += checked((int)n); return result; }
    private static void Require(ReadOnlySpan<byte> value, int at, int length) { if (at < 0 || length < 0 || length > value.Length - at) throw new FormatException("Truncated GroupV1 field."); }
    private static ushort CountDevices(ReadOnlySpan<byte> members, ushort expectedMembers)
    { var at = 0; var memberCount = 0; var devices = 0; while (at < members.Length) { Require(members, at, 2); var length = BinaryPrimitives.ReadUInt16BigEndian(members[at..]); at += 2; Require(members, at, length); if (length < 220) throw new FormatException("Invalid member entry."); var count = members[at + 219]; if (count is < 1 or > 5 || length != 220 + count * 70) throw new FormatException("Invalid member entry."); devices += count; memberCount++; at += length; } if (memberCount != expectedMembers || memberCount is < 1 or > 100 || devices is < 1 or > 500) throw new FormatException("Invalid verified member limits."); return checked((ushort)devices); }
    private static GroupStateStoreOpenException Failure(GroupStateStoreOpenFailure reason, string message, Exception? inner = null) => new(reason, message, inner);
    private sealed record OperationRow(byte[] Fingerprint, GroupId32 GroupId, GroupCommitDisposition Disposition, ulong Revision);
}
