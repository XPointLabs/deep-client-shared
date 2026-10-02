using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.AttachmentV1;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    internal Task<OwnedAttachmentPreparation?> ReconcileOwnedAttachmentsAsync(ProtectedDid2AttachmentJournal.State state,
        ReadOnlyMemory<byte> account, ulong generation, ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> select, CancellationToken ct)
    {
        RequireDirectId(account, nameof(account));
        if (generation == 0 || network.Length != 16) throw new ArgumentException("An owned attachment scope is required.");
        if (!select.IsEmpty) RequireDirectId(select, nameof(select));
        var local = account.ToArray(); var net = network.ToArray(); var op = select.ToArray();
        var gen = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(gen, generation);
        return Run();
        async Task<OwnedAttachmentPreparation?> Run()
        {
            try
            {
                return await WithReplayConnectionAsync(connection =>
                {
                    using var tx = connection.BeginTransaction(deferred: false); BindDirectInboxOwner(connection, tx, local, gen);
                    using var count = connection.CreateCommand(); count.Transaction = tx;
                    count.CommandText = "SELECT count(*) FROM local_attachment_objects;";
                    if (Convert.ToInt64(count.ExecuteScalar()) > ProtectedDid2AttachmentJournal.MaximumEntries + 1)
                        throw new CryptographicException("Local asset candidates exceed their bound.");
                    var found = new HashSet<string>(StringComparer.Ordinal); var orphans = new List<byte[]>();
                    var manifests = new Dictionary<string, byte[]>(StringComparer.Ordinal);
                    OwnedAttachmentPreparation? result = null;
                    try
                    {
                        using (var read = connection.CreateCommand())
                        {
                            read.Transaction = tx;
                            read.CommandText = "SELECT length(operation_id),operation_id,length(object_id),object_id,length(exact_manifest),typeof(exact_manifest),exact_manifest FROM local_attachment_objects ORDER BY operation_id;";
                            using var row = read.ExecuteReader();
                            while (row.Read())
                            {
                                ct.ThrowIfCancellationRequested();
                                if (row.GetInt64(0) != 32 || row.GetInt64(2) != 32 || row.GetInt64(4) is < 310 or > 4653 || row.GetString(5) != "blob")
                                    throw new CryptographicException("Local asset SQL has an invalid bounded shape.");
                                var key = (byte[])row[1]; var name = Convert.ToHexString(key);
                                if (!state.Entries.TryGetValue(name, out var entry)) { orphans.Add(key); continue; }
                                CryptographicOperations.ZeroMemory(key);
                                var objectId = (byte[])row[3]; var exact = (byte[])row[6];
                                try
                                {
                                    if (!DirectFixed(objectId, entry.Object) || !found.Add(name)) throw new CryptographicException("Local asset identity differs.");
                                    using var manifest = entry.RequireManifest(exact, net);
                                    manifests.Add(name, exact); exact = [];
                                }
                                finally { CryptographicOperations.ZeroMemory(objectId); CryptographicOperations.ZeroMemory(exact); }
                            }
                        }
                        if (found.Count != state.Entries.Count) throw new CryptographicException("Protected attachment custody lost its exact SQL object.");
                        // No protected command references these candidates. They
                        // have never been returned or authorized for upload.
                        foreach (var orphan in orphans)
                        {
                            using var delete = connection.CreateCommand(); delete.Transaction = tx;
                            delete.CommandText = "DELETE FROM local_attachment_objects WHERE operation_id=$op;"; delete.Parameters.AddWithValue("$op", orphan);
                            if (delete.ExecuteNonQuery() != 1) throw new CryptographicException("An inert asset candidate changed during cleanup.");
                        }
                        using var sizes = connection.CreateCommand(); sizes.Transaction = tx;
                        sizes.CommandText = "SELECT count(*),coalesce(sum(length(ciphertext)),0) FROM local_attachment_chunks;";
                        using (var row = sizes.ExecuteReader())
                        {
                            if (!row.Read() || row.GetInt64(0) > 100L * state.Entries.Count || row.GetInt64(1) > ProtectedDid2AttachmentJournal.MaximumCiphertextBytes)
                                throw new CryptographicException("Local attachment ciphertext exceeds its owned quota.");
                        }
                        foreach (var pair in state.Entries)
                        {
                            var exact = manifests[pair.Key]; using var manifest = pair.Value.RequireManifest(exact, net);
                            var selected = DirectFixed(pair.Value.Operation, op); var chunks = new List<byte[]>();
                            try
                            {
                                using var read = connection.CreateCommand(); read.Transaction = tx;
                                // Only selected payloads are materialized; all
                                // registered geometry is verified without BLOB allocation.
                                read.CommandText = selected
                                    ? "SELECT chunk_index,length(ciphertext),typeof(ciphertext),ciphertext FROM local_attachment_chunks WHERE operation_id=$op ORDER BY chunk_index;"
                                    : "SELECT chunk_index,length(ciphertext),typeof(ciphertext) FROM local_attachment_chunks WHERE operation_id=$op ORDER BY chunk_index;";
                                read.Parameters.AddWithValue("$op", pair.Value.Operation.ToArray()); using var row = read.ExecuteReader();
                                var index = 0;
                                while (row.Read())
                                {
                                    ct.ThrowIfCancellationRequested();
                                    if (index >= manifest.ChunkCount || row.GetInt64(0) != index || row.GetString(2) != "blob" ||
                                        row.GetInt64(1) != manifest.Chunks[index].CiphertextLength)
                                        throw new CryptographicException("Local attachment chunk geometry differs from custody.");
                                    if (selected)
                                    {
                                        var bytes = (byte[])row[3];
                                        if (!DirectFixed(SHA256.HashData(bytes), manifest.Chunks[index].CiphertextHash.Span))
                                        { CryptographicOperations.ZeroMemory(bytes); throw new CryptographicException("Local attachment ciphertext changed."); }
                                        chunks.Add(bytes);
                                    }
                                    index++;
                                }
                                if (index != manifest.ChunkCount) throw new CryptographicException("Local attachment custody lost a chunk.");
                                if (selected) { result = new(exact, chunks.ToArray(), pair.Value.PlaintextHash); chunks.Clear(); }
                            }
                            finally { foreach (var bytes in chunks) CryptographicOperations.ZeroMemory(bytes); }
                        }
                        ct.ThrowIfCancellationRequested(); tx.Commit(); var released = result; result = null; return Task.FromResult(released);
                    }
                    finally
                    {
                        result?.Dispose(); foreach (var bytes in orphans) CryptographicOperations.ZeroMemory(bytes);
                        foreach (var bytes in manifests.Values) CryptographicOperations.ZeroMemory(bytes);
                    }
                }, ct).ConfigureAwait(false);
            }
            finally { foreach (var bytes in new[] { local, net, op, gen }) CryptographicOperations.ZeroMemory(bytes); }
        }
    }

    internal async Task InsertAttachmentCandidateAsync(ReadOnlyMemory<byte> operation, OwnedAttachmentPreparation candidate,
        CancellationToken ct)
    {
        RequireDirectId(operation, nameof(operation)); var op = operation.ToArray();
        using var manifestOwner = candidate.OwnManifest(); var exact = manifestOwner.Use(bytes => bytes.ToArray());
        try
        {
            using var manifest = ApplicationCoreCodec.DecodeDam1(exact);
            await WithReplayConnectionAsync(connection =>
            {
                using var tx = connection.BeginTransaction(deferred: false);
                using var quota = connection.CreateCommand(); quota.Transaction = tx;
                quota.CommandText = "SELECT coalesce(sum(length(ciphertext)),0) FROM local_attachment_chunks;";
                var added = manifest.Chunks.Sum(entry => (long)entry.CiphertextLength);
                if (Convert.ToInt64(quota.ExecuteScalar()) + added > ProtectedDid2AttachmentJournal.MaximumCiphertextBytes)
                    throw new InvalidOperationException("Local attachment storage capacity is exhausted.");
                using var insert = connection.CreateCommand(); insert.Transaction = tx;
                insert.CommandText = "INSERT INTO local_attachment_objects VALUES($op,$id,$exact);";
                insert.Parameters.AddWithValue("$op", op); insert.Parameters.AddWithValue("$id", manifest.ObjectId.ToArray()); insert.Parameters.AddWithValue("$exact", exact);
                if (insert.ExecuteNonQuery() != 1) throw new CryptographicException("Local asset candidate was not retained.");
                for (uint index = 0; index < manifest.ChunkCount; index++)
                {
                    ct.ThrowIfCancellationRequested(); var bytes = candidate.CopyCiphertext(index);
                    try
                    {
                        if (bytes.Length != manifest.Chunks[(int)index].CiphertextLength ||
                            !DirectFixed(SHA256.HashData(bytes), manifest.Chunks[(int)index].CiphertextHash.Span))
                            throw new CryptographicException("Candidate chunk differs from its exact manifest.");
                        using var chunk = connection.CreateCommand(); chunk.Transaction = tx;
                        chunk.CommandText = "INSERT INTO local_attachment_chunks VALUES($op,$index,$bytes);";
                        chunk.Parameters.AddWithValue("$op", op); chunk.Parameters.AddWithValue("$index", index); chunk.Parameters.AddWithValue("$bytes", bytes);
                        if (chunk.ExecuteNonQuery() != 1) throw new CryptographicException("Candidate chunk was not retained.");
                    }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                }
                ct.ThrowIfCancellationRequested(); tx.Commit(); return Task.FromResult(true);
            }, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(op); CryptographicOperations.ZeroMemory(exact); }
    }
}
