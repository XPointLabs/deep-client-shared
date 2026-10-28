using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2IndexedArchive_DpeAndBraidContextsCommitRootBasisAndEveryActualSuffixHeader()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        var source = (await fixture.ReadNativeHistory(sender)).Exact.ToArray();
        var before = await fixture.AssertArchiveRetentionDigest(sender, requireBootstrapHeaders: true);
        await fixture.CompactActiveNativePrefix(sender, checked((int)(await fixture.ReadMessagingFloor(sender)).Ordinal));
        fixture.ColdReopenCompactionStorage();
        var after = await fixture.AssertArchiveRetentionDigest(sender, requireBootstrapHeaders: false);
        Assert.False(before.AsSpan().SequenceEqual(after), "Moving the independent archive basis did not change native replay retention.");
        var retainedSource = await fixture.ReadNativeHistory(sender);
        Assert.True(source.AsSpan().SequenceEqual(retainedSource.Exact.Span),
            "Indexed prefix adoption changed immutable enrollment-source history.");
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[]> AssertArchiveRetentionDigest(Did2MessagingSessionScope scope, bool requireBootstrapHeaders)
        {
            using var owned = await NativeStorage(scope).ReadOwnedAsync(Did2MessagingArchiveRoot.Slot(scope)) ?? throw new InvalidDataException();
            var archive = owned.Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope)); byte[]? result = null;
            await WithActiveNativeComparators(scope, (_, indexed, connection, stable) =>
            {
                var rows = new List<(ulong Ordinal, byte[] Predecessor, byte[] Head, byte[] Metadata)>();
                using (var read = connection.CreateCommand())
                {
                    read.CommandText = "SELECT ordinal,predecessor,head,metadata FROM journal ORDER BY ordinal;";
                    using var row = read.ExecuteReader();
                    while (row.Read()) rows.Add((checked((ulong)row.GetInt64(0)), row.GetFieldValue<byte[]>(1),
                        row.GetFieldValue<byte[]>(2), row.GetFieldValue<byte[]>(3)));
                }
                Assert.InRange(rows.Count, 0, 64);
                if (requireBootstrapHeaders)
                { Assert.Contains(rows, row => row.Metadata[5] == 1); Assert.Contains(rows, row => row.Metadata[5] == 3); }
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                hash.AppendData("Deep/STORE-V2/messaging-replay-retention"u8); hash.AppendData([0]);
                Append64(2); hash.AppendData(scope.Hash); hash.AppendData(archive.Exact.Span);
                hash.AppendData(archive.Basis.Exact.Span); hash.AppendData(stable.Exact.Span); Append64(checked((ulong)rows.Count));
                var previous = archive.Basis;
                foreach (var row in rows)
                {
                    Assert.Equal(previous.Ordinal + 1, row.Ordinal);
                    Assert.True(row.Predecessor.AsSpan().SequenceEqual(previous.Head));
                    Assert.True(row.Metadata.AsSpan(8, 188).SequenceEqual(previous.Exact.Span));
                    var next = Did2MessagingFloor.FromJournalMetadata(scope, previous, row.Metadata);
                    Assert.True(row.Head.AsSpan().SequenceEqual(next.Head)); previous = next;
                    Append64(row.Ordinal); hash.AppendData(row.Metadata);
                }
                Assert.True(previous.Exact.Span.SequenceEqual(stable.Exact.Span));
                result = hash.GetHashAndReset();
                var operation = Bytes(32, 0xbd);
                var dpe = indexed.CreateVerifiedTransitionContext(stable, operation, []);
                var braid = indexed.CreateVerifiedBraidTransitionContext(stable, operation, []);
                Assert.True(result.AsSpan().SequenceEqual(dpe.RetentionCommitment.Span));
                Assert.True(result.AsSpan().SequenceEqual(braid.RetentionCommitment.Span));
                if (rows.Count > 0)
                {
                    var selected = rows[0];
                    try
                    {
                        UpdateHead(Bytes(32, 0xbe));
                        Assert.Throws<CryptographicException>(() => indexed.CreateVerifiedTransitionContext(stable, operation, []));
                        Assert.Throws<CryptographicException>(() => indexed.CreateVerifiedBraidTransitionContext(stable, operation, []));
                    }
                    finally { UpdateHead(selected.Head); }
                    void UpdateHead(byte[] value)
                    {
                        using var update = connection.CreateCommand(); update.CommandText = "UPDATE journal SET head=$head WHERE ordinal=$ordinal;";
                        update.Parameters.AddWithValue("$head", value); update.Parameters.AddWithValue("$ordinal", checked((long)selected.Ordinal));
                        Assert.Equal(1, update.ExecuteNonQuery());
                    }
                }
                void Append64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); hash.AppendData(bytes); }
            });
            return result!;
        }
    }
}
