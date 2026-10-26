using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;
using Xunit.Abstractions;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2ActiveNativeCostTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(100)]
    [InlineData(1000)]
    [InlineData(10000)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ActiveArchive_StructuralNativeVerifierCostKeepsCompleteMapAndCipherScan(int count)
    {
        var samples = await DeepIdV2ContactPathAuthoritySourceTests.RunStructuralNativeArchiveCost(count);
        // The fixture/SQL/account lease and every payload are closed before
        // invoking this test observer. No private loan crosses the bridge.
        foreach (var sample in samples) output.WriteLine(JsonSerializer.Serialize(sample));
    }
}

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    // Narrow static fixture bridge keeps the main contact test class free of
    // instance state, preserving its existing isolation-scheduler contract.
    internal static async Task<IReadOnlyList<NativeArchiveCostSample>> RunStructuralNativeArchiveCost(int count)
    {
        if (count is not (100 or 1000 or 10000)) throw new ArgumentOutOfRangeException(nameof(count));
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        var samples = new List<NativeArchiveCostSample>();
        await fixture.WithActiveNativeComparators(sender, (_, _, connection, _) =>
        {
            // Verification-only native SQL fixture. These TEST roots are NEVER
            // installed into protected storage or consumed by a service opener.
            // Canonical cloned DPE2s reuse ciphertext/header material; they do
            // not establish AEAD, advancing ratchet, custody or business facts.
            using var corpus = InstallStructuralNativeArchive(connection, sender, count);
            var full = new Did2MessagingSqlJournal(connection, sender, corpus.History);
            var active = Did2MessagingSqlJournal.ForOrdinaryRuntime(connection, sender, corpus.History);
            Assert.Equal(corpus.Floor.Exact.ToArray(), full.VerifyTip().Exact.ToArray());
            Assert.Equal(corpus.Floor.Exact.ToArray(), active.VerifyOrdinaryState().Exact.ToArray());

            // Same actual provider/file, count, TEST root, selector and handle.
            // Setup and initial verification are outside all measured samples.
            // Alternate ordering; report process CPU/wall without speed claims.
            for (var repeat = 0; repeat < 3; repeat++)
            {
                if (repeat % 2 == 0)
                {
                    samples.Add(MeasureStructuralNativeRead(full, corpus, count, repeat, active: false));
                    samples.Add(MeasureStructuralNativeRead(active, corpus, count, repeat, active: true));
                }
                else
                {
                    samples.Add(MeasureStructuralNativeRead(active, corpus, count, repeat, active: true));
                    samples.Add(MeasureStructuralNativeRead(full, corpus, count, repeat, active: false));
                }
            }
        });
        return samples;
    }

    internal sealed record NativeArchiveCostSample(string Schema, bool StructuralOnly, string Algorithm,
        int Rows, int Repeat, double WallMilliseconds, double ProcessCpuMilliseconds,
        long Opens, long CipherScans, long MetadataRows, long SuffixRows, long PayloadVerifications,
        ulong WorkingCount, ulong ArchiveCount);

    private static NativeArchiveCostSample MeasureStructuralNativeRead(Did2MessagingSqlJournal journal,
        StructuralNativeArchive corpus, int count, int repeat, bool active)
    {
        using var process = Process.GetCurrentProcess();
        using var work = Did2MessagingSqlJournal.NativeWork.Measure();
        var cpu = process.TotalProcessorTime;
        var started = Stopwatch.GetTimestamp();
        using var selected = journal.ReadVerifiedOperation(corpus.Floor, corpus.Operation);
        var wall = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
        var usedCpu = (process.TotalProcessorTime - cpu).TotalMilliseconds;
        Assert.NotNull(selected);
        Assert.Equal(1, selected.Direction);
        Assert.Equal(corpus.SelectedOrdinal, selected.Ordinal);
        Assert.True(selected.ExactEnvelope.SequenceEqual(corpus.Envelope));
        Assert.Equal(0, work.Opens); // Explicit existing-handle microcost, not account open cost.
        Assert.Equal(active ? 1 : 0, work.CipherScans);
        Assert.Equal(count, work.MetadataRows);
        Assert.Equal(0, work.SuffixRows);
        Assert.Equal(active ? 1 : count, work.Payloads);
        Assert.Equal(0UL, work.WorkingCount);
        Assert.Equal(checked((ulong)count), work.ArchiveCount);
        // Payloads counts instrumented semantic verification calls, not all SQL
        // blob materializations or physical page reads. Full also selects its
        // requested row after the complete payload-verification walk; Active
        // retains a complete native cipher scan (whole-file I/O remains).
        return new("deep.structural-native-archive-cost.v1", true, active ? "active" : "full",
            count, repeat, wall, usedCpu, work.Opens, work.CipherScans, work.MetadataRows,
            work.SuffixRows, work.Payloads, work.WorkingCount, work.ArchiveCount);
    }

    private sealed record StructuralNativeArchive(Did2MessagingHistoryCheckpoint History, Did2MessagingFloor Floor,
        byte[] Operation, byte[] Envelope, ulong SelectedOrdinal) : IDisposable
    {
        public void Dispose()
        { CryptographicOperations.ZeroMemory(Operation); CryptographicOperations.ZeroMemory(Envelope); }
    }

    private static StructuralNativeArchive InstallStructuralNativeArchive(SqliteConnection connection,
        Did2MessagingSessionScope scope, int count)
    {
        var (originalOperation, originalMetadata, originalEnvelope) = ReadActiveOutgoing(connection);
        byte[] initial = [], last = [], selectedOperation = [], selectedEnvelope = [];
        try
        {
            Assert.Equal(Did2MessagingFloor.MetadataBytes, originalMetadata.Length);
            Assert.Equal(2, originalMetadata[5]); Assert.Equal(1, originalMetadata[6]);
            var predecessor = Did2MessagingFloor.Decode(originalMetadata.AsSpan(8, Did2MessagingFloor.Bytes), scope);
            var original = Dpe2Codec.Decode(originalEnvelope);
            using var transaction = connection.BeginTransaction();
            using (var read = connection.CreateCommand())
            {
                read.Transaction = transaction;
                read.CommandText = "SELECT metadata,typeof(metadata),length(metadata) FROM initial_events WHERE singleton=1;";
                using var row = read.ExecuteReader();
                Assert.True(row.Read()); Assert.Equal("blob", row.GetString(1));
                Assert.Equal(Did2MessagingFloor.MetadataBytes, row.GetInt64(2));
                initial = row.GetFieldValue<byte[]>(0); Assert.False(row.Read());
            }
            using (var clear = connection.CreateCommand())
            { clear.Transaction = transaction; clear.CommandText = "DELETE FROM events; DELETE FROM journal;"; clear.ExecuteNonQuery(); }
            using var insert = connection.CreateCommand(); insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO events(operation,ordinal,direction,envelope,plaintext,metadata) VALUES($op,$ordinal,1,$envelope,NULL,$metadata);";
            var operationParameter = insert.Parameters.Add("$op", SqliteType.Blob);
            var ordinalParameter = insert.Parameters.Add("$ordinal", SqliteType.Integer);
            var envelopeParameter = insert.Parameters.Add("$envelope", SqliteType.Blob);
            var metadataParameter = insert.Parameters.Add("$metadata", SqliteType.Blob);
            var selectedIndex = count / 2;
            Span<byte> ordinalBytes = stackalloc byte[8];
            for (var index = 0; index < count; index++)
            {
                BinaryPrimitives.WriteUInt64BigEndian(ordinalBytes, checked((ulong)index + 1));
                using var operationHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                operationHash.AppendData("Deep/TEST/structural-native-archive-operation"u8); operationHash.AppendData(ordinalBytes);
                var operation = operationHash.GetHashAndReset();
                var envelope = Dpe2Codec.Encode(new Dpe2Record(original.NetworkId.Span, original.SessionId.Span,
                    original.SenderDeviceId.Span, original.RecipientDeviceId.Span, operation, original.RatchetHeader, original.Ciphertext));
                var metadata = originalMetadata.ToArray();
                try
                {
                    var priorOrdinal = checked(predecessor.Ordinal + (ulong)index);
                    BinaryPrimitives.WriteUInt64BigEndian(metadata.AsSpan(8 + 36), priorOrdinal);
                    operation.CopyTo(metadata, 268);
                    MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(Dpe2Codec.Decode(envelope)).CopyTo(metadata, 332);
                    operationParameter.Value = operation; ordinalParameter.Value = checked((long)(priorOrdinal + 1));
                    envelopeParameter.Value = envelope; metadataParameter.Value = metadata;
                    Assert.Equal(1, insert.ExecuteNonQuery());
                    if (index == selectedIndex) { selectedOperation = operation.ToArray(); selectedEnvelope = envelope.ToArray(); }
                    if (index == count - 1) last = metadata.ToArray();
                }
                finally
                { CryptographicOperations.ZeroMemory(operation); CryptographicOperations.ZeroMemory(envelope); CryptographicOperations.ZeroMemory(metadata); }
            }
            // Independent per-row canonical structural metadata is deliberate:
            // this is NOT a genuine advancing ratchet/journal chain producer.
            var lastPredecessor = Did2MessagingFloor.Decode(last.AsSpan(8, Did2MessagingFloor.Bytes), scope);
            var basis = Did2MessagingFloor.FromJournalMetadata(scope, lastPredecessor, last);
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            digest.AppendData("Deep/STORE-V2/messaging-history-prefix"u8); digest.AppendData([0]);
            digest.AppendData(scope.Hash); digest.AppendData(basis.Exact.Span); digest.AppendData(initial);
            using (var read = connection.CreateCommand())
            {
                read.Transaction = transaction;
                read.CommandText = "SELECT ordinal,metadata FROM events NOT INDEXED ORDER BY ordinal;";
                using var row = read.ExecuteReader(); var actual = 0;
                while (row.Read())
                {
                    BinaryPrimitives.WriteUInt64BigEndian(ordinalBytes, checked((ulong)row.GetInt64(0)));
                    digest.AppendData(ordinalBytes); digest.AppendData(row.GetFieldValue<byte[]>(1)); actual++;
                }
                Assert.Equal(count, actual);
            }
            BinaryPrimitives.WriteUInt64BigEndian(ordinalBytes, checked((ulong)count)); digest.AppendData(ordinalBytes);
            var history = Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).NextProjection(
                scope, basis, initial, digest.GetHashAndReset(), checked((ulong)count));
            transaction.Commit();
            var result = new StructuralNativeArchive(history, basis, selectedOperation, selectedEnvelope,
                checked(predecessor.Ordinal + (ulong)selectedIndex + 1));
            selectedOperation = []; selectedEnvelope = []; return result;
        }
        finally
        {
            foreach (var bytes in new[] { originalOperation, originalMetadata, originalEnvelope, initial, last, selectedOperation, selectedEnvelope })
                CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
