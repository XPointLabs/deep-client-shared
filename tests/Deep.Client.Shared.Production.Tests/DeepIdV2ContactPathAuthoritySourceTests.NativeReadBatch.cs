using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("unselected-type")]
    [InlineData("unselected-envelope")]
    [InlineData("unselected-missing")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task NativeReadBatch_ActualEncryptedRowsRemainFreshOrderedAndWholeJournalVerified(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        async Task<byte[]> Send(string text)
        {
            using var command = await fixture.CreateOwnedText(sender, text);
            using var sent = await fixture.SendOwnedMessage(sender, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span));
            using var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray());
            return command.OperationId.ToArray();
        }
        var first = await Send("native read batch first"); var second = await Send("native read batch second");
        var absent = SHA256.HashData("absent native batch operation"u8);
        var floor = await fixture.ReadMessagingFloor(receiver);
        await fixture.WithRouteReadSql(receiver, (sql, connection) =>
        {
            var rows = sql.ReadVerifiedOperations(floor, [second, absent, first]);
            try
            {
                Assert.Equal(3, rows.Count); Assert.Null(rows[1]);
                Assert.True(rows[0]!.Ordinal > rows[2]!.Ordinal);
                using var single = sql.ReadVerifiedOperation(floor, second);
                Assert.Equal(single!.ExactEnvelope.ToArray(), rows[0]!.ExactEnvelope.ToArray());
            }
            finally { foreach (var row in rows) row?.Dispose(); }
            Assert.Throws<ObjectDisposedException>(() => rows[0]!.OwnAuthenticatedDmc2());
            CheckGroupHistorySnapshot(sql, floor, first, second, absent);
            if (defect == "none") return;
            using var corrupt = connection.CreateCommand();
            corrupt.CommandText = defect switch
            {
                "unselected-type" => "UPDATE events SET envelope=CAST(envelope AS TEXT) WHERE operation=$op;",
                "unselected-envelope" => "UPDATE events SET envelope=zeroblob(length(envelope)) WHERE operation=$op;",
                _ => "DELETE FROM events WHERE operation=$op;"
            };
            corrupt.Parameters.AddWithValue("$op", second); Assert.Equal(1, corrupt.ExecuteNonQuery());
            var before = ReadRouteReadRawSqlProjection(connection);
            var legacyError = Record.Exception(() => sql.ReadVerifiedOperations(floor, [first]));
            Assert.NotNull(legacyError);
            var groupError = Record.Exception(() =>
            {
                using var history = sql.OpenGroupHistorySnapshot(floor);
                var healthy = history.ReadOperations([first]);
                foreach (var row in healthy) row?.Dispose();
            });
            if (defect == "unselected-envelope")
            {
                Assert.True(legacyError is MessagingWireFormatException, ClosedNativeReadFailure(legacyError, "legacy-zero-envelope"));
                Assert.True(groupError is MessagingWireFormatException, ClosedNativeReadFailure(groupError, "group-zero-envelope"));
            }
            else Assert.True(groupError is CryptographicException or InvalidDataException, ClosedNativeReadFailure(groupError, "unselected-sibling"));
            Assert.Equal(before, ReadRouteReadRawSqlProjection(connection));
        });
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task GroupHistorySnapshot_ActualArchivedAndHotPagesKeepWholeNativeIntegrityAndBounds()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        async Task<byte[]> Send(string text)
        {
            using var draft = await fixture.CreateOwnedText(sender, text);
            using var sent = await fixture.SendOwnedMessage(sender, draft.OperationId, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
            using var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray());
            return draft.OperationId.ToArray();
        }
        var first = await Send("archived group-read snapshot kernel original");
        await fixture.ArchiveEntireEligibleSuffix(receiver);
        var second = await Send("hot group-read snapshot kernel original");
        var absent = SHA256.HashData("absent group-read snapshot kernel operation"u8);
        await fixture.WithActiveNativeComparators(receiver, (full, active, connection, floor) =>
        {
            // This tests the exact native kernel over genuine encrypted rows;
            // it does not manufacture group membership or signed group data.
            CheckGroupHistorySnapshot(full, floor, first, second, absent);
            CheckGroupHistorySnapshot(active, floor, first, second, absent);
            foreach (var operation in new[] { first, second })
            {
                byte[] original;
                using (var read = connection.CreateCommand())
                {
                    read.CommandText = "SELECT envelope FROM events WHERE operation=$op;";
                    read.Parameters.AddWithValue("$op", operation);
                    original = Assert.IsType<byte[]>(read.ExecuteScalar());
                }
                byte[] eventHash;
                using (var authenticated = active.ReadVerifiedOperation(floor, operation))
                    eventHash = Assert.IsType<OwnedDid2MessagingPersistedEvent>(authenticated).EventHash.ToArray();
                CheckIndexedOrdinaryReaders(full, floor, operation, eventHash, original);
                CheckIndexedOrdinaryReaders(active, floor, operation, eventHash, original);
                var parsed = Dpe2Codec.Decode(original);
                var ciphertext = new byte[parsed.Ciphertext.Length]; parsed.Ciphertext.CopyCiphertextTo(ciphertext); ciphertext[^1] ^= 1;
                var damaged = Dpe2Codec.Encode(new Dpe2Record(parsed.NetworkId.Span, parsed.SessionId.Span,
                    parsed.SenderDeviceId.Span, parsed.RecipientDeviceId.Span, parsed.OperationId.Span,
                    parsed.RatchetHeader, Dpe2Ciphertext.Import(ciphertext)));
                CryptographicOperations.ZeroMemory(ciphertext);
                _ = Dpe2Codec.Decode(damaged); // Valid framing; the committed ciphertext binding must fail.
                Assert.Equal(original.Length, damaged.Length);
                Assert.NotEqual(SHA256.HashData(original), SHA256.HashData(damaged));
                try
                {
                    Replace(damaged);
                    var before = ReadRouteReadRawSqlProjection(connection);
                    var legacyError = Record.Exception(() =>
                    {
                        var legacy = full.ReadVerifiedOperations(floor, [second, first]);
                        foreach (var row in legacy) row?.Dispose();
                    });
                    var fullError = Record.Exception(() => CheckGroupHistorySnapshot(full, floor, first, second, absent));
                    var activeError = Record.Exception(() => CheckGroupHistorySnapshot(active, floor, first, second, absent));
                    var closed = ClosedNativeReadFailure(fullError, "full") + ";" + ClosedNativeReadFailure(legacyError, "legacy") + ";" + ClosedNativeReadFailure(activeError, "active");
                    Assert.True(legacyError is CryptographicException or InvalidDataException, closed);
                    Assert.True(fullError is CryptographicException or InvalidDataException, closed);
                    Assert.True(activeError is CryptographicException or InvalidDataException, closed);
                    AssertIndexedOrdinaryReadersRefuse(full, floor, operation, eventHash, original);
                    AssertIndexedOrdinaryReadersRefuse(active, floor, operation, eventHash, original);
                    Assert.Equal(before, ReadRouteReadRawSqlProjection(connection));
                }
                finally { Replace(original); CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(damaged); CryptographicOperations.ZeroMemory(eventHash); }
                void Replace(byte[] envelope)
                {
                    using var change = connection.CreateCommand();
                    change.CommandText = "UPDATE events SET envelope=$envelope WHERE operation=$op;";
                    change.Parameters.AddWithValue("$envelope", envelope); change.Parameters.AddWithValue("$op", operation);
                    Assert.Equal(1, change.ExecuteNonQuery());
                }
            }
            CheckGroupHistorySnapshot(active, floor, first, second, absent);
        });
    }

    private static void CheckIndexedOrdinaryReaders(Did2MessagingSqlJournal sql, Did2MessagingFloor floor,
        byte[] operation, byte[] eventHash, byte[] envelope)
    {
        using var byOperation = sql.ReadVerifiedOperation(floor, operation);
        using var byEvent = sql.ReadVerifiedReceiveForEvent(floor, eventHash);
        Assert.NotNull(byOperation); Assert.NotNull(byEvent);
        Assert.Equal(envelope, byOperation.ExactEnvelope.ToArray());
        Assert.Equal(envelope, byEvent.ExactEnvelope.ToArray());
        Assert.Equal(ExactDpe2ReceiveReplayDisposition.ExactReplay,
            sql.CreateVerifiedTransitionContext(floor, operation, envelope).ReceiveReplayDisposition);
        using var state = sql.ReadVerifiedTransitionState(floor, operation, envelope, out var context);
        Assert.Equal(ExactDpe2ReceiveReplayDisposition.ExactReplay, context.ReceiveReplayDisposition);
    }

    private static void AssertIndexedOrdinaryReadersRefuse(Did2MessagingSqlJournal sql, Did2MessagingFloor floor,
        byte[] operation, byte[] eventHash, byte[] envelope)
    {
        var errors = new[]
        {
            Record.Exception(() => { using var row = sql.ReadVerifiedOperation(floor, operation); }),
            Record.Exception(() => { using var row = sql.ReadVerifiedReceiveForEvent(floor, eventHash); }),
            Record.Exception(() => sql.CreateVerifiedTransitionContext(floor, operation, envelope)),
            Record.Exception(() => { using var state = sql.ReadVerifiedTransitionState(floor, operation, envelope, out _); })
        };
        Assert.All(errors, error => Assert.True(error is CryptographicException, ClosedNativeReadFailure(error, "indexed-reader")));
    }

    private static string ClosedNativeReadFailure(Exception? error, string stage)
    {
        var member = error is null ? null : new System.Diagnostics.StackTrace(error, false).GetFrames()
            .Select(frame => frame.GetMethod()).FirstOrDefault(method => method?.DeclaringType?.Assembly == typeof(Did2MessagingSqlJournal).Assembly ||
                method?.DeclaringType?.Assembly == typeof(DeepIdV2ContactPathAuthoritySourceTests).Assembly);
        return stage + ":type=" + (error?.GetType().FullName ?? "none") + ";site=" +
            (member is null ? "none" : member.DeclaringType!.FullName + "." + member.Name);
    }

    private static void CheckGroupHistorySnapshot(Did2MessagingSqlJournal sql, Did2MessagingFloor floor,
        byte[] first, byte[] second, byte[] absent)
    {
        using var work = Did2MessagingSqlJournal.NativeWork.Measure();
        var history = sql.OpenGroupHistorySnapshot(floor);
        try
        {
            var metadataRows = work.MetadataRows; var scans = work.CipherScans;
            var rows = history.ReadOperations([second, absent]);
            try { Assert.Equal(2, rows.Count); Assert.NotNull(rows[0]); Assert.Null(rows[1]); }
            finally { foreach (var row in rows) row?.Dispose(); }
            Assert.Throws<ObjectDisposedException>(() => rows[0]!.OwnAuthenticatedDmc2());
            var older = history.ReadOperations([first]);
            try { Assert.Single(older); Assert.NotNull(older[0]); Assert.True(older[0]!.Ordinal < rows[0]!.Ordinal); }
            finally { foreach (var row in older) row?.Dispose(); }
            Assert.Equal(metadataRows, work.MetadataRows);
            Assert.Equal(scans, work.CipherScans);
            // Keep the existing32-envelope ceiling and checked selectors. A
            // stack-only snapshot cannot be captured by an assertion delegate.
            foreach (var invalid in new byte[][][] { [], [null!], [new byte[31]], [new byte[32]], [first, first], Enumerable.Repeat(first, 33).ToArray() })
            {
                Exception? rejection = null;
                try { _ = history.ReadOperations(invalid); } catch (Exception error) { rejection = error; }
                Assert.IsType<ArgumentException>(rejection);
            }
            Exception? nullRejection = null;
            try { _ = history.ReadOperations(null!); } catch (Exception error) { nullRejection = error; }
            Assert.IsType<ArgumentNullException>(nullRejection);
        }
        finally { history.Dispose(); }
        Exception? disposed = null;
        try { _ = history.ReadOperations([first]); } catch (Exception error) { disposed = error; }
        Assert.IsType<ObjectDisposedException>(disposed);
    }
}
