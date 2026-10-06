using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

// Structural metadata fixtures only. These do not mint a compaction authority
// or prove that an event/digest came from authenticated SQL/native custody.
public sealed class Did2MessagingHistoryCheckpointTests
{
    [Fact]
    public void EmptyAndForwardProjectionRoundTripWithIndependentLifetimeOrdinal()
    {
        var scope = Scope(); var empty = Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope);
        Assert.Equal(1UL, empty.Revision); Assert.Equal(0UL, empty.HistoryCount);
        Assert.Equal(Did2MessagingFloor.Empty(scope).Exact.ToArray(), empty.Basis.Exact.ToArray());
        var first = empty.NextProjection(scope, Basis(scope, 4097, 4096), Header(), Digest(), 4095);
        var next = first.NextProjection(scope, Basis(scope, 4098, 4097), Header(), Digest(2), 4096);
        Assert.Equal(3UL, next.Revision); Assert.Equal(4098UL, next.Basis.Ordinal);
        Assert.Equal(4096UL, next.HistoryCount);
        Assert.Equal(next.Exact.ToArray(), Did2MessagingHistoryCheckpoint.Decode(next.Exact.Span, scope).Exact.ToArray());
        var callerCopy = next.Exact.ToArray(); var restored = Did2MessagingHistoryCheckpoint.Decode(callerCopy, scope);
        callerCopy[264] ^= 1; Assert.Equal(next.Exact.ToArray(), restored.Exact.ToArray());
    }

    [Theory]
    [InlineData("length-short")]
    [InlineData("length-long")]
    [InlineData("generation")]
    [InlineData("reserved")]
    [InlineData("scope")]
    [InlineData("revision-zero")]
    [InlineData("revision-one")]
    [InlineData("pending")]
    [InlineData("latched")]
    [InlineData("ordinal-one")]
    [InlineData("ordinal-overflow")]
    [InlineData("count-overflow")]
    [InlineData("missing-initial")]
    [InlineData("missing-history")]
    public void ClosedGrammarRejectsMalformedProjection(string defect)
    {
        var scope = Scope(); var raw = Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope)
            .NextProjection(scope, Basis(scope, 3, 2), Header(), Digest(), 1).Exact.ToArray();
        switch (defect)
        {
            case "length-short": raw = raw[..^1]; break;
            case "length-long": raw = [..raw, 0]; break;
            case "generation": raw[0] = 2; break;
            case "reserved": raw[1] = 1; break;
            case "scope": raw[12] ^= 1; break;
            case "revision-zero": BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(4), 0); break;
            case "revision-one": BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(4), 1); break;
            case "pending": raw[45] = 2; break;
            case "latched": raw[46] = 2; raw.AsSpan(128, 64).Clear(); break;
            case "ordinal-one": BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(80), 1); BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(120), 1); break;
            case "ordinal-overflow": BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(80), (ulong)long.MaxValue + 1); break;
            case "count-overflow": BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(296), 2); break;
            case "missing-initial": raw.AsSpan(232, 32).Clear(); break;
            case "missing-history": raw.AsSpan(264, 32).Clear(); break;
            default: throw new InvalidOperationException();
        }
        // The floor and enclosing metadata each have their own closed reject;
        // an error is required, never a fallback/repair or normalized value.
        var error = Record.Exception(() => Did2MessagingHistoryCheckpoint.Decode(raw, scope));
        Assert.True(error is InvalidDataException or CryptographicException, error?.GetType().FullName ?? "No rejection");
    }

    [Theory]
    [InlineData(4)]
    [InlineData(232)]
    [InlineData(264)]
    [InlineData(296)]
    public void EmptyRegistrationRejectsUnexplainedRevisionCommitmentsOrRows(int offset)
    {
        var scope = Scope(); var raw = Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact.ToArray();
        raw[offset] ^= 1;
        Assert.Throws<InvalidDataException>(() => Did2MessagingHistoryCheckpoint.Decode(raw, scope));
    }

    [Theory]
    [InlineData("same-prefix")]
    [InlineData("lower-count")]
    [InlineData("lower-ratchet")]
    [InlineData("initial-replacement")]
    [InlineData("header-size")]
    [InlineData("digest-size")]
    [InlineData("revision-overflow")]
    public void SuccessorCannotRollbackOrReplaceAlreadyCommittedHistory(string defect)
    {
        var scope = Scope(); var first = Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope)
            .NextProjection(scope, Basis(scope, 3, 2), Header(), Digest(), 1);
        var basis = Basis(scope, 4, 3); var header = Header(); var digest = Digest(2); var count = 2UL;
        switch (defect)
        {
            case "same-prefix": basis = first.Basis; break;
            case "lower-count": count = 0; break;
            case "lower-ratchet": basis = Basis(scope, 4, 1); break;
            case "initial-replacement": header[0] ^= 1; break;
            case "header-size": header = header[..^1]; break;
            case "digest-size": digest = digest[..^1]; break;
            case "revision-overflow":
                var raw = first.Exact.ToArray(); BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(4), ulong.MaxValue);
                first = Did2MessagingHistoryCheckpoint.Decode(raw, scope); break;
            default: throw new InvalidOperationException();
        }
        var before = first.Exact.ToArray();
        var error = Record.Exception(() => first.NextProjection(scope, basis, header, digest, count));
        if (defect == "revision-overflow") Assert.IsType<OverflowException>(error);
        else Assert.True(error is InvalidDataException or CryptographicException, error?.GetType().FullName ?? "No rejection");
        Assert.Equal(before, first.Exact.ToArray());
    }

    [Fact]
    public async Task MandatoryProtectedReaderRejectsAbsentForeignAndCancelledWithoutInitialization()
    {
        var scope = Scope(); using var storage = new InMemoryDeepSecureStorage();
        await Assert.ThrowsAsync<InvalidDataException>(() => Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, default));
        using (var absent = await storage.ReadOwnedAsync(Did2MessagingHistoryCheckpoint.Slot(scope))) Assert.Null(absent);
        var foreign = Did2MessagingHistoryCheckpoint.RegisteredEmpty(Scope(2)).Exact.ToArray();
        await storage.WriteBatchAsync([new(Did2MessagingHistoryCheckpoint.Slot(scope), foreign)]);
        await Assert.ThrowsAsync<InvalidDataException>(() => Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, default));
        using (var unchanged = await storage.ReadOwnedAsync(Did2MessagingHistoryCheckpoint.Slot(scope)))
            Assert.Equal(foreign, unchanged!.Use(bytes => bytes.ToArray()));
        var current = Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact.ToArray();
        Assert.True(await storage.CompareExchangeAsync(Did2MessagingHistoryCheckpoint.Slot(scope), foreign, current));
        Assert.Equal(current, (await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, default)).Exact.ToArray());
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, cancellation.Token));
    }

    private static byte[] Header() => Enumerable.Repeat((byte)17, Did2MessagingFloor.MetadataBytes).ToArray();
    private static byte[] Digest(byte value = 1) => Enumerable.Repeat(value, 32).ToArray();
    private static Did2MessagingFloor Basis(Did2MessagingSessionScope scope, ulong ordinal, ulong generation)
    {
        var raw = Did2MessagingFloor.Empty(scope).Exact.ToArray(); raw[2] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(36), ordinal);
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(76), generation);
        raw.AsSpan(44, 32).Fill(1); raw.AsSpan(84, 64).Fill(2);
        return Did2MessagingFloor.Decode(raw, scope);
    }
    private static Did2MessagingSessionScope Scope(byte network = 1)
    {
        var bytes = new byte[404]; bytes[0] = 1; bytes[1] = 1; bytes.AsSpan(4, 16).Fill(network);
        foreach (var offset in new[] { 20, 52, 92, 132, 172, 212, 244, 276, 308, 340, 372 }) bytes.AsSpan(offset, 32).Fill(checked((byte)(offset % 251 + 1)));
        foreach (var offset in new[] { 84, 124, 164, 204 }) BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), 1);
        return Did2MessagingSessionScope.RestoreMetadata(bytes);
    }
}
