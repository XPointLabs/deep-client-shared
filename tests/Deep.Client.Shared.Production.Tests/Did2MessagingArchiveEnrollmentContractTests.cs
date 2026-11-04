using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

// Closed metadata fixtures only. Parsing these records does not authenticate
// source SQL, complete enrollment, or supply a native/runtime capability.
public sealed class Did2MessagingArchiveEnrollmentContractTests
{
    [Theory]
    [InlineData(1, 0, 0)]
    [InlineData(2, 0, 0)]
    [InlineData(2, 1, 0)]
    [InlineData(2, 0, 1)]
    [InlineData(2, 1, 1)]
    public void OrdinaryCatalogRequiresEverySessionIndexedWhileExplicitReaderPreservesExactKeys(byte version, byte first, byte second)
    {
        var (raw, scopes) = Catalog(version, first, second);
        using var enrollment = ProtectedDid2MessagingSessionCatalog.DecodeForEnrollment(raw, scopes[0].Network,
            scopes[0].LocalAccount, scopes[0].Instance);
        Assert.Equal(raw, enrollment.Exact.ToArray()); Assert.Equal(2, enrollment.Count);
        Assert.Equal(1UL + 2 + 2 + first + second, BinaryPrimitives.ReadUInt64BigEndian(raw.AsSpan(4)));
        if (version == 2 && first == 1 && second == 1)
        {
            using var ordinary = ProtectedDid2MessagingSessionCatalog.Decode(raw, scopes[0].Network, scopes[0].LocalAccount, scopes[0].Instance);
            Assert.True(ordinary.AllIndexed); Assert.Equal(raw, ordinary.Exact.ToArray());
        }
        else Reject(() => ProtectedDid2MessagingSessionCatalog.Decode(raw, scopes[0].Network, scopes[0].LocalAccount, scopes[0].Instance).Dispose());
        if (version == 2 && first == 1 && second == 0)
        {
            var comparison = enrollment.BeforeIndexedComparison(0);
            var expected = raw.ToArray(); expected[93] = 0;
            Put64(expected, 4, BinaryPrimitives.ReadUInt64BigEndian(raw.AsSpan(4)) - 1);
            Assert.Equal(expected, comparison); Assert.Equal(raw, enrollment.Exact.ToArray());
            // The comparison copy cannot become ordinary admission or change
            // another entry/key; it only recognizes one exact adoption result.
            Reject(() => ProtectedDid2MessagingSessionCatalog.Decode(comparison, scopes[0].Network, scopes[0].LocalAccount, scopes[0].Instance).Dispose());
            Assert.Equal(raw.AsSpan(94).ToArray(), comparison.AsSpan(94).ToArray());
        }
    }

    [Fact]
    public async Task FinalReadyOrMalformedProgressRemainsAnAccountWideOrdinaryReadFence()
    {
        var (raw, scopes) = Catalog(2, 1, 1); var scope = scopes[0];
        foreach (var progress in new[] { Progress(scope).Advance(scope, ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SchemaStaged,
                0, 0, Did2MessagingArchiveRoot.Empty(scope).PatriciaHash, Did2MessagingArchiveReducer.Empty(scope).Digest.Span)
            .Advance(scope, ProtectedDid2MessagingArchiveEnrollment.PhaseKind.Building, 0, 0,
                Did2MessagingArchiveRoot.Empty(scope).PatriciaHash, Did2MessagingArchiveReducer.Empty(scope).Digest.Span)
            .Advance(scope, ProtectedDid2MessagingArchiveEnrollment.PhaseKind.FinalReady, 0, 0,
                Did2MessagingArchiveRoot.Empty(scope).PatriciaHash, Did2MessagingArchiveReducer.Empty(scope).Digest.Span).Exact.ToArray(), new byte[] { 0 } })
        {
            using var storage = new InMemoryDeepSecureStorage();
            await storage.WriteBatchAsync([new(ProtectedDid2MessagingSessionCatalog.Slot, raw)]);
            var catalog = new ProtectedDid2MessagingSessionCatalog(storage, scope.Network, scope.LocalAccount, scope.Instance);
            using (var before = await catalog.ReadAsync(default)) Assert.True(before.AllIndexed);
            await storage.WriteBatchAsync([new(ProtectedDid2MessagingArchiveEnrollment.Slot, progress)]);
            await Assert.ThrowsAsync<InvalidOperationException>(() => catalog.ReadAsync(default));
            using var retained = await storage.ReadOwnedAsync(ProtectedDid2MessagingSessionCatalog.Slot);
            Assert.True(retained!.Use(bytes => bytes.SequenceEqual(raw)));
            using var stillFenced = await storage.ReadOwnedAsync(ProtectedDid2MessagingArchiveEnrollment.Slot);
            Assert.NotNull(stillFenced);
        }
    }

    [Fact]
    public void ProgressHasExactFrozenGuardsAndHashLinkedRevisionsWithoutGrantingEarlyAdoption()
    {
        var scope = Scope(1); var progress = Progress(scope); var empty = Did2MessagingArchiveRoot.Empty(scope);
        Assert.Equal(1120, progress.Exact.Length); Assert.Equal(1UL, progress.Revision);
        Assert.Equal(0UL, progress.Cursor); Assert.Equal(0UL, progress.Count);
        Assert.Equal(Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Basis.Exact.ToArray(), progress.TargetBasis.Exact.ToArray());
        Reject(() => progress.FinalRoot(scope));
        foreach (var phase in new[] { ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SchemaStaged,
            ProtectedDid2MessagingArchiveEnrollment.PhaseKind.Building, ProtectedDid2MessagingArchiveEnrollment.PhaseKind.FinalReady })
        {
            var prior = progress.Exact.ToArray();
            progress = progress.Advance(scope, phase, 0, 0, empty.PatriciaHash, Did2MessagingArchiveReducer.Empty(scope).Digest.Span);
            Assert.Equal(BinaryPrimitives.ReadUInt64BigEndian(prior.AsSpan(8)) + 1, progress.Revision);
            Assert.Equal(SHA256.HashData(prior), progress.PreviousHash.ToArray());
            Assert.Equal(prior.AsSpan(16, 968).ToArray(), progress.Exact.Span.Slice(16, 968).ToArray());
            Assert.Equal(prior, ProtectedDid2MessagingArchiveEnrollment.Decode(prior, scope).Exact.ToArray());
        }
        Assert.Equal(empty.Exact.ToArray(), progress.FinalRoot(scope).Exact.ToArray());
        Reject(() => progress.Advance(scope, ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SchemaStaged, 0, 0,
            empty.PatriciaHash, empty.SummaryHash));
    }

    [Theory]
    [InlineData("version")] [InlineData("phase")] [InlineData("reserved")] [InlineData("total")]
    [InlineData("revision")] [InlineData("scope")] [InlineData("guard")] [InlineData("cursor")]
    [InlineData("count")] [InlineData("patricia")] [InlineData("reducer")] [InlineData("previous")]
    [InlineData("tail")] [InlineData("truncated")] [InlineData("trailing")]
    public void HostileProgressCannotBecomeAnEnrollmentCandidate(string defect)
    {
        var scope = Scope(1); var raw = Progress(scope).Exact.ToArray();
        switch (defect)
        {
            case "version": raw[0] = 2; break;
            case "phase": raw[1] = 5; break;
            case "reserved": raw[2] = 1; break;
            case "total": raw[7] ^= 1; break;
            case "revision": raw.AsSpan(8, 8).Clear(); break;
            case "scope": raw[16] ^= 1; break;
            case "guard": raw.AsSpan(700, 32).Clear(); break;
            case "cursor": Put64(raw, 984, 1); break;
            case "count": Put64(raw, 992, 1); break;
            case "patricia": raw.AsSpan(1000, 32).Clear(); break;
            case "reducer": raw.AsSpan(1032, 32).Clear(); break;
            case "previous": raw[1064] = 1; break;
            case "tail": raw[1119] = 1; break;
            case "truncated": raw = raw[..^1]; break;
            case "trailing": raw = [.. raw, 0]; break;
        }
        Reject(() => ProtectedDid2MessagingArchiveEnrollment.Decode(raw, scope));
    }

    private static ProtectedDid2MessagingArchiveEnrollment Progress(Did2MessagingSessionScope scope)
    {
        var empty = Did2MessagingArchiveRoot.Empty(scope);
        return ProtectedDid2MessagingArchiveEnrollment.Create(scope, Did2MessagingFloor.Empty(scope),
            Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope), Enumerable.Range(0, 8).Select(i => (ReadOnlyMemory<byte>)Hash(900 + i)).ToArray(),
            empty.PatriciaHash, empty.SummaryHash);
    }
    private static (byte[] Raw, Did2MessagingSessionScope[] Scopes) Catalog(byte version, byte first, byte second)
    {
        var scopes = new[] { Scope(1), Scope(2) }.OrderBy(scope => Convert.ToHexString(scope.Hash), StringComparer.Ordinal).ToArray();
        var raw = new byte[92 + 2 * 440]; raw[0] = version;
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(2), 2); Put64(raw, 4, 5UL + first + second);
        scopes[0].Network.CopyTo(raw.AsSpan(12)); scopes[0].LocalAccount.CopyTo(raw.AsSpan(28)); scopes[0].Instance.CopyTo(raw.AsSpan(60));
        for (var index = 0; index < 2; index++)
        {
            var offset = 92 + index * 440; raw[offset] = 2; raw[offset + 1] = index == 0 ? first : second;
            scopes[index].Exact.CopyTo(raw.AsSpan(offset + 4)); Hash(800 + index).CopyTo(raw, offset + 408);
        }
        return (raw, scopes);
    }
    private static Did2MessagingSessionScope Scope(int variant)
    {
        var raw = new byte[404]; raw[0] = 1; raw[1] = 1; raw.AsSpan(4, 16).Fill(1);
        foreach (var offset in new[] { 20, 52, 92, 132, 172, 244, 276, 340, 372 }) Hash(offset).CopyTo(raw, offset);
        foreach (var offset in new[] { 212, 308 }) Hash(offset + variant).CopyTo(raw, offset);
        foreach (var offset in new[] { 84, 124, 164, 204 }) Put64(raw, offset, 1);
        return Did2MessagingSessionScope.RestoreMetadata(raw);
    }
    private static byte[] Hash(int value) => SHA256.HashData(BitConverter.GetBytes(value));
    private static void Put64(byte[] raw, int offset, ulong value) => BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(offset), value);
    private static void Reject(Action action)
    { var error = Record.Exception(action); Assert.True(error is InvalidDataException or CryptographicException, error?.GetType().Name ?? "Hostile metadata was accepted."); }
}
