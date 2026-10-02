using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Protocol.ApplicationCore;
using System.Text;
using System.Text.Json;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

// Structural codec/SQL parity only. Arbitrary fixture signatures never prove
// current endpoints, explicit user consent, DPE2 authentication or device E2E.
public sealed class Did2ContactAcceptCustodyTests
{
    [Fact]
    public void ProtectedCodecHasCanonicalScopeCountRolePositionAndLogicalBinding()
    {
        var scope = Scope(); var operation = B(32, 20); var accept = Accept(scope, operation);
        var entry = new byte[468 + accept.Length]; operation.CopyTo(entry, 0); scope.Exact.CopyTo(entry.AsSpan(32));
        B(32, 25).CopyTo(entry, 436); accept.CopyTo(entry, 468);
        using var state = new ProtectedDid2ContactAcceptJournal.State();
        state.Entries.Add(Convert.ToHexString(operation), ProtectedDid2ContactAcceptJournal.Entry.Decode(entry, scope.Network, scope.LocalAccount, scope.Instance));
        var encoded = ProtectedDid2ContactAcceptJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        using var decoded = ProtectedDid2ContactAcceptJournal.Decode(encoded, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Equal(accept, decoded.FindScope(scope)!.Accept.ToArray());
        Assert.Equal(2, encoded[0]);
        Assert.Equal(entry.Length, (int)BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(92)));
        foreach (var offset in new[] { 0, 1, 2, 11, 12, 28, 60, 92, 96 + 33, 96 + 436, 96 + 468 + 44 })
        {
            var changed = encoded.ToArray(); changed[offset] ^= 0x80;
            Assert.ThrowsAny<Exception>(() => ProtectedDid2ContactAcceptJournal.Decode(changed, scope.Network, scope.LocalAccount, scope.Instance));
            CryptographicOperations.ZeroMemory(changed);
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactAcceptJournal.Decode(encoded[..^1], scope.Network, scope.LocalAccount, scope.Instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactAcceptJournal.Decode([.. encoded, 0], scope.Network, scope.LocalAccount, scope.Instance));
        var retired = encoded.ToArray(); retired[0] = 1;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactAcceptJournal.Decode(retired, scope.Network, scope.LocalAccount, scope.Instance));
        CryptographicOperations.ZeroMemory(retired);
        var hostileLength = encoded.ToArray(); BinaryPrimitives.WriteUInt32BigEndian(hostileLength.AsSpan(92), uint.MaxValue);
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactAcceptJournal.Decode(hostileLength, scope.Network, scope.LocalAccount, scope.Instance));
        CryptographicOperations.ZeroMemory(hostileLength);
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactAcceptJournal.Decode(
            new byte[ProtectedDid2ContactAcceptJournal.MaximumBytes + 1], scope.Network, scope.LocalAccount, scope.Instance));
        var disposedEntry = decoded.FindScope(scope)!;
        decoded.Dispose(); Assert.Throws<ObjectDisposedException>(() => disposedEntry.Accept.ToArray());
        foreach (var bytes in new[] { operation, accept, entry, encoded }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ContactAcceptUsesClosedSeparateHandoffAndAuthoredPositionParity(bool sqlite)
    {
        var scope = Scope(); var op = B(32, 20); var exact = Accept(scope, op); var other = Accept(scope, B(32, 21));
        var path = Path.Combine(Path.GetTempPath(), "deep-accept-" + Guid.NewGuid().ToString("N") + ".db");
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using IDisposable store = sqlite ? new SqliteDeepMailboxStore(new(path, key)) : new InMemoryAuthenticatedDirectDmc2Inbox();
            using var first = AuthenticatedContactAcceptDmc2.CreateForTests(exact, scope);
            using var retry = AuthenticatedContactAcceptDmc2.CreateForTests(exact, scope);
            using var conflict = AuthenticatedContactAcceptDmc2.CreateForTests(other, scope);
            Task<DirectDmc2InboxDisposition> Apply(AuthenticatedContactAcceptDmc2 handoff) => store is SqliteDeepMailboxStore sql
                ? sql.MaterializeContactAcceptAsync(handoff) : ((InMemoryAuthenticatedDirectDmc2Inbox)store).MaterializeContactAcceptAsync(handoff);
            Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Apply(first));
            Assert.Equal(DirectDmc2InboxDisposition.ExactReplay, await Apply(retry));
            if (store is SqliteDeepMailboxStore disk)
            {
                Assert.Empty(await disk.ListDirectMessageCreatesAsync(scope.LocalAccount.ToArray(), 1, scope.Conversation.ToArray()));
                using var text = await disk.StageDirectTextAsync(scope.Network.ToArray(), scope.LocalAccount.ToArray(), 1,
                    scope.LocalDevice.ToArray(), scope.Conversation.ToArray(), scope.RemoteAccount.ToArray(), scope.RemoteDevice.ToArray(),
                    "after explicit acceptance", DateTimeOffset.FromUnixTimeMilliseconds(2000));
                Assert.Equal(4UL, text.SenderSequence);
            }
            Assert.Equal(DirectDmc2InboxDisposition.ForkLatched, await Apply(conflict));
            Assert.Equal(DirectDmc2InboxDisposition.ForkLatched, await Apply(first));
        }
        finally
        {
            foreach (var bytes in new[] { key, exact, other, op }) CryptographicOperations.ZeroMemory(bytes);
            foreach (var file in new[] { path, path + "-wal", path + "-shm", path + "-journal" }) File.Delete(file);
        }
    }

    internal static Did2MessagingSessionScope Scope()
    {
        var bytes = new byte[404]; bytes[0] = 1; bytes[1] = 2; B(16, 9).CopyTo(bytes, 4);
        foreach (var offset in new[] { 20, 52, 92, 132, 172, 212, 244, 276, 308, 340, 372 }) B(32, (byte)(offset % 200 + 1)).CopyTo(bytes, offset);
        foreach (var offset in new[] { 84, 124, 164, 204 }) BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), 1);
        return Did2MessagingSessionScope.RestoreMetadata(bytes);
    }
    internal static byte[] Accept(Did2MessagingSessionScope scope, byte[] operation)
    {
        // Exact current frozen framing is decoded, never promoted to runtime author authority.
        var xur = Record("XUR1", [scope.Network.ToArray(), scope.LocalAccount.ToArray(), B(32, 10), U64(0), new byte[32],
            Ref("PMT2", 1, 11), B(32, 12), B(32, 13), B(32, 14), U16(7), U64(1), U64(2), scope.LocalDevice.ToArray(), Ref("DPD1", 1, 15), B(64, 16)]);
        var package = FrozenPrivateRoute();
        var payload = new byte[682 + package.Length]; scope.Relationship.CopyTo(payload); B(32, 25).CopyTo(payload, 32);
        Ref("DAB2", 2, 26).CopyTo(payload, 64); scope.LocalDirectory.CopyTo(payload.AsSpan(102));
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(136), 538); xur.CopyTo(payload, 140);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(678), checked((uint)package.Length)); package.CopyTo(payload, 682);
        var exact = Record("DMC2", [scope.Network.ToArray(), ProtectedDid2ContactAcceptJournal.LogicalId(scope, operation),
            scope.Conversation.ToArray(), scope.LocalAccount.ToArray(), scope.LocalDevice.ToArray(), U64(3), U64(1000), U64(1900), U16(3), new byte[4], [], payload]);
        Assert.Equal(6199, exact.Length); Assert.Equal(Dmc2ContentKind.ContactAccept, ApplicationCoreCodec.DecodeDmc2(exact).ContentKind);
        CryptographicOperations.ZeroMemory(xur); CryptographicOperations.ZeroMemory(payload); return exact;
    }
    private static byte[] FrozenPrivateRoute()
    {
        var path = Directory.GetCurrentDirectory();
        while (path is not null)
        {
            var candidate = Path.Combine(path, "..", "docs", "survival-program", "releases", "v3.0.0", "specs", "contact-codec-v1.vectors.json");
            if (File.Exists(candidate))
            {
                using var document = JsonDocument.Parse(File.ReadAllBytes(candidate));
                var item = document.RootElement.GetProperty("primitives").EnumerateArray().Single(value => value.GetProperty("id").GetString() == "dmc2-contact-accept");
                var payload = Convert.FromHexString(item.GetProperty("fixtureBytesHex").GetString()!);
                var package = payload[682..];
                Assert.Equal(package.Length, (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(678)));
                _ = DeepIdV2ContactMailboxRouteCodec.Decode(package);
                return package;
            }
            path = Directory.GetParent(path)?.FullName;
        }
        throw new FileNotFoundException("Current private route fixture was not found.");
    }
    private static byte[] Record(string magic, byte[][] fields)
    {
        var bytes = new byte[12 + fields.Sum(field => 8 + field.Length)]; Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Length)); var offset = 12;
        for (var i = 0; i < fields.Length; i++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)(i + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 4), checked((uint)fields[i].Length));
            fields[i].CopyTo(bytes, offset + 8); offset += fields[i].Length + 8;
        }
        return bytes;
    }
    private static byte[] Ref(string magic, ushort version, byte fill)
    { var bytes = new byte[38]; Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), version); B(32, fill).CopyTo(bytes, 6); return bytes; }
    private static byte[] B(int size, byte fill) => Enumerable.Repeat(fill, size).ToArray();
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
}
