using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

// Structural local-custody tests, not a verified claim, handshake, native
// provider or delivery. No synthetic capability crosses a public crypto API.
public sealed class DeviceInitialSessionCustodyTests
{
    private static readonly byte[] Instance = Bytes(32, 3), Account = Bytes(32, 2), Network = Bytes(16, 1);

    [Fact]
    public void CheckpointHasClosedScopePhaseHashAndLength()
    {
        var empty = DeviceInitialSessionCheckpoint.Stable(Instance, Account, Network, 0, new byte[32]);
        using var stable = DeviceInitialSessionCheckpoint.Decode(empty, Instance, Account, Network);
        var payload = Bytes(180, 7);
        var pending = DeviceInitialSessionCheckpoint.Pending(Instance, Account, Network, stable, payload);
        using var decoded = DeviceInitialSessionCheckpoint.Decode(pending, Instance, Account, Network);
        Assert.Equal(2, decoded.Phase); Assert.Equal(1UL, decoded.Sequence); Assert.Equal(payload, decoded.Payload);
        foreach (var offset in new[] { 0, 1, 2, 3, 76, 108, 140, 44, 160 })
        {
            var changed = pending.ToArray(); changed[offset] ^= 1;
            Assert.ThrowsAny<CryptographicException>(() => DeviceInitialSessionCheckpoint.Decode(changed, Instance, Account, Network));
        }
        foreach (var offset in new[] { 4, 12, 156 })
        {
            var changed = pending.ToArray(); changed[offset] ^= 1;
            Assert.ThrowsAny<InvalidDataException>(() => DeviceInitialSessionCheckpoint.Decode(changed, Instance, Account, Network));
        }
        Assert.Throws<InvalidDataException>(() => DeviceInitialSessionCheckpoint.Decode(pending[..^1], Instance, Account, Network));
        using var full = DeviceInitialSessionCheckpoint.Decode(
            DeviceInitialSessionCheckpoint.Stable(Instance, Account, Network, 128, Bytes(32, 4)), Instance, Account, Network);
        Assert.Throws<InvalidDataException>(() => DeviceInitialSessionCheckpoint.Pending(Instance, Account, Network, full, payload));
        Assert.NotEqual(DeviceInitialSessionCheckpoint.EventHash([1], [2, 3]),
            DeviceInitialSessionCheckpoint.EventHash([1, 2], [3]));
        decoded.Dispose(); Assert.All(decoded.Payload, value => Assert.Equal(0, value));
    }

    [Fact]
    public void CompletedRowIsBoundedOwnedAndRejectsMixedDeviceState()
    {
        using var fixture = new Fixture(); var exact = fixture.Payload();
        using var owned = DeepIdV2InitialSessionCommit.RestoreCustody(exact);
        var original = owned.ExactDph2.ToArray(); exact[^1] ^= 1;
        Assert.Equal(original, owned.ExactDph2.ToArray());
        foreach (var offset in new[] { 0, 1 })
        {
            var changed = fixture.Payload(); changed[offset] ^= 1;
            Assert.Throws<InvalidDataException>(() => DeepIdV2InitialSessionCommit.RestoreCustody(changed));
        }
        foreach (var offset in new[] { 12, 148 })
        {
            var changed = fixture.Payload(); changed[offset] ^= 1;
            Assert.Throws<CryptographicException>(() => DeepIdV2InitialSessionCommit.RestoreCustody(changed));
        }
        var mixedDevice = fixture.Payload(); mixedDevice[fixture.TrsOffset + 108] ^= 1;
        Assert.Throws<MessagingCryptoV1StoreOpenException>(() => DeepIdV2InitialSessionCommit.RestoreCustody(mixedDevice));
        var changedPeer = fixture.Payload(); changedPeer[fixture.TrsOffset + 180] ^= 1;
        Assert.Throws<FormatException>(() => DeepIdV2InitialSessionCommit.RestoreCustody(changedPeer));
        var changedDirectory = fixture.Payload(); changedDirectory[fixture.TrsOffset + 148] ^= 1;
        var trs = changedDirectory.AsSpan(fixture.TrsOffset);
        MessagingCryptoV1Trs1.Sha256Domain("Deep/LocalState/V1/triple-ratchet-state-checksum", trs[..^32]).CopyTo(trs[^32..]);
        Assert.Throws<CryptographicException>(() => DeepIdV2InitialSessionCommit.RestoreCustody(changedDirectory));
        owned.Dispose(); Assert.Throws<ObjectDisposedException>(() => owned.ExactDph2);
        Assert.Empty(typeof(DeepIdV2InitialSessionCommit).GetConstructors());
        Assert.DoesNotContain(typeof(DeepIdV2InitialSessionCommit).GetProperties(), property => property.Name.Contains("Trs"));
    }

    [Fact]
    public void ConversationComesOnlyFromExactRetainedInitialEvents()
    {
        using var fixture = new Fixture();
        var init = fixture.InitialEvent(); var first = fixture.FirstEvent();
        using var owned = DeepIdV2InitialSessionCommit.RestoreCustody(fixture.Payload(init, first));
        Assert.Equal(Bytes(32, 40), owned.RequireInitialConversation(init, first));
        var returned = owned.RequireInitialConversation(init, first); returned[0] ^= 1;
        Assert.Equal(Bytes(32, 40), owned.RequireInitialConversation(init, first));
        using var reopened = DeepIdV2InitialSessionCommit.RestoreCustody(owned.CanonicalSpan);
        Assert.Equal(Bytes(32, 40), reopened.RequireInitialConversation(init, first));
        Assert.Throws<CryptographicException>(() => reopened.RequireInitialConversation(init, fixture.FirstEvent(conversation: 41)));
        Assert.Throws<CryptographicException>(() => reopened.RequireInitialConversation(first, init));
        Assert.Throws<InvalidDataException>(() => reopened.RequireInitialConversation(new byte[32769], first));
        using var noFirst = DeepIdV2InitialSessionCommit.RestoreCustody(fixture.Payload(init, []));
        Assert.Equal(Bytes(32, 40), noFirst.RequireInitialConversation(init, []));
        reopened.Dispose();
        Assert.Throws<ObjectDisposedException>(() => reopened.RequireInitialConversation(init, first));
    }

    [Theory]
    [InlineData(41, 2, 10, 2, 100001, 42)] // different conversation
    [InlineData(40, 3, 10, 2, 100001, 42)] // different account
    [InlineData(40, 2, 11, 2, 100001, 42)] // different device
    [InlineData(40, 2, 10, 1, 100001, 42)] // non-advancing sequence
    [InlineData(40, 2, 10, 2, 99999, 42)]  // earlier event time
    [InlineData(40, 2, 10, 2, 100001, 39)] // reused logical ID
    public void RehashedButInconsistentFirstEventCannotMintConversation(byte conversation, byte account,
        byte device, ulong sequence, ulong created, byte logical)
    {
        using var fixture = new Fixture(); var init = fixture.InitialEvent();
        var first = fixture.FirstEvent(conversation, account, device, sequence, created, logical);
        using var owned = DeepIdV2InitialSessionCommit.RestoreCustody(fixture.Payload(init, first));
        Assert.Throws<CryptographicException>(() => owned.RequireInitialConversation(init, first));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PendingRecoversExactResultBeforeOrAfterSqlCommit(bool failStabilization)
    {
        using var fixture = new Fixture();
        using (var store = fixture.Open()) await fixture.Initialize(store);
        var pending = fixture.Pending();
        Assert.True(await fixture.Storage.CompareExchangeAsync(DeviceInitialSessionCheckpoint.Slot,
            await fixture.ReadCheckpoint(), pending));
        if (failStabilization) fixture.Storage.FailNextStabilize = true;
        using (var store = fixture.Open())
        {
            if (failStabilization)
                await Assert.ThrowsAsync<IOException>(async () => await store.OpenInitialSessionCustodyAsync(fixture.Storage, Network, default));
            else await store.OpenInitialSessionCustodyAsync(fixture.Storage, Network, default);
        }
        // The failed stabilization left SQL committed, pending protected.
        // Reopen accepts only that exact result; never runs a handshake.
        using (var reopened = fixture.Open()) await reopened.OpenInitialSessionCustodyAsync(fixture.Storage, Network, default);
        Assert.Equal(fixture.Payload(), fixture.ReadPayload());
        Assert.Equal(1L, fixture.Count("device_initial_sessions"));
        Assert.Equal(1L, fixture.Count("device_agreement_authorizations"));
        using var checkpoint = await fixture.Storage.ReadOwnedAsync(DeviceInitialSessionCheckpoint.Slot);
        using var state = checkpoint!.Use(bytes => DeviceInitialSessionCheckpoint.Decode(bytes, Instance, Account, Network));
        Assert.Equal(1, state.Phase); Assert.Equal(1UL, state.Sequence); Assert.Empty(state.Payload);
    }

    [Theory]
    [InlineData("DELETE FROM device_initial_sessions;")]
    [InlineData("DELETE FROM device_operation_dedup WHERE operation_id IN (SELECT operation_id FROM device_initial_sessions);")]
    [InlineData("UPDATE device_agreement_authorizations SET purpose=2;")]
    [InlineData("UPDATE device_agreement_authorizations SET peer_public_key=zeroblob(32);")]
    public async Task StableCannotRepairRollbackOrSubstitutedBurn(string sql)
    {
        using var fixture = new Fixture();
        using (var store = fixture.Open()) await fixture.Initialize(store);
        Assert.True(await fixture.Storage.CompareExchangeAsync(DeviceInitialSessionCheckpoint.Slot,
            await fixture.ReadCheckpoint(), fixture.Pending()));
        using (var store = fixture.Open()) await store.OpenInitialSessionCustodyAsync(fixture.Storage, Network, default);
        var protectedBefore = await fixture.ReadCheckpoint(); fixture.Mutate(sql);
        if (sql.StartsWith("DELETE FROM device_operation_dedup", StringComparison.Ordinal))
        {
            var failure = Assert.Throws<DeviceStateStoreOpenException>(() => fixture.Open());
            Assert.Equal(DeviceStateStoreOpenFailure.Corrupt, failure.Reason);
        }
        else
        {
            using var reopened = fixture.Open();
            await Assert.ThrowsAsync<CryptographicException>(async () => await reopened.OpenInitialSessionCustodyAsync(fixture.Storage, Network, default));
        }
        Assert.Equal(protectedBefore, await fixture.ReadCheckpoint());
    }

    [Fact]
    public async Task MissingCheckpointFailsClosedWithoutRecreation()
    {
        using var fixture = new Fixture();
        using (var store = fixture.Open()) await fixture.Initialize(store);
        await fixture.Storage.DeleteBatchAsync([DeviceInitialSessionCheckpoint.Slot]);
        using var reopened = fixture.Open();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await reopened.OpenInitialSessionCustodyAsync(fixture.Storage, Network, default));
        Assert.Null(await fixture.Storage.ReadOwnedAsync(DeviceInitialSessionCheckpoint.Slot));
    }

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private sealed class Fixture : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "deep-initial-custody-" + Guid.NewGuid().ToString("N"));
        private readonly byte[] key = Bytes(32, 9), device = Bytes(32, 10), dpdHash = Bytes(32, 11), peer = Bytes(32, 12);
        private readonly ParsedDmd1 dmd;
        private readonly Dph2Record dph;
        internal FaultStorage Storage { get; } = new();
        internal int TrsOffset => 180 + dmd.CanonicalBytes.Length + Dph2Codec.Encode(dph).Length;
        internal Fixture()
        {
            Directory.CreateDirectory(directory);
            var dpd = ApplicationCoreCodec.CreateArtifactReference((ushort)ArtifactType.Dpd1, 776, dpdHash);
            dmd = ApplicationCoreCodec.AuthorDmd1(Network, Account, 1,
                ApplicationCoreCodec.CreateArtifactReference((ushort)ArtifactType.Dpa1, 644, Bytes(32, 13)),
                ApplicationCoreCodec.CreateArtifactReference((ushort)ArtifactType.Drs1, 356, Bytes(32, 14)),
                1, new byte[32], [new DeviceDirectoryEntry(device, dpd)], 100, Bytes(64, 15));
            var did = DeepIdV2Codec.AuthorDid2(Bytes(32, 16), Bytes(1952, 17), Bytes(16, 18));
            dph = new Dph2Record(Network, Account, device, 1, dpd.CanonicalBytes.Span, did.CanonicalBytes.Span,
                Bytes(32, 19), Bytes(32, 20), 1, Bytes(32, 21), Bytes(32, 22), Bytes(32, 23), 1,
                Bytes(32, 24), Bytes(32, 25), Dph2SelectedPrekey.LastResort(Bytes(32, 26), Bytes(32, 27)),
                Bytes(1088, 28), Bytes(32, 29), Bytes(24, 30), Dph2InitialCiphertext.Import(Bytes(4112, 31)));
        }
        internal SqliteDeviceStateStore Open() => new(new(Path.Combine(directory, "device.db"), key,
            DeviceAccountId32.FromBytes(Account), 1, 1, DeviceOperationId32.FromBytes(Instance)));
        internal async Task Initialize(SqliteDeviceStateStore store)
        {
            await Storage.WriteBatchAsync([new(DeviceInitialSessionCheckpoint.Slot,
                DeviceInitialSessionCheckpoint.Stable(Instance, Account, Network, 0, new byte[32]))]);
            await store.OpenInitialSessionCustodyAsync(Storage, Network, default);
            var evidence = CurrentDmd1Evidence.ForTesting(false, dmd.CanonicalBytes.Span, Network, Account, 1, 1,
                dmd.RecordHash.Span, new byte[32], 1, Bytes(32, 14),
                [new CurrentDmd1DeviceEvidence(device, 1, dpdHash, Bytes(32, 24))]);
            Assert.Equal(ProtectedCurrentDmd1CommitDisposition.Applied,
                (await store.CommitCurrentDmd1ForTestingAsync(DeviceOperationId32.FromBytes(Bytes(32, 32)), evidence, default)).Disposition);
        }
        internal byte[] Pending()
        {
            using var empty = DeviceInitialSessionCheckpoint.Decode(
                DeviceInitialSessionCheckpoint.Stable(Instance, Account, Network, 0, new byte[32]), Instance, Account, Network);
            return DeviceInitialSessionCheckpoint.Pending(Instance, Account, Network, empty, Payload());
        }
        internal byte[] InitialEvent() => ApplicationCoreCodec.AuthorDmc2(Network, Bytes(32, 39), Bytes(32, 40),
            Account, device, 1, 100000, 120000, Dmc2Flags.None, [],
            ApplicationCoreCodec.CreateSessionInitPayload(Bytes(32, 38), dmd,
                SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl)).CanonicalBytes.ToArray();
        internal byte[] FirstEvent(byte conversation = 40, byte senderAccount = 2, byte senderDevice = 10,
            ulong sequence = 2, ulong created = 100001, byte logical = 42) =>
            ApplicationCoreCodec.AuthorDmc2(Network, Bytes(32, logical), Bytes(32, conversation),
                Bytes(32, senderAccount), Bytes(32, senderDevice), sequence, created, 0, Dmc2Flags.None, [],
                ApplicationCoreCodec.CreateMessageCreatePayload("structural initial context")).CanonicalBytes.ToArray();
        internal byte[] Payload(byte[]? init = null, byte[]? first = null)
        {
            var evidence = CurrentDmd1Evidence.RestoreProtected(false, dmd.CanonicalBytes.Span, 1);
            var binding = LocalDeviceAgreementBinding.FromCompletedRecord(evidence, dph);
            var fingerprint = ProtectedCurrentDmd1Validation.FingerprintAgreement(evidence, binding,
                LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1, dph.ClaimOperationId.Span, peer);
            var dphBytes = Dph2Codec.Encode(dph); var trs = Trs();
            var payload = new byte[180 + dmd.CanonicalBytes.Length + dphBytes.Length + trs.Length]; payload[0] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(2), checked((ushort)dmd.CanonicalBytes.Length));
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(4), 1);
            Convert.FromHexString(fingerprint).CopyTo(payload, 12);
            Bytes(32, 33).CopyTo(payload, 44);
            (init is null ? Bytes(32, 34) : DeviceInitialSessionCheckpoint.EventHash(init, first ?? [])).CopyTo(payload, 76);
            Bytes(32, 35).CopyTo(payload, 108);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(140), checked((uint)dphBytes.Length));
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(144), checked((uint)trs.Length)); peer.CopyTo(payload, 148);
            dmd.CanonicalBytes.Span.CopyTo(payload.AsSpan(180)); dphBytes.CopyTo(payload, 180 + dmd.CanonicalBytes.Length);
            trs.CopyTo(payload, TrsOffset); CryptographicOperations.ZeroMemory(trs); return payload;
        }
        private byte[] Trs()
        {
            var trs = new byte[601]; "TRS1"u8.CopyTo(trs); trs[4] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(trs.AsSpan(5), 0x0201);
            BinaryPrimitives.WriteUInt32BigEndian(trs.AsSpan(8), 601);
            dph.SessionId.Span.CopyTo(trs.AsSpan(12)); device.CopyTo(trs, 108);
            BinaryPrimitives.WriteUInt64BigEndian(trs.AsSpan(140), 1);
            dmd.RecordHash.Span.CopyTo(trs.AsSpan(148));
            dph.ResponderDeviceId.Span.CopyTo(trs.AsSpan(180)); BinaryPrimitives.WriteUInt64BigEndian(trs.AsSpan(212), 1);
            BinaryPrimitives.WriteUInt64BigEndian(trs.AsSpan(252), 1);
            BinaryPrimitives.WriteUInt32BigEndian(trs.AsSpan(528), 1); trs[536] = 1; trs.AsSpan(537, 32).Fill(36);
            MessagingCryptoV1Trs1.Sha256Domain("Deep/LocalState/V1/triple-ratchet-state-checksum", trs.AsSpan(0, 569)).CopyTo(trs, 569);
            return trs;
        }
        private SqliteConnection Connect()
        {
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path.Combine(directory, "device.db"), Pooling = false }.ToString());
            connection.Open(); Assert.Equal(0, SQLitePCL.raw.sqlite3_key(connection.Handle, key)); return connection;
        }
        internal void Mutate(string sql) { using var connection = Connect(); using var command = connection.CreateCommand(); command.CommandText = sql; command.ExecuteNonQuery(); }
        internal long Count(string table) { using var connection = Connect(); using var command = connection.CreateCommand(); command.CommandText = "SELECT COUNT(*) FROM " + table; return (long)command.ExecuteScalar()!; }
        internal byte[] ReadPayload() { using var connection = Connect(); using var command = connection.CreateCommand(); command.CommandText = "SELECT payload FROM device_initial_sessions;"; return (byte[])command.ExecuteScalar()!; }
        internal async Task<byte[]> ReadCheckpoint() { using var value = await Storage.ReadOwnedAsync(DeviceInitialSessionCheckpoint.Slot); return value!.Use(bytes => bytes.ToArray()); }
        public void Dispose() { CryptographicOperations.ZeroMemory(key); Directory.Delete(directory, recursive: true); }
    }
    private sealed class FaultStorage : IDeepSecureStorage
    {
        private readonly InMemoryDeepSecureStorage inner = new();
        internal bool FailNextStabilize;
        public Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken cancellationToken = default) => inner.ReadOwnedAsync(slot, cancellationToken);
        public Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken cancellationToken = default) => inner.WriteBatchAsync(writes, cancellationToken);
        public Task DeleteBatchAsync(IReadOnlyList<string> slots, CancellationToken cancellationToken = default) => inner.DeleteBatchAsync(slots, cancellationToken);
        public Task PurgeStoreV2NamespaceAsync(CancellationToken cancellationToken = default) => inner.PurgeStoreV2NamespaceAsync(cancellationToken);
        public Task PurgeStoreV1NamespaceAsync(CancellationToken cancellationToken = default) => inner.PurgeStoreV1NamespaceAsync(cancellationToken);
        public Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement, CancellationToken cancellationToken = default)
        {
            if (FailNextStabilize && slot == DeviceInitialSessionCheckpoint.Slot && replacement.Span[1] == 1)
            { FailNextStabilize = false; throw new IOException("Injected protected stabilization stop."); }
            return inner.CompareExchangeAsync(slot, expected, replacement, cancellationToken);
        }
    }
}
