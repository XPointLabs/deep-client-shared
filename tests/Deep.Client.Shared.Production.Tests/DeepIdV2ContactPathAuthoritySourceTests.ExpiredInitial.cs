using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.PreKeyV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("pending")]
    [InlineData("sql")]
    [InlineData("stable")]
    [InlineData("lost-ack")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedMailboxReceive_ExpiredInitialHasTerminalCustodyNoSessionAndExactAck(string cut)
    {
        // Actual authenticated PQ Initial, encrypted cold store and native
        // consumption. Signed in-process issuer/terminal, NOT physical E2E.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, longMailboxWindow: true, encryptedStorage: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xd1), oneTimeIndex: 0);
        byte[] initial;
        using (var sent = await complete(fixture.Accounts)) initial = sent.ExactDph2.ToArray();
        var expiry = Math.Max(init.ExpiresAtUnixMilliseconds, hello.ExpiresAtUnixMilliseconds);
        var delta = checked(expiry / 1000 + 31 - fixture.CurrentProofTime);
        fixture.ProofTime += delta; fixture.Sample += delta;
        var grants = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var terminal = new OwnedReadTerminal(fixture, initial) { LoseAckReply = cut == "lost-ack" };
        var snapshot = await fixture.ExpiredInitialCatalogSnapshotAsync();
        if (cut is "pending" or "sql" or "stable")
        {
            var point = cut switch { "pending" => ResponderInitialSessionFailpoint.AfterPending,
                "sql" => ResponderInitialSessionFailpoint.AfterSqlCommit, _ => ResponderInitialSessionFailpoint.AfterStable };
            var hit = false;
            using (ResponderInitialSessionTestHooks.Push(value =>
            { if (value == point) { hit = true; throw new IOException("Injected terminal Initial boundary."); } }))
                await Assert.ThrowsAsync<IOException>(() => fixture.SynchronizeNativeReceiver(grants, terminal));
            Assert.True(hit); Assert.Equal(0, terminal.AckCalls);
            fixture.ColdReopenReceiverStoreStorage();
        }
        if (cut == "lost-ack")
        {
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SynchronizeNativeReceiver(grants, terminal));
            Assert.Equal(1, terminal.AckCalls);
            terminal.LoseAckReply = false; fixture.Sample += 40; fixture.ProofTime += 40;
            fixture.ColdReopenReceiverStoreStorage();
        }
        var result = await fixture.SynchronizeNativeReceiver(grants, terminal);
        Assert.Equal(1, result.ProcessedEnvelopes); Assert.Equal(1, result.DurableTombstones); Assert.False(result.HasMore);
        Assert.Equal(snapshot, await fixture.ExpiredInitialCatalogSnapshotAsync());
        Assert.Equal(1, terminal.RetrieveCalls);
        if (cut == "lost-ack") Assert.Equal(terminal.ExactAckRequests[0], terminal.ExactAckRequests[1]);
        using var retained = await fixture.FindReceiver(initial, reopen: true);
        Assert.NotNull(retained); Assert.True(retained.IsExpiredDisposal); Assert.False(retained.HasInitialState);
        Assert.Equal(40, retained.StoredStateSpan.Length);
        Assert.Throws<InvalidOperationException>(() => retained.ExactTrsSpan.ToArray());
        Assert.Equal(init.CanonicalBytes.ToArray(), retained.ExactInitSpan.ToArray());
        Assert.Equal(hello.CanonicalBytes.ToArray(), retained.ExactHelloSpan.ToArray());
        await fixture.AssertReceiverSqlAsync(1, initial);
        var metadata = retained.CanonicalSpan.ToArray(); var proof = retained.StoredStateSpan.ToArray();
        Assert.Throws<CryptographicException>(() => DeepIdV2InitialContactSessionCommit.RestoreCustody(metadata));
        var changed = proof.ToArray(); changed[0] ^= 1;
        Assert.Throws<CryptographicException>(() => DeepIdV2InitialContactSessionCommit.RestoreCustody(metadata, changed));
        var wrongKind = metadata.ToArray(); wrongKind[6] = 2;
        Assert.Throws<InvalidDataException>(() => DeepIdV2InitialContactSessionCommit.RestoreCustody(wrongKind, proof));
        var liveAlias = metadata.ToArray(); liveAlias[6] = 0;
        Assert.Throws<FormatException>(() => DeepIdV2InitialContactSessionCommit.RestoreCustody(liveAlias, proof));
        var tooEarly = metadata.ToArray(); var earlyProof = proof.ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(earlyProof, expiry / 1000 - 1);
        SHA256.HashData(earlyProof).CopyTo(tooEarly.AsSpan(136));
        Assert.Throws<CryptographicException>(() => DeepIdV2InitialContactSessionCommit.RestoreCustody(tooEarly, earlyProof));
        fixture.ColdReopenReceiverStoreStorage();
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.ReceiveNativeMailboxInitial(initial));
        Assert.Equal(snapshot, await fixture.ExpiredInitialCatalogSnapshotAsync());
        Assert.Equal(0, (await fixture.SynchronizeNativeReceiver(grants, terminal)).ProcessedEnvelopes);
        Assert.Equal(2, terminal.RetrieveCalls);
        if (cut == "none")
        {
            // The same retained accounts can now receive a separate current
            // request. No account reset, old-session revival or queue skip.
            var (next, _, _, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xd3), oneTimeIndex: 1);
            byte[] fresh;
            using (var sent = await next(fixture.Accounts)) fresh = sent.ExactDph2.ToArray();
            var nextTerminal = new OwnedReadTerminal(fixture, fresh) { Cursor = 2, ExpectedAckCounter = 5 };
            Assert.Equal(1, (await fixture.SynchronizeNativeReceiver(grants, nextTerminal)).DurableTombstones);
            var scope = await fixture.ReceiveNativeMailboxInitial(fresh);
            Assert.Equal(Did2ContactAcceptanceState.IncomingRequest, await fixture.ReadOwnedContactState(scope));
            await fixture.AssertReceiverSqlAsync(2, fresh);
            using var old = await fixture.FindReceiver(initial, reopen: true);
            Assert.NotNull(old); Assert.True(old.IsExpiredDisposal); Assert.False(old.HasInitialState);
        }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedMailboxReceive_ExpiryUncertaintyDoesNotConsumePrekeyOrAcknowledge()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, longMailboxWindow: true, encryptedStorage: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xd2), oneTimeIndex: 0);
        byte[] initial;
        using (var sent = await complete(fixture.Accounts)) initial = sent.ExactDph2.ToArray();
        var delta = checked(Math.Max(init.ExpiresAtUnixMilliseconds, hello.ExpiresAtUnixMilliseconds) / 1000 - fixture.CurrentProofTime);
        fixture.ProofTime += delta; fixture.Sample += delta;
        var grants = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var terminal = new OwnedReadTerminal(fixture, initial);
        await Assert.ThrowsAnyAsync<CryptographicException>(() => fixture.SynchronizeNativeReceiver(grants, terminal));
        Assert.Equal(0, terminal.AckCalls);
        Assert.Null(await fixture.FindReceiver(initial, reopen: true));
        fixture.ProofTime += 31; fixture.Sample += 31;
        Assert.Equal(1, (await fixture.SynchronizeNativeReceiver(grants, terminal)).DurableTombstones);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedMailboxReceive_ExpiredInitialMissingOrChangedNativeProofCannotAck(bool remove)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, longMailboxWindow: true, encryptedStorage: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xd4), oneTimeIndex: 0);
        byte[] initial;
        using (var sent = await complete(fixture.Accounts)) initial = sent.ExactDph2.ToArray();
        var delta = checked(Math.Max(init.ExpiresAtUnixMilliseconds, hello.ExpiresAtUnixMilliseconds) / 1000 + 31 - fixture.CurrentProofTime);
        fixture.ProofTime += delta; fixture.Sample += delta;
        var grants = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var terminal = new OwnedReadTerminal(fixture, initial);
        using (ResponderInitialSessionTestHooks.Push(point =>
        { if (point == ResponderInitialSessionFailpoint.AfterStable) throw new IOException("Stop before semantic ACK."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.SynchronizeNativeReceiver(grants, terminal));
        using (var genuine = await fixture.FindReceiver(initial, reopen: true))
        { Assert.NotNull(genuine); Assert.True(genuine.IsExpiredDisposal); }
        await fixture.DamageExpiredInitialProofAsync(remove);
        fixture.ColdReopenReceiverStoreStorage();
        await Assert.ThrowsAnyAsync<CryptographicException>(() => fixture.SynchronizeNativeReceiver(grants, terminal));
        Assert.Equal(0, terminal.AckCalls);
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[]> ExpiredInitialCatalogSnapshotAsync()
        {
            using var raw = await peerStorage.ReadOwnedAsync(ProtectedDid2MessagingSessionCatalog.Slot) ?? throw new InvalidDataException();
            return raw.Use(bytes => SHA256.HashData(bytes));
        }
        internal async Task DamageExpiredInitialProofAsync(bool remove)
        {
            await using var sql = await OpenPeerPreKeySqlAsync();
            using var write = sql.CreateCommand();
            write.CommandText = remove ? "DELETE FROM receiver_initial_state;" :
                "UPDATE receiver_initial_state SET exact_state=zeroblob(length(exact_state));";
            Assert.Equal(1, write.ExecuteNonQuery());
        }
    }
}
