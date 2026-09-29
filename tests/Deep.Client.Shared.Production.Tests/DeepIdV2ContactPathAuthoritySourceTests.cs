using System.Net;
using System.Buffers.Binary;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task DurableHistory_ExactPredecessorCasAndRawProjectionCannotReplaceAuthority()
    {
        await using var fixture = await Fixture.CreateAsync();
        var initial = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        var store = Assert.IsAssignableFrom<IDeepIdV2NetworkHistoryStore>(fixture.NetworkStore);
        var retained = (await store.ReadHistoryAsync(default))!;
        await fixture.AssertHistoryAnchorEnvelopeAsync(retained.ExactHistory);
        var altered = retained.ExactHistory.ToArray(); altered[^1] ^= 1;
        await Assert.ThrowsAsync<IOException>(async () =>
            await store.ApplyVerifiedHistoryAsync(new(retained.Snapshot, altered), initial, default));
        await Assert.ThrowsAsync<IOException>(async () => await store.ApplyVerifiedHistoryAsync(null, initial, default));
        store.RequireAccountScope((await fixture.Accounts.GetCurrentAsync())!.AccountId);
        Assert.Throws<CryptographicException>(() => store.RequireAccountScope(Bytes(32, 0xaa)));
        await fixture.AdvanceNetworkAsync();
        var next = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        await Assert.ThrowsAsync<IOException>(async () => await store.ApplyVerifiedHistoryAsync(retained, next, default));
        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.NetworkStore.CompareExchangeAsync(
            2, new(3, initial.ProtectedLkg!, false), default));
        Assert.Equal(2UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DurableHistory_MissingOrCorruptIndependentAnchorCannotReopen(bool corrupt)
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        await fixture.DamageHistoryAnchorAsync(corrupt);
        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.NetworkStore.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
    }

    [Fact]
    public async Task DurableHistory_HostileEnvelopeRejectsWithoutRewrite()
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        await using var connection = await fixture.OpenSqlAsync();
        using var read = connection.CreateCommand();
        read.CommandText = "SELECT payload FROM protected_lkg_root WHERE root_kind=7;";
        var original = Assert.IsType<byte[]>(read.ExecuteScalar());
        var unknownVersion = original.ToArray(); unknownVersion[5] = 3;
        var anchorAsFloor = original.ToArray(); anchorAsFloor[7] = 1;
        var wrongLength = original.ToArray(); wrongLength[67] ^= 1;
        byte[][] hostile = [unknownVersion, anchorAsFloor, wrongLength,
            original[..^1], [.. original, 0], new byte[68 + 16 + 225 + 2 * 65_535 + 1]];
        using var write = connection.CreateCommand();
        write.CommandText = "UPDATE protected_lkg_root SET payload=$payload WHERE root_kind=7;";
        var parameter = write.Parameters.Add("$payload", SqliteType.Blob);
        foreach (var payload in hostile)
        {
            parameter.Value = payload;
            Assert.Equal(1, write.ExecuteNonQuery());
            await Assert.ThrowsAsync<InvalidDataException>(async () => await fixture.NetworkStore.ReadAsync(default));
            Assert.Equal(payload, Assert.IsType<byte[]>(read.ExecuteScalar()));
        }
        parameter.Value = original;
        Assert.Equal(1, write.ExecuteNonQuery());
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Fact]
    public async Task DurableHistory_RehashedSqlHistoryCannotForgeIndependentAnchor()
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        await using var connection = await fixture.OpenSqlAsync();
        using var read = connection.CreateCommand();
        read.CommandText = "SELECT payload FROM protected_lkg_root WHERE root_kind=7;";
        var envelope = Assert.IsType<byte[]>(read.ExecuteScalar());
        envelope[^1] ^= 1;
        SHA256.HashData(envelope.AsSpan(68)).CopyTo(envelope, 32);
        using var write = connection.CreateCommand();
        write.CommandText = "UPDATE protected_lkg_root SET payload=$payload WHERE root_kind=7;";
        write.Parameters.AddWithValue("$payload", envelope);
        Assert.Equal(1, write.ExecuteNonQuery());
        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.NetworkStore.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
    }

    [Fact]
    public async Task DurableHistory_ReopenedAccountAdvancesChangedTipWithExpiredHistoricalKeys()
    {
        await using var fixture = await Fixture.CreateAsync(expiringHistory: true);
        var genesis = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        var store = Assert.IsAssignableFrom<IDeepIdV2NetworkHistoryStore>(fixture.NetworkStore);
        var retained = (await store.ReadHistoryAsync(default))!;
        Assert.Equal(0UL, retained.Snapshot.ProtectedLkg.ViewGeneration);
        Assert.Equal(OnionNetworkProtectedHistoryCodec.Encode(genesis), retained.ExactHistory.ToArray());
        await fixture.AdvanceNetworkAsync();
        fixture.ProofTime = 1_100; // Historical view expires at 1,090; no clock rollback.
        fixture.Sample = 200;
        var reopenedAccount = fixture.ReopenAccount();
        fixture.NetworkStore = await fixture.ReopenNetworkStoreAsync();
        var reopened = fixture.Source(reopenedAccount);
        var next = await reopened.VerifyCurrentNetworkAsync(Fixture.Network);
        Assert.Equal(1UL, next.ProtectedLkg!.ViewGeneration);
        Assert.True(OnionNetworkProtectedHistoryCodec.BindsPredecessor(next, retained.ExactHistory));
        Assert.Equal(2UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
        var exact = (await ((IDeepIdV2NetworkHistoryStore)fixture.NetworkStore).ReadHistoryAsync(default))!.ExactHistory;
        _ = await fixture.Source(reopenedAccount).VerifyCurrentNetworkAsync(Fixture.Network);
        Assert.Equal(2UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
        Assert.Equal(exact.ToArray(), (await ((IDeepIdV2NetworkHistoryStore)fixture.NetworkStore).ReadHistoryAsync(default))!.ExactHistory.ToArray());
        fixture.OmitHistoricalPolicy = true;
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.Source(reopenedAccount).VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Equal(2UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task DurableHistory_CrashAfterProjectionOrHistoryAnchorFailsClosed(int phase)
    {
        await using var fixture = await Fixture.CreateAsync();
        if (phase == 0) fixture.FailAfterNextNetworkMarker();
        else fixture.FailAfterNextHistoryAnchor();
        await Assert.ThrowsAsync<IOException>(async () =>
            await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await fixture.NetworkStore.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
    }

    [Theory]
    [InlineData(3)]
    [InlineData(7)]
    public async Task DurableHistory_MissingSqlHalfRejectsWithoutRepair(int rootKind)
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        await using var connection = await fixture.OpenSqlAsync();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM protected_lkg_root WHERE root_kind=$kind;";
        command.Parameters.AddWithValue("$kind", rootKind);
        Assert.Equal(1, command.ExecuteNonQuery());
        await Assert.ThrowsAsync<InvalidDataException>(async () => await fixture.NetworkStore.ReadAsync(default));
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.ReopenNetworkStoreAsync());
    }

    [Fact]
    public async Task ClaimPath_UsesFreshAccountProofAndV2OnlyCanonicalPlacement()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var placement = await source.GetCurrentForPreKeyClaimAsync(Fixture.Network, Fixture.Service);
        var wire = Claim(placement.Placement.ViewHash.Span, placement.Placement.PlacementHash.Span);
        var request = ContactResolveCanonicalPathRequest.Decode(wire);
        Assert.Equal(ContactServiceRequestKind.ClaimPreKey, request.RequestKind);
        Assert.Equal(Fixture.Service, request.ShardKey.ToArray());
        var current = await source.GetCurrentAsync(request, default);
        Assert.Equal(2, fixture.ProofRequests);
        Assert.True(current.Placement.Binds(ContactServiceRequestKind.ClaimPreKey, Fixture.Service));
        var onion = OnionTerminalPayloadVerifierV1.VerifyRequest(current.Network,
            OnionOperation.ContactResolve, wire);
        Assert.Equal(wire, onion.CanonicalBytes.ToArray());
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        var paths = new ContactResolvePrivacyPathProvider(source, custody.Guards);
        var prepared = await paths.PrepareExactAsync(OnionOperation.ContactResolve, request,
            current.Placement.RankedReplicaNodeIds[1], default);
        Assert.Equal(3, fixture.ProofRequests);
        Assert.Equal(wire, prepared.Attempt.Request.CanonicalBytes.ToArray());
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(custody.Entropy),
            new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
        using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request, default);
        Assert.False(built.Frame.IsEmpty); // Real codec/entropy, not socket/device delivery.

        var old = wire.ToArray(); BinaryPrimitives.WriteUInt16BigEndian(old.AsSpan(4), 1);
        Assert.Throws<ApplicationCoreFormatException>(() => ContactResolveCanonicalPathRequest.Decode(old));
        var wrong = Claim(placement.Placement.ViewHash.Span, Bytes(32, 0xee));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.GetCurrentAsync(ContactResolveCanonicalPathRequest.Decode(wrong), default));
        fixture.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(async () => await source.GetCurrentAsync(request, default));

        static byte[] Claim(ReadOnlySpan<byte> view, ReadOnlySpan<byte> placementHash) =>
            DeepIdV2PreKeyClaimRequestCodec.Encode(Fixture.Network, Bytes(32, 0xb0), view,
                placementHash, 1_000, 1_200, Fixture.Service, Bytes(32, 0xb1),
                Bytes(32, 0xb2), Bytes(32, 0xb3), Bytes(32, 0xb4));
    }

    [Fact]
    public async Task FullSignedSuccessorHistory_CanMintRepeatedlyAndReopenWithoutReplayingGenesisAgainstTip()
    {
        await using var fixture = await Fixture.CreateAsync(withSuccessor: true);
        var source = fixture.Source();
        var network = await source.VerifyCurrentNetworkAsync(Fixture.Network);
        Assert.Equal(1UL, network.ProtectedLkg!.ViewGeneration);
        _ = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        _ = await source.VerifyCurrentNetworkAsync(Fixture.Network);
        var reopened = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        Assert.Equal(XPointNetworkProtectedLkgCodec.Encode(network.ProtectedLkg),
            XPointNetworkProtectedLkgCodec.Encode(reopened.ProtectedLkg!));
        Assert.Equal(4, fixture.ProofRequests);
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
        fixture.OmitHistoricalPolicy = true;
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await source.VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Fact]
    public async Task InitialInventory_UsesRealCurrentClosureAndPreservesExactRetryAfterReopen()
    {
        // The approved whole ML-KEM asset is currently validated on Windows.
        // This fixture is native/SQL evidence, not physical-device evidence.
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var staged = await fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
        Assert.Equal(1, fixture.ProofRequests);
        fixture.VerifyInventory(staged, (await source.VerifyForOwnPreKeyAuthoringAsync(
            fixture.Accounts, default)).Proof);
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
        Assert.Equal(32, publication.OneTimeMembers.Count);
        var inventoryExpires = BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(15).Span);
        Assert.True(inventoryExpires > 1_500); // Short-lived ADH1 is refreshed, not signed into pre-key lifetime.
        Assert.True(inventoryExpires <= DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span).ExpiresAtUnixSeconds);
        Assert.Equal(86_400UL, inventoryExpires - BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(14).Span));
        var service = DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span);
        var placement = await source.GetCurrentForPublicationAsync(Fixture.Network, service.Field(2));
        Assert.Equal(placement.Placement.PlacementHash.ToArray(), publication.PlacementHash.ToArray());
        Assert.True(await fixture.Accounts.HasOwnStagedPreKeyInventoryAsync());
        Assert.Null(await fixture.Accounts.ReadOwnPreKeyCommitPairAsync());
        await AssertRealOnionCustodyAsync(fixture, source, staged, publication, placement);
        fixture.RejectProof = true;
        var before = fixture.ProofRequests;
        var retry = await fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
        var reopened = fixture.ReopenAccount();
        var afterRestart = await reopened.EnsureOwnInitialPreKeyInventoryAsync(fixture.Source(reopened));
        Assert.Equal(staged.ExactXpp1.ToArray(), retry.ExactXpp1.ToArray());
        Assert.Equal(staged.ExactXpp1.ToArray(), afterRestart.ExactXpp1.ToArray());
        Assert.Equal(staged.ExactXps1.ToArray(), afterRestart.ExactXps1.ToArray());
        Assert.Equal(before, fixture.ProofRequests); // Stored retry is not fresh authority.
        await Assert.ThrowsAnyAsync<IOException>(async () =>
            await source.GetCurrentForPublicationAsync(Fixture.Network, service.Field(2)));
        var custody = await reopened.OpenOwnOnionClientCustodyAsync();
        await Assert.ThrowsAnyAsync<IOException>(() => reopened.PublishOwnStagedPreKeyInventoryAsync(
            fixture.Source(reopened), custody)); // Stored retry cannot dispatch without fresh proof.
    }

    [Fact]
    public async Task ExpiredProtectedInventoryRejectsLocallyBeforeOnionDispatchWithoutReplacingKeys()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        await fixture.StageExpiredInventoryAsync(source);
        var exact = (await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync())!.ExactXpp1.ToArray();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        await Assert.ThrowsAsync<ApplicationCoreFormatException>(() =>
            fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(source, custody));
        Assert.Equal(exact, (await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync())!.ExactXpp1.ToArray());
        Assert.Null(await fixture.Accounts.ReadOwnPreKeyCommitPairAsync());
        Assert.Null(await custody.Guards.ReadAsync(default)); // No path/entropy reservation or send.
    }

    [Fact]
    public async Task CompletedPublication_ReopenReauthenticatesExactPairWithoutOnionReservation()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var expected = await fixture.StageAndRecordPairAsync();
        var reopened = fixture.ReopenAccount();
        var custody = await reopened.OpenOwnOnionClientCustodyAsync();
        var before = fixture.ProofRequests;
        var actual = await reopened.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(reopened), custody);
        Assert.Equal(before + 1, fixture.ProofRequests); // Fresh proof, not stored-authority reuse.
        Assert.Equal(expected.ExactFirstXic1.ToArray(), actual.ExactFirstXic1.ToArray());
        Assert.Equal(expected.ExactSecondXic1.ToArray(), actual.ExactSecondXic1.ToArray());
        Assert.Null(await custody.Guards.ReadAsync(default)); // No request/path/entropy or network dispatch.
        var again = await reopened.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(reopened), custody);
        Assert.Equal(before + 2, fixture.ProofRequests);
        Assert.Equal(expected.ExactFirstXic1.ToArray(), again.ExactFirstXic1.ToArray());
        Assert.Null(await custody.Guards.ReadAsync(default));
    }

    [Fact]
    public async Task CompletedPublication_DoesNotSubstituteSavedPairForFreshProof()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var expected = await fixture.StageAndRecordPairAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        fixture.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(() => fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(
            fixture.Source(), custody));
        Assert.Null(await custody.Guards.ReadAsync(default));
        Assert.Equal(expected.ExactFirstXic1.ToArray(),
            (await fixture.Accounts.ReadOwnPreKeyCommitPairAsync())!.ExactFirstXic1.ToArray());
    }

    [Fact]
    public async Task CompletedPublication_ExpiredInventoryRemainsExpiredDespiteValidStoredSignatures()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var expected = await fixture.StageAndRecordPairAsync(expiredInventory: true);
        var staged = (await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync())!.ExactXpp1.ToArray();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        await Assert.ThrowsAsync<ApplicationCoreFormatException>(() =>
            fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(), custody));
        Assert.Null(await custody.Guards.ReadAsync(default));
        Assert.Equal(staged, (await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync())!.ExactXpp1.ToArray());
        Assert.Equal(expected.ExactFirstXic1.ToArray(),
            (await fixture.Accounts.ReadOwnPreKeyCommitPairAsync())!.ExactFirstXic1.ToArray());
    }

    [Fact]
    public async Task CompletedPublication_RejectsAlteredNetworkClosureDespiteValidStoredPair()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.StageAndRecordPairAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        fixture.AlterNode = true;
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(), custody));
        Assert.Null(await custody.Guards.ReadAsync(default));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task CompletedPublication_RejectsBadSignatureOrUnselectedReplicaWithoutRepublishing(
        bool badSignature, bool unselectedReplica)
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var expected = await fixture.StageAndRecordPairAsync(badSignature, unselectedReplica);
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        await Assert.ThrowsAsync<ApplicationCoreFormatException>(() =>
            fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(), custody));
        Assert.Null(await custody.Guards.ReadAsync(default));
        Assert.Equal(expected.ExactFirstXic1.ToArray(),
            (await fixture.Accounts.ReadOwnPreKeyCommitPairAsync())!.ExactFirstXic1.ToArray());
    }

    [Fact]
    public async Task CompletedPublication_RechecksFreshnessAfterSuspendedProtectedPairRead()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.StageAndRecordPairAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        var injected = false;
        fixture.AfterNextCommitPairRead(() =>
        {
            // The 30-second nonce-response window is not the lifetime of an
            // already verified current-value capability. Advance past the
            // actual revocation-freshness TTL, not an assumed 40-second lease.
            fixture.Sample += AccountDirectoryCurrentProofVerifier.RevocationFreshnessTtlSeconds;
            injected = true;
        });
        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(), custody));
        Assert.Null(await custody.Guards.ReadAsync(default));
        Assert.True(injected);
    }

    [Fact]
    public async Task CompletedPublication_RechecksCancellationAfterSuspendedProtectedPairRead()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var expected = await fixture.StageAndRecordPairAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        using var cancel = new CancellationTokenSource();
        fixture.AfterNextCommitPairRead(cancel.Cancel);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(), custody, cancel.Token));
        Assert.Null(await custody.Guards.ReadAsync(default));
        Assert.Equal(expected.ExactFirstXic1.ToArray(),
            (await fixture.Accounts.ReadOwnPreKeyCommitPairAsync())!.ExactFirstXic1.ToArray());
    }

    private static async Task AssertRealOnionCustodyAsync(Fixture fixture,
        DeepIdV2ContactPathAuthoritySource source, StagedDeepIdV2PreKeyPublication staged,
        ParsedXpp1V2 publication, ContactResolvePathAuthority authority)
    {
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        var fragments = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(staged.ExactXpp1.Span,
            authority.Placement.ViewHash.Span, staged.ExactDid2.Span, staged.ExactDca1.Span, staged.ExactXps1.Span);
        var request = ContactResolveCanonicalPathRequest.FromDid2BoundedPublication(
            DeepIdV2BoundedPreKeyPublicationCodec.Decode(fragments[0]), publication.Manifest.Field(2).Span,
            Math.Min(BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(15).Span),
                authority.Placement.ValidUntilUnixSeconds));
        var paths = new ContactResolvePrivacyPathProvider(source, custody.Guards);
        var ledger = new CapturingEntropyLedger(custody.Entropy);
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(ledger),
            new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
        // Exercise both rotating marker slots beyond their initial insert.
        // Two frames alone missed the third-write immutable-slot defect.
        foreach (var exit in authority.Placement.RankedReplicaNodeIds.Concat(authority.Placement.RankedReplicaNodeIds))
        {
            var prepared = await paths.PrepareExactAsync(OnionOperation.ContactResolve, request, exit, default);
            var entry = OnionEntryTransportFactory.Create(prepared.Attempt.Path);
            entry.EnsureCurrent();
            using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request, default);
            Assert.False(built.Frame.IsEmpty);
            Assert.NotNull(ledger.LastBatch);
            Assert.Equal(OnionEntropyCommitOutcome.Duplicate,
                await custody.Entropy.CommitAsync(ledger.LastBatch!, default));
        }
        var reopened = await fixture.ReopenAccount().OpenOwnOnionClientCustodyAsync();
        Assert.Equal(OnionEntropyCommitOutcome.Duplicate,
            await reopened.Entropy.CommitAsync(ledger.LastBatch!, default));
        Assert.Equal(EntryGuardStateCodec.Encode((await custody.Guards.ReadAsync(default))!),
            EntryGuardStateCodec.Encode((await reopened.Guards.ReadAsync(default))!));
        // A frame was sealed locally; no network send, XIC1 or device claim.
    }

    private sealed class CapturingEntropyLedger(IOnionEntropyUniquenessLedger inner) : IOnionEntropyUniquenessLedger
    {
        internal OnionEntropyCommitmentBatch? LastBatch { get; private set; }
        public async ValueTask<OnionEntropyCommitOutcome> CommitAsync(OnionEntropyCommitmentBatch batch, CancellationToken ct)
        {
            var result = await inner.CommitAsync(batch, ct);
            if (result == OnionEntropyCommitOutcome.Committed) LastBatch = batch;
            return result;
        }
    }

    private sealed class RejectClientReceiveVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(OnionKeyHandle keyHandle,
            ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct) =>
            throw new InvalidOperationException("The client must never ask for an XNode receive key.");
    }

    [Fact]
    public async Task InitialInventory_MissingProofCancellationAndWrongOwnerDoNotStage()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source, cancelled.Token));
        Assert.Equal(0, fixture.ProofRequests);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            fixture.ReopenAccount().EnsureOwnInitialPreKeyInventoryAsync(source));
        Assert.Equal(0, fixture.ProofRequests);
        fixture.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(() =>
            fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source));
        Assert.Equal(1, fixture.ProofRequests);
        Assert.Null(await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync());
    }

    [Fact]
    public async Task OwnAuthoringAuthority_RejectsExpiredClockAndChangedNetworkCustody()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var authoring = await source.VerifyForOwnPreKeyAuthoringAsync(fixture.Accounts, default);
        fixture.Sample = authoring.Proof.FreshnessDeadlineMonotonicSeconds;
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.RecheckOwnPreKeyAuthoringAsync(authoring, default));
        fixture.Sample = 100;
        var floor = (await fixture.NetworkStore.ReadAsync(default))!;
        await fixture.NetworkStore.CompareExchangeAsync(floor.Revision,
            new(floor.Revision + 1, floor.ProtectedLkg, true), default);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.RecheckOwnPreKeyAuthoringAsync(authoring, default));
        Assert.Null(await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync());
    }

    [Fact]
    public async Task RealDid2AccountAndSignedNetwork_VerifyThenMintRechecksProofAndRehydratesExactFloor()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var network = await source.VerifyCurrentNetworkAsync(Fixture.Network);
        network.EnsureCurrent();
        Assert.NotNull(await fixture.NetworkStore.ReadAsync(default));
        Assert.Equal(1, fixture.ProofRequests);
        var first = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.True(first.Placement.Binds(ContactServiceRequestKind.PublishPreKeyInventory, Fixture.Service));
        Assert.NotNull(await fixture.NetworkStore.ReadAsync(default));
        var second = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.Equal(first.Placement.PlacementHash.ToArray(), second.Placement.PlacementHash.ToArray());
        Assert.Equal(3, fixture.ProofRequests);
        var reopened = fixture.Source();
        var restoredNetwork = await reopened.VerifyCurrentNetworkAsync(Fixture.Network);
        restoredNetwork.EnsureCurrent();
        Assert.Equal(XPointNetworkProtectedLkgCodec.Encode(
                Assert.IsType<XPointNetworkProtectedLkg>(network.ProtectedLkg)),
            XPointNetworkProtectedLkgCodec.Encode(
                Assert.IsType<XPointNetworkProtectedLkg>(restoredNetwork.ProtectedLkg)));
        var restored = await reopened.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.Equal(first.Placement.PlacementHash.ToArray(), restored.Placement.PlacementHash.ToArray());
        Assert.Equal(5, fixture.ProofRequests);
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Fact]
    public async Task MissingFreshProof_CannotReusePreviouslyMintedNetworkAuthority()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        _ = await source.VerifyCurrentNetworkAsync(Fixture.Network);
        fixture.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(async () =>
            await source.VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Equal(2, fixture.ProofRequests);
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
        fixture.RejectProof = false;
        _ = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.Equal(3, fixture.ProofRequests);
    }

    [Fact]
    public async Task AlteredSignedNodeClosure_DoesNotInitializeNetworkCustody()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.AlterNode = true;
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Null(await fixture.NetworkStore.ReadAsync(default));
    }

    [Fact]
    public async Task UnrelatedNetworkAndProtectedFork_RejectBeforeFetchingAnyProof()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await source.GetCurrentForPublicationAsync(Bytes(16, 0x22), Fixture.Service));
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await source.VerifyCurrentNetworkAsync(Bytes(16, 0x22)));
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await source.GetCurrentForPublicationAsync(Fixture.Network, new byte[32]));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await source.VerifyCurrentNetworkAsync(Fixture.Network, cancelled.Token));
        Assert.Equal(0, fixture.ProofRequests);
        _ = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        var current = (await fixture.NetworkStore.ReadAsync(default))!;
        await fixture.NetworkStore.CompareExchangeAsync(current.Revision,
            new(current.Revision + 1, current.ProtectedLkg, true), default);
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service));
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await source.VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Equal(1, fixture.ProofRequests);
    }

    [Fact]
    public void RawNetworkClosureOwnsCopiesAndRejectsOversizedListsBeforeCopying()
    {
        var value = new byte[] { 1 };
        ReadOnlyMemory<byte>[] one = [value];
        var closure = new DeepIdV2NetworkClosureArtifacts(one, one, one, one, one, one, one);
        value[0] = 2;
        Assert.Equal((byte)1, closure.ExactOrderedXnv1Chain[0].Span[0]);
        Assert.True(MemoryMarshal.TryGetArray(closure.ExactOrderedXnv1Chain[0], out var exported));
        exported.Array![exported.Offset] = 3;
        Assert.Equal((byte)1, closure.ExactOrderedXnv1Chain[0].Span[0]);
        var tooMany = Enumerable.Repeat<ReadOnlyMemory<byte>>(value, 4097).ToArray();
        Assert.Throws<ArgumentException>(() =>
            new DeepIdV2NetworkClosureArtifacts(one, one, one, tooMany, tooMany, one, one));
        Assert.Throws<ArgumentException>(() =>
            new DeepIdV2NetworkClosureArtifacts(one, one, one, [value, value], one, one, one));
    }

    [Fact]
    public void AccountPublisherRequiresDid2OnlyAuthoritySource()
    {
        var method = typeof(DeepIdV2AccountService).GetMethod(
            nameof(DeepIdV2AccountService.PublishOwnStagedPreKeyInventoryAsync))!;
        Assert.Equal(typeof(DeepIdV2ContactPathAuthoritySource), method.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(DeepIdV2OnionClientCustody), method.GetParameters()[1].ParameterType);
        Assert.Empty(typeof(DeepIdV2OnionClientCustody).GetConstructors());
    }

    [Fact]
    public async Task OnionGuardCustody_PreservesCasAfterReopenAndRejectsSqlRollbackAndForeignOwner()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        Assert.Null(await custody.Guards.ReadAsync(default));
        var first = Guard(1);
        Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
            (await custody.Guards.CompareExchangeAsync(null, first, default)).Disposition);
        Assert.Equal(EntryGuardStoreWriteDisposition.Conflict,
            (await custody.Guards.CompareExchangeAsync(null, first, default)).Disposition);
        var reopenedAccount = fixture.ReopenAccount();
        var reopened = await reopenedAccount.OpenOwnOnionClientCustodyAsync();
        Assert.Equal(EntryGuardStateCodec.Encode(first),
            EntryGuardStateCodec.Encode((await reopened.Guards.ReadAsync(default))!));
        await Assert.ThrowsAsync<ArgumentException>(() => reopenedAccount.PublishOwnStagedPreKeyInventoryAsync(
            fixture.Source(reopenedAccount), custody));
        Assert.Equal(0, fixture.ProofRequests);
        var second = Guard(2);
        Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
            (await reopened.Guards.CompareExchangeAsync(1, second, default)).Disposition);
        for (ulong revision = 3; revision <= 8; revision++)
            Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
                (await reopened.Guards.CompareExchangeAsync(revision - 1, Guard(revision), default)).Disposition);
        await using (var connection = await fixture.OpenSqlAsync())
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE protected_lkg_root SET revision=1,payload=$payload WHERE root_kind=4;";
            command.Parameters.AddWithValue("$payload", EntryGuardStateCodec.Encode(first));
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        await Assert.ThrowsAsync<CryptographicException>(async () => await reopened.Guards.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => reopenedAccount.OpenOwnOnionClientCustodyAsync());
        await fixture.ResetAccountAsync();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await custody.Guards.ReadAsync(default));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(5)]
    public async Task OnionGuardMarkerBeforeSqlCrash_RejectsReadAndReopenWithoutEmittingAuthority(int committed)
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        for (ulong revision = 1; revision <= (ulong)committed; revision++)
            Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
                (await custody.Guards.CompareExchangeAsync(revision == 1 ? null : revision - 1, Guard(revision), default)).Disposition);
        fixture.FailAfterNextOnionMarker();
        await Assert.ThrowsAsync<IOException>(async () =>
            await custody.Guards.CompareExchangeAsync(committed == 0 ? null : (ulong)committed, Guard((ulong)committed + 1), default));
        await Assert.ThrowsAsync<CryptographicException>(async () => await custody.Guards.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.Accounts.OpenOwnOnionClientCustodyAsync());
        Assert.Equal(0, fixture.ProofRequests);
    }

    private static EntryGuardState Guard(ulong revision) => new(revision, Fixture.Network,
        1, Bytes(32, 0x21), Bytes(32, 0x22), Bytes(32, 0x23), [Bytes(32, 0x23)]);

    [Fact]
    public async Task AccountNetworkFloor_RejectsSqlRollbackCorruptionDeletionAndRepin()
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        var initial = (await fixture.NetworkStore.ReadAsync(default))!;
        Assert.Equal(XPointNetworkStoreWriteDisposition.Conflict,
            (await fixture.NetworkStore.CompareExchangeAsync(null, initial, default)).Disposition);
        await using var connection = await fixture.OpenSqlAsync();
        byte[] Payload(int kind = 3)
        {
            using var read = connection.CreateCommand();
            read.CommandText = "SELECT payload FROM protected_lkg_root WHERE root_kind=$kind;";
            read.Parameters.AddWithValue("$kind", kind);
            return Assert.IsType<byte[]>(read.ExecuteScalar());
        }
        void Replace(long revision, byte[] payload, int kind = 3)
        {
            using var write = connection.CreateCommand();
            write.CommandText = "UPDATE protected_lkg_root SET revision=$revision,payload=$payload WHERE root_kind=$kind;";
            write.Parameters.AddWithValue("$kind", kind);
            write.Parameters.AddWithValue("$revision", revision);
            write.Parameters.AddWithValue("$payload", payload);
            Assert.Equal(1, write.ExecuteNonQuery());
        }
        var oldPayload = Payload();
        var oldHistory = Payload(7);
        var latched = new XPointNetworkStateSnapshot(2, initial.ProtectedLkg, true);
        Assert.Equal(XPointNetworkStoreWriteDisposition.Applied,
            (await fixture.NetworkStore.CompareExchangeAsync(1, latched, default)).Disposition);
        var currentPayload = Payload();
        var currentHistory = Payload(7);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await fixture.NetworkStore.CompareExchangeAsync(2, new(3, initial.ProtectedLkg, false), default));
        var reopened = await fixture.ReopenNetworkStoreAsync();
        Assert.True((await reopened.ReadAsync(default))!.ForkLatched);
        Replace(1, oldPayload);
        Replace(1, oldHistory, 7); // Restore the whole SQL snapshot, not a split row.
        await Assert.ThrowsAsync<CryptographicException>(async () => await reopened.ReadAsync(default));
        Replace(2, currentPayload);
        Replace(2, currentHistory, 7);
        Assert.True((await reopened.ReadAsync(default))!.ForkLatched);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync(changedPin: true));
        Replace(2, [1]);
        await Assert.ThrowsAsync<InvalidDataException>(async () => await reopened.ReadAsync(default));
        using (var delete = connection.CreateCommand())
        {
            delete.CommandText = "DELETE FROM protected_lkg_root WHERE root_kind IN (3,7);";
            Assert.Equal(2, delete.ExecuteNonQuery());
        }
        await Assert.ThrowsAsync<CryptographicException>(async () => await reopened.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
        await connection.DisposeAsync();
        await fixture.ResetAccountAsync();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await reopened.ReadAsync(default));
    }

    [Fact]
    public async Task NetworkMarkerCommittedBeforeSqlCrash_RejectsEmptyFloorAndReopen()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.FailAfterNextNetworkMarker();
        await Assert.ThrowsAsync<IOException>(async () =>
            await fixture.Source().GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service));
        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.NetworkStore.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
    }

    /// <summary>Real account-owned SQLCipher DID2 state and native ML-DSA;
    /// signed public network ceremony and nonce-bound HTTP proof bytes. The
    /// HTTP/secure-storage adapters are in-memory; directory and network
    /// floors use real SQLCipher. This is not TLS, ONION or device evidence.</summary>
    private sealed class Fixture : HttpMessageHandler, IAsyncDisposable,
        IOnionMonotonicClock
    {
        internal static readonly byte[] Network = Bytes(16, 0x11);
        internal static readonly byte[] Service = Bytes(32, 0x35);
        private static readonly byte[] Boot = Bytes(16, 0xf3);
        private readonly string directory = Path.Combine(Path.GetTempPath(),
            "deep-did2-path-" + Guid.NewGuid().ToString("N"));
        private readonly InMemoryDeepSecureStorage innerStorage = new();
        private readonly NetworkMarkerFaultStorage storage;
        private readonly Signer root = new(0x20);
        private readonly Signer[] witnesses = [new(0x30), new(0x31), new(0x32)];
        private readonly Signer[] nodes = [new(0x70), new(0x71), new(0x72)];
        private readonly IDeepMlDsa65VerifierLease pq = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        private VerifiedXPointNetworkBootstrap bootstrap = null!;
        private AuthoredXPointNetworkOperationalGenesis operational = null!;
        private AuthoredXPointNetworkOperationalSuccessor? successor;
        private AuthoredAccountDirectoryHeadMutation genesis = null!;
        private AuthoredAccountDirectoryHeadMutation head = null!;
        private VerifiedAdc1V2 checkpoint = null!;
        private DeepIdV2AccountService accounts = null!;
        private DeepIdV2DirectoryProofClient proofs = null!;
        private HttpClient http = null!;
        private HttpDeepIdV2NetworkClosureArtifactSource closure = null!;
        internal IXPointNetworkStateStore NetworkStore { get; set; } = null!;
        internal int ProofRequests { get; private set; }
        internal bool RejectProof { get; set; }
        internal bool AlterNode { get; set; }
        internal bool OmitHistoricalPolicy { get; set; }
        internal ulong Sample { get; set; } = 100;
        internal ulong ProofTime { get; set; } = 1_100;
        internal DeepIdV2AccountService Accounts => accounts;
        internal DeepIdV2AccountService ReopenAccount() => new(storage, directory, Network, 1,
            new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
            DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);

        internal void AfterNextCommitPairRead(Action action) => storage.AfterCommitPairRead = action;

        // Storage-level internal recording deliberately omits transport verification
        // so negative tests prove the public completion path does not trust a marker.
        internal async Task<DeepIdV2PreKeyCommitSnapshot> StageAndRecordPairAsync(
            bool badSignature = false, bool unselectedReplica = false, bool expiredInventory = false)
        {
            var source = Source();
            if (expiredInventory) await StageExpiredInventoryAsync(source);
            var staged = expiredInventory
                ? (await accounts.ReadOwnStagedPreKeyPublicationAsync())!
                : await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
            var authority = await source.GetCurrentForPublicationAsync(Network, publication.Manifest.Field(2));
            var selected = authority.Placement.RankedReplicaNodeIds;
            var signers = selected.Select(id => nodes.Single(node =>
                node.SignerId.Span.SequenceEqual(id.Span))).ToArray();
            if (unselectedReplica)
                signers[0] = nodes.Single(node => !selected.Any(id => node.SignerId.Span.SequenceEqual(id.Span)));
            var first = Receipt(signers[0]);
            var second = Receipt(signers[1]);
            if (!badSignature && !unselectedReplica)
                DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(publication, authority.Placement, first, second);
            await accounts.RecordPreKeyCommitPairAfterVerificationAsync(staged.ExactXpp1, first, second);
            return (await accounts.ReadOwnPreKeyCommitPairAsync())!;

            ParsedXic1V2 Receipt(Signer signer)
            {
                var time = new byte[8];
                BinaryPrimitives.WriteUInt64BigEndian(time, Math.Min(1_100UL,
                    BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(15).Span) - 1));
                ReadOnlyMemory<byte>[] fields = [publication.NetworkId, publication.PublicationOperationId,
                    publication.Manifest.ExactHash, publication.PlacementHash, signer.SignerId, time];
                var signature = signer.SignCommit(DeepIdV2PreKeyCommitReceiptCodec.CreateSignatureInput(fields));
                if (badSignature) signature[0] ^= 1;
                return DeepIdV2PreKeyCommitReceiptCodec.Decode(DeepIdV2PreKeyCommitReceiptCodec.Encode(fields, signature));
            }
        }

        internal void VerifyInventory(StagedDeepIdV2PreKeyPublication staged,
            VerifiedDeepIdV2DirectoryFreshness fresh)
        {
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(
                DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span),
                checkpoint.Binding, checkpoint.Directory);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh, dca, Boot, Sample);
            DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(checkpoint.Binding.DeepId,
                staged.ExactXps1.Span, authorization,
                DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span), Boot, Sample);
        }

        internal async Task StageExpiredInventoryAsync(DeepIdV2ContactPathAuthoritySource source)
        {
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            using var author = await accounts.OpenLocalPreKeyAuthoringAuthorityAsync();
            var context = new Deep.Protocol.MessagingCrypto.Dpk2AuthoringContext(
                ApplicationCoreVerifier.StartDmd1Lineage(checkpoint.Directory).Next, 1, 1, 1, 1_000, 1_000, 1_100);
            var service = author.AuthorPreKeyServiceV2(context, checkpoint.Binding, 32, 1);
            var placement = ContactServicePlacementFactory.Create(fresh.Network,
                ContactServiceRequestKind.PublishPreKeyInventory, service.ServiceCapability);
            var drs = new byte[38];
            "DRS1"u8.CopyTo(drs);
            BinaryPrimitives.WriteUInt16BigEndian(drs.AsSpan(4), 1);
            checkpoint.Binding.Identity.Revocations.Snapshot.CanonicalHash.Span.CopyTo(drs.AsSpan(6));
            using var inventory = author.AuthorInventoryV2(context, checkpoint.Binding, service, drs,
                new byte[32], Bytes(32, 0x67), placement.PlacementHash.Span, 32, 1);
            await accounts.StageOwnInitialPreKeyInventoryAsync(service, inventory);
        }

        private Fixture() => storage = new(innerStorage);
        internal void FailAfterNextNetworkMarker() => storage.FailAfterNetworkMarker = true;
        internal void FailAfterNextHistoryAnchor() => storage.FailAfterHistoryAnchor = true;
        internal async Task AssertHistoryAnchorEnvelopeAsync(ReadOnlyMemory<byte> history)
        {
            using var anchor = await innerStorage.ReadOwnedAsync(Assert.IsType<string>(storage.LastHistoryAnchorSlot));
            var value = anchor!.Use(bytes => bytes.ToArray());
            try
            {
                Assert.Equal(68, value.Length);
                Assert.Equal("DNF2"u8.ToArray(), value[..4]);
                Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(4)));
                Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(6)));
                Assert.Equal((uint)history.Length, BinaryPrimitives.ReadUInt32BigEndian(value.AsSpan(64)));
                Assert.Equal(SHA256.HashData(history.Span), value[32..64]);
            }
            finally { CryptographicOperations.ZeroMemory(value); }
        }
        internal async Task DamageHistoryAnchorAsync(bool corrupt)
        {
            var slot = Assert.IsType<string>(storage.LastHistoryAnchorSlot);
            if (!corrupt) { await innerStorage.DeleteBatchAsync([slot]); return; }
            using var owned = await innerStorage.ReadOwnedAsync(slot);
            var value = owned!.Use(bytes => bytes.ToArray()); value[^1] ^= 1;
            try
            {
                // Fault injection replaces the immutable slot; production writes
                // must continue rejecting an already occupied anchor revision.
                await innerStorage.DeleteBatchAsync([slot]);
                await innerStorage.WriteBatchAsync([new DeepSecureStorageWrite(slot, value)]);
            }
            finally { CryptographicOperations.ZeroMemory(value); }
        }
        internal void FailAfterNextOnionMarker() => storage.FailAfterOnionMarker = true;
        internal Task ResetAccountAsync() => accounts.ResetExplicitlyAsync();

        internal async Task<IXPointNetworkStateStore> ReopenNetworkStoreAsync(bool changedPin = false)
        {
            var reopened = new DeepIdV2AccountService(storage, directory, Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            var pin = changedPin ? new XPointNetworkGenesisPin(Network, Bytes(32, 0x55)) : bootstrap.GenesisPin;
            return await reopened.OpenNetworkLkgStoreAsync(pin);
        }

        internal async Task<SqliteConnection> OpenSqlAsync()
        {
            using var record = await storage.ReadOwnedAsync("deep.store.v2.sql-generation");
            var key = record!.Use(value => value.Slice(88, 32).ToArray());
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = Path.Combine(directory, "deep-store-v2-account.dsv2"),
              Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
            try
            {
                connection.Open();
                Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(connection.Handle, key));
                return connection;
            }
            catch { connection.Dispose(); throw; }
            finally { CryptographicOperations.ZeroMemory(key); }
        }

        internal static async Task<Fixture> CreateAsync(bool withSuccessor = false, bool expiringHistory = false)
        {
            var fixture = new Fixture();
            try { await fixture.InitializeAsync(withSuccessor, expiringHistory); return fixture; }
            catch { await fixture.DisposeAsync(); throw; }
        }

        private async Task InitializeAsync(bool withSuccessor, bool expiringHistory)
        {
            Directory.CreateDirectory(directory);
            accounts = new(storage, directory, Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            await accounts.CreateAsync("DID2 path test");
            bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                new(Bytes(32, 0x12), Network,
                    [new(root.RootKeyId.Span, 0, root.Ed25519PublicKey.Span, root.CustodyDomainHash.Span)], 1,
                    witnesses.Select(w => new XPointNetworkBootstrapWitnessKey(w.SignerId.Span, 0,
                        w.Ed25519PublicKey.Span, w.FailureDomainHash.Span)).ToArray(), 2,
                    [new(Bytes(32, 0x60), Bytes(32, 0x61), 1, "time1.invalid", 4460, Bytes(32, 0x62), 5),
                     new(Bytes(32, 0x63), Bytes(32, 0x64), 1, "time2.invalid", 4460, Bytes(32, 0x65), 5)],
                    5, 10, 900, 900, 10_000, 900, 9_000, 1, 1), [root]);
            var descriptors = nodes.Select((signer, index) => new XPointNetworkOperationalNode(signer,
                Bytes(32, (byte)(0x80 + index)), Bytes(32, (byte)(0x90 + index)),
                Bytes(32, (byte)(0xa0 + index)), Bytes(32, (byte)(0xb0 + index)),
                (uint)(64_500 + index), 840, Bytes(32, (byte)(0xc0 + index)),
                IPAddress.Parse($"192.0.2.{index + 1}"), 443,
                Bytes(32, (byte)(0xd0 + index)), Bytes(32, (byte)(0xd8 + index)),
                ScalarMult.Base(Bytes(32, (byte)(0xe0 + index))),
                ScalarMult.Base(Bytes(32, (byte)(0xe8 + index))),
                Enumerable.Range(0, 5).Select(role => (ReadOnlyMemory<byte>)
                    PublicKey((byte)(0x10 + index * 5 + role))).ToArray())).ToArray();
            if (expiringHistory) ProofTime = 1_020;
            operational = await XPointNetworkOperationalGenesisAuthor.AuthorAsync(new(
                Bytes(32, 0x12), bootstrap, [root], witnesses, descriptors, Bytes(32, 0xf1),
                Bytes(32, 0xf4), Bytes(32, 0xf5), Bytes(32, 0xf6), PublicKey(0x31), PublicKey(0x32),
                990, 1_000, expiringHistory ? 1_090UL : 1_500UL, Bytes(32, 0xf2), Boot, 100, 100, 100, ProofTime, 5));
            var admission = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(
                await accounts.PrepareGenesisAdmissionAsync()).Admission;
            checkpoint = DeepIdV2GenesisAdmissionVerifier.Verify(admission, 1_000, 1, 2, pq);
            genesis = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
                bootstrap.Authority, 990, 1_500, witnesses);
            head = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority,
                genesis.ProtectedHead, new([], [], [checkpoint], 990, 1_500, 2), witnesses);
            if (withSuccessor)
                await AdvanceNetworkAsync();
            var floor = await accounts.OpenDirectoryLkgStoreAsync(bootstrap.Authority,
                genesis.ExactAdh1, genesis.CoreHash);
            NetworkStore = await accounts.OpenNetworkLkgStoreAsync(bootstrap.GenesisPin);
            http = new(this, disposeHandler: false);
            var transport = new HttpServiceRequestTransport(http,
                DeepIdV2DirectoryProofClient.CreateTransportOptions("https://registry.example/"),
                HttpServiceEndpointPolicy.Production);
            proofs = new(transport, new HttpServiceRequestTransport(new HttpClient(this, disposeHandler: false),
                DeepIdV2DirectoryProofClient.CreateHistoryTransportOptions("https://registry.example/"),
                HttpServiceEndpointPolicy.Production), this, pq, floor);
            closure = new(new HttpServiceRequestTransport(new HttpClient(this, disposeHandler: false),
                HttpDeepIdV2NetworkClosureArtifactSource.CreateTransportOptions("https://registry.example/"),
                HttpServiceEndpointPolicy.Production));
        }

        internal async Task AdvanceNetworkAsync()
        {
            Assert.Null(successor);
            var rollovers = nodes.Select((signer, index) => new XPointNetworkOperationalNodeRollover(
                signer, Bytes(32, (byte)(0x40 + index)), Bytes(32, (byte)(0x48 + index)),
                ScalarMult.Base(Bytes(32, (byte)(0x50 + index))),
                ScalarMult.Base(Bytes(32, (byte)(0x58 + index))))).ToArray();
            successor = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(new(
                Bytes(32, 0x13), bootstrap, [root], witnesses, rollovers,
                operational.ExactXvp1, operational.ExactXnd1, [operational.ExactXnv1],
                operational.ExactXnh1, operational.ExactPma2, operational.ExactPmt2,
                XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(operational.ExactXnh1.Span),
                Deep.Protocol.ContactV1.ContactCodec.Decode("PMT2", operational.ExactPmt2.Span).ArtifactHash.Span,
                HeadReference(head.CoreHash.Span), 1_070, 1_080, 1_500));
        }

        internal DeepIdV2ContactPathAuthoritySource Source(DeepIdV2AccountService? account = null) =>
            new(bootstrap.GenesisPin, account ?? accounts, proofs, closure, NetworkStore, this);

        private DeepIdV2NetworkClosureArtifacts PublicClosure()
        {
            var descriptors = (successor?.ExactXnd1 ?? operational.ExactXnd1)
                .Select(value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
            if (AlterNode) { var bytes = descriptors[0].ToArray(); bytes[^1] ^= 1; descriptors[0] = bytes; }
            if (successor is not null)
                return new DeepIdV2NetworkClosureArtifacts(
                    [bootstrap.ExactXna1], [bootstrap.ExactDts1],
                    OmitHistoricalPolicy ? [successor.ExactXvp1] : [operational.ExactXvp1, successor.ExactXvp1],
                    [operational.ExactXnv1, successor.ExactXnv1],
                    [operational.ExactXnh1, successor.ExactXnh1], descriptors,
                    [operational.ExactPmt2, successor.ExactPmt2]);
            return new DeepIdV2NetworkClosureArtifacts(
                [bootstrap.ExactXna1], [bootstrap.ExactDts1], [operational.ExactXvp1],
                [operational.ExactXnv1], [operational.ExactXnh1], descriptors, [operational.ExactPmt2]);
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == HttpDeepIdV2NetworkClosureArtifactSource.EndpointPath)
            {
                var network = XPointNetworkClosureWireCodec.DecodeRequest(
                    await request.Content!.ReadAsByteArrayAsync(cancellationToken));
                Assert.Equal(Network, network);
                var raw = PublicClosure();
                var encoded = XPointNetworkClosureWireCodec.EncodeResponse(network,
                    raw.ExactXna1AuthorityChain, raw.ExactDts1PolicyChain,
                    raw.ExactOrderedXvp1Chain, raw.ExactOrderedXnv1Chain,
                    raw.ExactOrderedXnh1Chain, raw.ExactActiveXnd1, raw.ExactOrderedPmt2Chain);
                var distributed = new HttpResponseMessage(HttpStatusCode.OK)
                { RequestMessage = request, Content = new ByteArrayContent(encoded) };
                distributed.Content.Headers.ContentType = new(XPointNetworkClosureWireCodec.ResponseMediaType);
                return distributed;
            }
            if (request.RequestUri.AbsolutePath == "/api/v2/account-directory/history")
            {
                if (RejectProof) return new(HttpStatusCode.ServiceUnavailable) { RequestMessage = request };
                var exact = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
                var encoded = DeepIdV2DirectoryHistoryWireCodec.AuthorResponse(bootstrap.Authority, exact,
                    [genesis.ProtectedHead, head.ProtectedHead], head.ExactAllTransitions);
                var historyResponse = new HttpResponseMessage(HttpStatusCode.OK)
                { RequestMessage = request, Content = new ByteArrayContent(encoded) };
                historyResponse.Content.Headers.ContentType = new(DeepIdV2DirectoryHistoryWireCodec.ResponseMediaType);
                return historyResponse;
            }
            ProofRequests++;
            if (RejectProof) return new(HttpStatusCode.ServiceUnavailable) { RequestMessage = request };
            var query = DeepIdV2DirectoryProofWireCodec.DecodeRequest(
                await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            var floor = query.Lookup.MinimumAdhGeneration switch
            {
                0 => genesis.ProtectedHead,
                1 => head.ProtectedHead,
                _ => throw new CryptographicException("Unknown test directory floor.")
            };
            var material = DeepIdV2DirectoryProofMaterialAuthor.Create(head.ProtectedHead,
                head.ExactAllTransitions, [checkpoint], query.DirectoryLeafKey.Span, floor);
            var issued = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(bootstrap.Authority,
                new(Network, query.Nonce.Span, query.BootId.Span, query.ClientMonotonicSendSample,
                    head.ExactAdh1.Span, (successor?.ExactXnv1 ?? operational.ExactXnv1).Span, ProofTime, 5, ProofTime, ProofTime + 30,
                    AccountDirectoryDtt1IssuanceEpoch.Derive(bootstrap.Authority, ProofTime, 5), 2),
                material, witnesses, 1, pq, cancellationToken);
            var body = DeepIdV2DirectoryProofWireCodec.EncodeResponse(query, issued);
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            { RequestMessage = request, Content = new ByteArrayContent(body) };
            response.Content.Headers.ContentType = new(DeepIdV2DirectoryProofWireCodec.ResponseMediaType);
            response.Headers.CacheControl = new() { NoStore = true };
            return response;
        }

        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(Boot, Sample));
        }

        public ValueTask DisposeAsync()
        {
            closure?.Dispose(); proofs?.Dispose(); http?.Dispose(); pq.Dispose(); innerStorage.Dispose();
            foreach (var signer in witnesses.Concat(nodes).Append(root)) signer.Dispose();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
            Dispose(); return ValueTask.CompletedTask;
        }
    }

    private sealed class NetworkMarkerFaultStorage(IDeepSecureStorage inner) : IDeepSecureStorage
    {
        internal Action? AfterCommitPairRead { get; set; }
        internal bool FailAfterNetworkMarker { get; set; }
        internal bool FailAfterHistoryAnchor { get; set; }
        internal string? LastHistoryAnchorSlot { get; private set; }
        internal bool FailAfterOnionMarker { get; set; }
        public async Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected,
            ReadOnlyMemory<byte> replacement, CancellationToken ct = default)
        {
            var applied = await inner.CompareExchangeAsync(slot, expected, replacement, ct);
            if (applied && FailAfterOnionMarker && slot.Contains(".onion-custody.", StringComparison.Ordinal))
            {
                FailAfterOnionMarker = false;
                throw new IOException("Injected stop after ONION marker, before SQL commit.");
            }
            return applied;
        }
        public async Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken ct = default)
        {
            var value = await inner.ReadOwnedAsync(slot, ct);
            if (slot == "deep.store.v2.prekey-commit-pair-v1" && AfterCommitPairRead is { } action)
            {
                AfterCommitPairRead = null;
                action();
            }
            return value;
        }
        public async Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken ct = default)
        {
            LastHistoryAnchorSlot = writes.SingleOrDefault(write =>
                write.Slot.Contains(".network-lkg-floor.history.", StringComparison.Ordinal))?.Slot ?? LastHistoryAnchorSlot;
            if (FailAfterNetworkMarker && writes.Any(write => write.Slot.Contains(".network-lkg-floor.", StringComparison.Ordinal)))
            {
                FailAfterNetworkMarker = false;
                // Commit only the first projection marker, before the history anchor.
                await inner.WriteBatchAsync([writes[0]], ct);
                throw new IOException("Injected stop after network marker, before history anchor and SQL commit.");
            }
            await inner.WriteBatchAsync(writes, ct);
            if (FailAfterOnionMarker && writes.Any(write => write.Slot.Contains(".onion-custody.", StringComparison.Ordinal)))
            {
                FailAfterOnionMarker = false;
                throw new IOException("Injected stop after ONION marker, before SQL commit.");
            }
            if (FailAfterHistoryAnchor && writes.Any(write => write.Slot.Contains(".network-lkg-floor.history.", StringComparison.Ordinal)))
            {
                FailAfterHistoryAnchor = false;
                throw new IOException("Injected stop after both network anchors, before SQL commit.");
            }
        }
        public Task DeleteBatchAsync(IReadOnlyList<string> slots, CancellationToken ct = default) => inner.DeleteBatchAsync(slots, ct);
        public Task PurgeStoreV1NamespaceAsync(CancellationToken ct = default) => inner.PurgeStoreV1NamespaceAsync(ct);
        public Task PurgeStoreV2NamespaceAsync(CancellationToken ct = default) => inner.PurgeStoreV2NamespaceAsync(ct);
    }

    private sealed class Signer : IDisposable, IXPointNetworkBootstrapRootSigner,
        IXPointNetworkWitnessSigner, IAccountDirectoryAdh1WitnessSigner
    {
        private readonly byte marker;
        private readonly KeyPair key;
        internal Signer(byte marker)
        {
            this.marker = marker;
            var seed = Bytes(32, marker);
            try { key = PublicKeyAuth.GenerateKeyPair(seed); }
            finally { CryptographicOperations.ZeroMemory(seed); }
        }
        public ReadOnlyMemory<byte> RootKeyId => Bytes(32, marker);
        public ReadOnlyMemory<byte> SignerId => marker >= 0x70 ? key.PublicKey : RootKeyId;
        public ReadOnlyMemory<byte> WitnessId => SignerId;
        public ulong KeyGeneration => 0;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, (byte)(marker + 0x40));
        public ReadOnlyMemory<byte> FailureDomainHash => CustodyDomainHash;
        public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request,
            Memory<byte> signature64, CancellationToken ct) => Sign(request.SigningInput, signature64, ct);
        public ValueTask<int> SignAsync(XPointNetworkOperationalSigningRequest request,
            Memory<byte> signature64, CancellationToken ct) => Sign(request.SigningInput, signature64, ct);
        internal byte[] SignCommit(ReadOnlyMemory<byte> input) => PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey);
        private ValueTask<int> Sign(ReadOnlyMemory<byte> input, Memory<byte> destination, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey).CopyTo(destination);
            return ValueTask.FromResult(64);
        }
        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(ReadOnlyMemory<byte> input, CancellationToken ct) => Witness(input, ct);
        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(ReadOnlyMemory<byte> input, CancellationToken ct) => Witness(input, ct);
        private ValueTask<ReadOnlyMemory<byte>> Witness(ReadOnlyMemory<byte> input, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey));
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
    private static byte[] HeadReference(ReadOnlySpan<byte> coreHash)
    {
        var reference = new byte[38];
        "ADH1"u8.CopyTo(reference);
        BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 1);
        coreHash.CopyTo(reference.AsSpan(6));
        return reference;
    }
    private static byte[] PublicKey(byte marker)
    {
        var seed = Bytes(32, marker); var pair = PublicKeyAuth.GenerateKeyPair(seed);
        try { return pair.PublicKey.ToArray(); }
        finally { CryptographicOperations.ZeroMemory(seed); CryptographicOperations.ZeroMemory(pair.PrivateKey); }
    }
}
