using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.PreKeyV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true, false)] [InlineData(false, false)]
    [InlineData(true, true)] [InlineData(false, true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2InitialSourceSegments_ActualProviderSubstitutionRejectsAndColdReadRecovers(
        bool senderSource, bool finalAdmission)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, receiver) = await fixture.PrepareActiveNativePair();
        await fixture.CheckInitialSourcePhysicalBoundary(senderSource ? sender : receiver, finalAdmission);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2InitialSourceSegments_ReceiverPendingConsumptionCompletesAfterCancellationOrLostStableCas(bool lostStableResult)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (_, receiver) = await fixture.PrepareActiveNativePair();
        await fixture.CheckReceiverPendingSourceCompletion(receiver, lostStableResult);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2InitialSourceSegments_FinalAdmissionRejoinsOtherCancelledScopeFloorAndHistory(bool history)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        await fixture.CheckCancelledSourceFinalRootJoin(sender, history);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2EstablishedNative_SendReceiveRouteAndColdAckNeverOpenOriginalSourceSqlAcrossCallbacks()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300);
        await fixture.CheckEstablishedNativeWithoutSourceSql(sender, receiver);
    }

    [Theory]
    [InlineData(true, false)] [InlineData(false, false)]
    [InlineData(true, true)] [InlineData(false, true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2EstablishedNative_ActualRetirementRemainsMandatoryWithoutOriginalSourceSql(bool senderSource, bool missing)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, receiver) = await fixture.PrepareActiveNativePair();
        await fixture.CheckEstablishedRetirement(senderSource ? sender : receiver, missing);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckEstablishedNativeWithoutSourceSql(Did2MessagingSessionScope sender, Did2MessagingSessionScope receiver)
        {
            var senderPath = Path.Combine(directory, "deep-store-v2-account.dsv2");
            var receiverPath = Path.Combine(directory, "peer", "deep-store-v2-account.dsv2");
            // An actual SQLite open in any path, including after a protected
            // callback or managed cold reopen, conflicts with these real locks.
            using var senderSource = new FileStream(SqliteDeepIdV2AccountGeneration.DeviceStatePath(senderPath), FileMode.Open, FileAccess.Read, FileShare.None);
            using var receiverSource = new FileStream(SqliteDeepIdV2AccountGeneration.PreKeyStatePath(receiverPath), FileMode.Open, FileAccess.Read, FileShare.None);
            var callback = false;
            storage.AfterMessagingRegistrationReadGroup = () => callback = true;
            try
            {
                using (var text = await CreateOwnedText(sender, "established native source provenance"))
                using (var sent = await SendOwnedMessage(sender, text.OperationId, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span)))
                using (var received = await ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray()))
                    Assert.Equal(sent.EventHash.ToArray(), received.EventHash.ToArray());
                Assert.True(callback, "The actual protected native inventory callback must precede established work.");
                byte[] envelope;
                using (var route = await CreateOwnedRouteUpdate(sender))
                using (var sent = await SendOwnedRouteUpdate(sender, route.OperationId)) envelope = sent.ExactEnvelope.ToArray();
                DropNativeRuntimes();
                var grants = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: false);
                var terminal = new OwnedReadTerminal(this, envelope);
                var ack = await SynchronizeNativeReceiver(grants, terminal);
                Assert.Equal(1, ack.ProcessedEnvelopes); Assert.Equal(1, ack.DurableTombstones);
                Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
                using var replay = await ReceiveOwnedMessage(receiver, envelope);
                Assert.Equal(3, replay.RouteProcessing[0]);
            }
            finally { storage.AfterMessagingRegistrationReadGroup = null; }
        }

        internal async Task CheckEstablishedRetirement(Did2MessagingSessionScope scope, bool missing)
        {
            var folder = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var accountPath = Path.Combine(folder, "deep-store-v2-account.dsv2");
            var actualStorage = NativeStorage(scope);
            using var original = await actualStorage.ReadOwnedAsync(ProtectedInitialKeyRetirementJournal.Slot) ?? throw new InvalidDataException();
            var exact = original.Use(bytes => bytes.ToArray()); byte[]? damaged = null;
            if (!missing)
            {
                var state = ProtectedInitialKeyRetirementJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
                var selected = Assert.Single(state.Entries.Values, entry => entry.Role == (scope.IsInitiator ? 1 : 2) &&
                    entry.ScopeHash.SequenceEqual(scope.Hash));
                var changed = selected.Exact.ToArray(); changed[140] ^= 1; // Exact selected original TRS commitment.
                try { state.Entries[selected.Coordinate] = new ProtectedInitialKeyRetirementJournal.Entry(changed); }
                finally { CryptographicOperations.ZeroMemory(changed); }
                damaged = ProtectedInitialKeyRetirementJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
                Assert.Equal(1, exact.Zip(damaged, (before, after) => before != after).Count(different => different));
            }
            original.Dispose();
            var accountLease = new DeepIdV2AccountFileLease(Path.Combine(folder, "deep-store-v2-account.lock"));
            var owner = new ProtectedDeepIdV2AccountOwner(actualStorage, accountLease, accountPath, Network, 1);
            using var current = await owner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidDataException();
            var sourcePath = scope.IsInitiator ? SqliteDeepIdV2AccountGeneration.DeviceStatePath(accountPath) : SqliteDeepIdV2AccountGeneration.PreKeyStatePath(accountPath);
            using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.None);
            Assert.True(missing
                ? await actualStorage.CompareAndDeleteAsync(ProtectedInitialKeyRetirementJournal.Slot, exact, [ProtectedInitialKeyRetirementJournal.Slot])
                : await actualStorage.CompareExchangeAsync(ProtectedInitialKeyRetirementJournal.Slot, exact, damaged!));
            try
            {
                using var held = await accountLease.AcquireAsync(default);
                var error = await Record.ExceptionAsync(async () =>
                {
                    using var opened = await SqliteDeepIdV2AccountGeneration.OpenOrdinaryMessagingUnderLeaseAsync(actualStorage, accountPath, current, scope, default);
                });
                Assert.True(error is InvalidDataException or CryptographicException or FormatException,
                    "Established admission must reject changed retirement independently of original SQL: " + error?.GetType().Name);
            }
            finally
            {
                if (missing) await actualStorage.WriteBatchAsync([new DeepSecureStorageWrite(ProtectedInitialKeyRetirementJournal.Slot, exact)]);
                else Assert.True(await actualStorage.CompareExchangeAsync(ProtectedInitialKeyRetirementJournal.Slot, damaged!, exact));
                CryptographicOperations.ZeroMemory(exact); if (damaged is not null) CryptographicOperations.ZeroMemory(damaged);
            }
            using (var held = await accountLease.AcquireAsync(default))
            using (var opened = await SqliteDeepIdV2AccountGeneration.OpenOrdinaryMessagingUnderLeaseAsync(actualStorage, accountPath, current, scope, default)) { }
        }

        internal async Task CheckCancelledSourceFinalRootJoin(Did2MessagingSessionScope active, bool history)
        {
            var intent = Bytes(32, 0xda); var pending = await PrepareNativeHelloCompletion(intent, oneTimeIndex: 0);
            var cancelled = await RegisterEmptySenderForCancellation(intent, pending.Init, pending.Hello, pending.Complete, initialize: true);
            await CancelPreSessionInitial(intent);
            var slot = history ? Did2MessagingHistoryCheckpoint.Slot(cancelled) : cancelled.FloorSlot;
            var actualStorage = NativeStorage(active);
            using var raw = await actualStorage.ReadOwnedAsync(slot) ?? throw new InvalidDataException();
            var exact = raw.Use(bytes => bytes.ToArray()); var substituted = exact.ToArray(); substituted[^1] ^= 1;
            raw.Dispose();
            var protectedStorage = new NetworkMarkerFaultStorage(actualStorage);
            var accountPath = Path.Combine(directory, "deep-store-v2-account.dsv2");
            var accountLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            var owner = new ProtectedDeepIdV2AccountOwner(protectedStorage, accountLease, accountPath, Network, 1);
            using var current = await owner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidDataException();
            var hit = false;
            protectedStorage.AfterInitialSourceHeadsReadGroup = () =>
            {
                // Cancellation emptiness has already been checked. The later
                // final source inventory must still carry this other scope.
                hit = true;
                Assert.True(actualStorage.CompareExchangeAsync(slot, exact, substituted).GetAwaiter().GetResult());
            };
            try
            {
                using var held = await accountLease.AcquireAsync(default);
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                {
                    using var opened = await SqliteDeepIdV2AccountGeneration.OpenMessagingArchiveAuditUnderLeaseAsync(
                        protectedStorage, accountPath, current, active, default);
                });
                Assert.True(hit);
            }
            finally
            {
                protectedStorage.AfterInitialSourceHeadsReadGroup = null;
                Assert.True(await actualStorage.CompareExchangeAsync(slot, substituted, exact));
                CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(substituted);
            }
            using (var held = await accountLease.AcquireAsync(default))
            using (var opened = await SqliteDeepIdV2AccountGeneration.OpenMessagingArchiveAuditUnderLeaseAsync(
                protectedStorage, accountPath, current, active, default)) { }
        }
        internal async Task CheckReceiverPendingSourceCompletion(Did2MessagingSessionScope receiver, bool lostStableResult)
        {
            var peer = peerAccounts!; var source = Source(peer); var local = peerCheckpoint!;
            var initial = await peer.EnsureOwnPreKeyInventoryAsync(source);
            _ = await StageAndRecordPairAsync(owner: peer);
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(peer, default);
            var old = DeepIdV2PreKeyServiceCodec.Decode(initial.ExactXps1.Span);
            using (var author = await peer.OpenLocalPreKeyAuthoringAuthorityAsync())
            {
                var context = new Dpk2AuthoringContext(ApplicationCoreVerifier.StartDmd1Lineage(local.Directory).Next,
                    2, 1, 1, fresh.Proof.TrustedLowerUnixSeconds, fresh.Proof.TrustedLowerUnixSeconds,
                    BinaryPrimitives.ReadUInt64BigEndian(old.Field(11).Span) + 60);
                var service = author.AuthorPreKeyServiceV2(context, local.Binding, 32, 1, old.CanonicalBytes.Span);
                var placement = ContactServicePlacementFactory.Create(fresh.Network, ContactServiceRequestKind.PublishPreKeyInventory, service.ServiceCapability);
                var drs = new byte[38]; "DRS1"u8.CopyTo(drs); BinaryPrimitives.WriteUInt16BigEndian(drs.AsSpan(4), 1);
                local.Binding.Identity.Revocations.Snapshot.CanonicalHash.Span.CopyTo(drs.AsSpan(6));
                using var inventory = author.AuthorInventoryV2(context, local.Binding, service, drs, new byte[32],
                    Bytes(32, 0xd7), placement.PlacementHash.Span, 32, 1);
                await peer.StageOwnSuccessorPreKeyInventoryAsync(service, inventory);
            }
            _ = await StageAndRecordPairAsync(owner: peer);
            var staged = (await peer.ReadOwnStagedPreKeyPublicationAsync())!;
            var publicationHash = SHA256.HashData(staged.ExactXpp1.Span);
            var slot = ProtectedPreKeyInventoryChain.EntrySlot(publicationHash);
            var (complete, _, _, _, _) = await PrepareNativeHelloCompletion(Bytes(32, 0xd8), oneTimeIndex: 0);
            using var sent = await complete(accounts); var envelope = sent.ExactDph2.ToArray();
            using (ResponderInitialSessionTestHooks.Push(point =>
                { if (point == ResponderInitialSessionFailpoint.AfterPending) throw new IOException("Pending receiver source before native admission."); }))
                await Assert.ThrowsAsync<IOException>(() => CompleteReceiver(envelope));
            var folder = Path.Combine(directory, "peer"); var accountPath = Path.Combine(folder, "deep-store-v2-account.dsv2");
            var protectedStorage = new NetworkMarkerFaultStorage(NativeStorage(receiver));
            var ownerLease = new DeepIdV2AccountFileLease(Path.Combine(folder, "deep-store-v2-account.lock"));
            var owner = new ProtectedDeepIdV2AccountOwner(protectedStorage, ownerLease, accountPath, Network, 1);
            using var current = await owner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidDataException();
            var nativeBefore = await ReadMessagingFloor(receiver);
            using var cancellation = new CancellationTokenSource(); var consumed = false; var stableCommitted = false; var actualPendingRead = false;
            protectedStorage.AfterSourceRecoveryReadGroup = phase =>
            {
                Assert.Equal(2, phase); actualPendingRead = true;
                // Recovery reacquires its private checkpoint together with
                // registration BEFORE opening the physical source segment.
                using var exclusive = new FileStream(SqliteDeepIdV2AccountGeneration.PreKeyStatePath(accountPath), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            };
            protectedStorage.AfterSourceSuccessorConsumption = () =>
            {
                Assert.True(actualPendingRead); consumed = true;
                using var exclusive = new FileStream(SqliteDeepIdV2AccountGeneration.PreKeyStatePath(accountPath), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                if (!lostStableResult) cancellation.Cancel();
            };
            protectedStorage.AfterSourceReceiverStable = () =>
            {
                stableCommitted = true;
                if (lostStableResult) throw new IOException("Lost result after stable source CAS.");
            };
            using (var held = await ownerLease.AcquireAsync(default))
            {
                var failure = await Record.ExceptionAsync(async () =>
                {
                    using var opened = await SqliteDeepIdV2AccountGeneration.OpenMessagingArchiveAuditUnderLeaseAsync(
                        protectedStorage, accountPath, current, receiver, cancellation.Token);
                });
                Assert.True(actualPendingRead); Assert.True(consumed); Assert.True(stableCommitted);
                Assert.True(lostStableResult ? failure is IOException : failure is OperationCanceledException);
            }
            await AssertConsumed();
            using (var checkpoint = await peerStorage.ReadOwnedAsync(ResponderInitialSessionCheckpoint.Slot))
                Assert.Equal(1, checkpoint!.Use(bytes => bytes[1]));
            DropNativeRuntimes(); ColdReopenReceiverStoreStorage();
            protectedStorage = new NetworkMarkerFaultStorage(NativeStorage(receiver));
            using (var held = await ownerLease.AcquireAsync(default))
            using (var opened = await SqliteDeepIdV2AccountGeneration.OpenMessagingArchiveAuditUnderLeaseAsync(
                protectedStorage, accountPath, current, receiver, default)) { }
            await AssertConsumed();
            Assert.Equal(nativeBefore.Exact.ToArray(), (await ReadMessagingFloor(receiver)).Exact.ToArray());
            using var recovered = await FindReceiver(envelope, reopen: true); Assert.NotNull(recovered);
            Assert.Equal(sent.SessionId.ToArray(), recovered!.SessionId.ToArray());
            await using (var sql = await OpenPeerPreKeySqlAsync())
            using (var query = sql.CreateCommand())
            {
                query.CommandText = "SELECT COUNT(*) FROM receiver_sessions;"; Assert.Equal(2L, (long)query.ExecuteScalar()!);
                query.CommandText = "SELECT COUNT(*) FROM secrets WHERE exact_dpk2_hash=$hash;";
                query.Parameters.AddWithValue("$hash", Dph2Codec.Decode(envelope).ExactDpk2Hash.ToArray());
                Assert.Equal(0L, (long)query.ExecuteScalar()!);
            }

            async Task AssertConsumed()
            {
                using var exact = await peerStorage.ReadOwnedAsync(slot);
                using var installed = await peerStorage.ReadOwnedAsync("deep.store.v2.prekey-installed");
                var scope = installed!.Use(bytes => bytes.ToArray());
                using var entry = exact!.Use(bytes => ProtectedPreKeyInventoryChain.Entry.Decode(bytes, scope, publicationHash));
                var secret = entry.CopySealedSecret(0);
                try { Assert.Empty(secret); } finally { CryptographicOperations.ZeroMemory(secret); }
            }
        }
        internal async Task CheckInitialSourcePhysicalBoundary(Did2MessagingSessionScope scope, bool finalAdmission)
        {
            var folder = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var accountPath = Path.Combine(folder, "deep-store-v2-account.dsv2");
            var sourcePath = scope.IsInitiator ? SqliteDeepIdV2AccountGeneration.DeviceStatePath(accountPath) :
                SqliteDeepIdV2AccountGeneration.PreKeyStatePath(accountPath);
            var protectedStorage = new NetworkMarkerFaultStorage(NativeStorage(scope));
            var lease = new DeepIdV2AccountFileLease(Path.Combine(folder, "deep-store-v2-account.lock"));
            var owner = new ProtectedDeepIdV2AccountOwner(protectedStorage, lease, accountPath, Network, 1);
            using var current = await owner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidDataException();
            using var held = await lease.AcquireAsync(default);
            async Task Open()
            {
                using var opened = await SqliteDeepIdV2AccountGeneration.OpenMessagingArchiveAuditUnderLeaseAsync(
                    protectedStorage, accountPath, current, scope, default);
                held.RequireOwner(lease);
            }
            await Open(); // The failure cannot be blamed on uninitialized source custody.
            var stable = await ReadMessagingFloor(scope);
            var original = await File.ReadAllBytesAsync(sourcePath);
            Assert.True(original.Length > 100);
            var damaged = original.ToArray(); damaged[100] ^= 1;
            var hit = false; var exclusiveWriteCompleted = false;
            void Substitute()
            {
                hit = true;
                // On Windows this also proves the source's physical SQL handle
                // was closed before entering the actual protected provider.
                using var file = new FileStream(sourcePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                file.Write(damaged); file.Flush(true); exclusiveWriteCompleted = true;
            }
            if (finalAdmission) protectedStorage.AfterMessagingRegistrationReadGroup = Substitute;
            else protectedStorage.AfterRetirementReadGroup = Substitute;
            try
            {
                var error = await Record.ExceptionAsync(Open);
                Assert.True(hit, "The actual protected provider callback did not run.");
                Assert.True(exclusiveWriteCompleted, "A physical source handle crossed the provider callback.");
                Assert.True(error is DeviceStateStoreOpenException or SqliteException or CryptographicException or InvalidDataException,
                    "Fresh admission released a substituted original source: " + (error?.GetType().Name ?? "none"));
                Assert.Equal(stable.Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
            }
            finally
            {
                protectedStorage.AfterMessagingRegistrationReadGroup = null;
                protectedStorage.AfterRetirementReadGroup = null;
                await File.WriteAllBytesAsync(sourcePath, original);
                CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(damaged);
            }
            DropNativeRuntimes();
            if (scope.IsInitiator) ColdReopenCompactionStorage(); else ColdReopenReceiverStoreStorage();
            await Open();
            Assert.Equal(stable.Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
        }
    }
}
