using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.PreKeyV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2OwnedPreKeyInventory_ActualSqlKeyLeaseAndColdRecovery(bool encryptedStorage)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: encryptedStorage);
        await fixture.CheckOwnedPreKeyInventoryAsync(encryptedStorage);
    }

    [Theory]
    [InlineData((int)ResponderInitialSessionFailpoint.AfterPending)]
    [InlineData((int)ResponderInitialSessionFailpoint.AfterSqlCommit)]
    [InlineData((int)ResponderInitialSessionFailpoint.AfterSuccessorSecretDelete)]
    [InlineData((int)ResponderInitialSessionFailpoint.AfterStable)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedPreKeyInventory_ReceiverConsumesOnceAndRecoversAllBoundaries(int point)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckSuccessorReceiverAsync((ResponderInitialSessionFailpoint)point);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedPreKeyInventory_LastResortCounterSpansEpochsAndPreservesPendingHello()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckEpochLastResortAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckEpochLastResortAsync()
        {
            var peer = peerAccounts!; var local = peerCheckpoint!; var source = Source(peer);
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(peer, default);
            var issued = fresh.Proof.TrustedLowerUnixSeconds;
            var expires = Math.Min(checked(issued + 100), local.Binding.Identity.ActiveDevices.Single().Certificate.ExpiresAtUnixSeconds);
            using var author = await peer.OpenLocalPreKeyAuthoringAuthorityAsync();
            var context = new Dpk2AuthoringContext(ApplicationCoreVerifier.StartDmd1Lineage(local.Directory).Next,
                1, 1, 1, issued, issued, expires);
            var service = author.AuthorPreKeyServiceV2(context, local.Binding, 32, 2);
            using var initial = AuthorEpoch(1, new byte[32], 0xd1);
            await peer.StageOwnInitialPreKeyInventoryAsync(service, initial);
            _ = await StageAndRecordPairAsync(owner: peer);
            var (oldComplete, _, _, _, _) = await PrepareNativeHelloCompletion(Bytes(32, 0xd2));
            using var oldSent = await oldComplete(accounts); // Counter1 is still in flight.

            var prior = DeepIdV2PreKeyPublicationCodec.Decode(initial.ExactXpp1.Span);
            using var next = AuthorEpoch(2, prior.Manifest.ExactHash.ToArray(), 0xd3);
            await peer.StageOwnSuccessorPreKeyInventoryAsync(service, next);
            _ = await StageAndRecordPairAsync(owner: peer);
            var (newComplete, _, _, _, _) = await PrepareNativeHelloCompletion(Bytes(32, 0xd4), lastResortCounter: 2);
            using var newSent = await newComplete(accounts);
            using var firstReceived = await CompleteReceiver(newSent.ExactDph2);
            await AssertLastResortStateAsync(exhausted: false);
            using var resumed = await FindReceiver(newSent.ExactDph2, reopen: true);
            Assert.NotNull(resumed);
            using var oldReceived = await CompleteReceiver(oldSent.ExactDph2);
            Assert.True(oldSent.SessionId.Span.SequenceEqual(oldReceived.SessionId.Span), "Old pending Hello changed across inventory succession.");
            await AssertLastResortStateAsync(exhausted: true);
            using var replay = await FindReceiver(oldSent.ExactDph2, reopen: true);
            Assert.NotNull(replay);

            // This valid independently signed claim incorrectly reuses global
            // counter1 on a different epoch's LR key. The retained receiver
            // rejects it before opening ciphertext or consuming another key.
            var (conflictComplete, _, _, _, _) = await PrepareNativeHelloCompletion(Bytes(32, 0xd5));
            using var conflict = await conflictComplete(accounts);
            var refusal = await Assert.ThrowsAsync<CryptographicException>(() => FindReceiver(conflict.ExactDph2, reopen: true));
            Assert.Equal("Receiver last-resort service counter was already consumed by a different session.", refusal.Message);
            await AssertLastResortStateAsync(exhausted: true);
            var nextPublic = DeepIdV2PreKeyPublicationCodec.Decode(next.ExactXpp1.Span);
            using var exhaustedEpoch = AuthorEpoch(3, nextPublic.Manifest.ExactHash.ToArray(), 0xd6);
            var exhaustion = await Assert.ThrowsAsync<CryptographicException>(() => peer.StageOwnSuccessorPreKeyInventoryAsync(service, exhaustedEpoch));
            Assert.Equal("A replenished inventory cannot reset an exhausted last-resort service counter.", exhaustion.Message);
            var retained = (await peer.ReadOwnStagedPreKeyPublicationAsync())!;
            Assert.True(retained.ExactXpp1.Span.SequenceEqual(next.ExactXpp1.Span), "Exhausted service changed protected inventory custody.");

            AuthoredDpk2InventoryV2 AuthorEpoch(ulong epoch, byte[] predecessor, byte operation)
            {
                var epochContext = new Dpk2AuthoringContext(context.CurrentDirectory, 1, epoch, 1, issued, issued, expires);
                var placement = ContactServicePlacementFactory.Create(fresh.Network, ContactServiceRequestKind.PublishPreKeyInventory, service.ServiceCapability);
                var drs = new byte[38]; "DRS1"u8.CopyTo(drs); BinaryPrimitives.WriteUInt16BigEndian(drs.AsSpan(4), 1);
                local.Binding.Identity.Revocations.Snapshot.CanonicalHash.Span.CopyTo(drs.AsSpan(6));
                return author.AuthorInventoryV2(epochContext, local.Binding, service, drs, predecessor,
                    Bytes(32, operation), placement.PlacementHash.Span, 32, 2);
            }

            async Task AssertLastResortStateAsync(bool exhausted)
            {
                var hash = SHA256.HashData(next.ExactXpp1.Span);
                using var installed = await peerStorage.ReadOwnedAsync("deep.store.v2.prekey-installed");
                var scope = installed!.Use(value => value.ToArray());
                using var exact = await peerStorage.ReadOwnedAsync(ProtectedPreKeyInventoryChain.EntrySlot(hash));
                using var entry = exact!.Use(value => ProtectedPreKeyInventoryChain.Entry.Decode(value, scope, hash));
                var blob = entry.CopySealedSecret(32);
                try { Assert.Equal(exhausted, blob.Length == 0); }
                finally { CryptographicOperations.ZeroMemory(blob); }
                await using var connection = await OpenPeerPreKeySqlAsync();
                using (var count = connection.CreateCommand())
                {
                    count.CommandText = "SELECT COUNT(*) FROM secrets;";
                    Assert.Equal(exhausted ? 32L : 33L, (long)count.ExecuteScalar()!);
                }
            }
        }

        internal async Task CheckSuccessorReceiverAsync(ResponderInitialSessionFailpoint point)
        {
            var peer = peerAccounts!; var local = peerCheckpoint!; var source = Source(peer);
            var initial = await peer.EnsureOwnInitialPreKeyInventoryAsync(source);
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
                    Bytes(32, 0xc7), placement.PlacementHash.Span, 32, 1);
                var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof,
                    DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(initial.ExactDca1.Span), local.Binding, local.Directory), Boot, Sample);
                DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(local.Binding.DeepId, service.ExactXps1.Span, authorization,
                    DeepIdV2PreKeyPublicationCodec.Decode(inventory.ExactXpp1.Span), Boot, Sample);
                await peer.StageOwnSuccessorPreKeyInventoryAsync(service, inventory);
            }
            _ = await StageAndRecordPairAsync(owner: peer);
            var staged = (await peer.ReadOwnStagedPreKeyPublicationAsync())!;
            var hash = SHA256.HashData(staged.ExactXpp1.Span);
            using var installed = await peerStorage.ReadOwnedAsync("deep.store.v2.prekey-installed");
            var scope = installed!.Use(value => value.ToArray());
            var (complete, hello, init, _, _) = await PrepareNativeHelloCompletion(Bytes(32, 0xc8), oneTimeIndex: 0);
            using var sent = await complete(accounts); var exact = sent.ExactDph2.ToArray();
            var hit = false;
            using (ResponderInitialSessionTestHooks.Push(actual =>
                { if (actual == point) { hit = true; throw new IOException("Injected successor receiver interruption."); } }))
                await Assert.ThrowsAsync<IOException>(() => CompleteReceiver(exact));
            Assert.True(hit);
            await AssertSecretAsync(point is ResponderInitialSessionFailpoint.AfterSuccessorSecretDelete or ResponderInitialSessionFailpoint.AfterStable);
            using var recovered = await FindReceiver(exact, reopen: true);
            Assert.NotNull(recovered);
            Assert.True(CryptographicOperations.FixedTimeEquals(sent.SessionId.Span, recovered.SessionId.Span), "Recovered receiver session changed.");
            Assert.True(recovered.ExactInitSpan.SequenceEqual(init.CanonicalBytes.Span), "Recovered Initial changed.");
            Assert.True(recovered.ExactHelloSpan.SequenceEqual(hello.CanonicalBytes.Span), "Recovered Hello changed.");
            await AssertSecretAsync(consumed: true);
            var proofRequests = ProofRequests;
            using var replay = await CompleteReceiver(exact);
            Assert.True(replay.CanonicalSpan.SequenceEqual(recovered.CanonicalSpan), "Exact receiver replay changed.");
            Assert.Equal(proofRequests, ProofRequests);
            await AssertReceiverSqlAsync(1, exact, successor: true);
            await RollBackReceiverSqlAsync();
            await Assert.ThrowsAsync<CryptographicException>(() => FindReceiver(exact, reopen: true));
            await AssertSecretAsync(consumed: true);

            async Task AssertSecretAsync(bool consumed)
            {
                using var record = await peerStorage.ReadOwnedAsync(ProtectedPreKeyInventoryChain.EntrySlot(hash));
                using var parsed = record!.Use(value => ProtectedPreKeyInventoryChain.Entry.Decode(value, scope, hash));
                var blob = parsed.CopySealedSecret(0);
                try { Assert.Equal(consumed, blob.Length == 0); }
                finally { CryptographicOperations.ZeroMemory(blob); }
            }
        }

        internal async Task CheckOwnedPreKeyInventoryAsync(bool encrypted)
        {
            var source = Source(); var initial = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var initialPair = await StageAndRecordPairAsync();
            var accountId = (await accounts.GetCurrentAsync())!.AccountId.ToArray();
            var address = (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText;
            var beforeReadback = await ReadbackAsync();
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof,
                DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(initial.ExactDca1.Span),
                    checkpoint.Binding, checkpoint.Directory), Boot, Sample);
            using var author = await accounts.OpenLocalPreKeyAuthoringAuthorityAsync();
            var oldService = DeepIdV2PreKeyServiceCodec.Decode(initial.ExactXps1.Span);
            var first = Author(oldService, 0xb1);
            using var firstInventory = first.Inventory;
            var expectedFirst = firstInventory.ExactXpp1.ToArray();
            await accounts.StageOwnSuccessorPreKeyInventoryAsync(first.Service, firstInventory);
            Assert.Null(await accounts.ReadOwnPreKeyCommitPairAsync());
            await Assert.ThrowsAsync<IOException>(ReadbackAsync);
            if (encrypted) ColdReopenCompactionStorage();
            var reopened = ReopenAccount();
            var restored = (await reopened.ReadOwnStagedPreKeyPublicationAsync())!;
            Assert.True(CryptographicOperations.FixedTimeEquals(expectedFirst, restored.ExactXpp1.Span), "Owned SQL-key inventory changed after reopen.");
            Assert.Equal(address, (await reopened.GetCurrentAsync())!.PermanentId.CanonicalText);
            var retry = await reopened.EnsureOwnInitialPreKeyInventoryAsync(Source(reopened));
            Assert.True(CryptographicOperations.FixedTimeEquals(expectedFirst, retry.ExactXpp1.Span), "Pending publication must retain exact keys and operation.");

            var next = Author(DeepIdV2PreKeyServiceCodec.Decode(restored.ExactXps1.Span), 0xb2);
            using var nextInventory = next.Inventory;
            await Assert.ThrowsAsync<CryptographicException>(() => reopened.StageOwnSuccessorPreKeyInventoryAsync(next.Service, nextInventory));
            _ = await StageAndRecordPairAsync();
            var committedReadback = await ReadbackAsync();
            Assert.False(CryptographicOperations.FixedTimeEquals(beforeReadback, committedReadback));
            if (encrypted) ColdReopenCompactionStorage();
            var reopenedReadback = await ReadbackAsync();
            Assert.True(CryptographicOperations.FixedTimeEquals(committedReadback, reopenedReadback), "Source readback changed across cold reopen.");

            // A well-framed but unauthenticated sealed key must reject at the
            // actual SQL-key owner, not only at the isolated format boundary.
            var firstHash = SHA256.HashData(expectedFirst);
            var slot = ProtectedPreKeyInventoryChain.EntrySlot(firstHash);
            using var owned = await storage.ReadOwnedAsync(slot);
            var exact = owned!.Use(value => value.ToArray()); var corrupt = exact.ToArray(); corrupt[^1] ^= 1;
            Assert.True(await storage.CompareExchangeAsync(slot, exact, corrupt));
            try { await Assert.ThrowsAsync<CryptographicException>(() => ReopenAccount().ReadOwnStagedPreKeyPublicationAsync()); }
            finally
            {
                Assert.True(await storage.CompareExchangeAsync(slot, corrupt, exact));
                CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(corrupt);
            }

            storage.FailAfterPreKeySuccessorInsert = true;
            await Assert.ThrowsAsync<IOException>(() => reopened.StageOwnSuccessorPreKeyInventoryAsync(next.Service, nextInventory));
            if (encrypted) ColdReopenCompactionStorage();
            var recovered = ReopenAccount();
            var pending = (await recovered.ReadOwnStagedPreKeyPublicationAsync())!;
            Assert.True(CryptographicOperations.FixedTimeEquals(nextInventory.ExactXpp1.Span, pending.ExactXpp1.Span), "Lost response cannot reauthor the inventory.");
            Assert.Null(await recovered.ReadOwnPreKeyCommitPairAsync());
            _ = await StageAndRecordPairAsync();
            Assert.NotNull(await recovered.ReadOwnPreKeyCommitPairAsync());
            var retainedInitialPair = await ReadInitialPairAsync();
            Assert.True(CryptographicOperations.FixedTimeEquals(initialPair.ExactFirstXic1.Span,
                retainedInitialPair.AsSpan(64, initialPair.ExactFirstXic1.Length)), "Initial replica evidence changed.");
            Assert.Equal(address, (await recovered.GetCurrentAsync())!.PermanentId.CanonicalText);
            _ = await ReadbackAsync();

            (AuthoredDeepIdV2PreKeyService Service, AuthoredDpk2InventoryV2 Inventory) Author(ParsedXps1V2 previous, byte operation)
            {
                var context = new Dpk2AuthoringContext(ApplicationCoreVerifier.StartDmd1Lineage(checkpoint.Directory).Next,
                    checked(BinaryPrimitives.ReadUInt64BigEndian(previous.Field(5).Span) + 1), 1, 1,
                    fresh.Proof.TrustedLowerUnixSeconds, fresh.Proof.TrustedLowerUnixSeconds,
                    checked(BinaryPrimitives.ReadUInt64BigEndian(previous.Field(11).Span) + 60));
                var service = author.AuthorPreKeyServiceV2(context, checkpoint.Binding, 32, 1, previous.CanonicalBytes.Span);
                var placement = ContactServicePlacementFactory.Create(fresh.Network, ContactServiceRequestKind.PublishPreKeyInventory, service.ServiceCapability);
                var drs = new byte[38]; "DRS1"u8.CopyTo(drs); BinaryPrimitives.WriteUInt16BigEndian(drs.AsSpan(4), 1);
                checkpoint.Binding.Identity.Revocations.Snapshot.CanonicalHash.Span.CopyTo(drs.AsSpan(6));
                var inventory = author.AuthorInventoryV2(context, checkpoint.Binding, service, drs, new byte[32],
                    Bytes(32, operation), placement.PlacementHash.Span, 32, 1);
                try
                {
                    DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(checkpoint.Binding.DeepId, service.ExactXps1.Span,
                        authorization, DeepIdV2PreKeyPublicationCodec.Decode(inventory.ExactXpp1.Span), Boot, Sample);
                    return (service, inventory);
                }
                catch { inventory.Dispose(); throw; }
            }

            async Task<byte[]> ReadInitialPairAsync()
            {
                using var marker = await storage.ReadOwnedAsync("deep.store.v2.prekey-commit-pair-v1");
                return marker!.Use(value => value.ToArray());
            }

            async Task<byte[]> ReadbackAsync()
            {
                using var record = await storage.ReadOwnedAsync("deep.store.v2.sql-generation");
                var instance = record!.Use(value => value.Slice(56, 32).ToArray());
                var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
                using var held = await lease.AcquireAsync(default);
                return await SqliteDeepIdV2AccountGeneration.ReadExistingPreKeySourceReadbackUnderLeaseAsync(storage,
                    Path.Combine(directory, "deep-store-v2-account.dsv2"), Network, accountId, instance, held, lease, default);
            }
        }
    }
}
