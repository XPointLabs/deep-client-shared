using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    [InlineData(true, true, true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreKeyMaintenance_ExpiredCommittedInventoryRecoversExactOwner(
        bool encrypted, bool expiredService, bool lostResponse)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: encrypted);
        await fixture.CheckPreKeyMaintenanceAsync(encrypted, expiredService, lostResponse);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreKeyMaintenance_ServiceRestoreRejectsForeignOrChangedSupport(int shape)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: shape is 2 or 3);
        await fixture.CheckServiceRestoreRefusalAsync(shape);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreKeyMaintenance_CommittedServiceForcesOwnedContactSuccessorAndKeepsLocator()
    {
        // A genuinely signed root horizon covers the ordinary day-long
        // resource. Short DTS/view freshness is still independently checked.
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        await fixture.CheckMaintainedContactPublicationAsync(canAdvance: true);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2PreKeyMaintenance_ShortAuthorityBlocksNewReachabilityWithoutMutatingContact()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckMaintainedContactPublicationAsync(canAdvance: false);
    }

    private sealed partial class Fixture
    {
        internal void FailAfterNextPreKeySuccessorInsert() => storage.FailAfterPreKeySuccessorInsert = true;
        internal async Task<byte[]> ReadInitialPreKeyPairBytesAsync()
        {
            using var owned = await storage.ReadOwnedAsync("deep.store.v2.prekey-commit-pair-v1");
            return owned!.Use(value => value.ToArray());
        }

        internal async Task CheckMaintainedContactPublicationAsync(bool canAdvance)
        {
            var backend = new RenewalBackend(this, genesisRouteLifetimeSeconds: 120);
            var original = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend);
            _ = await StageAndRecordPairAsync();
            var old = (await accounts.ReadOwnStagedPreKeyPublicationAsync())!;
            var oldXps = DeepIdV2PreKeyServiceCodec.Decode(old.ExactXps1.Span);
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            var name = Convert.ToHexString(plan.Intent.Span);
            byte[] oldOwnerCapability, oldLocator;
            using (var state = await RouteState())
            {
                var oldRequest = ContactPublicationAuthorityWireCodec.DecodeRequest(state.Entries[name].Record(9).Span);
                oldOwnerCapability = oldRequest.OwnerRetrieveCapability.ToArray(); oldLocator = oldRequest.LocatorHash.ToArray();
            }
            var source = Source(); var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            using (var author = await accounts.OpenLocalPreKeyAuthoringAuthorityAsync())
            {
                var issued = fresh.Proof.TrustedLowerUnixSeconds;
                var context = new Dpk2AuthoringContext(ApplicationCoreVerifier.StartDmd1Lineage(checkpoint.Directory).Next,
                    2, 1, 1, issued, issued, BinaryPrimitives.ReadUInt64BigEndian(oldXps.Field(11).Span) + 60);
                var service = author.AuthorPreKeyServiceV2(context, checkpoint.Binding, 32, 1, oldXps.CanonicalBytes.Span);
                var placement = ContactServicePlacementFactory.Create(fresh.Network, ContactServiceRequestKind.PublishPreKeyInventory, service.ServiceCapability);
                var drs = new byte[38]; "DRS1"u8.CopyTo(drs); BinaryPrimitives.WriteUInt16BigEndian(drs.AsSpan(4), 1);
                checkpoint.Binding.Identity.Revocations.Snapshot.CanonicalHash.Span.CopyTo(drs.AsSpan(6));
                using var inventory = author.AuthorInventoryV2(context, checkpoint.Binding, service, drs,
                    new byte[32], Bytes(32, 0xe2), placement.PlacementHash.Span, 32, 1);
                await accounts.StageOwnSuccessorPreKeyInventoryAsync(service, inventory);
            }
            var before = await RouteSnapshot(); var routeCalls = backend.RouteCalls;
            await Assert.ThrowsAsync<CryptographicException>(() => accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend));
            Assert.Equal(routeCalls, backend.RouteCalls);
            var rejected = await RouteSnapshot();
            Assert.True(before.AsSpan().SequenceEqual(rejected), "Uncommitted service changed contact custody.");
            CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(rejected);
            _ = await StageAndRecordPairAsync();
            ColdReopenCompactionStorage(); var reopened = ReopenAccount();
            if (!canAdvance)
            {
                var prior = await RouteSnapshot(); var callsBefore = backend.RouteCalls;
                var refusal = await Assert.ThrowsAsync<CryptographicException>(() => reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend));
                Assert.Equal("Current authority cannot extend the exact reachability predecessor.", refusal.Message);
                Assert.Equal(callsBefore, backend.RouteCalls);
                var afterRefusal = await RouteSnapshot();
                Assert.True(prior.AsSpan().SequenceEqual(afterRefusal), "Insufficient authority changed contact custody.");
                CryptographicOperations.ZeroMemory(prior); CryptographicOperations.ZeroMemory(afterRefusal);
                return;
            }
            var next = await reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend);
            Assert.Equal(original.Generation + 1, next.Generation);
            var staged = (await reopened.ReadOwnStagedPreKeyPublicationAsync())!;
            using var promoted = await RouteState();
            var entry = promoted.Entries[name];
            var contact = DeepIdV2ResolverClosureCodec.Decode(entry.Record(7).Span);
            Assert.True(contact.Bundle.Field(12).Span[5..].SequenceEqual(staged.ExactXps1.Span), "Published contact did not adopt committed service.");
            var request = ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span);
            Assert.True(request.LocatorHash.Span.SequenceEqual(oldLocator), "Prekey maintenance changed permanent locator.");
            Assert.True(request.OwnerRetrieveCapability.Span.SequenceEqual(oldOwnerCapability), "Owner Retrieve capability changed.");
            var calls = (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls);
            var retry = await reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend);
            Assert.True(retry.ExactXpo1.Span.SequenceEqual(next.ExactXpo1.Span), "Completed contact retry minted another publication.");
            Assert.Equal(calls, (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls));
        }
        internal async Task CheckPreKeyMaintenanceAsync(bool encrypted, bool expiredService, bool lostResponse)
        {
            var source = Source();
            // Seed exact historically committed signed support. Its expiry is
            // the input under test, never extended or used as fresh authority.
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            using (var author = await accounts.OpenLocalPreKeyAuthoringAuthorityAsync())
            {
                var directory = ApplicationCoreVerifier.StartDmd1Lineage(checkpoint.Directory).Next;
                var serviceContext = new Dpk2AuthoringContext(directory, 1, 1, 1, 1_000, 1_000, expiredService ? 1_100UL : 1_300UL);
                var service = author.AuthorPreKeyServiceV2(serviceContext, checkpoint.Binding, 32, 1);
                var inventoryContext = new Dpk2AuthoringContext(directory, 1, 1, 1, 1_000, 1_000, 1_100);
                var placement = ContactServicePlacementFactory.Create(fresh.Network, ContactServiceRequestKind.PublishPreKeyInventory, service.ServiceCapability);
                var drs = new byte[38]; "DRS1"u8.CopyTo(drs); BinaryPrimitives.WriteUInt16BigEndian(drs.AsSpan(4), 1);
                checkpoint.Binding.Identity.Revocations.Snapshot.CanonicalHash.Span.CopyTo(drs.AsSpan(6));
                using var inventory = author.AuthorInventoryV2(inventoryContext, checkpoint.Binding, service, drs,
                    new byte[32], Bytes(32, 0xe1), placement.PlacementHash.Span, 32, 1);
                await accounts.StageOwnInitialPreKeyInventoryAsync(service, inventory);
            }
            _ = await StageAndRecordPairAsync();
            var old = (await accounts.ReadOwnStagedPreKeyPublicationAsync())!;
            var oldPublication = DeepIdV2PreKeyPublicationCodec.Decode(old.ExactXpp1.Span);
            var oldService = DeepIdV2PreKeyServiceCodec.Decode(old.ExactXps1.Span);
            var before = (await accounts.GetCurrentAsync())!;
            using var initialPair = await storage.ReadOwnedAsync("deep.store.v2.prekey-commit-pair-v1");
            var exactInitialPair = initialPair!.Use(value => value.ToArray());
            if (encrypted) ColdReopenCompactionStorage();
            var owner = ReopenAccount();
            storage.FailAfterPreKeySuccessorInsert = lostResponse;
            if (lostResponse)
                await Assert.ThrowsAsync<IOException>(() => owner.EnsureOwnPreKeyInventoryAsync(Source(owner)));
            var current = await owner.EnsureOwnPreKeyInventoryAsync(Source(owner));
            if (encrypted && !expiredService && !lostResponse)
            {
                // Separate actual owners/leases restore the same pending
                // candidate; they cannot mint a competing publication.
                var other = ReopenAccount();
                var retries = await Task.WhenAll(owner.EnsureOwnPreKeyInventoryAsync(Source(owner)),
                    other.EnsureOwnPreKeyInventoryAsync(Source(other)));
                Assert.True(retries.All(value => value.ExactXpp1.Span.SequenceEqual(current.ExactXpp1.Span)), "Concurrent owner retry changed exact pending inventory.");
            }
            var next = DeepIdV2PreKeyPublicationCodec.Decode(current.ExactXpp1.Span);
            var xps = DeepIdV2PreKeyServiceCodec.Decode(current.ExactXps1.Span);
            Assert.Equal(expiredService ? 2UL : 1UL, BinaryPrimitives.ReadUInt64BigEndian(xps.Field(5).Span));
            Assert.Equal(expiredService ? 1UL : 2UL, BinaryPrimitives.ReadUInt64BigEndian(next.Manifest.Field(7).Span));
            Assert.True(xps.Field(2).Span.SequenceEqual(oldService.Field(2).Span), "Service capability changed during maintenance.");
            if (expiredService)
            {
                Assert.True(xps.Field(6).Span.SequenceEqual(SHA256.HashData(old.ExactXps1.Span)), "Service predecessor changed.");
                Assert.True(BinaryPrimitives.ReadUInt64BigEndian(xps.Field(11).Span) > BinaryPrimitives.ReadUInt64BigEndian(oldService.Field(11).Span));
            }
            else
            {
                Assert.True(current.ExactXps1.Span.SequenceEqual(old.ExactXps1.Span), "Same-service replenishment re-signed the descriptor.");
                Assert.True(next.Manifest.Field(8).Span.SequenceEqual(oldPublication.Manifest.ExactHash.Span), "Inventory predecessor changed.");
            }
            Assert.Null(await owner.ReadOwnPreKeyCommitPairAsync());
            fresh = await Source(owner).VerifyForOwnPreKeyAuthoringAsync(owner, default);
            VerifyInventory(current, fresh.Proof);
            var after = (await owner.GetCurrentAsync())!;
            Assert.Equal(before.PermanentId.CanonicalText, after.PermanentId.CanonicalText);
            Assert.True(before.AccountId.Span.SequenceEqual(after.AccountId.Span), "Account changed during maintenance.");
            RejectProof = true; var requests = ProofRequests;
            if (encrypted) ColdReopenCompactionStorage();
            var reopened = ReopenAccount();
            var retry = await reopened.EnsureOwnPreKeyInventoryAsync(Source(reopened));
            Assert.Equal(requests, ProofRequests);
            Assert.True(retry.ExactXpp1.Span.SequenceEqual(current.ExactXpp1.Span), "Pending retry minted replacement keys.");
            using var retained = await storage.ReadOwnedAsync("deep.store.v2.prekey-commit-pair-v1");
            Assert.True(retained!.Use(value => value.SequenceEqual(exactInitialPair)), "Original replica custody changed.");
        }

        internal async Task CheckServiceRestoreRefusalAsync(int shape)
        {
            var initial = await accounts.EnsureOwnPreKeyInventoryAsync(Source());
            var xps = DeepIdV2PreKeyServiceCodec.Decode(initial.ExactXps1.Span);
            var issued = BinaryPrimitives.ReadUInt64BigEndian(xps.Field(10).Span);
            var expires = BinaryPrimitives.ReadUInt64BigEndian(xps.Field(11).Span);
            var directory = ApplicationCoreVerifier.StartDmd1Lineage(shape == 3 ? peerCheckpoint!.Directory : checkpoint.Directory).Next;
            var context = new Dpk2AuthoringContext(directory, shape == 1 ? 2UL : 1UL, 2, 1,
                shape == 4 ? issued - 1 : issued, shape == 4 ? issued - 1 : issued,
                shape == 5 ? expires + 1 : expires);
            using var author = await ReopenAccount().OpenLocalPreKeyAuthoringAuthorityAsync();
            var exact = initial.ExactXps1.ToArray();
            if (shape == 0) exact[^1] ^= 1;
            void Restore() => author.RestorePreKeyServiceV2(context,
                shape == 2 ? peerCheckpoint!.Binding : checkpoint.Binding, exact);
            if (shape == 0) Assert.Throws<ApplicationCoreFormatException>(Restore);
            else if (shape == 3) Assert.Throws<Deep.Protocol.DeepNative.RecordException>(Restore);
            else Assert.Throws<CryptographicException>(Restore);
            var valid = new Dpk2AuthoringContext(ApplicationCoreVerifier.StartDmd1Lineage(checkpoint.Directory).Next,
                1, 2, 1, issued, issued, expires);
            var restored = author.RestorePreKeyServiceV2(valid, checkpoint.Binding, initial.ExactXps1.Span);
            var restoredBytes = restored.ExactXps1.ToArray();
            exact.AsSpan().Clear();
            Assert.True(restoredBytes.AsSpan().SequenceEqual(initial.ExactXps1.Span), "Service restore changed signed bytes.");
            author.Dispose();
            Assert.Throws<ObjectDisposedException>(() => author.RestorePreKeyServiceV2(valid, checkpoint.Binding, initial.ExactXps1.Span));
        }
    }
}
