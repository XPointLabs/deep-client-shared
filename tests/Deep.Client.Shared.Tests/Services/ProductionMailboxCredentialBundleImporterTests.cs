using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

[Collection("SQLite global pool isolation")]
public sealed class ProductionMailboxCredentialBundleImporterTests
{
    [Fact]
    public async Task LocalOwner_ImportsExactRetrievePairAndDistinctReplicaEpochs()
    {
        var context = await CreateBundleContextAsync();
        var fixture = context.Fixture;
        var clock = context.Clock;
        var holder = context.Holder;
        var bundle = context.Bundle;
        var mailbox = context.Mailbox;
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-importer-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();

            var material = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store,
                    holder,
                    bundle,
                    bundle.MailboxOwnerEd25519PublicKey,
                    fixture.BuildAnchor,
                    trust,
                    fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    clock);

            Assert.Equal(holder.SessionId, material.LocalSessionId);
            Assert.Equal(
                [MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve],
                material.Authority.TrustedIssuers.Select(static issuer => issuer.Domain));
            var route = await store.ReadScopedMailboxRouteAsync(
                material.SelfSelector, material.Authority);
            Assert.Equal(mailbox, route.MailboxId.Bytes.ToArray());
            Assert.Equal(fixture.CurrentPlacement.Bytes.ToArray(),
                route.PlacementId.Bytes.ToArray());
            Assert.Equal(1UL, (await trust.ReadAsync())!.Revision);

            var replay = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store,
                    holder,
                    bundle,
                    bundle.MailboxOwnerEd25519PublicKey,
                    fixture.BuildAnchor,
                    trust,
                    fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    clock);
            Assert.Equal(material.SelfSelector.ScopeId.ToArray(),
                replay.SelfSelector.ScopeId.ToArray());
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task LocalOwner_OfflineCheckpointCatchesUpAcrossGenerationGap()
    {
        var context = await CreateBundleContextAsync();
        var rotatedFixture = ProductionMailboxProvisioningContractTests
            .CreateRotatedSignedFixture(context.Fixture, generationSteps: 3);
        var rotatedBundle = CreateRotatedLocalOwnerBundle(
            context, rotatedFixture,
            ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint);
        var root = Path.Combine(Path.GetTempPath(), "deep-production-offline-catchup-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            var initial = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store, context.Holder, context.Bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor, trust, context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged, context.Clock);

            var caughtUp = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store, context.Holder, rotatedBundle,
                    rotatedBundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor, trust, context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged, context.Clock);

            Assert.Equal(initial.SelfSelector.ScopeId.ToArray(),
                caughtUp.SelfSelector.ScopeId.ToArray());
            Assert.Equal(2UL, (await trust.ReadAsync())!.Revision);
            Assert.Equal(2, trust.Writes);
            _ = await store.ReadScopedMailboxRouteAsync(
                caughtUp.SelfSelector, caughtUp.Authority);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                    store, context.Holder, context.Bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor, trust, context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged, context.Clock));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task LocalOwner_DirectSuccessorRotatesExactNextEpoch()
    {
        var context = await CreateBundleContextAsync();
        var rotatedFixture = ProductionMailboxProvisioningContractTests
            .CreateRotatedSignedFixture(context.Fixture, generationSteps: 1);
        var rotatedBundle = CreateRotatedLocalOwnerBundle(
            context, rotatedFixture,
            ProductionMailboxSelectionSuccessorMode.DirectPromotion);
        var root = Path.Combine(Path.GetTempPath(), "deep-production-direct-successor-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            _ = await ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                store, context.Holder, context.Bundle,
                context.Bundle.MailboxOwnerEd25519PublicKey,
                context.Fixture.BuildAnchor, trust, context.Fixture.ClientIdentity,
                MailboxInfrastructureOwnership.OfficialManaged, context.Clock);
            var rotated = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store, context.Holder, rotatedBundle,
                    rotatedBundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor, trust, context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged, context.Clock);
            _ = await store.ReadScopedMailboxRouteAsync(
                rotated.SelfSelector, rotated.Authority);
            Assert.Equal(2UL, (await trust.ReadAsync())!.Revision);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task LocalOwner_OfflineCheckpointRestartRecoversAmbiguousTrustCommit()
    {
        var context = await CreateBundleContextAsync();
        var rotatedFixture = ProductionMailboxProvisioningContractTests
            .CreateRotatedSignedFixture(context.Fixture, generationSteps: 3);
        var rotatedBundle = CreateRotatedLocalOwnerBundle(
            context, rotatedFixture,
            ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint);
        var database = Path.Combine(Path.GetTempPath(), "deep-production-offline-restart-" +
            Guid.NewGuid().ToString("N"), "state.db");
        Directory.CreateDirectory(Path.GetDirectoryName(database)!);
        var trust = new MemoryTrustStore();
        try
        {
            using (var store = new SqliteSessionStore(database))
            {
                _ = await ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                    store, context.Holder, context.Bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor, trust, context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged, context.Clock);
                await Assert.ThrowsAsync<InjectedPublicationFaultException>(() =>
                    ProductionMailboxCredentialBundleImporter
                        .ImportLocalOwnerWithFaultInjectionAsync(
                            store, context.Holder, rotatedBundle,
                            rotatedBundle.MailboxOwnerEd25519PublicKey,
                            context.Fixture.BuildAnchor, trust,
                            context.Fixture.ClientIdentity,
                            MailboxInfrastructureOwnership.OfficialManaged,
                            point =>
                            {
                                if (point == ProductionMailboxCredentialBundleImporter
                                        .PublicationFaultPoint.AfterTrustCommit)
                                    throw new InjectedPublicationFaultException();
                            },
                            context.Clock));
                Assert.Equal(2UL, (await trust.ReadAsync())!.Revision);
            }

            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            using var restarted = new SqliteSessionStore(database);
            var recovered = await ProductionMailboxCredentialBundleImporter
                .TryRecoverPendingLocalOwnerAsync(
                    restarted, context.Holder, context.Fixture.BuildAnchor, trust,
                    context.Fixture.ClientIdentity,
                    rotatedBundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged, context.Clock);
            Assert.NotNull(recovered);
            _ = await restarted.ReadScopedMailboxRouteAsync(
                recovered.SelfSelector, recovered.Authority);
            Assert.Equal(2, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(Path.GetDirectoryName(database)!, recursive: true);
        }
    }

    [Fact]
    public async Task PeerDeposit_ImportsExactDepositPairForAuthenticatedContact()
    {
        var context = await CreatePeerBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-peer-importer-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();

            var material = await ProductionMailboxCredentialBundleImporter
                .ImportPeerDepositAsync(
                    store,
                    context.Holder,
                    context.RecipientSessionId,
                    context.RecipientOwnerPublicKey,
                    context.Bundle,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);

            Assert.Equal(context.Holder.SessionId, material.LocalSessionId);
            Assert.Equal(context.RecipientSessionId, material.RecipientSessionId);
            Assert.Equal(
                [MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve],
                material.Authority.TrustedIssuers.Select(static issuer => issuer.Domain));
            Assert.Equal(MailboxCredentialScopeKind.Peer, material.PeerSelector.Kind);
            Assert.Equal(context.RecipientPublicKey,
                material.PeerSelector.SubjectId.ToArray());
            var route = await store.ReadScopedMailboxRouteAsync(
                material.PeerSelector, material.Authority);
            Assert.Equal(context.Mailbox, route.MailboxId.Bytes.ToArray());
            Assert.Equal(context.Fixture.CurrentPlacement.Bytes.ToArray(),
                route.PlacementId.Bytes.ToArray());
            Assert.Equal(1UL, (await trust.ReadAsync())!.Revision);

            var replay = await ProductionMailboxCredentialBundleImporter
                .ImportPeerDepositAsync(
                    store,
                    context.Holder,
                    context.RecipientSessionId,
                    context.RecipientOwnerPublicKey,
                    context.Bundle,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    new FixedTimeProvider(
                        ProductionMailboxProvisioningContractTests.Now + 1));
            Assert.Equal(material.PeerSelector.ScopeId.ToArray(),
                replay.PeerSelector.ScopeId.ToArray());
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PeerDeposit_RotatesStableSelectorByMonotonicRouteSequence()
    {
        var context = await CreatePeerBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-peer-rotation-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            var first = await ProductionMailboxCredentialBundleImporter
                .ImportPeerDepositAsync(
                    store, context.Holder, context.RecipientSessionId,
                    context.RecipientOwnerPublicKey, context.Bundle,
                    context.Fixture.BuildAnchor, trust, context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged, context.Clock);
            var rotatedBundle = RotatePeerBundle(context, routeSequence: 2, serialSeed: 0xd2);

            var rotated = await ProductionMailboxCredentialBundleImporter
                .ImportPeerDepositAsync(
                    store, context.Holder, context.RecipientSessionId,
                    context.RecipientOwnerPublicKey, rotatedBundle,
                    context.Fixture.BuildAnchor, trust, context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged, context.Clock);

            Assert.Equal(first.PeerSelector.ScopeId.ToArray(),
                rotated.PeerSelector.ScopeId.ToArray());
            _ = await store.ReadScopedMailboxRouteAsync(
                rotated.PeerSelector, rotated.Authority);
            Assert.Equal(1, trust.Writes);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter.ImportPeerDepositAsync(
                    store, context.Holder, context.RecipientSessionId,
                    context.RecipientOwnerPublicKey, context.Bundle,
                    context.Fixture.BuildAnchor, trust, context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged, context.Clock));
            _ = await store.ReadScopedMailboxRouteAsync(
                rotated.PeerSelector, rotated.Authority);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PeerDeposit_RestartRecoversTrustCommitBeforeCredentialCommit()
    {
        var context = await CreatePeerBundleContextAsync();
        var database = Path.Combine(Path.GetTempPath(), "deep-production-peer-recovery-" +
            Guid.NewGuid().ToString("N"), "state.db");
        Directory.CreateDirectory(Path.GetDirectoryName(database)!);
        var trust = new MemoryTrustStore();
        try
        {
            using (var store = new SqliteSessionStore(database))
            {
                var error = await Assert.ThrowsAsync<InjectedPublicationFaultException>(() =>
                    ProductionMailboxCredentialBundleImporter
                        .ImportPeerDepositWithFaultInjectionAsync(
                            store, context.Holder, context.RecipientSessionId,
                            context.RecipientOwnerPublicKey, context.Bundle,
                            context.Fixture.BuildAnchor, trust,
                            context.Fixture.ClientIdentity,
                            MailboxInfrastructureOwnership.OfficialManaged,
                            point =>
                            {
                                if (point == ProductionMailboxCredentialBundleImporter
                                        .PublicationFaultPoint.AfterTrustCommit)
                                    throw new InjectedPublicationFaultException();
                            },
                            context.Clock));
                Assert.NotNull(error);
                Assert.Equal(1UL, (await trust.ReadAsync())!.Revision);
            }

            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            using var restarted = new SqliteSessionStore(database);
            var recovered = await ProductionMailboxCredentialBundleImporter
                .ImportPeerDepositAsync(
                    restarted, context.Holder, context.RecipientSessionId,
                    context.RecipientOwnerPublicKey, context.Bundle,
                    context.Fixture.BuildAnchor, trust, context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged, context.Clock);
            _ = await restarted.ReadScopedMailboxRouteAsync(
                recovered.PeerSelector, recovered.Authority);
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(Path.GetDirectoryName(database)!, recursive: true);
        }
    }

    [Fact]
    public async Task PeerDeposit_RecoversAmbiguousSqliteCompletionByExactReadback()
    {
        var context = await CreatePeerBundleContextAsync();
        var database = Path.Combine(Path.GetTempPath(), "deep-production-peer-ambiguous-" +
            Guid.NewGuid().ToString("N"), "state.db");
        Directory.CreateDirectory(Path.GetDirectoryName(database)!);
        var afterCommit = 0;
        try
        {
            using var store = new SqliteSessionStore(
                new SqliteSessionStoreOptions(database),
                point =>
                {
                    if (point == ClientMailboxCommitFaultPoint.AfterCommit &&
                        Interlocked.Increment(ref afterCommit) == 2)
                        throw new InjectedPublicationFaultException();
                });
            var trust = new MemoryTrustStore();
            var imported = await ProductionMailboxCredentialBundleImporter
                .ImportPeerDepositAsync(
                    store, context.Holder, context.RecipientSessionId,
                    context.RecipientOwnerPublicKey, context.Bundle,
                    context.Fixture.BuildAnchor, trust, context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged, context.Clock);
            _ = await store.ReadScopedMailboxRouteAsync(
                imported.PeerSelector, imported.Authority);
            Assert.Equal(2, afterCommit);
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(Path.GetDirectoryName(database)!, recursive: true);
        }
    }

    [Fact]
    public async Task PeerDeposit_RejectsRetrieveGrantsBeforeMutation()
    {
        var context = await CreatePeerBundleContextAsync();
        var authority = ProductionMailboxAuthorityCodec.Decode(
            context.Bundle.ControlPlane.CanonicalAuthority.Span);
        var topology = ProductionMailboxTopologyCodec.Decode(
            context.Bundle.ControlPlane.CanonicalTopology.Span);
        var retrieveCurrent = Grant(
            topology.CurrentEpoch,
            authority,
            context.Holder.Ed25519PublicKey.ToArray(),
            context.Fixture.CurrentPlacement,
            Bytes(0xd1, 16),
            context.Fixture.IssuerPrivateKey,
            MailboxCapabilityDomain.Retrieve);
        var retrieveNext = Grant(
            topology.NextEpoch,
            authority,
            context.Holder.Ed25519PublicKey.ToArray(),
            context.Fixture.NextPlacement,
            Bytes(0xe1, 16),
            context.Fixture.IssuerPrivateKey,
            MailboxCapabilityDomain.Retrieve);
        var bundle = context.Bundle with
        {
            Grants =
            [
                Binding(retrieveCurrent),
                Binding(retrieveNext)
            ]
        };
        var root = Path.Combine(Path.GetTempPath(), "deep-production-peer-retrieve-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter.ImportPeerDepositAsync(
                    store,
                    context.Holder,
                    context.RecipientSessionId,
                    context.RecipientOwnerPublicKey,
                    bundle,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock));
            Assert.Equal(0, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("session")]
    [InlineData("owner")]
    [InlineData("route")]
    public async Task PeerDeposit_RejectsWrongAuthenticatedContactOrRouteBeforeMutation(
        string mutation)
    {
        var context = await CreatePeerBundleContextAsync();
        var expectedSession = mutation == "session"
            ? SessionIdFromEd25519(PublicKeyAuth.GenerateKeyPair(Bytes(0x91, 32)).PublicKey)
            : context.RecipientSessionId;
        var expectedOwner = mutation == "owner"
            ? PublicKeyAuth.GenerateKeyPair(Bytes(0x92, 32)).PublicKey
            : context.RecipientOwnerPublicKey;
        var bundle = mutation == "route"
            ? context.Bundle with
            {
                BlindedMailboxId = ChangedBytes(context.Bundle.BlindedMailboxId)
            }
            : context.Bundle;
        var root = Path.Combine(Path.GetTempPath(), "deep-production-peer-contact-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter.ImportPeerDepositAsync(
                    store,
                    context.Holder,
                    expectedSession,
                    expectedOwner,
                    bundle,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock));
            Assert.Equal(0, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PeerDeposit_RejectsExpiredBundleAndConflictingReplay()
    {
        var context = await CreatePeerBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-peer-replay-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            var imported = await ProductionMailboxCredentialBundleImporter
                .ImportPeerDepositAsync(
                    store,
                    context.Holder,
                    context.RecipientSessionId,
                    context.RecipientOwnerPublicKey,
                    context.Bundle,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);

            var authority = ProductionMailboxAuthorityCodec.Decode(
                context.Bundle.ControlPlane.CanonicalAuthority.Span);
            var topology = ProductionMailboxTopologyCodec.Decode(
                context.Bundle.ControlPlane.CanonicalTopology.Span);
            var conflict = context.Bundle with
            {
                Grants =
                [
                    Binding(Grant(topology.CurrentEpoch, authority,
                        context.Holder.Ed25519PublicKey.ToArray(),
                        context.Fixture.CurrentPlacement, Bytes(0xf1, 16),
                        context.Fixture.IssuerPrivateKey,
                        MailboxCapabilityDomain.Deposit)),
                    Binding(Grant(topology.NextEpoch, authority,
                        context.Holder.Ed25519PublicKey.ToArray(),
                        context.Fixture.NextPlacement, Bytes(0xa1, 16),
                        context.Fixture.IssuerPrivateKey,
                        MailboxCapabilityDomain.Deposit))
                ]
            };
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter.ImportPeerDepositAsync(
                    store,
                    context.Holder,
                    context.RecipientSessionId,
                    context.RecipientOwnerPublicKey,
                    conflict,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock));
            _ = await store.ReadScopedMailboxRouteAsync(
                imported.PeerSelector, imported.Authority);

            using var expiredStore = new SqliteSessionStore(
                Path.Combine(root, "expired.db"));
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter.ImportPeerDepositAsync(
                    expiredStore,
                    context.Holder,
                    context.RecipientSessionId,
                    context.RecipientOwnerPublicKey,
                    context.Bundle,
                    context.Fixture.BuildAnchor,
                    new MemoryTrustStore(),
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    new FixedTimeProvider(context.Bundle.ExpiresAtUnixSeconds + 1)));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PeerDeposit_IsNotAcceptedByLocalOwnerImporter()
    {
        var fixture = ProductionMailboxProvisioningContractTests
            .CreateSignedFixture(sharedPlacement: true);
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(0x31, 32)).PublicKey;
        var bundle = new ProductionMailboxLocalOwnerBundle(
            holder,
            Bytes(0x51, 32),
            Bytes(0x61, 32),
            Bytes(0x71, 32),
            fixture.CurrentPlacement.Bytes,
            ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(
                fixture.CurrentPlacement),
            fixture.Artifacts,
            [],
            [new ProductionMailboxGrantBinding(
                MailboxCapabilityDomain.Deposit, 9, 70, new byte[272])],
            new byte[ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength],
            Bytes(0x81, 32),
            new byte[ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength],
            Bytes(0x82, 32),
            ReadOnlyMemory<byte>.Empty,
            ReadOnlyMemory<byte>.Empty,
            ProductionMailboxProvisioningContractTests.Now,
            ProductionMailboxProvisioningContractTests.Now + 100);
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-importer-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                    store,
                    new MailboxHolderIdentity(SessionIdFromEd25519(holder), holder),
                    bundle,
                    bundle.MailboxOwnerEd25519PublicKey,
                    fixture.BuildAnchor,
                    new MemoryTrustStore(),
                    fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    new FixedTimeProvider(ProductionMailboxProvisioningContractTests.Now)));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("mailbox")]
    [InlineData("placement")]
    [InlineData("selection")]
    [InlineData("owner")]
    [InlineData("certificate")]
    [InlineData("advertisement")]
    [InlineData("certificate-hash")]
    [InlineData("idempotency")]
    [InlineData("successor")]
    public async Task LocalOwner_RouteAndIssuanceTamperingFailsBeforePublication(
        string mutation)
    {
        var context = await CreateBundleContextAsync();
        var bundle = MutateBundle(context.Bundle, mutation);
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-route-negative-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                    store,
                    context.Holder,
                    bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock));
            Assert.Equal(0, trust.Writes);
            Assert.Null(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                ActiveBundleKey(context.Holder)));
            Assert.Null(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                PublicationKey(context.Holder)));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ActiveBundle_BackdatedVerifiedAtIsCorruptAndCannotRefresh()
    {
        var context = await CreateBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-backdate-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            await ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                store,
                context.Holder,
                context.Bundle,
                context.Bundle.MailboxOwnerEd25519PublicKey,
                context.Fixture.BuildAnchor,
                trust,
                context.Fixture.ClientIdentity,
                MailboxInfrastructureOwnership.OfficialManaged,
                context.Clock);
            var key = ActiveBundleKey(context.Holder);
            var active = Assert.IsType<ProductionMailboxRuntimePublicationJournal>(
                await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(key));
            await store.SetAsync(key, active with
            {
                VerifiedAtUnixSeconds = active.VerifiedAtUnixSeconds - 1
            });

            var result = await ProductionMailboxCredentialBundleImporter
                .LoadActiveLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    new FixedTimeProvider(
                        ProductionMailboxProvisioningContractTests.Now + 101));

            Assert.Equal(ProductionMailboxActiveBundleStatus.Corrupt, result.Status);
            Assert.Null(result.Material);
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CallerRouteBuffers_AreFrozenBeforeTrustStoreCallback()
    {
        var context = await CreateBundleContextAsync();
        var mutableAdvertisement = context.Bundle.CanonicalRouteAdvertisement.ToArray();
        var expectedHash = SHA256.HashData(mutableAdvertisement);
        var bundle = context.Bundle with
        {
            CanonicalRouteAdvertisement = mutableAdvertisement,
            RouteAdvertisementSha256 = expectedHash
        };
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-freeze-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore
            {
                BeforeRead = () => mutableAdvertisement[^1] ^= 1
            };

            _ = await ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                store,
                context.Holder,
                bundle,
                context.Bundle.MailboxOwnerEd25519PublicKey,
                context.Fixture.BuildAnchor,
                trust,
                context.Fixture.ClientIdentity,
                MailboxInfrastructureOwnership.OfficialManaged,
                context.Clock);

            var active = Assert.IsType<ProductionMailboxRuntimePublicationJournal>(
                await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                    ActiveBundleKey(context.Holder)));
            Assert.Equal(Convert.ToHexStringLower(expectedHash),
                active.RouteAdvertisementSha256);
            Assert.NotEqual(expectedHash, SHA256.HashData(mutableAdvertisement));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CallerClientIdentity_IsFrozenOnceBeforeTrustAndClockCallbacks()
    {
        var context = await CreateBundleContextAsync();
        var mutableSigner = context.Fixture.ClientIdentity
            .SigningCertificateSha256.ToArray();
        var mutableBuild = context.Fixture.ClientIdentity.BuildArtifactSha256.ToArray();
        var identity = context.Fixture.ClientIdentity with
        {
            SigningCertificateSha256 = mutableSigner,
            BuildArtifactSha256 = mutableBuild
        };
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-identity-freeze-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore
            {
                BeforeRead = () =>
                {
                    mutableSigner[^1] ^= 1;
                    mutableBuild[^1] ^= 1;
                }
            };

            var material = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor,
                    trust,
                    identity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);

            Assert.Equal(context.Holder.SessionId, material.LocalSessionId);
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ClientIdentityMutation_CannotSplitApprovalFromIdempotency()
    {
        var context = await CreateBundleContextAsync();
        var mutableSigner = context.Fixture.ClientIdentity
            .SigningCertificateSha256.ToArray();
        var mutableBuild = context.Fixture.ClientIdentity.BuildArtifactSha256.ToArray();
        var changedSigner = mutableSigner.ToArray();
        var changedBuild = mutableBuild.ToArray();
        changedSigner[^1] ^= 1;
        changedBuild[^1] ^= 1;
        var identity = context.Fixture.ClientIdentity with
        {
            SigningCertificateSha256 = mutableSigner,
            BuildArtifactSha256 = mutableBuild
        };
        var bundle = context.Bundle with
        {
            IdempotencyKey = ComputeLocalOwnerIdempotency(
                context.Fixture,
                context.Holder.Ed25519PublicKey.Span,
                context.Bundle.MailboxOwnerEd25519PublicKey.Span,
                changedSigner,
                changedBuild)
        };
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-identity-split-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore
            {
                BeforeRead = () =>
                {
                    changedSigner.CopyTo(mutableSigner, 0);
                    changedBuild.CopyTo(mutableBuild, 0);
                }
            };

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                    store,
                    context.Holder,
                    bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor,
                    trust,
                    identity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock));

            Assert.Equal(1, trust.Reads);
            Assert.Equal(0, trust.Writes);
            Assert.Null(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                PublicationKey(context.Holder)));
            Assert.Null(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                ActiveBundleKey(context.Holder)));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task IndexOnlyCollections_AreSnapshottedWithoutEnumeration()
    {
        var context = await CreateBundleContextAsync();
        var selections = context.Bundle.Selections.Select(selection => selection with
        {
            Replicas = new IndexOnlyList<ProductionMailboxReplicaBinding>(
                selection.Replicas.ToArray())
        }).ToArray();
        var bundle = context.Bundle with
        {
            Selections = new IndexOnlyList<ProductionMailboxSelectionBinding>(selections),
            Grants = new IndexOnlyList<ProductionMailboxGrantBinding>(
                context.Bundle.Grants.ToArray())
        };
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-index-snapshot-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var material = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store,
                    context.Holder,
                    bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor,
                    new MemoryTrustStore(),
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);
            Assert.Equal(context.Holder.SessionId, material.LocalSessionId);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task MultiMegabyteReplicaUri_IsRejectedBeforeTrustAndEncodingAllocation()
    {
        var context = await CreateBundleContextAsync();
        var hugeEndpoint = new Uri("https://node.example/" +
            new string('a', 8 * 1024 * 1024));
        var firstSelection = context.Bundle.Selections[0];
        var replicas = firstSelection.Replicas.ToArray();
        replicas[0] = replicas[0] with { HttpsEndpoint = hugeEndpoint };
        var selections = context.Bundle.Selections.ToArray();
        selections[0] = firstSelection with { Replicas = replicas };
        var bundle = context.Bundle with { Selections = selections };
        var trust = new MemoryTrustStore();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-uri-bounds-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var before = GC.GetAllocatedBytesForCurrentThread();
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                    store,
                    context.Holder,
                    bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock));
            Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before,
                0, 512 * 1024);
            Assert.Equal(0, trust.Reads);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RouteExpiry_IsHardActiveBoundaryNotHistoricalGrace()
    {
        var context = await CreateBundleContextAsync(routeLifetimeSeconds: 40);
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-route-expiry-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            await ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                store,
                context.Holder,
                context.Bundle,
                context.Bundle.MailboxOwnerEd25519PublicKey,
                context.Fixture.BuildAnchor,
                trust,
                context.Fixture.ClientIdentity,
                MailboxInfrastructureOwnership.OfficialManaged,
                context.Clock);

            var refresh = await ProductionMailboxCredentialBundleImporter
                .LoadActiveLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    new FixedTimeProvider(
                        ProductionMailboxProvisioningContractTests.Now + 16));
            Assert.Equal(ProductionMailboxActiveBundleStatus.RefreshRecommended,
                refresh.Status);
            Assert.NotNull(refresh.Material);

            var expired = await ProductionMailboxCredentialBundleImporter
                .LoadActiveLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    new FixedTimeProvider(
                        ProductionMailboxProvisioningContractTests.Now + 41));
            Assert.Equal(ProductionMailboxActiveBundleStatus.Expired, expired.Status);
            Assert.Null(expired.Material);
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task OversizedRoute_IsRejectedBeforeTrustCallbackWithBoundedAllocation()
    {
        var context = await CreateBundleContextAsync();
        var trust = new MemoryTrustStore();
        var oversized = new byte[8 * 1024 * 1024];
        var bundle = context.Bundle with { CanonicalRouteCertificate = oversized };
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-bounds-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var before = GC.GetAllocatedBytesForCurrentThread();
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                    store,
                    context.Holder,
                    bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock));
            Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before,
                0, 512 * 1024);
            Assert.Equal(0, trust.Reads);
            Assert.Equal(0, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task FutureVerifiedAt_IsCorruptWithoutHistoricalBackdating()
    {
        var context = await CreateBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-future-time-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            await ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                store,
                context.Holder,
                context.Bundle,
                context.Bundle.MailboxOwnerEd25519PublicKey,
                context.Fixture.BuildAnchor,
                trust,
                context.Fixture.ClientIdentity,
                MailboxInfrastructureOwnership.OfficialManaged,
                context.Clock);
            var key = ActiveBundleKey(context.Holder);
            var active = Assert.IsType<ProductionMailboxRuntimePublicationJournal>(
                await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(key));
            await store.SetAsync(key, active with
            {
                VerifiedAtUnixSeconds = active.VerifiedAtUnixSeconds + 1
            });
            var readsBefore = trust.Reads;

            var result = await ProductionMailboxCredentialBundleImporter
                .LoadActiveLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);

            Assert.Equal(ProductionMailboxActiveBundleStatus.Corrupt, result.Status);
            Assert.Equal(readsBefore, trust.Reads);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task LegacyPlj1Framing_IsRejectedWithoutCompatibilityFallback()
    {
        var context = await CreateBundleContextAsync();
        var encoded = ProductionMailboxLocalOwnerJournalCodec.Encode(context.Bundle);
        encoded[3] = (byte)'1';
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxLocalOwnerJournalCodec.Decode(encoded));
    }

    [Theory]
    [InlineData((int)ProductionMailboxCredentialBundleImporter.PublicationFaultPoint.AfterJournalCommit)]
    [InlineData((int)ProductionMailboxCredentialBundleImporter.PublicationFaultPoint.AfterTrustCommit)]
    [InlineData((int)ProductionMailboxCredentialBundleImporter.PublicationFaultPoint.AfterRuntimeCommit)]
    public async Task PublicationBoundaryFault_ExactRetryRecoversToCoupledState(
        int faultPointValue)
    {
        var faultPoint = (ProductionMailboxCredentialBundleImporter.PublicationFaultPoint)
            faultPointValue;
        var context = await CreateBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-recovery-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            var faulted = 0;

            await Assert.ThrowsAsync<InjectedPublicationFaultException>(() =>
                ProductionMailboxCredentialBundleImporter
                    .ImportLocalOwnerWithFaultInjectionAsync(
                        store,
                        context.Holder,
                        context.Bundle,
                        context.Bundle.MailboxOwnerEd25519PublicKey,
                        context.Fixture.BuildAnchor,
                        trust,
                        context.Fixture.ClientIdentity,
                        MailboxInfrastructureOwnership.OfficialManaged,
                        point =>
                        {
                            if (point == faultPoint &&
                                Interlocked.Exchange(ref faulted, 1) == 0)
                                throw new InjectedPublicationFaultException();
                        },
                        context.Clock));

            var publicationKey = "deep.mailbox.production-local-owner.v1:" +
                context.Holder.SessionId.Value + ":publication-v1";
            var activeBundleKey = ActiveBundleKey(context.Holder);
            var pending = await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                publicationKey);
            if (faultPoint == ProductionMailboxCredentialBundleImporter
                    .PublicationFaultPoint.AfterRuntimeCommit)
            {
                Assert.Null(pending);
                Assert.NotNull(await store
                    .GetAsync<ProductionMailboxRuntimePublicationJournal>(activeBundleKey));
                Assert.NotNull(await trust.ReadAsync());
            }
            else
            {
                Assert.NotNull(pending);
                Assert.Null(await store
                    .GetAsync<ProductionMailboxRuntimePublicationJournal>(activeBundleKey));
                Assert.Equal(
                    faultPoint == ProductionMailboxCredentialBundleImporter
                        .PublicationFaultPoint.AfterTrustCommit,
                    await trust.ReadAsync() is not null);
                Assert.Null(await store.GetAsync<MailboxBundleRuntimeCheckpoint>(
                    "deep.mailbox.production-local-owner.v1:" +
                    context.Holder.SessionId.Value));
            }

            var recovered = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);

            Assert.Equal(context.Holder.SessionId, recovered.LocalSessionId);
            Assert.Null(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                publicationKey));
            Assert.NotNull(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                activeBundleKey));
            Assert.Equal(context.Mailbox,
                (await store.ReadScopedMailboxRouteAsync(
                    recovered.SelfSelector, recovered.Authority)).MailboxId.Bytes.ToArray());
            Assert.Equal(1UL, (await trust.ReadAsync())!.Revision);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task AmbiguousTrustCommitThatActuallyPersisted_ContinuesPublication()
    {
        var context = await CreateBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-ambiguous-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore { ThrowAfterNextCommit = true };

            var material = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);

            Assert.Equal(context.Mailbox,
                (await store.ReadScopedMailboxRouteAsync(
                    material.SelfSelector, material.Authority)).MailboxId.Bytes.ToArray());
            Assert.Equal(1UL, (await trust.ReadAsync())!.Revision);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task AmbiguousSqliteRuntimeCommitThatActuallyPersisted_IsReadBackExactly()
    {
        var context = await CreateBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-sqlite-ambiguous-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var durableCommitCount = 0;
            using var store = new SqliteSessionStore(
                new SqliteSessionStoreOptions(Path.Combine(root, "state.db")),
                point =>
                {
                    if (point == ClientMailboxCommitFaultPoint.AfterCommit &&
                        Interlocked.Increment(ref durableCommitCount) == 2)
                        throw new InjectedPublicationFaultException();
                });
            var trust = new MemoryTrustStore();

            var material = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);

            Assert.Equal(context.Holder.SessionId, material.LocalSessionId);
            Assert.Null(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                PublicationKey(context.Holder)));
            Assert.NotNull(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                ActiveBundleKey(context.Holder)));
            Assert.Equal(context.Mailbox,
                (await store.ReadScopedMailboxRouteAsync(
                    material.SelfSelector, material.Authority)).MailboxId.Bytes.ToArray());
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task AmbiguousSqliteJournalCommitThatActuallyPersisted_ContinuesPublication()
    {
        var context = await CreateBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-journal-ambiguous-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var faulted = 0;
            using var store = new SqliteSessionStore(
                new SqliteSessionStoreOptions(Path.Combine(root, "state.db")),
                point =>
                {
                    if (point == ClientMailboxCommitFaultPoint.AfterCommit &&
                        Interlocked.Exchange(ref faulted, 1) == 0)
                        throw new InjectedPublicationFaultException();
                });
            var trust = new MemoryTrustStore();

            var material = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);

            Assert.Equal(context.Holder.SessionId, material.LocalSessionId);
            Assert.Null(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                PublicationKey(context.Holder)));
            Assert.NotNull(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                ActiveBundleKey(context.Holder)));
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StartupRecovery_AfterTrustCommitCompletesOfflineFromSignedJournal()
    {
        var context = await CreateBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-offline-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            await Assert.ThrowsAsync<InjectedPublicationFaultException>(() =>
                ProductionMailboxCredentialBundleImporter
                    .ImportLocalOwnerWithFaultInjectionAsync(
                        store,
                        context.Holder,
                        context.Bundle,
                        context.Bundle.MailboxOwnerEd25519PublicKey,
                        context.Fixture.BuildAnchor,
                        trust,
                        context.Fixture.ClientIdentity,
                        MailboxInfrastructureOwnership.OfficialManaged,
                        point =>
                        {
                            if (point == ProductionMailboxCredentialBundleImporter
                                    .PublicationFaultPoint.AfterTrustCommit)
                                throw new InjectedPublicationFaultException();
                        },
                        context.Clock));

            var recovered = await ProductionMailboxCredentialBundleImporter
                .TryRecoverPendingLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);

            Assert.NotNull(recovered);
            Assert.Equal(context.Mailbox,
                (await store.ReadScopedMailboxRouteAsync(
                    recovered.SelfSelector, recovered.Authority)).MailboxId.Bytes.ToArray());
            Assert.Null(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                PublicationKey(context.Holder)));
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task NormalRestart_LoadsAndReverifiesCommittedActiveBundleWithoutNetwork()
    {
        var context = await CreateBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-active-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            var imported = await ProductionMailboxCredentialBundleImporter
                .ImportLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Bundle,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);

            Assert.True(imported.Authority.RequiresManagedEntitlement);
            Assert.True(imported.Authority.IsEntitled);
            new MailboxDeliveryDecision(
                MailboxTransportProtocol.AuthenticatedMau2,
                MailboxInfrastructureOwnership.OfficialManaged,
                imported.Authority,
                imported.SelfSelector).Validate();
            Assert.NotNull(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                ActiveBundleKey(context.Holder)));

            var restarted = await ProductionMailboxCredentialBundleImporter
                .LoadActiveLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);

            Assert.Equal(ProductionMailboxActiveBundleStatus.Valid, restarted.Status);
            Assert.NotNull(restarted.Material);
            Assert.NotNull(restarted.PublicRoute);
            Assert.Equal(context.Bundle.MailboxOwnerEd25519PublicKey.ToArray(),
                restarted.PublicRoute.MailboxOwnerEd25519PublicKey.ToArray());
            Assert.Equal(context.Bundle.CanonicalRouteAdvertisement.ToArray(),
                restarted.PublicRoute.CanonicalRouteAdvertisement.ToArray());
            Assert.Equal(context.Holder.SessionId, restarted.Material.LocalSessionId);
            Assert.True(restarted.Material.Authority.RequiresManagedEntitlement);
            Assert.True(restarted.Material.Authority.IsEntitled);
            Assert.Equal(1, trust.Writes);
            Assert.Null(await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(
                PublicationKey(context.Holder)));

            var activeKey = ActiveBundleKey(context.Holder);
            var active = Assert.IsType<ProductionMailboxRuntimePublicationJournal>(
                await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(activeKey));
            await store.SetAsync(activeKey, active with
            {
                SignedBundleBase64 = Convert.ToBase64String([0x00])
            });
            var corrupt = await ProductionMailboxCredentialBundleImporter
                .LoadActiveLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    context.Clock);
            Assert.Equal(ProductionMailboxActiveBundleStatus.Corrupt, corrupt.Status);
            Assert.Null(corrupt.Material);
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ActiveBundle_RefreshesBeforeExpiryAndOnlyAuthenticatedExpiredCanRefresh()
    {
        var context = await CreateBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-refresh-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            await ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                store,
                context.Holder,
                context.Bundle,
                context.Bundle.MailboxOwnerEd25519PublicKey,
                context.Fixture.BuildAnchor,
                trust,
                context.Fixture.ClientIdentity,
                MailboxInfrastructureOwnership.OfficialManaged,
                context.Clock);

            var refresh = await ProductionMailboxCredentialBundleImporter
                .LoadActiveLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    new FixedTimeProvider(ProductionMailboxProvisioningContractTests.Now + 74));
            Assert.Equal(
                ProductionMailboxActiveBundleStatus.RefreshRecommended,
                refresh.Status);
            Assert.NotNull(refresh.Material);

            var expired = await ProductionMailboxCredentialBundleImporter
                .LoadActiveLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    new FixedTimeProvider(ProductionMailboxProvisioningContractTests.Now + 101));
            Assert.Equal(ProductionMailboxActiveBundleStatus.Expired, expired.Status);
            Assert.Null(expired.Material);
            Assert.Equal(1, trust.Writes);

            var wrongOwner = await ProductionMailboxCredentialBundleImporter
                .LoadActiveLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    Bytes(0xe1, 32),
                    MailboxInfrastructureOwnership.OfficialManaged,
                    new FixedTimeProvider(
                        ProductionMailboxProvisioningContractTests.Now + 101));
            Assert.Equal(ProductionMailboxActiveBundleStatus.Corrupt, wrongOwner.Status);
            Assert.Null(wrongOwner.Material);

            var activeKey = ActiveBundleKey(context.Holder);
            var active = Assert.IsType<ProductionMailboxRuntimePublicationJournal>(
                await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(activeKey));
            var tamperedAuthority = context.Bundle.ControlPlane.CanonicalAuthority.ToArray();
            tamperedAuthority[^1] ^= 0x01;
            var tamperedBundle = context.Bundle with
            {
                ControlPlane = context.Bundle.ControlPlane with
                {
                    CanonicalAuthority = tamperedAuthority
                }
            };
            var encodedTampered = ProductionMailboxLocalOwnerJournalCodec.Encode(
                tamperedBundle);
            await store.SetAsync(activeKey, active with
            {
                SignedBundleBase64 = Convert.ToBase64String(encodedTampered),
                SignedBundleSha256 = Convert.ToHexStringLower(
                    SHA256.HashData(encodedTampered))
            });
            CryptographicOperations.ZeroMemory(encodedTampered);

            var tampered = await ProductionMailboxCredentialBundleImporter
                .LoadActiveLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    new FixedTimeProvider(
                        ProductionMailboxProvisioningContractTests.Now + 101));
            Assert.Equal(ProductionMailboxActiveBundleStatus.Corrupt, tampered.Status);
            Assert.Null(tampered.Material);
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("mailbox")]
    [InlineData("placement")]
    [InlineData("selection")]
    [InlineData("owner")]
    [InlineData("certificate")]
    [InlineData("advertisement")]
    public async Task ExpiredActiveBundle_RouteTamperingIsCorruptNotRefreshable(
        string mutation)
    {
        var context = await CreateBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-expired-route-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            await ProductionMailboxCredentialBundleImporter.ImportLocalOwnerAsync(
                store,
                context.Holder,
                context.Bundle,
                context.Bundle.MailboxOwnerEd25519PublicKey,
                context.Fixture.BuildAnchor,
                trust,
                context.Fixture.ClientIdentity,
                MailboxInfrastructureOwnership.OfficialManaged,
                context.Clock);
            var key = ActiveBundleKey(context.Holder);
            var active = Assert.IsType<ProductionMailboxRuntimePublicationJournal>(
                await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(key));
            var encoded = ProductionMailboxLocalOwnerJournalCodec.Encode(
                MutateBundle(context.Bundle, mutation));
            await store.SetAsync(key, active with
            {
                SignedBundleBase64 = Convert.ToBase64String(encoded),
                SignedBundleSha256 = Convert.ToHexStringLower(SHA256.HashData(encoded))
            });
            CryptographicOperations.ZeroMemory(encoded);

            var result = await ProductionMailboxCredentialBundleImporter
                .LoadActiveLocalOwnerAsync(
                    store,
                    context.Holder,
                    context.Fixture.BuildAnchor,
                    trust,
                    context.Fixture.ClientIdentity,
                    context.Bundle.MailboxOwnerEd25519PublicKey,
                    MailboxInfrastructureOwnership.OfficialManaged,
                    new FixedTimeProvider(
                        ProductionMailboxProvisioningContractTests.Now + 101));

            Assert.Equal(ProductionMailboxActiveBundleStatus.Corrupt, result.Status);
            Assert.Null(result.Material);
            Assert.Equal(1, trust.Writes);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StartupRecovery_CorruptSignedJournalFailsClosedWithDiagnostic()
    {
        var context = await CreateBundleContextAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-production-mailbox-corrupt-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var store = new SqliteSessionStore(Path.Combine(root, "state.db"));
            var trust = new MemoryTrustStore();
            await Assert.ThrowsAsync<InjectedPublicationFaultException>(() =>
                ProductionMailboxCredentialBundleImporter
                    .ImportLocalOwnerWithFaultInjectionAsync(
                        store,
                        context.Holder,
                        context.Bundle,
                        context.Bundle.MailboxOwnerEd25519PublicKey,
                        context.Fixture.BuildAnchor,
                        trust,
                        context.Fixture.ClientIdentity,
                        MailboxInfrastructureOwnership.OfficialManaged,
                        point =>
                        {
                            if (point == ProductionMailboxCredentialBundleImporter
                                    .PublicationFaultPoint.AfterTrustCommit)
                                throw new InjectedPublicationFaultException();
                        },
                        context.Clock));
            var key = PublicationKey(context.Holder);
            var journal = Assert.IsType<ProductionMailboxRuntimePublicationJournal>(
                await store.GetAsync<ProductionMailboxRuntimePublicationJournal>(key));
            await store.SetAsync(key, journal with
            {
                SignedBundleBase64 = Convert.ToBase64String([0x00])
            });

            var error = await Assert.ThrowsAsync<InvalidDataException>(() =>
                ProductionMailboxCredentialBundleImporter
                    .TryRecoverPendingLocalOwnerAsync(
                        store,
                        context.Holder,
                        context.Fixture.BuildAnchor,
                        trust,
                        context.Fixture.ClientIdentity,
                        context.Bundle.MailboxOwnerEd25519PublicKey,
                        MailboxInfrastructureOwnership.OfficialManaged,
                        context.Clock));

            Assert.Equal(
                "Pending production mailbox publication journal bundle is corrupt.",
                error.Message);
            Assert.Null(await store.GetAsync<MailboxBundleRuntimeCheckpoint>(
                "deep.mailbox.production-local-owner.v1:" +
                context.Holder.SessionId.Value));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    private static string PublicationKey(MailboxHolderIdentity holder) =>
        "deep.mailbox.production-local-owner.v1:" + holder.SessionId.Value +
        ":publication-v1";

    private static string ActiveBundleKey(MailboxHolderIdentity holder) =>
        "deep.mailbox.production-local-owner.v1:" + holder.SessionId.Value +
        ":active-public-bundle-v1";

    private static async Task<BundleContext> CreateBundleContextAsync(
        ulong routeLifetimeSeconds = 300)
    {
        var fixture = ProductionMailboxProvisioningContractTests
            .CreateSignedFixture(sharedPlacement: true);
        var clock = new FixedTimeProvider(ProductionMailboxProvisioningContractTests.Now);
        var preview = await ProductionMailboxControlPlaneVerifier.VerifyAsync(
            fixture.Artifacts,
            fixture.BuildAnchor,
            new MemoryTrustStore(),
            fixture.ClientIdentity,
            MailboxInfrastructureOwnership.OfficialManaged,
            fixture.CurrentPlacement,
            fixture.NextPlacement,
            clock);
        var holderPair = PublicKeyAuth.GenerateKeyPair(Bytes(0x31, 32));
        var holder = new MailboxHolderIdentity(
            SessionIdFromEd25519(holderPair.PublicKey), holderPair.PublicKey);
        var mailbox = Bytes(0x71, 32);
        var currentGrant = Grant(
            preview.Topology.Snapshot.CurrentEpoch,
            preview.Authority.Authority,
            holderPair.PublicKey,
            fixture.CurrentPlacement,
            Bytes(0xb1, 16),
            fixture.IssuerPrivateKey);
        var nextGrant = Grant(
            preview.Topology.Snapshot.NextEpoch,
            preview.Authority.Authority,
            holderPair.PublicKey,
            fixture.NextPlacement,
            Bytes(0xc1, 16),
            fixture.IssuerPrivateKey);
        var ownerPair = PublicKeyAuth.GenerateKeyPair(Bytes(0x51, 32));
        var route = CreateRouteClosure(
            preview.Authority,
            fixture,
            ownerPair,
            mailbox,
            fixture.CurrentPlacement,
            routeLifetimeSeconds);
        var idempotency = ComputeLocalOwnerIdempotency(
            fixture,
            holderPair.PublicKey,
            ownerPair.PublicKey);
        var bundle = new ProductionMailboxLocalOwnerBundle(
            holderPair.PublicKey,
            ownerPair.PublicKey,
            idempotency,
            mailbox,
            fixture.CurrentPlacement.Bytes,
            ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(
                fixture.CurrentPlacement),
            fixture.Artifacts,
            [
                Selection(preview.CurrentSelection,
                    fixture.Artifacts.CanonicalCurrentSelection),
                Selection(preview.NextSelection,
                    fixture.Artifacts.CanonicalNextSelection)
            ],
            [
                new ProductionMailboxGrantBinding(
                    MailboxCapabilityDomain.Retrieve,
                    currentGrant.Epoch,
                    currentGrant.Generation,
                    MailboxAuthenticatedCapabilityCodec.EncodeGrant(currentGrant)),
                new ProductionMailboxGrantBinding(
                    MailboxCapabilityDomain.Retrieve,
                    nextGrant.Epoch,
                    nextGrant.Generation,
                    MailboxAuthenticatedCapabilityCodec.EncodeGrant(nextGrant))
            ],
            route.Certificate,
            SHA256.HashData(route.Certificate),
            route.Advertisement,
            SHA256.HashData(route.Advertisement),
            ReadOnlyMemory<byte>.Empty,
            ReadOnlyMemory<byte>.Empty,
            ProductionMailboxProvisioningContractTests.Now,
            preview.Topology.Snapshot.CurrentEpoch.NotAfterUnixSeconds);
        return new BundleContext(
            fixture, clock, holder, ownerPair.PrivateKey, mailbox, bundle);
    }

    private static async Task<PeerBundleContext> CreatePeerBundleContextAsync()
    {
        var fixture = ProductionMailboxProvisioningContractTests
            .CreateSignedFixture(sharedPlacement: true);
        var clock = new FixedTimeProvider(ProductionMailboxProvisioningContractTests.Now);
        var preview = await ProductionMailboxControlPlaneVerifier.VerifyAsync(
            fixture.Artifacts,
            fixture.BuildAnchor,
            new MemoryTrustStore(),
            fixture.ClientIdentity,
            MailboxInfrastructureOwnership.OfficialManaged,
            fixture.CurrentPlacement,
            fixture.NextPlacement,
            clock);
        var holderPair = PublicKeyAuth.GenerateKeyPair(Bytes(0x32, 32));
        var holder = new MailboxHolderIdentity(
            SessionIdFromEd25519(holderPair.PublicKey), holderPair.PublicKey);
        var recipientPair = PublicKeyAuth.GenerateKeyPair(Bytes(0x42, 32));
        var recipientSessionId = SessionIdFromEd25519(recipientPair.PublicKey);
        var recipientOwner = PublicKeyAuth.GenerateKeyPair(Bytes(0x52, 32));
        var mailbox = Bytes(0x72, 32);
        var route = CreateRouteClosure(
            preview.Authority,
            fixture,
            recipientOwner,
            mailbox,
            fixture.CurrentPlacement,
            routeLifetimeSeconds: 300);
        var currentGrant = Grant(
            preview.Topology.Snapshot.CurrentEpoch,
            preview.Authority.Authority,
            holderPair.PublicKey,
            fixture.CurrentPlacement,
            Bytes(0xb2, 16),
            fixture.IssuerPrivateKey,
            MailboxCapabilityDomain.Deposit);
        var nextGrant = Grant(
            preview.Topology.Snapshot.NextEpoch,
            preview.Authority.Authority,
            holderPair.PublicKey,
            fixture.NextPlacement,
            Bytes(0xc2, 16),
            fixture.IssuerPrivateKey,
            MailboxCapabilityDomain.Deposit);
        var selectionCommitment =
            ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(
                fixture.CurrentPlacement);
        var idempotency = ComputePeerDepositIdempotency(
            fixture,
            holderPair.PublicKey,
            recipientOwner.PublicKey,
            mailbox,
            fixture.CurrentPlacement.Bytes.Span,
            selectionCommitment);
        var bundle = new ProductionMailboxPeerDepositBundle(
            holderPair.PublicKey,
            recipientPair.PublicKey,
            recipientOwner.PublicKey,
            idempotency,
            mailbox,
            fixture.CurrentPlacement.Bytes,
            selectionCommitment,
            fixture.Artifacts,
            [
                Selection(preview.CurrentSelection,
                    fixture.Artifacts.CanonicalCurrentSelection),
                Selection(preview.NextSelection,
                    fixture.Artifacts.CanonicalNextSelection)
            ],
            [Binding(currentGrant), Binding(nextGrant)],
            route.Advertisement,
            SHA256.HashData(route.Advertisement),
            ProductionMailboxProvisioningContractTests.Now,
            preview.Topology.Snapshot.CurrentEpoch.NotAfterUnixSeconds);
        return new PeerBundleContext(
            fixture,
            clock,
            holder,
            recipientSessionId,
            recipientPair.PublicKey,
            recipientOwner.PublicKey,
            recipientOwner.PrivateKey,
            mailbox,
            bundle);
    }

    private static ProductionMailboxLocalOwnerBundle CreateRotatedLocalOwnerBundle(
        BundleContext context,
        ProductionMailboxProvisioningContractTests.SignedFixture rotated,
        ProductionMailboxSelectionSuccessorMode mode)
    {
        var oldAuthority = ProductionMailboxAuthorityCodec.Decode(
            context.Bundle.ControlPlane.CanonicalAuthority.Span);
        var oldTopology = ProductionMailboxTopologyCodec.Decode(
            context.Bundle.ControlPlane.CanonicalTopology.Span);
        var authority = ProductionMailboxAuthorityCodec.Decode(
            rotated.Artifacts.CanonicalAuthority.Span);
        var topology = ProductionMailboxTopologyCodec.Decode(
            rotated.Artifacts.CanonicalTopology.Span);
        var owner = PublicKeyAuth.GenerateKeyPair(context.OwnerPrivateKey[..32]);
        var placement = rotated.CurrentPlacement;
        var selectionCommitment =
            ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(placement);
        var route = CreateRouteClosure(
            authority,
            SHA256.HashData(rotated.Artifacts.CanonicalAuthority.Span),
            rotated,
            owner,
            context.Mailbox,
            placement,
            routeLifetimeSeconds: 300,
            routeSequence: 2);
        var currentGrant = Grant(
            topology.CurrentEpoch,
            authority,
            context.Holder.Ed25519PublicKey.ToArray(),
            placement,
            Bytes(0xe2, 16),
            rotated.IssuerPrivateKey);
        var nextGrant = Grant(
            topology.NextEpoch,
            authority,
            context.Holder.Ed25519PublicKey.ToArray(),
            placement,
            Bytes(0xf2, 16),
            rotated.IssuerPrivateKey);
        var oldSelection = context.Bundle.ControlPlane.CanonicalNextSelection.ToArray();
        var newSelection = rotated.Artifacts.CanonicalCurrentSelection.ToArray();
        var oldProof = ProductionMailboxTopologyCodec.DecodeSelection(oldSelection);
        var newProof = ProductionMailboxTopologyCodec.DecodeSelection(newSelection);
        var successor = new ProductionMailboxSelectionSuccessorProof
        {
            Mode = mode,
            NetworkId = authority.NetworkId,
            OldEpoch = oldProof.Epoch,
            OldEpochGeneration = oldProof.Generation,
            NewEpoch = newProof.Epoch,
            NewEpochGeneration = newProof.Generation,
            MailboxOwnerEd25519PublicKey = owner.PublicKey,
            BlindedMailboxId = context.Mailbox,
            BlindedPlacementId = placement.Bytes,
            SelectionInputCommitment = selectionCommitment,
            OldCanonicalAuthorityHash = SHA256.HashData(
                context.Bundle.ControlPlane.CanonicalAuthority.Span),
            NewCanonicalAuthorityHash = SHA256.HashData(
                rotated.Artifacts.CanonicalAuthority.Span),
            OldTopologyGeneration = oldTopology.TopologyGeneration,
            OldCanonicalTopologyHash = SHA256.HashData(
                context.Bundle.ControlPlane.CanonicalTopology.Span),
            NewTopologyGeneration = topology.TopologyGeneration,
            NewCanonicalTopologyHash = SHA256.HashData(
                rotated.Artifacts.CanonicalTopology.Span),
            OldCanonicalSelectionHash = SHA256.HashData(oldSelection),
            NewCanonicalSelectionHash = SHA256.HashData(newSelection),
            IssuedAtUnixSeconds = ProductionMailboxProvisioningContractTests.Now,
            ExpiresAtUnixSeconds = checked(
                ProductionMailboxProvisioningContractTests.Now + 40),
            CanonicalNewAuthority = rotated.Artifacts.CanonicalAuthority.ToArray(),
            OldCanonicalSelection = oldSelection,
            NewCanonicalSelection = newSelection,
            OldIssuerSignature = new byte[64],
            NewIssuerSignature = new byte[64]
        };
        if (mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
        {
            successor = successor with
            {
                OldIssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxSelectionSuccessorCodec
                        .GetOldIssuerSigningBytes(successor),
                    context.Fixture.IssuerPrivateKey)
            };
        }
        successor = successor with
        {
            NewIssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxSelectionSuccessorCodec
                    .GetNewIssuerSigningBytes(successor),
                rotated.IssuerPrivateKey)
        };
        var canonicalSuccessor =
            ProductionMailboxSelectionSuccessorCodec.Encode(successor);
        return new ProductionMailboxLocalOwnerBundle(
            context.Holder.Ed25519PublicKey.ToArray(),
            owner.PublicKey,
            ComputeLocalOwnerIdempotency(
                rotated, context.Holder.Ed25519PublicKey.Span, owner.PublicKey),
            context.Mailbox,
            placement.Bytes,
            selectionCommitment,
            rotated.Artifacts,
            [
                SelectionBinding(rotated.Artifacts.CanonicalCurrentSelection, topology),
                SelectionBinding(rotated.Artifacts.CanonicalNextSelection, topology)
            ],
            [
                mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
                    ? context.Bundle.Grants[1]
                    : Binding(currentGrant),
                Binding(nextGrant)
            ],
            route.Certificate,
            SHA256.HashData(route.Certificate),
            route.Advertisement,
            SHA256.HashData(route.Advertisement),
            canonicalSuccessor,
            SHA256.HashData(canonicalSuccessor),
            ProductionMailboxProvisioningContractTests.Now,
            topology.CurrentEpoch.NotAfterUnixSeconds);
    }

    private static ProductionMailboxSelectionBinding SelectionBinding(
        ReadOnlyMemory<byte> canonical,
        ProductionMailboxTopologySnapshot topology)
    {
        var proof = ProductionMailboxTopologyCodec.DecodeSelection(canonical.Span);
        var epoch = proof.Epoch == topology.CurrentEpoch.Epoch
            ? topology.CurrentEpoch
            : proof.Epoch == topology.NextEpoch.Epoch
                ? topology.NextEpoch
                : throw new InvalidDataException("Selection epoch is outside topology.");
        return new ProductionMailboxSelectionBinding(
            proof.Epoch,
            proof.Generation,
            canonical.ToArray(),
            proof.Replicas.Select(replica =>
            {
                var node = epoch.Nodes.Single(value =>
                    value.NodeId.Span.SequenceEqual(replica.ReplicaId.Span));
                return new ProductionMailboxReplicaBinding(
                    node.NodeId.ToArray(),
                    new Uri(node.HttpsEndpoint, UriKind.Absolute),
                    node.CurrentSpkiSha256.ToArray(),
                    node.NextSpkiSha256.ToArray());
            }).ToArray());
    }

    private static ProductionMailboxPeerDepositBundle RotatePeerBundle(
        PeerBundleContext context,
        ulong routeSequence,
        byte serialSeed)
    {
        var authority = ProductionMailboxAuthorityCodec.Decode(
            context.Bundle.ControlPlane.CanonicalAuthority.Span);
        var topology = ProductionMailboxTopologyCodec.Decode(
            context.Bundle.ControlPlane.CanonicalTopology.Span);
        var advertisement = ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(
            context.Bundle.CanonicalRouteAdvertisement.Span) with
        {
            Sequence = routeSequence,
            OwnerSignature = new byte[64]
        };
        advertisement = advertisement with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec
                    .GetAdvertisementSigningBytes(advertisement),
                context.RecipientOwnerPrivateKey)
        };
        var encodedAdvertisement =
            ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(advertisement);
        var currentGrant = Grant(
            topology.CurrentEpoch,
            authority,
            context.Holder.Ed25519PublicKey.ToArray(),
            context.Fixture.CurrentPlacement,
            Bytes(serialSeed, 16),
            context.Fixture.IssuerPrivateKey,
            MailboxCapabilityDomain.Deposit);
        var nextGrant = Grant(
            topology.NextEpoch,
            authority,
            context.Holder.Ed25519PublicKey.ToArray(),
            context.Fixture.NextPlacement,
            Bytes(checked((byte)(serialSeed + 0x10)), 16),
            context.Fixture.IssuerPrivateKey,
            MailboxCapabilityDomain.Deposit);
        return context.Bundle with
        {
            Grants = [Binding(currentGrant), Binding(nextGrant)],
            CanonicalRouteAdvertisement = encodedAdvertisement,
            RouteAdvertisementSha256 = SHA256.HashData(encodedAdvertisement)
        };
    }

    private static ProductionMailboxSelectionBinding Selection(
        VerifiedProductionMailboxSelection verified,
        ReadOnlyMemory<byte> canonical) => new(
            verified.Proof.Epoch,
            verified.Proof.Generation,
            canonical,
            verified.Replicas.Select(static replica =>
                new ProductionMailboxReplicaBinding(
                    replica.ReplicaId,
                    replica.HttpsEndpoint,
                    replica.CurrentSpkiSha256,
                    replica.NextSpkiSha256)).ToArray());

    private static ProductionMailboxLocalOwnerBundle MutateBundle(
        ProductionMailboxLocalOwnerBundle source,
        string mutation)
    {
        static byte[] Changed(ReadOnlyMemory<byte> value)
        {
            var changed = value.ToArray();
            changed[^1] ^= 1;
            return changed;
        }
        return mutation switch
        {
            "mailbox" => source with { BlindedMailboxId = Changed(source.BlindedMailboxId) },
            "placement" => source with
                { BlindedPlacementId = Changed(source.BlindedPlacementId) },
            "selection" => source with
                { SelectionInputCommitment = Changed(source.SelectionInputCommitment) },
            "owner" => source with
                { MailboxOwnerEd25519PublicKey = Changed(source.MailboxOwnerEd25519PublicKey) },
            "certificate" => source with
            {
                CanonicalRouteCertificate = Changed(source.CanonicalRouteCertificate),
                RouteCertificateSha256 = SHA256.HashData(
                    Changed(source.CanonicalRouteCertificate))
            },
            "advertisement" => source with
            {
                CanonicalRouteAdvertisement = Changed(source.CanonicalRouteAdvertisement),
                RouteAdvertisementSha256 = SHA256.HashData(
                    Changed(source.CanonicalRouteAdvertisement))
            },
            "certificate-hash" => source with
                { RouteCertificateSha256 = Changed(source.RouteCertificateSha256) },
            "idempotency" => source with { IdempotencyKey = Changed(source.IdempotencyKey) },
            "successor" => source with
            {
                CanonicalSelectionSuccessor = new byte[64],
                SelectionSuccessorSha256 = Bytes(0xf1, 32)
            },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation))
        };
    }

    private static RouteClosure CreateRouteClosure(
        VerifiedProductionMailboxAuthority authority,
        ProductionMailboxProvisioningContractTests.SignedFixture fixture,
        KeyPair owner,
        byte[] mailbox,
        BlindedPlacementId placement,
        ulong routeLifetimeSeconds) => CreateRouteClosure(
            authority.Authority,
            authority.CanonicalAuthorityHash,
            fixture,
            owner,
            mailbox,
            placement,
            routeLifetimeSeconds,
            routeSequence: 1);

    private static RouteClosure CreateRouteClosure(
        ProductionMailboxAuthority authority,
        ReadOnlyMemory<byte> canonicalAuthorityHash,
        ProductionMailboxProvisioningContractTests.SignedFixture fixture,
        KeyPair owner,
        byte[] mailbox,
        BlindedPlacementId placement,
        ulong routeLifetimeSeconds,
        ulong routeSequence)
    {
        var certificate = new ProductionMailboxRouteCertificate
        {
            NetworkId = authority.NetworkId,
            AuthorityGeneration = authority.AuthorityGeneration,
            CanonicalAuthorityHash = canonicalAuthorityHash,
            IssuerEd25519PublicKey = authority.MailboxIssuerEd25519PublicKey,
            MailboxOwnerEd25519PublicKey = owner.PublicKey,
            BlindedMailboxId = mailbox,
            BlindedPlacementId = placement.Bytes,
            SelectionInputCommitment =
                ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(placement),
            IssuedAtUnixSeconds = ProductionMailboxProvisioningContractTests.Now - 10,
            ExpiresAtUnixSeconds = checked(
                ProductionMailboxProvisioningContractTests.Now + routeLifetimeSeconds),
            IssuerSignature = new byte[64]
        };
        certificate = certificate with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec
                    .GetCertificateSigningBytes(certificate),
                fixture.IssuerPrivateKey)
        };
        var advertisement = new ProductionMailboxRouteAdvertisement
        {
            Certificate = certificate,
            Sequence = routeSequence,
            PublishedAtUnixSeconds = ProductionMailboxProvisioningContractTests.Now,
            ExpiresAtUnixSeconds = certificate.ExpiresAtUnixSeconds,
            OwnerSignature = new byte[64]
        };
        advertisement = advertisement with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec
                    .GetAdvertisementSigningBytes(advertisement),
                owner.PrivateKey)
        };
        return new RouteClosure(
            ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(certificate),
            ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(advertisement));
    }

    private static byte[] ComputeLocalOwnerIdempotency(
        ProductionMailboxProvisioningContractTests.SignedFixture fixture,
        ReadOnlySpan<byte> holder,
        ReadOnlySpan<byte> owner,
        ReadOnlySpan<byte> signingCertificateSha256 = default,
        ReadOnlySpan<byte> buildArtifactSha256 = default)
    {
        if (signingCertificateSha256.IsEmpty)
            signingCertificateSha256 = fixture.ClientIdentity
                .SigningCertificateSha256.Span;
        if (buildArtifactSha256.IsEmpty)
            buildArtifactSha256 = fixture.ClientIdentity.BuildArtifactSha256.Span;
        Span<byte> zero = stackalloc byte[32];
        return ProductionMailboxIssuanceIdempotency.Compute(
            SHA256.HashData(fixture.Artifacts.CanonicalAuthority.Span),
            SHA256.HashData(fixture.Artifacts.CanonicalRevocationSnapshot.Span),
            SHA256.HashData(fixture.Artifacts.CanonicalTopology.Span),
            holder,
            owner,
            zero,
            zero,
            zero,
            ProductionMailboxIssuanceIntent.LocalOwner,
            fixture.ClientIdentity.Platform == MailboxClientPlatform.Android
                ? ProductionMailboxClientPlatform.Android
                : ProductionMailboxClientPlatform.Windows,
            signingCertificateSha256,
            buildArtifactSha256,
            zero);
    }

    private static byte[] ComputePeerDepositIdempotency(
        ProductionMailboxProvisioningContractTests.SignedFixture fixture,
        ReadOnlySpan<byte> holder,
        ReadOnlySpan<byte> owner,
        ReadOnlySpan<byte> mailbox,
        ReadOnlySpan<byte> placement,
        ReadOnlySpan<byte> selectionCommitment)
    {
        Span<byte> zero = stackalloc byte[32];
        return ProductionMailboxIssuanceIdempotency.Compute(
            SHA256.HashData(fixture.Artifacts.CanonicalAuthority.Span),
            SHA256.HashData(fixture.Artifacts.CanonicalRevocationSnapshot.Span),
            SHA256.HashData(fixture.Artifacts.CanonicalTopology.Span),
            holder,
            owner,
            mailbox,
            placement,
            selectionCommitment,
            ProductionMailboxIssuanceIntent.PeerDeposit,
            fixture.ClientIdentity.Platform == MailboxClientPlatform.Android
                ? ProductionMailboxClientPlatform.Android
                : ProductionMailboxClientPlatform.Windows,
            fixture.ClientIdentity.SigningCertificateSha256.Span,
            fixture.ClientIdentity.BuildArtifactSha256.Span,
            zero);
    }

    private static ProductionMailboxGrantBinding Binding(
        MailboxAuthenticatedGrant grant) => new(
            grant.Domain,
            grant.Epoch,
            grant.Generation,
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant));

    private static MailboxAuthenticatedGrant Grant(
        ProductionMailboxTopologyEpoch epoch,
        ProductionMailboxAuthority authority,
        byte[] holder,
        BlindedPlacementId placement,
        byte[] serial,
        byte[] issuerPrivateKey,
        MailboxCapabilityDomain domain = MailboxCapabilityDomain.Retrieve)
    {
        var unsigned = new MailboxAuthenticatedGrant
        {
            Domain = domain,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            NetworkId = authority.NetworkId,
            Epoch = epoch.Epoch,
            Generation = epoch.Generation,
            Serial = serial,
            NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
            ExpiresAtUnixSeconds = epoch.NotAfterUnixSeconds,
            OverlapUntilUnixSeconds = 0,
            PlacementCommitment = MailboxPlacementCommitment.Compute(placement),
            MembershipCommitment = epoch.MembershipCommitment,
            IssuerPublicKey = authority.MailboxIssuerEd25519PublicKey,
            HolderPublicKey = holder,
            IssuerSignature = new byte[64]
        };
        return unsigned with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(unsigned),
                issuerPrivateKey)
        };
    }

    private static SessionId SessionIdFromEd25519(byte[] publicKey)
    {
        var curve = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(publicKey);
        return new SessionId("05" + Convert.ToHexStringLower(curve));
    }

    private static byte[] Bytes(byte seed, int length) => Enumerable.Range(0, length)
        .Select(index => unchecked((byte)(seed + index))).ToArray();

    private static byte[] ChangedBytes(ReadOnlyMemory<byte> value)
    {
        var changed = value.ToArray();
        changed[^1] ^= 1;
        return changed;
    }

    private sealed class FixedTimeProvider(ulong now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() =>
            DateTimeOffset.FromUnixTimeSeconds(checked((long)now));
    }

    private sealed class MemoryTrustStore : IProductionMailboxTrustStateStore
    {
        private ProductionMailboxTrustState? state;
        public int Writes { get; private set; }
        public int Reads { get; private set; }
        public bool ThrowAfterNextCommit { get; init; }
        public Action? BeforeRead { get; init; }

        public Task<ProductionMailboxTrustState?> ReadAsync(
            CancellationToken cancellationToken = default)
        {
            Reads++;
            BeforeRead?.Invoke();
            return Task.FromResult(state);
        }

        public Task CommitAsync(
            ulong expectedRevision,
            ProductionMailboxTrustState replacement,
            CancellationToken cancellationToken = default)
        {
            if ((state?.Revision ?? 0) != expectedRevision)
                throw new InvalidOperationException("compare/exchange failed");
            state = replacement;
            Writes++;
            if (ThrowAfterNextCommit && Writes == 1)
                throw new InjectedPublicationFaultException();
            return Task.CompletedTask;
        }
    }

    private sealed record BundleContext(
        ProductionMailboxProvisioningContractTests.SignedFixture Fixture,
        FixedTimeProvider Clock,
        MailboxHolderIdentity Holder,
        byte[] OwnerPrivateKey,
        byte[] Mailbox,
        ProductionMailboxLocalOwnerBundle Bundle);

    private sealed record PeerBundleContext(
        ProductionMailboxProvisioningContractTests.SignedFixture Fixture,
        FixedTimeProvider Clock,
        MailboxHolderIdentity Holder,
        SessionId RecipientSessionId,
        byte[] RecipientPublicKey,
        byte[] RecipientOwnerPublicKey,
        byte[] RecipientOwnerPrivateKey,
        byte[] Mailbox,
        ProductionMailboxPeerDepositBundle Bundle);

    private sealed record RouteClosure(byte[] Certificate, byte[] Advertisement);

    private sealed class IndexOnlyList<T>(T[] values) : IReadOnlyList<T>
    {
        public int Count => values.Length;
        public T this[int index] => values[index];
        public IEnumerator<T> GetEnumerator() =>
            throw new InvalidOperationException("Enumeration is forbidden by this fixture.");
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() =>
            GetEnumerator();
    }

    private sealed class InjectedPublicationFaultException : Exception;
}
