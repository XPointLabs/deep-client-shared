using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Persistence.PreKeyV2;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2AccountServiceTests
{
    [Fact]
    public async Task CurrentDid2DeviceStateMountsAndDoesNotRecreateLostAgreementLedger()
    {
        if (!SupportedProvider()) return;
        var directory = Path.Combine(Path.GetTempPath(),
            "deep-did2-device-state-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var storage = new InMemoryDeepSecureStorage();
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            var clock = new FrozenClock(
                DateTimeOffset.FromUnixTimeSeconds(1_900_000_000));
            var accounts = new DeepIdV2AccountService(storage, directory,
                network, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            _ = await accounts.CreateAsync("Alice");
            using (var mounted = await accounts.OpenCurrentDeviceStateStoreAsync())
                Assert.NotNull(mounted);
            await accounts.DeleteRetainedRecoveryPhraseAsync();
            var resumed = new DeepIdV2AccountService(storage, directory,
                network, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            using (var mounted = await resumed.OpenCurrentDeviceStateStoreAsync())
                Assert.NotNull(mounted);

            var statePath = Path.Combine(directory,
                "deep-store-v2-account.dsv2.devices.dvs1");
            Assert.True(File.Exists(statePath));
            File.Delete(statePath);
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await resumed.OpenCurrentDeviceStateStoreAsync());
            Assert.False(File.Exists(statePath));

            await resumed.ResetExplicitlyAsync();
            Assert.False(File.Exists(Path.Combine(directory,
                "deep-store-v2-account.dsv2")));
            _ = await resumed.CreateAsync("Bob");
            using var newStore = await resumed.OpenCurrentDeviceStateStoreAsync();
            Assert.NotNull(newStore);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task VerifiedDid2GenesisInstallsExactCurrentDmd1AcrossRestart()
    {
        if (!SupportedProvider()) return;
        var directory = Path.Combine(Path.GetTempPath(),
            "deep-did2-dmd1-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var storage = new InMemoryDeepSecureStorage();
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            var clock = new FrozenClock(
                DateTimeOffset.FromUnixTimeSeconds(1_900_000_000));
            var accounts = new DeepIdV2AccountService(storage, directory,
                network, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            var created = await accounts.CreateAsync("Alice");
            var key = RandomNumberGenerator.GetBytes(32);
            var instanceId = RandomNumberGenerator.GetBytes(32);
            var path = Path.Combine(directory, "device-current.dvs1");
            var options = new SqliteDeviceStateStoreOptions(path, key,
                DeviceAccountId32.FromBytes(created.AccountId.Span), 1, 1,
                DeviceOperationId32.FromBytes(instanceId));
            try
            {
                using (var store = new SqliteDeviceStateStore(options))
                {
                    Assert.Equal(ProtectedCurrentDmd1CommitDisposition.Applied,
                        (await accounts.CommitOwnGenesisDmd1Async(store)).Disposition);
                    Assert.Equal(ProtectedCurrentDmd1CommitDisposition.ExactReplay,
                        (await accounts.CommitOwnGenesisDmd1Async(store)).Disposition);
                }
                await accounts.DeleteRetainedRecoveryPhraseAsync();
                var resumed = new DeepIdV2AccountService(storage, directory,
                    network, 1, clock,
                    DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
                using (var reopened = new SqliteDeviceStateStore(
                    new SqliteDeviceStateStoreOptions(path, key,
                        DeviceAccountId32.FromBytes(created.AccountId.Span),
                        1, 1, DeviceOperationId32.FromBytes(instanceId),
                        allowCreate: false)))
                    Assert.Equal(ProtectedCurrentDmd1CommitDisposition.ExactReplay,
                        (await resumed.CommitOwnGenesisDmd1Async(reopened))
                        .Disposition);
                var wrongAccount = created.AccountId.ToArray();
                wrongAccount[0] ^= 1;
                using var wrongScope = new SqliteDeviceStateStore(
                    new SqliteDeviceStateStoreOptions(
                        Path.Combine(directory, "wrong-scope.dvs1"), key,
                        DeviceAccountId32.FromBytes(wrongAccount), 1, 1,
                        DeviceOperationId32.FromBytes(
                            RandomNumberGenerator.GetBytes(32))));
                Assert.Equal(ProtectedCurrentDmd1CommitDisposition.Conflict,
                    (await resumed.CommitOwnGenesisDmd1Async(wrongScope))
                    .Disposition);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(instanceId);
            }
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task PublicServiceCreatesResumesAndDeletesPhraseWithoutV1Fallback()
    {
        if (!SupportedProvider()) return;
        var directory = Path.Combine(Path.GetTempPath(),
            "deep-did2-service-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var storage = new FaultingDeepSecureStorage();
            await storage.WriteBatchAsync(
                [new DeepSecureStorageWrite("deep.store.v1.keep", new byte[] { 7 })]);
            var network = Enumerable.Range(1, 16).Select(static value =>
                (byte)value).ToArray();
            var clock = new FrozenClock(
                DateTimeOffset.FromUnixTimeSeconds(1_900_000_000));
            var first = new DeepIdV2AccountService(storage, directory,
                network, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            Assert.Null(await first.GetCurrentAsync());
            var created = await first.CreateAsync(" Alice ");
            Assert.Equal("Alice", created.DisplayName);
            Assert.Equal(created.PermanentId,
                DeepPermanentIdV2.ParseCanonical(
                    created.PermanentId.CanonicalText));
            Assert.Equal(32, created.AccountId.Length);
            byte[] firstDeviceId;
            byte[] firstAgreementPublicKey;
            using (var agreement = await first.OpenLocalDeviceAgreementAuthorityAsync())
            {
                Assert.Equal(network, agreement.NetworkId.ToArray());
                Assert.Equal(created.AccountId.ToArray(), agreement.AccountId.ToArray());
                Assert.Equal(32, agreement.DeviceId.Length);
                Assert.Equal(32, agreement.AgreementPublicKey.Length);
                firstDeviceId = agreement.DeviceId.ToArray();
                firstAgreementPublicKey = agreement.AgreementPublicKey.ToArray();
            }
            using (var prekeys = await first.OpenLocalPreKeyAuthoringAuthorityAsync())
            {
                Assert.Equal(firstDeviceId, prekeys.DeviceId.ToArray());
                Assert.Equal<ulong>(1, prekeys.DeviceGeneration);
            }
            var callerCopy = created.AccountId.ToArray();
            callerCopy.AsSpan().Clear();
            Assert.NotEqual(callerCopy, created.AccountId.ToArray());
            var publicGenesis = await new ProtectedDeepIdV2GenesisContactStore(
                storage, network, created.AccountId.Span).ReadUntrustedAsync(
                default);
            Assert.NotNull(publicGenesis);
            var readCapability = DeepIdV2Codec.DecodeDeepIdText(
                created.PermanentId.CanonicalText).ReadCapability;
            Assert.Equal(-1, publicGenesis!.ExactDid2.Span.IndexOf(
                readCapability));
            Assert.True(DeepIdV2Codec.DecodeDid2(
                publicGenesis.ExactDid2.Span).MatchesResolverReadCapability(
                    readCapability));
            var admission = await first.PrepareGenesisAdmissionAsync();
            var decodedAdmission = DeepIdV2GenesisAdmissionWireCodec
                .DecodeRequest(admission);
            Assert.Equal(publicGenesis.ExactDid2.ToArray(),
                decodedAdmission.Admission.ExactDid2.ToArray());
            Assert.Equal(-1, admission.AsSpan().IndexOf(readCapability));
            var leaf = DeepIdV2AccountDirectoryCodec.Decode(
                decodedAdmission.Admission.ExactAdc1V2.Span).DirectoryLeafKey;
            var head = UntrustedHead(network);
            var receipt = DeepIdV2GenesisAdmissionWireCodec.EncodeReceipt(
                new DeepIdV2GenesisAdmissionReceipt(
                    decodedAdmission.OperationId.Span, leaf.Span, head));
            using (var transport = new HttpServiceRequestTransport(
                       new HttpClient(new FixedReceiptHandler(receipt)),
                       DeepIdV2GenesisAdmissionClient.CreateTransportOptions(
                           "https://registry.example/"),
                       HttpServiceEndpointPolicy.Production))
            using (var client = new DeepIdV2GenesisAdmissionClient(transport))
            {
                var untrusted = await client.AdmitAsync(admission);
                Assert.Equal(receipt,
                    DeepIdV2GenesisAdmissionWireCodec.EncodeReceipt(untrusted));
            }
            var wrongOperation = decodedAdmission.OperationId.ToArray();
            wrongOperation[0] ^= 1;
            var mismatchedReceipt = DeepIdV2GenesisAdmissionWireCodec.EncodeReceipt(
                new DeepIdV2GenesisAdmissionReceipt(wrongOperation,
                    leaf.Span, head));
            using (var transport = new HttpServiceRequestTransport(
                       new HttpClient(new FixedReceiptHandler(mismatchedReceipt)),
                       DeepIdV2GenesisAdmissionClient.CreateTransportOptions(
                           "https://registry.example/"),
                       HttpServiceEndpointPolicy.Production))
            using (var client = new DeepIdV2GenesisAdmissionClient(transport))
                await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(
                    async () => await client.AdmitAsync(admission));
            using (var phrase = await first.ReadRetainedRecoveryPhraseAsync())
                Assert.NotNull(phrase);

            var otherNetwork = network.ToArray();
            otherNetwork[0] ^= 1;
            var wrongScope = new DeepIdV2AccountService(storage, directory,
                otherNetwork, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            await Assert.ThrowsAnyAsync<Exception>(() =>
                wrongScope.GetCurrentAsync());

            var resumed = new DeepIdV2AccountService(storage, directory,
                network, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            var account = await resumed.GetCurrentAsync();
            Assert.NotNull(account);
            Assert.Equal(created.AccountId.ToArray(), account.AccountId.ToArray());
            Assert.Equal(created.PermanentId, account.PermanentId);
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => resumed.CreateAsync("Second"));

            await resumed.DeleteRetainedRecoveryPhraseAsync();
            Assert.Null(await new DeepIdV2AccountService(storage, directory,
                network, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess)
                .ReadRetainedRecoveryPhraseAsync());
            Assert.Equal(created.PermanentId,
                (await resumed.GetCurrentAsync())!.PermanentId);
            var afterPhraseDeletion = new DeepIdV2AccountService(storage,
                directory, network, 1, clock,
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            Assert.Equal(created.PermanentId,
                (await afterPhraseDeletion.GetCurrentAsync())!.PermanentId);
            Assert.Equal(admission,
                await afterPhraseDeletion.PrepareGenesisAdmissionAsync());
            using (var agreement = await afterPhraseDeletion
                       .OpenLocalDeviceAgreementAuthorityAsync())
            {
                Assert.Equal(firstDeviceId, agreement.DeviceId.ToArray());
                Assert.Equal(firstAgreementPublicKey,
                    agreement.AgreementPublicKey.ToArray());
            }
            using (var prekeys = await afterPhraseDeletion
                       .OpenLocalPreKeyAuthoringAuthorityAsync())
            {
                Assert.Equal(firstDeviceId, prekeys.DeviceId.ToArray());
                using var verifier = DeepMlDsa65CandidateVerifierFactory
                    .OpenForCurrentProcess();
                var publicEvidence = await new ProtectedDeepIdV2GenesisContactStore(
                    storage, network, created.AccountId.Span).ReadVerifiedAsync(
                    1_900_000_000, 1, verifier, default);
                Assert.NotNull(publicEvidence);
                var currentDirectory = ApplicationCoreVerifier.StartDmd1Lineage(
                    publicEvidence!.Directory).Next;
                var context = new Dpk2AuthoringContext(
                    currentDirectory, 1, 1, 1, 1_900_000_000,
                    1_900_000_000, 1_900_086_400);
                if (OperatingSystem.IsWindows())
                {
                    using var offering = prekeys.AuthorOneTimeV2(context);
                    Assert.Equal(firstDeviceId,
                        offering.Record.ResponderDeviceId.ToArray());
                    var parsed = DeepIdV2Dpk2Codec.Decode(offering.ExactDpk2.Span);
                    Assert.Equal(offering.ExactDpk2Hash.ToArray(),
                        parsed.ExactHash.ToArray());
                    Assert.Throws<MessagingWireFormatException>(() =>
                        Dpk2Codec.Decode(offering.ExactDpk2.Span));
                    var signer = publicEvidence.Binding.Identity.ActiveDevices
                        .Single(device => device.Certificate.DeviceId.Span
                            .SequenceEqual(firstDeviceId))
                        .Certificate.DeviceEd25519PublicKey.ToArray();
                    Assert.True(PublicKeyAuth.VerifyDetached(
                        offering.Record.SignedX25519PrekeySignature.ToArray(),
                        DeepIdV2Dpk2Codec.GetX25519SignedPrekeySignatureInput(
                            offering.Record), signer));
                    Assert.True(PublicKeyAuth.VerifyDetached(
                        offering.Record.MlKemPrekeySignature.ToArray(),
                        DeepIdV2Dpk2Codec.GetMlKemPrekeySignatureInput(
                            offering.Record), signer));
                    Assert.True(PublicKeyAuth.VerifyDetached(
                        offering.Record.BundleSignature.ToArray(),
                        DeepIdV2Dpk2Codec.GetPrekeyBundleSignatureInput(
                            offering.Record), signer));
                    using var lastResort = prekeys.AuthorLastResortV2(
                        context, reuseLimit: 9);
                    Assert.Equal(Dpk2PrekeyKind.LastResort,
                        DeepIdV2Dpk2Codec.Decode(lastResort.ExactDpk2.Span)
                            .Kind);
                    Assert.True(PublicKeyAuth.VerifyDetached(
                        lastResort.Record.BundleSignature.ToArray(),
                        DeepIdV2Dpk2Codec.GetPrekeyBundleSignatureInput(
                            lastResort.Record), signer));
                    Assert.Throws<MessagingWireFormatException>(() =>
                        Dpk2Codec.Decode(lastResort.ExactDpk2.Span));
                    var service = prekeys.AuthorPreKeyServiceV2(context,
                        publicEvidence.Binding, 32, 9);
                    var drsReference = TestReference("DRS1", 0x93);
                    DeepIdV2PreKeyServiceCodec.VerifyDeviceSignature(
                        DeepIdV2PreKeyServiceCodec.Decode(service.ExactXps1.Span),
                        signer);
                    var publicationOperation = Enumerable.Repeat((byte)0x94, 32)
                        .ToArray();
                    var placement = Enumerable.Repeat((byte)0x95, 32).ToArray();
                    Assert.Throws<ArgumentException>(() => prekeys.AuthorInventoryV2(
                        context, publicEvidence.Binding, service,
                        drsReference, new byte[32],
                        publicationOperation, placement, 31, 9));
                    var stricterService = prekeys.AuthorPreKeyServiceV2(
                        context, publicEvidence.Binding, 33, 8);
                    Assert.Throws<CryptographicException>(() =>
                        prekeys.AuthorInventoryV2(context,
                            publicEvidence.Binding, stricterService,
                            drsReference, new byte[32],
                            publicationOperation, placement, 32, 9));
                    var unrelatedDirectory = Path.Combine(directory,
                        "unrelated-did2-binding");
                    Directory.CreateDirectory(unrelatedDirectory);
                    try
                    {
                        using var unrelatedStorage = new InMemoryDeepSecureStorage();
                        var unrelated = new DeepIdV2AccountService(
                            unrelatedStorage, unrelatedDirectory, network, 1,
                            clock, DeepMlDsa65CandidateVerifierFactory
                                .OpenForCurrentProcess);
                        var unrelatedAccount = await unrelated.CreateAsync("Other");
                        var unrelatedPublic = await new
                            ProtectedDeepIdV2GenesisContactStore(
                                unrelatedStorage, network,
                                unrelatedAccount.AccountId.Span)
                            .ReadVerifiedAsync(1_900_000_000, 1, verifier,
                                default);
                        Assert.NotNull(unrelatedPublic);
                        Assert.Throws<CryptographicException>(() =>
                            prekeys.AuthorInventoryV2(context,
                                unrelatedPublic!.Binding, service,
                                drsReference, new byte[32],
                                publicationOperation, placement, 32, 9));
                    }
                    finally { Directory.Delete(unrelatedDirectory, true); }
                    using (var inventory = prekeys.AuthorInventoryV2(
                               context, publicEvidence.Binding,
                               service, drsReference,
                               new byte[32], publicationOperation, placement,
                               32, 9))
                    {
                        var publication = DeepIdV2PreKeyPublicationCodec.Decode(
                            inventory.ExactXpp1.Span);
                        Assert.Equal(32, inventory.OneTimeOfferings.Count);
                        Assert.Equal(32, publication.OneTimeMembers.Count);
                        Assert.Equal(inventory.ExactXpi1.ToArray(),
                            publication.Manifest.CanonicalBytes.ToArray());
                        Assert.Equal(inventory.OneTimeOfferings[0].ExactDpk2.ToArray(),
                            publication.OneTimeMembers[0].CanonicalBytes.ToArray());
                        Assert.Equal(inventory.LastResortOffering.ExactDpk2.ToArray(),
                            publication.LastResortMember.CanonicalBytes.ToArray());
                        Assert.True(PublicKeyAuth.VerifyDetached(
                            publication.Manifest.Field(16).ToArray(),
                            publication.Manifest.SignatureInput.ToArray(), signer));
                        Assert.ThrowsAny<Exception>(() => Deep.Protocol.ContactV1
                            .Xpi1Codec.Decode(inventory.ExactXpi1.Span));
                        Assert.ThrowsAny<Exception>(() => Deep.Protocol.ContactV1
                            .Xpp1Codec.Decode(inventory.ExactXpp1.Span));
                        var statePath = Path.Combine(directory, "prekeys-v2.pkv2");
                        var databaseKey = RandomNumberGenerator.GetBytes(32);
                        try
                        {
                            await using (var store = new SqlitePreKeyV2InventoryStore(
                                statePath, databaseKey, network, created.AccountId.Span,
                                publicEvidence.Binding.Identity.Account.Certificate
                                    .AccountGeneration, firstDeviceId, 1,
                                offering.Record.ResponderDpd1Ref.Span, signer,
                                allowCreate: true))
                            {
                                Assert.False(store.HasStagedInventory);
                                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                                    store.StageInitialAsync(service, inventory,
                                        beforeCommit: _ => throw new
                                            InvalidOperationException("test crash before commit")));
                                Assert.False(store.HasStagedInventory);
                            }
                            using var retry = prekeys.AuthorInventoryV2(
                                context, publicEvidence.Binding,
                                service, drsReference,
                                new byte[32], RandomNumberGenerator.GetBytes(32),
                                placement, 32, 9);
                            await using (var store = new SqlitePreKeyV2InventoryStore(
                                statePath, databaseKey, network, created.AccountId.Span,
                                publicEvidence.Binding.Identity.Account.Certificate
                                    .AccountGeneration, firstDeviceId, 1,
                                offering.Record.ResponderDpd1Ref.Span, signer,
                                allowCreate: false))
                            {
                                var foreignService = prekeys.AuthorPreKeyServiceV2(
                                    context, publicEvidence.Binding, 32, 9);
                                await Assert.ThrowsAnyAsync<Exception>(() =>
                                    store.StageInitialAsync(foreignService, retry));
                                Assert.False(store.HasStagedInventory);
                                await store.StageInitialAsync(service, retry);
                                Assert.True(store.HasStagedInventory);
                                Assert.Equal(service.ExactXps1.ToArray(),
                                    store.ReadStagedService());
                                await Assert.ThrowsAsync<CryptographicException>(() =>
                                    store.StageInitialAsync(service, retry));
                            }
                            await using (var reopened = new SqlitePreKeyV2InventoryStore(
                                statePath, databaseKey, network, created.AccountId.Span,
                                publicEvidence.Binding.Identity.Account.Certificate
                                    .AccountGeneration, firstDeviceId, 1,
                                offering.Record.ResponderDpd1Ref.Span, signer,
                                allowCreate: false))
                            {
                                Assert.True(reopened.HasStagedInventory);
                                Assert.Equal(service.ExactXps1.ToArray(),
                                    reopened.ReadStagedService());
                            }
                            var wrongNetwork = network.ToArray();
                            wrongNetwork[0] ^= 1;
                            Assert.Throws<CryptographicException>(() =>
                                new SqlitePreKeyV2InventoryStore(statePath,
                                    databaseKey, wrongNetwork, created.AccountId.Span,
                                    1, firstDeviceId, 1,
                                    offering.Record.ResponderDpd1Ref.Span,
                                    signer, allowCreate: false));
                            var wrongKey = RandomNumberGenerator.GetBytes(32);
                            try
                            {
                                Assert.ThrowsAny<Exception>(() =>
                                    new SqlitePreKeyV2InventoryStore(statePath,
                                        wrongKey, network, created.AccountId.Span,
                                        1, firstDeviceId, 1,
                                        offering.Record.ResponderDpd1Ref.Span,
                                        signer, allowCreate: false));
                            }
                            finally { CryptographicOperations.ZeroMemory(wrongKey); }
                        }
                        finally { CryptographicOperations.ZeroMemory(databaseKey); }
                    }
                    Assert.False(await afterPhraseDeletion
                        .HasOwnStagedPreKeyInventoryAsync());
                    Assert.Null(await afterPhraseDeletion
                        .ReadOwnStagedPreKeyPublicationAsync());
                    using (var ownInventory = prekeys.AuthorInventoryV2(
                               context, publicEvidence.Binding,
                               service, drsReference,
                               new byte[32], RandomNumberGenerator.GetBytes(32),
                               placement, 32, 9))
                    {
                        storage.FailNextInstallAfterWrite = true;
                        await Assert.ThrowsAsync<IOException>(() =>
                            afterPhraseDeletion.StageOwnInitialPreKeyInventoryAsync(
                                service, ownInventory));
                        Assert.False(await resumed.HasOwnStagedPreKeyInventoryAsync());
                        storage.FailNextTipWrite = true;
                        await Assert.ThrowsAsync<IOException>(() =>
                            afterPhraseDeletion.StageOwnInitialPreKeyInventoryAsync(
                                service, ownInventory));
                        Assert.True(await resumed.HasOwnStagedPreKeyInventoryAsync());
                        await afterPhraseDeletion.StageOwnInitialPreKeyInventoryAsync(
                            service, ownInventory);
                        var staged = await afterPhraseDeletion
                            .ReadOwnStagedPreKeyPublicationAsync();
                        Assert.NotNull(staged);
                        Assert.Equal(ownInventory.ExactXpp1.ToArray(),
                            staged.ExactXpp1.ToArray());
                        Assert.Equal(service.ExactXps1.ToArray(),
                            staged.ExactXps1.ToArray());
                        Assert.Equal(publicEvidence.Binding.DeepId.CanonicalBytes.ToArray(),
                            staged.ExactDid2.ToArray());
                        Assert.Equal(publicEvidence.Authorization.Record.CanonicalBytes.ToArray(),
                            staged.ExactDca1.ToArray());
                        var reopenedStaged = await resumed
                            .ReadOwnStagedPreKeyPublicationAsync();
                        Assert.NotNull(reopenedStaged);
                        Assert.Equal(staged.ExactXpp1.ToArray(),
                            reopenedStaged.ExactXpp1.ToArray());
                        Assert.Equal(staged.ExactXps1.ToArray(),
                            reopenedStaged.ExactXps1.ToArray());
                        Assert.Null(await resumed.ReadOwnPreKeyCommitPairAsync());
                        var exactPublication = DeepIdV2PreKeyPublicationCodec
                            .Decode(staged.ExactXpp1.Span);
                        var commitTime = new byte[8];
                        BinaryPrimitives.WriteUInt64BigEndian(commitTime,
                            1_900_000_001);
                        ParsedXic1V2 Receipt(byte replica) =>
                            DeepIdV2PreKeyCommitReceiptCodec.Decode(
                                DeepIdV2PreKeyCommitReceiptCodec.Encode(
                                    new ReadOnlyMemory<byte>[]
                                    {
                                        exactPublication.NetworkId,
                                        exactPublication.PublicationOperationId,
                                        exactPublication.Manifest.ExactHash,
                                        exactPublication.PlacementHash,
                                        Enumerable.Repeat(replica, 32).ToArray(),
                                        commitTime
                                    }, Enumerable.Repeat((byte)0xa5, 64)
                                        .ToArray()));
                        // The transport verifies signatures and live placement;
                        // this fixture isolates protected crash/replay custody.
                        var firstReceipt = Receipt(0xa1);
                        var secondReceipt = Receipt(0xa2);
                        storage.FailNextCommitWrite = true;
                        await Assert.ThrowsAsync<IOException>(() =>
                            afterPhraseDeletion
                                .RecordPreKeyCommitPairAfterVerificationAsync(
                                    staged.ExactXpp1, firstReceipt,
                                    secondReceipt));
                        Assert.Null(await resumed.ReadOwnPreKeyCommitPairAsync());
                        await afterPhraseDeletion
                            .RecordPreKeyCommitPairAfterVerificationAsync(
                                staged.ExactXpp1, firstReceipt,
                                secondReceipt);
                        var committed = await resumed
                            .ReadOwnPreKeyCommitPairAsync();
                        Assert.NotNull(committed);
                        Assert.Equal(firstReceipt.CanonicalBytes.ToArray(),
                            committed.ExactFirstXic1.ToArray());
                        Assert.Equal(secondReceipt.CanonicalBytes.ToArray(),
                            committed.ExactSecondXic1.ToArray());
                        await resumed.RecordPreKeyCommitPairAfterVerificationAsync(
                            staged.ExactXpp1, firstReceipt, secondReceipt);
                        await Assert.ThrowsAsync<CryptographicException>(() =>
                            resumed.RecordPreKeyCommitPairAfterVerificationAsync(
                                staged.ExactXpp1, firstReceipt, Receipt(0xa3)));
                    }
                    var ownedPreKeyPath = Path.Combine(directory,
                        "deep-store-v2-account.dsv2.prekeys.pkv2");
                    Assert.True(File.Exists(ownedPreKeyPath));
                    File.Delete(ownedPreKeyPath);
                    await Assert.ThrowsAsync<InvalidDataException>(() =>
                        resumed.HasOwnStagedPreKeyInventoryAsync());
                    await Assert.ThrowsAsync<InvalidDataException>(() =>
                        resumed.ReadOwnStagedPreKeyPublicationAsync());
                    await Assert.ThrowsAsync<InvalidDataException>(() =>
                        resumed.ReadOwnPreKeyCommitPairAsync());
                    var scope = new Dpk2PreKeyPersistenceScope(
                        offering.Record.NetworkId.Span,
                        offering.Record.ResponderAccountId.Span,
                        publicEvidence.Binding.Identity.Account.Certificate
                            .AccountGeneration,
                        offering.Record.ResponderDeviceId.Span,
                        offering.Record.ResponderDeviceGeneration,
                        offering.Record.ResponderDpd1Ref.Span);
                    var key = Enumerable.Repeat((byte)0x79, 32).ToArray();
                    try
                    {
                        using var protector = new Dpk2PreKeyPersistenceProtector(key);
                        var sealedSecret = offering.SealSecretForPersistence(
                            protector, scope);
                        using var restored = protector.Restore(sealedSecret,
                            offering.ExactDpk2, scope);
                        Assert.Equal(offering.ExactDpk2Hash.ToArray(),
                            restored.ExactDpk2Hash.ToArray());
                        Assert.Throws<CryptographicException>(() =>
                            protector.Restore(sealedSecret,
                                Dpk2Codec.Encode(offering.Record), scope));
                    }
                    finally { CryptographicOperations.ZeroMemory(key); }
                }
                else
                    Assert.Throws<PlatformNotSupportedException>(() =>
                        prekeys.AuthorOneTimeV2(context));
            }

            await storage.DeleteBatchAsync(
                ["deep.store.v2.resolver-read-capability"]);
            await Assert.ThrowsAnyAsync<Exception>(() =>
                resumed.GetCurrentAsync());
            await Assert.ThrowsAnyAsync<Exception>(() =>
                resumed.OpenLocalDeviceAgreementAuthorityAsync());
            await Assert.ThrowsAnyAsync<Exception>(() =>
                resumed.OpenLocalPreKeyAuthoringAuthorityAsync());

            await resumed.ResetExplicitlyAsync();
            Assert.Null(await resumed.GetCurrentAsync());
            using var v1 = await storage.ReadOwnedAsync("deep.store.v1.keep");
            Assert.NotNull(v1);
        }
        finally
        {
            foreach (var path in Directory.EnumerateFiles(directory))
                File.Delete(path);
            Directory.Delete(directory);
        }
    }

    private static bool SupportedProvider() =>
        OperatingSystem.IsWindows() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is
            (System.Runtime.InteropServices.Architecture.X64 or
             System.Runtime.InteropServices.Architecture.Arm64) ||
        OperatingSystem.IsLinux() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
            System.Runtime.InteropServices.Architecture.X64;

    private static byte[] TestReference(string magic, byte hashByte)
    {
        var reference = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(reference, 0);
        BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 1);
        reference.AsSpan(6).Fill(hashByte);
        return reference;
    }

    private static byte[] UntrustedHead(ReadOnlySpan<byte> network)
    {
        var authorityReference = new byte[38];
        "XNA1"u8.CopyTo(authorityReference);
        BinaryPrimitives.WriteUInt16BigEndian(authorityReference.AsSpan(4), 1);
        authorityReference.AsSpan(6).Fill(9);
        return AccountDirectoryAdh1Codec.Encode(new AccountDirectoryAdh1(
            network, 0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            DeepIdV2DirectorySparseMap.EmptyMapRoot.Span,
            authorityReference, Enumerable.Repeat((byte)8, 32).ToArray(),
            1, 3_601, 2,
            [new AccountDirectoryAdh1WitnessEntry(
                Enumerable.Repeat((byte)10, 32).ToArray(),
                Enumerable.Repeat((byte)11, 64).ToArray())]));
    }

    private sealed class FixedReceiptHandler(byte[] receipt) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new ByteArrayContent(receipt)
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue(
                DeepIdV2GenesisAdmissionWireCodec.ResponseMediaType);
            return Task.FromResult(response);
        }
    }

    private sealed class FaultingDeepSecureStorage : IDeepSecureStorage,
        IDisposable
    {
        private readonly InMemoryDeepSecureStorage inner = new();

        internal bool FailNextTipWrite { get; set; }
        internal bool FailNextInstallAfterWrite { get; set; }
        internal bool FailNextCommitWrite { get; set; }

        public Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected,
            ReadOnlyMemory<byte> replacement, CancellationToken ct = default) =>
            inner.CompareExchangeAsync(slot, expected, replacement, ct);

        public Task<OwnedDeepSecret?> ReadOwnedAsync(string slot,
            CancellationToken cancellationToken = default) =>
            inner.ReadOwnedAsync(slot, cancellationToken);

        public async Task WriteBatchAsync(
            IReadOnlyList<DeepSecureStorageWrite> writes,
            CancellationToken cancellationToken = default)
        {
            if (FailNextInstallAfterWrite && writes.Any(static write =>
                    write.Slot == "deep.store.v2.prekey-installed"))
            {
                FailNextInstallAfterWrite = false;
                await inner.WriteBatchAsync(writes, cancellationToken);
                throw new IOException("Injected failure after pre-key install marker.");
            }
            if (FailNextTipWrite && writes.Any(static write => write.Slot ==
                    "deep.store.v2.prekey-inventory-tip"))
            {
                FailNextTipWrite = false;
                throw new IOException("Injected failure after inventory SQL commit.");
            }
            if (FailNextCommitWrite && writes.Any(static write => write.Slot ==
                    "deep.store.v2.prekey-commit-pair-v1"))
            {
                FailNextCommitWrite = false;
                throw new IOException("Injected failure before commit pair custody.");
            }
            await inner.WriteBatchAsync(writes, cancellationToken);
        }

        public Task DeleteBatchAsync(IReadOnlyList<string> slots,
            CancellationToken cancellationToken = default) =>
            inner.DeleteBatchAsync(slots, cancellationToken);

        public Task PurgeStoreV1NamespaceAsync(
            CancellationToken cancellationToken = default) =>
            inner.PurgeStoreV1NamespaceAsync(cancellationToken);

        public Task PurgeStoreV2NamespaceAsync(
            CancellationToken cancellationToken = default) =>
            inner.PurgeStoreV2NamespaceAsync(cancellationToken);

        public void Dispose() => inner.Dispose();
    }
}
