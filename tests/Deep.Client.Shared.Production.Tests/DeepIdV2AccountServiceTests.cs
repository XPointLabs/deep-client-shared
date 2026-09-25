using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2AccountServiceTests
{
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
            using var storage = new InMemoryDeepSecureStorage();
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
                    using var offering = prekeys.AuthorOneTime(context);
                    Assert.Equal(firstDeviceId,
                        offering.Record.ResponderDeviceId.ToArray());
                    Assert.Equal(32, offering.ExactDpk2Hash.Length);
                }
                else
                    Assert.Throws<PlatformNotSupportedException>(() =>
                        prekeys.AuthorOneTime(context));
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
}
