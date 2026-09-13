using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Tests.Services;

public sealed class DeepGenesisDeviceActivationTests
{
    private static readonly byte[] Network =
        Convert.FromHexString("edc5dc1516a847a65fc8ba0e690d000d");
    private static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(1_900_000_000);

    [Fact]
    public async Task ActivatedIdentity_RestoresAfterRetainedPhraseIsDeleted()
    {
        var accountStore = new InMemoryDeepAccountStore();
        var secureStorage = new InMemoryDeepSecureStorage();
        var accounts = Service(accountStore, secureStorage);
        var created = await accounts.CreateAsync("Alice");

        var first = await accounts.EnsureGenesisDeviceActivatedAsync();
        await accounts.DeleteRetainedRecoveryPhraseAsync();
        Assert.False(await accounts.HasRetainedRecoveryPhraseAsync());

        var restarted = Service(accountStore, secureStorage);
        var restored = await restarted.EnsureGenesisDeviceActivatedAsync();
        var restoredIdentity = await restarted.GetLocalIdentityAsync();
        using var agreement = await restarted.OpenCurrentDeviceAgreementAuthorityAsync(
            restoredIdentity!, restored.VerifiedDevice);

        Assert.Equal(
            created.Identity.Device.DeviceId.Bytes.ToArray(),
            restored.VerifiedDevice.Certificate.DeviceId.ToArray());
        Assert.Equal(
            first.VerifiedDevice.Certificate.CanonicalHash.ToArray(),
            restored.VerifiedDevice.Certificate.CanonicalHash.ToArray());
        Assert.Equal(
            first.CurrentDirectory.Head.Record.RecordHash.ToArray(),
            restored.CurrentDirectory.Head.Record.RecordHash.ToArray());
        Assert.Equal(
            first.AddressBinding.Head.Record.RecordHash.ToArray(),
            restored.AddressBinding.Head.Record.RecordHash.ToArray());
        Assert.Equal(
            first.ContactPublicationAuthorization.Verified.Record.RecordHash.ToArray(),
            restored.ContactPublicationAuthorization.Verified.Record.RecordHash.ToArray());
        Assert.Equal(
            AccountDirectoryAdc1Codec.Encode(first.DirectoryCheckpoint.Checkpoint),
            AccountDirectoryAdc1Codec.Encode(restored.DirectoryCheckpoint.Checkpoint));
        Assert.Equal(1UL, restored.CurrentDirectory.Head.Record.DirectoryGeneration);
        Assert.Equal(0UL, restored.AddressBinding.Head.Record.BindingGeneration);
        Assert.Equal(
            restored.VerifiedDevice.Certificate.CanonicalHash.ToArray(),
            agreement.ExactDpd1Hash.ToArray());
        Assert.Equal(ApplicationLineageDisposition.AcceptedGenesis,
            ApplicationCoreVerifier.StartDmd1Lineage(restored.CurrentDirectory.Head).Disposition);
    }

    [Fact]
    public async Task DeleteBeforeExplicitActivation_CompletesDurableActivationFirst()
    {
        var accountStore = new InMemoryDeepAccountStore();
        var secureStorage = new InMemoryDeepSecureStorage();
        var accounts = Service(accountStore, secureStorage);
        await accounts.CreateAsync("Alice");
        await accounts.DeleteRetainedRecoveryPhraseAsync();

        Assert.False(await accounts.HasRetainedRecoveryPhraseAsync());
        var restored = await Service(accountStore, secureStorage)
            .EnsureGenesisDeviceActivatedAsync();
        Assert.Equal(1UL, restored.CurrentDirectory.Head.Record.DirectoryGeneration);
    }

    [Fact]
    public async Task GenesisAdmissionRequest_IsDeterministicAndIndependentlyVerifiable()
    {
        var accounts = Service(
            new InMemoryDeepAccountStore(),
            new InMemoryDeepSecureStorage());
        await accounts.CreateAsync("Alice");
        var activation = await accounts.EnsureGenesisDeviceActivatedAsync();

        var first = AccountDirectoryGenesisAdmissionClient.CreateRequest(activation);
        var second = AccountDirectoryGenesisAdmissionClient.CreateRequest(activation);
        var exact = AccountDirectoryGenesisAdmissionWireCodec.EncodeRequest(first);
        var decoded = AccountDirectoryGenesisAdmissionWireCodec.DecodeRequest(exact);
        var verified = AccountDirectoryGenesisAdmissionVerifier.Verify(
            decoded.Admission,
            (ulong)Now.ToUnixTimeSeconds(),
            deploymentProfileId: 1,
            supportedReader: 1);

        Assert.Equal(first.OperationId.ToArray(), second.OperationId.ToArray());
        Assert.False(first.OperationId.Span.SequenceEqual(new byte[32]));
        Assert.Equal(
            AccountDirectoryAdc1Codec.Encode(activation.DirectoryCheckpoint.Checkpoint),
            AccountDirectoryAdc1Codec.Encode(verified.Checkpoint));
        Assert.Equal(
            activation.DirectoryCheckpoint.Checkpoint.DirectoryLeafKey.ToArray(),
            verified.Checkpoint.DirectoryLeafKey.ToArray());
    }

    private static DeepAccountService Service(
        IDeepAccountStore accountStore,
        IDeepSecureStorage secureStorage) =>
        new(accountStore, secureStorage, new FrozenClock(Now), Network);
}
