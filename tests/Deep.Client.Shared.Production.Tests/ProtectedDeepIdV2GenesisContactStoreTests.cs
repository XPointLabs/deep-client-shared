using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ProtectedDeepIdV2GenesisContactStoreTests
{
    [Fact]
    public async Task VerifiedPqGenesisIsImmutableAndRestoresExactHedgedBinding()
    {
        if (!SupportedProvider()) return;
        var network = Enumerable.Range(1, 16).Select(static value =>
            (byte)value).ToArray();
        using var phrase = DeepRecoveryV1.Generate();
        using var recovery = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase, network, 1);
        using var storage = new InMemoryDeepSecureStorage();
        using var device = new OwnedGenesisDeviceSecrets();
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000, 1);
        var accountId = account.AccountIdentity.AccountId.Bytes.ToArray();
        var issuance = new ProtectedGenesisDeviceIssuancePersistence(
            storage, network, accountId);
        var issued = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, device, issuance, 1_900_000_100,
            1_900_086_500, 1_900_172_900);
        var verifiedDevice = issued.IssuedDevice?.Verified ??
            throw new InvalidOperationException("Device issuance did not complete.");
        var closure = ApplicationCoreVerifier.CreateIdentityClosure(
            verifiedDevice.Identity, [verifiedDevice]);
        var binding = recovery.AuthorGenesisDab2(phrase, closure, 1);
        var directory = recovery.AuthorGenesisDmd1(closure, 1_900_000_200);
        var authorization = recovery.AuthorGenesisDca1V2(binding,
            directory, verifiedDevice, 1_900_000_300);
        var checkpoint = recovery.AuthorGenesisAdc1V2(binding, directory,
            1_900_000_300);
        var store = new ProtectedDeepIdV2GenesisContactStore(storage,
            network, accountId);

        Assert.Null(await store.ReadUntrustedAsync(default));
        await store.WriteVerifiedAsync(binding.Head, authorization,
            checkpoint, default);
        await store.WriteVerifiedAsync(binding.Head, authorization,
            checkpoint, default);
        var restored = await store.ReadUntrustedAsync(default);
        Assert.NotNull(restored);
        Assert.Equal(account.CanonicalDpa1.ToArray(),
            restored.ExactDpa1.ToArray());
        Assert.Equal(account.CanonicalDrs1.ToArray(),
            restored.ExactDrs1.ToArray());
        Assert.Equal(verifiedDevice.Certificate.CanonicalBytes.ToArray(),
            restored.ExactDpd1.ToArray());
        Assert.Equal(directory.Head.Record.CanonicalBytes.ToArray(),
            restored.ExactDmd1.ToArray());
        Assert.Equal(binding.Head.DeepId.CanonicalBytes.ToArray(),
            restored.ExactDid2.ToArray());
        Assert.Equal(binding.Head.Record.CanonicalBytes.ToArray(),
            restored.ExactDab2.ToArray());
        Assert.Equal(authorization.Record.CanonicalBytes.ToArray(),
            restored.ExactDca1V2.ToArray());
        Assert.Equal(checkpoint.Checkpoint.CanonicalBytes.ToArray(),
            restored.ExactAdc1V2.ToArray());
        using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        var verifiedRestore = await store.ReadVerifiedAsync(1_900_000_300, 1,
            verifier, default);
        Assert.NotNull(verifiedRestore);
        Assert.Equal(binding.Head.Record.CanonicalBytes.ToArray(),
            verifiedRestore.Binding.Record.CanonicalBytes.ToArray());
        Assert.Equal(checkpoint.Checkpoint.CanonicalBytes.ToArray(),
            verifiedRestore.Checkpoint.Checkpoint.CanonicalBytes.ToArray());
        var otherAccountId = accountId.ToArray();
        otherAccountId[0] ^= 1;
        Assert.Null(await new ProtectedDeepIdV2GenesisContactStore(storage,
            network, otherAccountId).ReadUntrustedAsync(default));
        var otherNetwork = network.ToArray();
        otherNetwork[0] ^= 1;
        Assert.Null(await new ProtectedDeepIdV2GenesisContactStore(storage,
            otherNetwork, accountId).ReadUntrustedAsync(default));
        using var original = await storage.ReadOwnedAsync(
            ContactSlot(network, accountId));
        Assert.NotNull(original);
        var copiedRecord = new byte[original.Length];
        original.CopyTo(copiedRecord);
        using var wrongScopeStorage = new InMemoryDeepSecureStorage();
        await wrongScopeStorage.WriteBatchAsync(
            [new DeepSecureStorageWrite(
                ContactSlot(otherNetwork, accountId), copiedRecord)]);
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(
            () => new ProtectedDeepIdV2GenesisContactStore(wrongScopeStorage,
                otherNetwork, accountId).ReadVerifiedAsync(1_900_000_300, 1,
                verifier, default).AsTask());

        var otherBinding = recovery.AuthorGenesisDab2(phrase, closure, 1);
        Assert.NotEqual(binding.Head.Record.CanonicalBytes.ToArray(),
            otherBinding.Head.Record.CanonicalBytes.ToArray());
        var otherAuthorization = recovery.AuthorGenesisDca1V2(otherBinding,
            directory, verifiedDevice, 1_900_000_300);
        var otherCheckpoint = recovery.AuthorGenesisAdc1V2(otherBinding,
            directory, 1_900_000_300);
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(
            () => store.WriteVerifiedAsync(otherBinding.Head,
                otherAuthorization, otherCheckpoint, default).AsTask());
        Assert.Equal(binding.Head.Record.CanonicalBytes.ToArray(),
            (await store.ReadUntrustedAsync(default))!.ExactDab2.ToArray());
        var bootstrap = new ProtectedDeepIdV2GenesisBootstrap(storage,
            network, accountId);
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(
            () => bootstrap.ReadVerifiedAsync(1_900_000_300, 1,
                verifier, default).AsTask());
        using (var completed = await bootstrap.CommitAsync(device, binding.Head,
            authorization, checkpoint, 1_900_000_300, 1, verifier, default))
            Assert.Equal(binding.Head.Record.CanonicalBytes.ToArray(),
                completed.PublicEvidence.Binding.Record.CanonicalBytes.ToArray());
        using var secretFirstStorage = new InMemoryDeepSecureStorage();
        var secretFirstStore = new ProtectedDeepIdV2GenesisDeviceSecretsStore(
            secretFirstStorage, network, accountId);
        await secretFirstStore.WriteVerifiedAsync(device,
            closure.ActiveDevices.Single(), default);
        var secretFirstBootstrap = new ProtectedDeepIdV2GenesisBootstrap(
            secretFirstStorage, network, accountId);
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(
            () => secretFirstBootstrap.ReadVerifiedAsync(1_900_000_300, 1,
                verifier, default).AsTask());
        using (var completed = await secretFirstBootstrap.CommitAsync(device,
            binding.Head, authorization, checkpoint, 1_900_000_300, 1,
            verifier, default))
            Assert.Equal(binding.Head.Record.CanonicalBytes.ToArray(),
                completed.PublicEvidence.Binding.Record.CanonicalBytes.ToArray());
        recovery.Dispose();
        phrase.Dispose();
        using var afterAuthorityDeletion = await bootstrap.ReadVerifiedAsync(
            1_900_000_300, 1, verifier, default);
        Assert.Equal(binding.Head.Record.CanonicalBytes.ToArray(),
            afterAuthorityDeletion!.PublicEvidence.Binding.Record.CanonicalBytes.ToArray());
    }

    [Fact]
    public async Task MalformedV2RecordNeverRestoresAsContactEvidence()
    {
        using var storage = new InMemoryDeepSecureStorage();
        var network = Enumerable.Repeat((byte)1, 16).ToArray();
        var accountId = Enumerable.Repeat((byte)2, 32).ToArray();
        await storage.WriteBatchAsync(
            [new DeepSecureStorageWrite(ContactSlot(network, accountId),
                "DGC1"u8.ToArray())]);
        var store = new ProtectedDeepIdV2GenesisContactStore(storage,
            network, accountId);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => store.ReadUntrustedAsync(default).AsTask());
    }

    private static string ContactSlot(byte[] network, byte[] accountId) =>
        "deep.store.v2." + Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(
                network.Concat(accountId).ToArray())) + ".genesis-contact";

    private static bool SupportedProvider() =>
        OperatingSystem.IsWindows() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is
            (System.Runtime.InteropServices.Architecture.X64 or
             System.Runtime.InteropServices.Architecture.Arm64) ||
        OperatingSystem.IsLinux() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
            System.Runtime.InteropServices.Architecture.X64;
}
