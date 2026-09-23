using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2OfflineGenesisIssuerTests
{
    [Fact]
    public async Task CreatesAndRestoresExactDID2WithoutV1Slots()
    {
        if (!SupportedProvider()) return;
        var network = Enumerable.Range(1, 16).Select(static value =>
            (byte)value).ToArray();
        using var storage = new InMemoryDeepSecureStorage();
        using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        var issuer = new DeepIdV2OfflineGenesisIssuer(storage, network, 1);
        using var created = await issuer.CreateAsync(1_900_000_000,
            verifier, default);
        var accountId = created.AccountId.ToArray();
        var exactDid2 = created.Verified.PublicEvidence.Binding.DeepId
            .CanonicalBytes.ToArray();
        var exactDab2 = created.Verified.PublicEvidence.Binding.Record
            .CanonicalBytes.ToArray();
        var issuanceScope = Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(
                network.Concat(accountId).ToArray())[..16]);
        using var v2Profile = await storage.ReadOwnedAsync(
            $"deep.store.v2.{issuanceScope}.dxp.profile");
        Assert.NotNull(v2Profile);
        Assert.Null(await storage.ReadOwnedAsync(
            $"deep.store.v1.{issuanceScope}.dxp.profile"));

        var bootstrap = new ProtectedDeepIdV2GenesisBootstrap(storage,
            network, accountId);
        using (var fromNewBootstrapInstance = await bootstrap.ReadVerifiedAsync(
            1_900_000_003, 1, verifier, default))
        {
            Assert.NotNull(fromNewBootstrapInstance);
            Assert.Equal(exactDid2, fromNewBootstrapInstance.PublicEvidence.Binding.DeepId
                .CanonicalBytes.ToArray());
            Assert.Equal(exactDab2, fromNewBootstrapInstance.PublicEvidence.Binding.Record
                .CanonicalBytes.ToArray());
        }
        var phraseStore = new ProtectedDeepIdV2RecoveryPhraseStore(storage,
            network, accountId);
        using (var retained = await phraseStore.ReadVerifiedAsync(default))
            Assert.NotNull(retained);
        await phraseStore.DeleteAfterVerifiedBootstrapAsync(
            1_900_000_003, 1, verifier, default);
        Assert.Null(await phraseStore.ReadVerifiedAsync(default));
        using var afterDeletion = await bootstrap.ReadVerifiedAsync(
            1_900_000_003, 1, verifier, default);
        Assert.Equal(exactDab2, afterDeletion!.PublicEvidence.Binding.Record
            .CanonicalBytes.ToArray());
    }

    private static bool SupportedProvider() =>
        OperatingSystem.IsWindows() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is
            (System.Runtime.InteropServices.Architecture.X64 or
             System.Runtime.InteropServices.Architecture.Arm64) ||
        OperatingSystem.IsLinux() &&
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
            System.Runtime.InteropServices.Architecture.X64;
}
