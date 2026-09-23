using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ProtectedDeepIdV2GenesisDeviceSecretsStoreTests
{
    [Fact]
    public async Task RestoresOnlyTheVerifiedGenesisDeviceAfterAuthorityDeletion()
    {
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
            storage, network, accountId, GenesisIssuanceStoreNamespace.StoreV2);
        var issued = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, device, issuance, 1_900_000_100,
            1_900_086_500, 1_900_172_900);
        var scopeHash = System.Security.Cryptography.SHA256.HashData(
            network.Concat(accountId).ToArray());
        var issuanceScope = Convert.ToHexStringLower(scopeHash[..16]);
        using var v2Profile = await storage.ReadOwnedAsync(
            $"deep.store.v2.{issuanceScope}.dxp.profile");
        Assert.NotNull(v2Profile);
        Assert.Null(await storage.ReadOwnedAsync(
            $"deep.store.v1.{issuanceScope}.dxp.profile"));
        var verifiedDevice = issued.IssuedDevice?.Verified ??
            throw new InvalidOperationException("Device issuance did not complete.");
        var closure = ApplicationCoreVerifier.CreateIdentityClosure(
            verifiedDevice.Identity, [verifiedDevice]);
        var publicDevice = closure.ActiveDevices.Single();
        var store = new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage,
            network, accountId);
        Assert.Null(await store.ReadVerifiedAsync(publicDevice, default));
        using (var unrelatedDevice = new OwnedGenesisDeviceSecrets())
            await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(
                () => store.WriteVerifiedAsync(unrelatedDevice,
                    publicDevice, default).AsTask());
        await store.WriteVerifiedAsync(device, publicDevice, default);
        await store.WriteVerifiedAsync(device, publicDevice, default);
        device.Dispose();
        recovery.Dispose();
        phrase.Dispose();
        using var restored = await store.ReadVerifiedAsync(
            publicDevice, default);
        Assert.NotNull(restored);
        Assert.Equal(verifiedDevice.Certificate.DeviceId.ToArray(),
            restored.DeviceId.Bytes.ToArray());
        Assert.Equal(verifiedDevice.Certificate.DeviceEd25519PublicKey.ToArray(),
            restored.SigningPublicKey.Bytes.ToArray());
        Assert.Equal(verifiedDevice.Certificate.DeviceX25519PublicKey.ToArray(),
            restored.AgreementPublicKey.Bytes.ToArray());
        var otherAccountId = accountId.ToArray();
        otherAccountId[0] ^= 1;
        var wrongScopeStore = new ProtectedDeepIdV2GenesisDeviceSecretsStore(
            storage, network, otherAccountId);
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(
            () => wrongScopeStore.ReadVerifiedAsync(publicDevice,
                default).AsTask());
    }
}
