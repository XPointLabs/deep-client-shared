using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.Persistence.DeviceV1;

public sealed class ProtectedGenesisDeviceIssuancePersistenceTests
{
    private const string Mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    private static readonly byte[] Network =
        Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray();

    [Fact]
    public async Task VerifiedGenesisDevice_RestoresAfterRecoveryAuthorityIsGone()
    {
        using var storage = new InMemoryDeepSecureStorage();
        using var device = new OwnedGenesisDeviceSecrets();
        byte[] dpa;
        byte[] drs;
        byte[] dpd;
        byte[] accountId;
        using (var recovery = Recovery())
        {
            var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
                recovery, 1_900_000_000);
            dpa = account.CanonicalDpa1.ToArray();
            drs = account.CanonicalDrs1.ToArray();
            accountId = recovery.AccountIdentity.AccountId.Bytes.ToArray();
            var issued = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                recovery,
                account,
                device,
                new ProtectedGenesisDeviceIssuancePersistence(storage, Network, accountId),
                1_900_000_100,
                1_934_560_100,
                1_943_200_100);
            dpd = issued.IssuedDevice!.CanonicalDpd1.ToArray();
        }

        var restored = await Dnp1IdentityAuthoringV1.RestoreGenesisDeviceAsync(
            dpa,
            drs,
            device,
            new ProtectedGenesisDeviceIssuancePersistence(storage, Network, accountId),
            1_900_000_200);

        Assert.Equal(dpd, restored.IssuedDevice!.CanonicalDpd1.ToArray());
        Assert.Equal(2UL, restored.IssuedDevice.DurableReceipt.SourceRevision);
        Assert.Equal(1UL, restored.IssuedDevice.SubjectCasReceipt.SubjectRevision);
    }

    [Fact]
    public async Task ExistingSubject_RejectsAChangedDeviceSecretOwner()
    {
        using var storage = new InMemoryDeepSecureStorage();
        using var recovery = Recovery();
        using var firstDevice = new OwnedGenesisDeviceSecrets();
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, 1_900_000_000);
        var accountId = recovery.AccountIdentity.AccountId.Bytes.ToArray();
        var persistence = new ProtectedGenesisDeviceIssuancePersistence(
            storage, Network, accountId);
        await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery,
            account,
            firstDevice,
            persistence,
            1_900_000_100,
            1_934_560_100,
            1_943_200_100);

        using var changedDevice = new OwnedGenesisDeviceSecrets();
        await Assert.ThrowsAsync<Deep.Protocol.DeepNative.RecordException>(async () =>
            await Dnp1IdentityAuthoringV1.RestoreGenesisDeviceAsync(
                account.CanonicalDpa1,
                account.CanonicalDrs1,
                changedDevice,
                new ProtectedGenesisDeviceIssuancePersistence(storage, Network, accountId),
                1_900_000_200));
    }

    private static DeepRecoveryAccountCapabilities Recovery()
    {
        var bytes = Encoding.ASCII.GetBytes(Mnemonic);
        try
        {
            using var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(bytes);
            return DeepRecoveryV1.DeriveAccountCapabilities(phrase, Network, 1);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
