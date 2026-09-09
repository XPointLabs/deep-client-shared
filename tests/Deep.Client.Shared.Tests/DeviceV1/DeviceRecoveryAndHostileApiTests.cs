using System.Reflection;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Protocol.Identity.DeviceV1;

namespace Deep.Client.Shared.Tests.DeviceV1;

public sealed class DeviceRecoveryAndHostileApiTests
{
    [Fact]
    public void ReturningAndPhraseRecovery_AreExplicitAndNeverCloneSecrets()
    {
        var returning = DeviceRecoveryIntent.ReturningDevice(DeviceV1Fixture.Account(), 1,
            DeviceV1Fixture.Device(0x20));
        var phrase = DeviceRecoveryIntent.FromPhrase(DeviceV1Fixture.Account(), 1,
            DeviceV1Fixture.Device(0x21));
        Assert.Equal(DeviceRecoveryOutcome.ReturningDeviceLocalStateRequired, returning.Outcome);
        Assert.False(returning.CreatesNewDevice);
        Assert.Equal(DeviceRecoveryOutcome.NewDeviceWithoutHistory, phrase.Outcome);
        Assert.True(phrase.CreatesNewDevice);
        Assert.False(returning.ClonesPrivateKeysOrRatchetDatabase);
        Assert.False(phrase.ClonesPrivateKeysOrRatchetDatabase);
    }

    [Fact]
    public void PublicHistoryApi_CannotElevateBoolOrBareHash()
    {
        var publicMethods = typeof(DeviceRecoveryIntent).GetMethods(BindingFlags.Public | BindingFlags.Static);
        Assert.DoesNotContain(publicMethods.SelectMany(static m => m.GetParameters()),
            static p => p.ParameterType == typeof(bool) || p.ParameterType == typeof(byte[])
                || p.ParameterType == typeof(ReadOnlyMemory<byte>));
        var backup = Assert.Single(publicMethods, static m => m.Name == nameof(DeviceRecoveryIntent.FromPhrase)
            && m.GetParameters().Length == 1);
        Assert.Equal(typeof(VerifiedDeviceBackupAuthorization), backup.GetParameters()[0].ParameterType);
        Assert.All(typeof(VerifiedDeviceBackupAuthorization).GetConstructors(),
            static constructor => Assert.False(constructor.IsPublic));
        Assert.All(typeof(VerifiedDeviceHistoryTransferAuthorization).GetConstructors(),
            static constructor => Assert.False(constructor.IsPublic));
    }

    [Fact]
    public void PublicDeviceData_ContainsNoPrivateKeyOrRatchetPayload()
    {
        var exposed = new[] { typeof(DeviceRecoveryIntent), typeof(DeviceMutationIntent),
            typeof(DeviceHistoryDecisionSnapshot) };
        Assert.DoesNotContain(exposed.SelectMany(static t => t.GetProperties(BindingFlags.Public | BindingFlags.Instance)),
            static property => property.PropertyType != typeof(bool)
                && (property.Name.Contains("PrivateKey", StringComparison.OrdinalIgnoreCase)
                    || property.Name.Contains("Ratchet", StringComparison.OrdinalIgnoreCase)));
        Assert.False(DeviceRecoveryIntent.FromPhrase(DeviceV1Fixture.Account(), 1,
            DeviceV1Fixture.Device(0x22)).ClonesPrivateKeysOrRatchetDatabase);
    }

    [Fact]
    public void TransactionFingerprint_BindsRecoveryModeOutcomeSourceAndBackup()
    {
        var active = DeviceV1Fixture.Active(0x20, 0x50);
        var head = DeviceV1Fixture.Directory(1, 0x40, 0x60, [active]);
        var state = new DeviceAccountStateSnapshot(1, DeviceDirectoryState.Start(head).Next, []);
        var enrollment = DeviceV1Fixture.Enrollment(0x21, 0x51);
        var successor = DeviceV1Fixture.Directory(2, 0x41, 0x60,
            [active, DeviceV1Fixture.Active(0x21, 0x51)], head.DirectoryHash);
        var phrase = DeviceRecoveryIntent.FromPhrase(DeviceV1Fixture.Account(), 1, enrollment.DeviceId);
        var backup = DeviceRecoveryIntent.RestorePersisted(DeviceRecoveryMode.PhraseCreatesNewDevice,
            DeviceRecoveryOutcome.NewDeviceWithEncryptedBackup, DeviceV1Fixture.Account(), 1,
            enrollment.DeviceId, null, DeviceHistoryPolicy.AuthenticatedEncryptedBackup,
            DeviceV1Fixture.Bytes(32, 0x70));
        var transfer = DeviceRecoveryIntent.RestorePersisted(DeviceRecoveryMode.ExistingDeviceEnrollsNewDevice,
            DeviceRecoveryOutcome.NewDeviceWithEncryptedTransfer, DeviceV1Fixture.Account(), 1,
            enrollment.DeviceId, active.DeviceId, DeviceHistoryPolicy.AuthenticatedEncryptedDeviceTransfer, null);
        string Fingerprint(DeviceRecoveryIntent recovery)
        {
            var intent = DeviceMutationIntent.RestorePersisted(DeviceMutationKind.Enroll,
                DeviceV1Fixture.Account(), 1, 1, head.DirectoryHash, enrollment, null, recovery, null,
                [], [], successor.ActiveDevices);
            return DeviceTransactionPlan.CommitEnrollment(state, DeviceV1Fixture.Operation(0x90),
                intent, successor).Fingerprint();
        }
        Assert.Equal(3, new[] { Fingerprint(phrase), Fingerprint(backup), Fingerprint(transfer) }.Distinct().Count());
    }
}
