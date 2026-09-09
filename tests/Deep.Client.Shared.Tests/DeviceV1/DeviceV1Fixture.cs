using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Protocol.DeepNative;
using System.Buffers.Binary;

namespace Deep.Client.Shared.Tests.DeviceV1;

internal static class DeviceV1Fixture
{
    internal static byte[] Bytes(int length, byte marker) =>
        Enumerable.Range(0, length).Select(i => unchecked((byte)(marker + i))).ToArray();
    internal static DeviceAccountId32 Account(byte marker = 0x10) => DeviceAccountId32.FromBytes(Bytes(32, marker));
    internal static DeviceIdentifier32 Device(byte marker) => DeviceIdentifier32.FromBytes(Bytes(32, marker));
    internal static DeviceOperationId32 Operation(byte marker) => DeviceOperationId32.FromBytes(Bytes(32, marker));
    internal static LogicalMessageId32 Message(byte marker) => LogicalMessageId32.FromBytes(Bytes(32, marker));
    internal static VerifiedActiveDeviceFacts Active(byte device, byte certificate) =>
        new(Device(device), DeviceCertificateHash32.FromBytes(Bytes(32, certificate)));
    internal static VerifiedDeviceDirectoryFacts Directory(ulong generation, byte hash, byte drsHash,
        IEnumerable<VerifiedActiveDeviceFacts> active, DeviceDirectoryHash32? predecessor = null,
        ulong drsRevision = 1, DeviceAccountId32? account = null, ulong accountGeneration = 1) =>
        VerifiedDeviceDirectoryFacts.RestorePersisted(account ?? Account(), accountGeneration, generation,
            DeviceDirectoryHash32.FromBytes(Bytes(32, hash)), predecessor?.ToArray() ?? new byte[32],
            drsRevision, DeviceRevocationHash32.FromBytes(Bytes(32, drsHash)), active);
    internal static VerifiedEnrollmentDeviceFacts Enrollment(byte device, byte certificate, byte drsHash = 0x60,
        ulong drsRevision = 1, ulong accountGeneration = 1) =>
        VerifiedEnrollmentDeviceFacts.RestorePersisted(Account(), accountGeneration, drsRevision,
            DeviceRevocationHash32.FromBytes(Bytes(32, drsHash)), Device(device),
            DeviceCertificateHash32.FromBytes(Bytes(32, certificate)));
    internal static DeviceRevocationPlaneOperations Planes(byte start = 0x90) =>
        new(Operation(start), Operation((byte)(start + 1)), Operation((byte)(start + 2)),
            Operation((byte)(start + 3)), Operation((byte)(start + 4)), Operation((byte)(start + 5)));
    internal static DeviceContactWorkItemId32 Contact(byte marker) =>
        DeviceContactWorkItemId32.FromBytes(Bytes(32, marker));
    internal static DeviceGroupWorkItemId32 Group(byte marker) =>
        DeviceGroupWorkItemId32.FromBytes(Bytes(32, marker));
    internal static DeviceLocalRevocationFloorEntry Floor(DeviceIdentifier32 device,
        DeviceOperationId32? saga = null) => new(Account(), 1, device, DpdReference(0xA0), 1,
            DeviceRevocationHash32.FromBytes(Bytes(32, 0x60)), 2,
            DeviceRevocationHash32.FromBytes(Bytes(32, 0x61)), saga ?? Operation(0x88));

    internal static DeviceMutationIntent RevokeIntent(DeviceDirectoryState current,
        DeviceIdentifier32 revoked, VerifiedDeviceDirectoryFacts successor, byte planeStart = 0x90)
    {
        var commitment = DeviceRevocationCommitment.RestorePersisted(Account(), 1, revoked,
            DpdReference(0xA0), current.Head.RevocationRevision, current.Head.RevocationHash,
            successor.RevocationRevision, successor.RevocationHash, successor, Bytes(32, 0xB0), Bytes(32, 0xB1));
        return DeviceMutationIntent.RestorePersisted(DeviceMutationKind.Revoke, Account(), 1,
            current.Head.DirectoryGeneration, current.Head.DirectoryHash, null, commitment, null,
            Planes(planeStart), [Contact(0xC0), Contact(0xC1)], [Group(0xD0)], successor.ActiveDevices);
    }

    internal static byte[] DpdReference(byte marker)
    {
        var result = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(result, (ushort)ArtifactType.Dpd1);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(2), 776);
        Bytes(32, marker).CopyTo(result, 6);
        return result;
    }

    internal static async Task<DeviceAccountStateSnapshot> BootstrapAsync(IDeviceStateStore store,
        VerifiedDeviceDirectoryFacts genesis, byte operation = 0x80)
    {
        var result = await store.CommitAsync(DeviceTransactionPlan.Bootstrap(Operation(operation), genesis),
            CancellationToken.None);
        Assert.Equal(DeviceCommitDisposition.Applied, result.Disposition);
        return Assert.IsType<DeviceAccountStateSnapshot>(result.Snapshot);
    }

    internal static async Task<(DeviceAccountStateSnapshot State, DeviceOperationId32 Saga, DeviceIdentifier32 Revoked)>
        CommitFloorAsync(IDeviceStateStore store)
    {
        var a = Active(0x20, 0x50); var b = Active(0x21, 0x51);
        var genesis = Directory(1, 0x40, 0x60, [a, b]);
        var current = await BootstrapAsync(store, genesis);
        var successor = Directory(2, 0x41, 0x61, [a], genesis.DirectoryHash, 2);
        var saga = Operation(0x89); var intent = RevokeIntent(current.Directory, b.DeviceId, successor);
        var prepared = await store.CommitAsync(DeviceTransactionPlan.PrepareRevocation(current,
            Operation(0x81), saga, intent), CancellationToken.None);
        var floor = await store.CommitAsync(DeviceTransactionPlan.CommitRevocationFloor(prepared.Snapshot!,
            Operation(0x82), saga), CancellationToken.None);
        Assert.Equal(DeviceCommitDisposition.Applied, floor.Disposition);
        return (floor.Snapshot!, saga, b.DeviceId);
    }
}
