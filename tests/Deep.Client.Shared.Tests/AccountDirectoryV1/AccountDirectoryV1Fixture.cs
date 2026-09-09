using Deep.Client.Shared.Domain.AccountDirectoryV1;
using Deep.Client.Shared.Services.AccountDirectoryV1;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Client.Shared.Tests.AccountDirectoryV1;

internal static class AccountDirectoryV1Fixture
{
    internal static byte[] Bytes(int length, byte marker) => Enumerable.Repeat(marker, length).ToArray();
    internal static AccountDirectoryLeafKey32 Leaf(byte marker = 0x31) => AccountDirectoryLeafKey32.FromBytes(Bytes(32, marker));
    internal static AccountDirectoryAuthorizationId32 Authorization(byte marker = 0x41) => AccountDirectoryAuthorizationId32.FromBytes(Bytes(32, marker));
    internal static AccountDirectoryDeviceId32 Device(byte marker = 0x51) => AccountDirectoryDeviceId32.FromBytes(Bytes(32, marker));

    internal static AccountDirectoryProtectedLkgState Lkg(ulong generation = 1, ulong treeSize = 1,
        byte hashMarker = 0x61, byte networkMarker = 0x11) => AccountDirectoryProtectedLkgState.RestorePersisted(
            ExactAdh(generation, treeSize, networkMarker), Bytes(32, hashMarker), generation, treeSize);

    internal static AccountDirectorySubjectState Subject(AccountDirectoryClientState state = AccountDirectoryClientState.Current,
        AccountDirectoryRefreshReason reason = AccountDirectoryRefreshReason.None, byte leafMarker = 0x31,
        byte authorizationMarker = 0x41, byte deviceMarker = 0x51, ulong accountGeneration = 1,
        ulong directoryGeneration = 1, ulong sample = 100, ulong deadline = 200) => new(
            Leaf(leafMarker), state, reason, AdcReference(0x71), accountGeneration, directoryGeneration,
            Bytes(16, 0x21), sample, deadline, Authorization(authorizationMarker), Device(deviceMarker));

    internal static AccountDirectoryVerifiedUpdate Update(AccountDirectoryProtectedLkgState next,
        AccountDirectorySubjectState? subject = null, AccountDirectoryProtectedLkgState? caller = null) => new(
            next, subject ?? Subject(), caller is not null, caller?.TreeSize ?? 0,
            caller is null ? new byte[32] : caller.CoreHash.ToArray());

    internal static AccountDirectoryStateSnapshot Snapshot(ulong revision = 1,
        AccountDirectoryProtectedLkgState? lkg = null, bool fork = false,
        params AccountDirectorySubjectState[] subjects) => new(revision, lkg ?? Lkg(), fork,
            subjects.Length == 0 ? [Subject(fork ? AccountDirectoryClientState.DirectoryForkBlocked : AccountDirectoryClientState.Current)] : subjects);

    private static byte[] ExactAdh(ulong generation, ulong treeSize, byte networkMarker)
    {
        var predecessor = generation == 0 ? new byte[32] : Bytes(32, 0x81);
        var reference = new byte[38]; "XNA1"u8.CopyTo(reference); reference[5] = 1; Bytes(32, 0x91).CopyTo(reference, 6);
        return AccountDirectoryAdh1Codec.Encode(new AccountDirectoryAdh1(Bytes(16, networkMarker), generation,
            predecessor, treeSize, Bytes(32, 0xA1), Bytes(32, 0xA2), reference, Bytes(32, 0xA3),
            1_000, 2_000, 1, [new AccountDirectoryAdh1WitnessEntry(Bytes(32, 0xB1), Bytes(64, 0xB2))]));
    }

    private static byte[] AdcReference(byte marker)
    {
        var value = new byte[38]; "ADC1"u8.CopyTo(value); value[5] = 1; Bytes(32, marker).CopyTo(value, 6); return value;
    }
}
