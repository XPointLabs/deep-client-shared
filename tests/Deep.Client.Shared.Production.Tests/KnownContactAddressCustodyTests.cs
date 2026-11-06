using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Production.Tests;

public sealed class KnownContactAddressCustodyTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void ScopedCanonicalAddressBookRejectsUnknownScopeTrailingDataAndTruncation(int fault)
    {
        var network = Enumerable.Repeat((byte)1, 16).ToArray();
        var account = Enumerable.Repeat((byte)2, 32).ToArray();
        var instance = Enumerable.Repeat((byte)3, 32).ToArray();
        var capability = Enumerable.Repeat((byte)4, 16).ToArray();
        var address = DeepPermanentIdV2.FromCredential(DeepIdV2Codec.AuthorDid2(
            account, Enumerable.Repeat((byte)5, 1952).ToArray(), capability), capability);
        var exact = ProtectedKnownContactAddresses.Encode(new Dictionary<string, DeepPermanentIdV2>
            { [new string('a', 64)] = address }, network, account, instance);
        Assert.Equal(address, Assert.Single(ProtectedKnownContactAddresses.Decode(exact, network, account, instance)).Value);
        switch (fault)
        {
            case 0: exact[0] = 2; break;
            case 1: exact[4] ^= 1; break;
            case 2: exact[52] ^= 1; break;
            case 3: exact = [.. exact, 0]; break;
            default: exact = exact[..^1]; break;
        }
        Assert.Throws<InvalidDataException>(() => ProtectedKnownContactAddresses.Decode(exact, network, account, instance));
    }
}
