using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2PreKeyPublicationTransportTests
{
    [Fact]
    public void StageAcknowledgement_AcceptsOnlyExactDurableSuccess()
    {
        DeepIdV2PreKeyPublicationTransport.EnsureStaged([1]);
        DeepIdV2PreKeyPublicationTransport.EnsureStaged([3]);

        foreach (var rejected in new byte[][]
                 { [], [0], [2], [4], [1, 3], [3, 0] })
            Assert.Throws<CryptographicException>(() =>
                DeepIdV2PreKeyPublicationTransport.EnsureStaged(rejected));
    }
}
