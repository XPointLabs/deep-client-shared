using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

// Pure guard equivalence, not signed time, custody, or device evidence.
public sealed class CurrentClaimReadTimeTests
{
    [Fact]
    public void ClosedReasonsPreserveAllFormerBoundaryDecisions()
    {
        byte[] first = [1, 2], second = [1, 3];
        foreach (var sample in new ulong[] { 0, 1, 2, ulong.MaxValue })
        foreach (var fresh in new ulong[] { 0, 1, 2, ulong.MaxValue })
        foreach (var sameBoot in new[] { false, true })
        foreach (var issued in new ulong[] { 0, 1, 2, ulong.MaxValue })
        foreach (var expires in new ulong[] { 0, 1, 2, ulong.MaxValue })
        {
            var boot = sameBoot ? first : second;
            var expected = sample < fresh || !sameBoot || issued > 1UL || expires <= 2UL;
            var error = Record.Exception(() => ProtectedDeepIdV2AccountOwner.RequireCurrentClaimRead(
                sample, first, fresh, boot, issued, expires, 1, 2));
            if (!expected) Assert.Null(error);
            else Assert.IsType<CryptographicException>(error);
        }
    }

    [Theory]
    [InlineData(0UL, false, 3UL, 2UL, "Owned claim route clock precedes the protected freshness reading.")]
    [InlineData(1UL, false, 3UL, 2UL, "Owned claim route clock changed its protected boot.")]
    [InlineData(1UL, true, 3UL, 2UL, "Owned claim read issuance exceeds trusted lower time.")]
    [InlineData(1UL, true, 1UL, 2UL, "Owned claim read expiry does not cover trusted upper time.")]
    public void FirstFailedPredicateHasAFixedReason(ulong sample, bool sameBoot, ulong issued, ulong expires, string reason)
    {
        byte[] first = [1], second = [2];
        var error = Assert.Throws<CryptographicException>(() => ProtectedDeepIdV2AccountOwner.RequireCurrentClaimRead(
            sample, first, 1, sameBoot ? first : second, issued, expires, 1, 2));
        Assert.Equal(reason, error.Message);
    }
}
