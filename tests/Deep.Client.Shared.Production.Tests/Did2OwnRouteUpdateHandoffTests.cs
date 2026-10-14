using System.Reflection;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2OwnRouteUpdateHandoffTests
{
    [Fact]
    public void HistoricalOwnControlHandoffHasNoRawConstructorOrDirectContentAuthority()
    {
        // Shape coverage only; native/cold/consent qualification belongs to the
        // actual owned control cycle, not a synthetic positive handoff.
        var type = typeof(AuthenticatedOwnRouteUpdateDmc2);
        Assert.True(type.IsSealed);
        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(type.GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance),
            constructor => !constructor.IsPrivate);
        Assert.False(typeof(AuthenticatedDirectDmc2).IsAssignableFrom(type));
        Assert.DoesNotContain(type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static),
            method => method.Name == "CreateForTests");
    }

    [Theory]
    [InlineData(typeof(AuthenticatedPeerRouteUpdateDmc2))]
    [InlineData(typeof(ProtectedDeepIdV2AccountOwner.OwnedPeerRouteProcessingOutcome))]
    public void PeerProcessingAndHistoricalHandoffHaveNoRawOrTestAuthorityConstructor(Type type)
    {
        Assert.True(type.IsSealed);
        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(type.GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance), constructor => !constructor.IsPrivate);
        Assert.DoesNotContain(type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static),
            method => method.Name == "CreateForTests");
    }
}
