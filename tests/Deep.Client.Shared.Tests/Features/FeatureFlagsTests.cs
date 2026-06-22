using Deep.Client.Shared.Features;

namespace Deep.Client.Shared.Tests.Features;

public sealed class FeatureFlagsTests
{
    [Fact]
    public void ReleaseDefaults_RequiresTransportAndDisablesStub()
    {
        Assert.True(ClientFeatureFlags.ReleaseDefaults.TransportRequired);
        Assert.False(ClientFeatureFlags.ReleaseDefaults.StubTransportAllowed);
        Assert.True(ClientFeatureFlags.ReleaseDefaults.CallsEnabled);
    }

    [Fact]
    public void DebugDefaults_DoesNotRequireTransportAndAllowsStub()
    {
        Assert.False(ClientFeatureFlags.Defaults.TransportRequired);
        Assert.True(ClientFeatureFlags.Defaults.StubTransportAllowed);
    }

    [Fact]
    public void ReleaseInvariant_TransportRequiredImpliesNoStub()
    {
        var release = ClientFeatureFlags.ReleaseDefaults;

        if (release.TransportRequired)
        {
            Assert.False(release.StubTransportAllowed);
        }
    }
}
