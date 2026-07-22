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
        Assert.True(ClientFeatureFlags.ReleaseDefaults.MetadataPrivateTransportRequired);
    }

    [Fact]
    public void DebugDefaults_DoesNotRequireTransportAndAllowsStub()
    {
        Assert.False(ClientFeatureFlags.Defaults.TransportRequired);
        Assert.True(ClientFeatureFlags.Defaults.StubTransportAllowed);
        Assert.False(ClientFeatureFlags.Defaults.MetadataPrivateTransportRequired);
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

    [Fact]
    public void MembershipTrustAndLegacyRollback_AreDormantInEveryDefault()
    {
        Assert.False(ClientFeatureFlags.Defaults.MembershipTrustEnabled);
        Assert.False(ClientFeatureFlags.Defaults.LegacyEmbeddedBootstrapRollbackAllowed);
        Assert.False(ClientFeatureFlags.ReleaseDefaults.MembershipTrustEnabled);
        Assert.False(ClientFeatureFlags.ReleaseDefaults.LegacyEmbeddedBootstrapRollbackAllowed);
        Assert.False(ClientFeatureFlags.Defaults.PersistentTransportOutboxEnabled);
        Assert.False(ClientFeatureFlags.ReleaseDefaults.PersistentTransportOutboxEnabled);
    }

    [Fact]
    public void ExistingPositionalArguments_RemainSourceCompatible()
    {
        var flags = new ClientFeatureFlags(
            true, false, false, false, true, true, true, false, true);

        Assert.False(flags.MembershipTrustEnabled);
        Assert.False(flags.LegacyEmbeddedBootstrapRollbackAllowed);
        Assert.False(flags.PersistentTransportOutboxEnabled);
    }
}
