using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Production.Tests;

public sealed class FixturePrerequisiteTests
{
    [Fact]
    [Trait("FixturePreflight", "true")]
    public void FixturePreflight_FrozenContactAcceptVectorReachesTheActualConsumer()
    {
        var scope = Did2ContactAcceptCustodyTests.Scope();
        var operation = Enumerable.Repeat((byte)20, 32).ToArray();
        var exact = Did2ContactAcceptCustodyTests.Accept(scope, operation);
        try { Assert.Equal(Dmc2ContentKind.ContactAccept, ApplicationCoreCodec.DecodeDmc2(exact).ContentKind); }
        finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(operation); }
    }

    [Fact]
    [Trait("FixturePreflight", "true")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public void FixturePreflight_ApprovedNativeProvidersOpenWithoutActivatingMessaging()
    {
        using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        using var kem = MessagingE2eeProductionReadiness.OpenApprovedMlKemPrerequisite();
        Assert.False(string.IsNullOrWhiteSpace(kem.ProviderIdentifier));
        Assert.True(kem.Report.ApprovedMlKemAssetDeclared);
        Assert.False(kem.Report.CanActivate);
    }
}
