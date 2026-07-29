using System.Text.Json;
using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Tests.Services;

public sealed class MembershipTrustPrivacyTests
{
    [Fact]
    public void PublicStatusSerialization_IsCoarseAndExcludesSyntheticCanaries()
    {
        var canaries = new[]
        {
            "https://private.invalid/path",
            "192.0.2.44",
            "network-canary",
            "signer-canary",
            "entry-canary",
            "profile-canary",
            "signature-canary"
        };
        var status = MembershipTrustStatus.For(
            MembershipTrustState.ForkDetected,
            MembershipTrustEvent.EquivocationObserved);
        var json = JsonSerializer.Serialize(status);

        Assert.All(canaries, canary =>
            Assert.DoesNotContain(canary, json, StringComparison.Ordinal));
        Assert.DoesNotContain("exception", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hash", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("envelope", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProductionSource_HasNoFixtureVerifierSigningHelperOrRuntimeRegistration()
    {
        var root = FindRepositoryRoot();
        var sourceRoot = Path.Combine(root, "src", "Deep.Client.Shared");
        var files = Directory.EnumerateFiles(sourceRoot, "*.cs", SearchOption.AllDirectories).ToArray();
        var production = string.Join('\n', files.Select(File.ReadAllText));
        var runtime = File.ReadAllText(Path.Combine(sourceRoot, "State", "ClientRuntime.cs"));

        Assert.DoesNotContain("FixtureMembershipVerifier", production, StringComparison.Ordinal);
        Assert.DoesNotContain("DeterministicMembershipVerifier", production, StringComparison.Ordinal);
        Assert.DoesNotContain("MembershipSigningDomains.Frame", production, StringComparison.Ordinal);
        Assert.DoesNotContain("MembershipTrustService", runtime, StringComparison.Ordinal);
        Assert.DoesNotContain("IMembershipSignatureVerifier", runtime, StringComparison.Ordinal);
    }

    [Fact]
    public void PublicStatusText_IsFixedAndContainsNoRuntimeMaterial()
    {
        foreach (var state in Enum.GetValues<MembershipTrustState>())
        {
            var status = MembershipTrustStatus.For(state);
            Assert.Equal(state.ToString(), status.State.ToString());
            Assert.Equal(state == MembershipTrustState.Healthy, status.Usable);
        }
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null &&
               !File.Exists(Path.Combine(current.FullName, "Deep.Client.Shared.slnx")))
        {
            current = current.Parent;
        }
        return current?.FullName ?? throw new DirectoryNotFoundException();
    }
}
