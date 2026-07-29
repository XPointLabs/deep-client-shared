using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.3.0-p10b3.60ce2e3";
    private const string CarrierVersion = "0.2.0-p10b3.60ce2e3";
    private const string ProtocolSource =
        "60ce2e3a5140f245d6bcfecf60fa456c26ffe730";
    private const string CarrierSource =
        "dfb182d65d3e8d3ee44a2246ae94c68159bc692d";

    [Fact]
    public void UnifiedP10b3PackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "p10b3");
        using var document = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(vendor, "package-provenance.json")));
        var root = document.RootElement;
        Assert.Equal("deep-client-p10b3-offline-package-set.v1",
            root.GetProperty("schema").GetString());
        Assert.Equal(ProtocolSource,
            root.GetProperty("protocolSourceCommit").GetString());
        Assert.Equal(CarrierSource,
            root.GetProperty("profileCarrierSourceCommit").GetString());
        Assert.Equal("local-only-not-published",
            root.GetProperty("publication").GetString());

        var packages = root.GetProperty("packages").EnumerateArray().ToArray();
        Assert.Equal(5, packages.Length);
        var files = Directory.GetFiles(Path.Combine(vendor, "packages"), "*.nupkg")
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            packages.Select(value => Path.GetFileName(value.GetProperty("file").GetString()!))
                .Order(StringComparer.Ordinal),
            files);
        foreach (var package in packages)
        {
            var path = Path.Combine(vendor, package.GetProperty("file").GetString()!);
            Assert.Equal(package.GetProperty("bytes").GetInt64(), new FileInfo(path).Length);
            Assert.Equal(package.GetProperty("sha256").GetString(), Sha256(path));
        }
    }

    [Fact]
    public void ProjectAndLocksResolveOneExactProtocolGraph()
    {
        var root = RepositoryRoot();
        var project = XDocument.Load(Path.Combine(
            root, "src", "Deep.Client.Shared", "Deep.Client.Shared.csproj"));
        var references = project.Descendants("PackageReference").ToDictionary(
            value => value.Attribute("Include")!.Value,
            value => value.Attribute("Version")!.Value,
            StringComparer.Ordinal);
        Assert.Equal($"[{ProtocolVersion}]", references["Deep.Protocol"]);
        Assert.Equal($"[{ProtocolVersion}]", references["Deep.Protocol.MembershipRoutes"]);
        Assert.Equal($"[{CarrierVersion}]", references["Deep.Protocol.ProfileCarrier"]);

        foreach (var relative in new[]
                 {
                     Path.Combine("src", "Deep.Client.Shared", "packages.lock.json"),
                     Path.Combine("tests", "Deep.Client.Shared.Tests", "packages.lock.json")
                 })
        {
            using var document = JsonDocument.Parse(
                File.ReadAllBytes(Path.Combine(root, relative)));
            var dependencies = document.RootElement.GetProperty("dependencies")
                .GetProperty("net10.0");
            AssertResolved(dependencies, "Deep.Protocol", ProtocolVersion);
            AssertResolved(dependencies, "Deep.Protocol.Abstractions", ProtocolVersion);
            AssertResolved(dependencies, "Deep.Protocol.MembershipRoutes", ProtocolVersion);
            AssertResolved(dependencies, "Deep.Protocol.ProfileCarrier", CarrierVersion);
            AssertResolved(dependencies, "Deep.Protocol.Protobuf", ProtocolVersion);
            Assert.Equal(
                $"[{ProtocolVersion}]",
                dependencies.GetProperty("Deep.Protocol.ProfileCarrier")
                    .GetProperty("dependencies")
                    .GetProperty("Deep.Protocol")
                    .GetString());
        }
    }

    [Fact]
    public void CarrierNuspecSeparatesCarrierIdentityFromProtocolDependency()
    {
        var package = Path.Combine(
            RepositoryRoot(),
            "vendor",
            "p10b3",
            "packages",
            $"Deep.Protocol.ProfileCarrier.{CarrierVersion}.nupkg");
        using var archive = ZipFile.OpenRead(package);
        var nuspec = Assert.Single(archive.Entries,
            value => value.FullName == "Deep.Protocol.ProfileCarrier.nuspec");
        using var stream = nuspec.Open();
        var xml = XDocument.Load(stream);
        XNamespace ns = xml.Root!.Name.Namespace;
        var metadata = xml.Root.Element(ns + "metadata")!;
        Assert.Equal(
            CarrierSource,
            metadata.Element(ns + "repository")!.Attribute("commit")!.Value);
        var protocol = Assert.Single(metadata.Descendants(ns + "dependency"),
            value => value.Attribute("id")!.Value == "Deep.Protocol");
        Assert.Equal($"[{ProtocolVersion}]", protocol.Attribute("version")!.Value);
        Assert.NotEqual(ProtocolSource, CarrierSource);
    }

    [Fact]
    public void NuGetSourcesAreLocalAndDeepPackagesMapOnlyToP10b3()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "NuGet.Config"));
        Assert.Contains("<clear", text, StringComparison.Ordinal);
        Assert.Contains("p10b3-protocol-local-pinned", text, StringComparison.Ordinal);
        Assert.Contains("vendor\\p10b3\\packages", text, StringComparison.Ordinal);
        Assert.Contains("Deep.Protocol*", text, StringComparison.Ordinal);
        Assert.DoesNotContain("nuget.org", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("http://", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UnifiedPackagePinRejectsVersionHashAndProjectReferenceDrift()
    {
        var root = RepositoryRoot();
        var manifest = File.ReadAllText(Path.Combine(
            root, "vendor", "p10b3", "package-provenance.json"));
        var project = File.ReadAllText(Path.Combine(
            root, "src", "Deep.Client.Shared", "Deep.Client.Shared.csproj"));
        AssertPackagePin(manifest, project);
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(ProtocolVersion, "0.3.0-p10b3.invalid",
                StringComparison.Ordinal),
            project));
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(
                "e2d03040daaf7c7fe29952db3cfbc3227fb9f0da42740b5f57f65a02ae8118a2",
                new string('0', 64),
                StringComparison.Ordinal),
            project));
        Assert.Throws<InvalidDataException>(() =>
            AssertPackagePin(manifest, project + "<ProjectReference Include=\"drift\" />"));
    }

    [Fact]
    public void ProductionProfileGraphRemainsDormant()
    {
        var root = RepositoryRoot();
        var path = Path.Combine(root, "src", "Deep.Client.Shared", "Services",
            "DormantSelfHostedProfileVerificationService.cs");
        var source = File.ReadAllText(path);
        Assert.Contains("ProfileCarrierVerifier.VerifyExact", source);
        var runtime = File.ReadAllText(Path.Combine(
            root, "src", "Deep.Client.Shared", "State", "ClientRuntime.cs"));
        Assert.DoesNotContain("DormantSelfHostedProfileVerification", runtime);
    }

    private static void AssertPackagePin(string manifestText, string projectText)
    {
        using var document = JsonDocument.Parse(manifestText);
        var packages = document.RootElement.GetProperty("packages")
            .EnumerateArray().ToArray();
        if (document.RootElement.GetProperty("protocolSourceCommit").GetString()
                != ProtocolSource
            || document.RootElement.GetProperty("profileCarrierSourceCommit").GetString()
                != CarrierSource
            || packages.Length != 5
            || packages.Where(value =>
                    value.GetProperty("id").GetString() !=
                    "Deep.Protocol.ProfileCarrier")
                .Any(value => value.GetProperty("version").GetString() != ProtocolVersion)
            || packages.Single(value =>
                    value.GetProperty("id").GetString() ==
                    "Deep.Protocol.ProfileCarrier")
                .GetProperty("version").GetString() != CarrierVersion
            || packages.Single(value =>
                    value.GetProperty("id").GetString() ==
                    "Deep.Protocol.ProfileCarrier")
                .GetProperty("sha256").GetString()
                != "e2d03040daaf7c7fe29952db3cfbc3227fb9f0da42740b5f57f65a02ae8118a2"
            || !projectText.Contains(
                $"Deep.Protocol\" Version=\"[{ProtocolVersion}]",
                StringComparison.Ordinal)
            || !projectText.Contains(
                $"Deep.Protocol.MembershipRoutes\" Version=\"[{ProtocolVersion}]",
                StringComparison.Ordinal)
            || !projectText.Contains(
                $"Deep.Protocol.ProfileCarrier\" Version=\"[{CarrierVersion}]",
                StringComparison.Ordinal)
            || projectText.Contains("ProjectReference", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Unified P10B3 package pin validation failed.");
        }
    }

    private static void AssertResolved(
        JsonElement dependencies,
        string id,
        string version) =>
        Assert.Equal(version, dependencies.GetProperty(id).GetProperty("resolved").GetString());

    private static string Sha256(string path) =>
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

    internal static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Deep.Client.Shared.slnx")))
        {
            directory = directory.Parent;
        }
        return directory?.FullName ??
            throw new InvalidOperationException("Repository root missing.");
    }
}
