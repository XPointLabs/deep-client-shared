using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.4.0-production.1059184";
    private const string CarrierVersion = "0.4.0-survival.1059184";
    private const string ProtocolSource =
        "105918421eb5621bec86aeaac56013b269472aa7";
    private const string CarrierSource =
        "105918421eb5621bec86aeaac56013b269472aa7";
    private static readonly ExpectedPackage[] ExpectedPackages =
    [
        new("Deep.Protocol", ProtocolVersion, 218_889,
            "e4c29cd2de20d7863cdb7af993468953208e6a8097cee4de2a7cdfb468918c7f",
            "e9ca4409a1976287d83e0b8866c659d0fdcce46c14f28e03482eeafb16bb8e7e783739d4662aad20bcde29d4ec6221cffe24782ac30429cb7d937f8c0b3d609f",
            "6cpECaGXYofYPguIZsZZ0P3M5GwU8o4DSC7q+xa7jn54NznUZiqtILzeKdTsYiHP/iR4KsMEKct9k3+MCz1gnw==",
            ProtocolSource),
        new("Deep.Protocol.Abstractions", ProtocolVersion, 25_043,
            "dcb00f2646b5a8bcf907f3936f761a00a6f0f360386e6631cd6e6513c711efe8",
            "bf83ff15bb158ed99d2a89696908a7f1e1bd7103ab01a04ff63c8ee229e8277e96afcd5fffe9b67dfda738802abbe07a60671581795ee255a09dc8f4ec734b90",
            "v4P/FbsVjtmdKolpaQin8eG9cQOrAaBP9jyO4inoJ36Wr81f/+m2ff2nOIAqu+B6YGcVgXle4lWgncj07HNLkA==",
            ProtocolSource),
        new("Deep.Protocol.MembershipRoutes", ProtocolVersion, 54_559,
            "c2c1f3a5179cc10d32ed479225d730b9961fc7fbe7bd2e328b96f2a3fab1447b",
            "a14c22458a0ac9f74cc4a864364f084386436db8dd8d457e7bcb7ff61036454d9d80e6f2062c65b41dd94a174bfc385665e5e3073dcc7472ee364e95db0230bc",
            "oUwiRYoKyfdMxKhkNk8IQ4ZDbbjdjUV+e8t/9hA2RU2dgObyBixltB3ZShdL/DhWZeXjBz3MdHLuNk6V2wIwvA==",
            ProtocolSource),
        new("Deep.Protocol.ProfileCarrier", CarrierVersion, 49_716,
            "3b03f0ee3e3491e849bea02fd4ef71882f44d3623f6039913bf7595b972cfa90",
            "a7a519c7bab16fdbd3d0993f4070daf68dbf182b9e7e1cf5128c3b3f12b55748a84227464858eb5c6c59b2036b22831678363c26e8a229a55f34a3607a5cc560",
            "p6UZx7qxb9vT0Jk/QHDa9o2/GCuefhz1Eow7PxK1V0ioQidGSFjrXGxZsgNrIoMWeDY8JuiiKaVfNKNgelzFYA==",
            CarrierSource),
        new("Deep.Protocol.Protobuf", ProtocolVersion, 50_302,
            "8912fa06c207bf48cddd251347ab7e7544c03485dff4222a3ec2fb86b8f13a56",
            "b5894d8db2c5f7635d05011dd5e58ceb76f927028d296bd55b3eeaba3ee58dfaa25a518e66ff113312cf53cb1a5d7e0f3d964a6de463981da8761f7291715e1c",
            "tYlNjbLF92NdBQEd1eWM63b5JwKNKWvVWz7quj7ljfqiWlGOZv8RMxLPU8saXX4PPZZKbeRjmB2odh9ykXFeHA==",
            ProtocolSource)
    ];

    [Fact]
    public void UnifiedSurvivalBetaPackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "production-1059184");
        using var document = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(vendor, "package-manifest.json")));
        var root = document.RootElement;
        Assert.Equal("deep-production-protocol-closure.v2",
            root.GetProperty("schema").GetString());
        Assert.Equal(ProtocolSource,
            root.GetProperty("sourceCommit").GetString());
        Assert.Equal("local-only-not-published",
            root.GetProperty("publication").GetString());

        var packages = root.GetProperty("packages").EnumerateArray().ToArray();
        Assert.Equal(ExpectedPackages.Length, packages.Length);
        var files = Directory.GetFiles(Path.Combine(vendor, "packages"), "*.nupkg")
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            packages.Select(value => Path.GetFileName(value.GetProperty("file").GetString()!))
                .Order(StringComparer.Ordinal),
            files);
        foreach (var expected in ExpectedPackages)
        {
            var package = Assert.Single(packages,
                value => value.GetProperty("id").GetString() == expected.Id);
            var path = Path.Combine(vendor, package.GetProperty("file").GetString()!);
            Assert.Equal(expected.Version, package.GetProperty("version").GetString());
            Assert.Equal(expected.Bytes, package.GetProperty("bytes").GetInt64());
            Assert.Equal(expected.Sha256, package.GetProperty("sha256").GetString());
            Assert.Equal(expected.Sha512, package.GetProperty("sha512").GetString());
            Assert.Equal(expected.ContentHash, package.GetProperty("contentHash").GetString());
            Assert.Equal(expected.Bytes, new FileInfo(path).Length);
            Assert.Equal(expected.Sha256, Sha256(path));
            Assert.Equal(expected.Sha512, Sha512(path));
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
            foreach (var expected in ExpectedPackages)
                AssertResolved(dependencies, expected);
            Assert.Equal(
                $"[{ProtocolVersion}]",
                dependencies.GetProperty("Deep.Protocol.ProfileCarrier")
                    .GetProperty("dependencies")
                    .GetProperty("Deep.Protocol")
                    .GetString());
        }
    }

    [Fact]
    public void NuspecIdentityVersionAndRepositoryAreHardPinned()
    {
        foreach (var expected in ExpectedPackages)
        {
            var package = Path.Combine(
                RepositoryRoot(),
                "vendor",
                "production-1059184",
                "packages",
                $"{expected.Id}.{expected.Version}.nupkg");
            using var archive = ZipFile.OpenRead(package);
            var nuspec = Assert.Single(archive.Entries,
                value => value.FullName == $"{expected.Id}.nuspec");
            using var stream = nuspec.Open();
            var xml = XDocument.Load(stream);
            XNamespace ns = xml.Root!.Name.Namespace;
            var metadata = xml.Root.Element(ns + "metadata")!;
            Assert.Equal(expected.Id, metadata.Element(ns + "id")!.Value);
            Assert.Equal(expected.Version, metadata.Element(ns + "version")!.Value);
            Assert.Equal(
                expected.Source,
                metadata.Element(ns + "repository")!.Attribute("commit")!.Value);
            var requiredInternal = expected.Id switch
            {
                "Deep.Protocol" => new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["Deep.Protocol.Abstractions"] = $"[{ProtocolVersion}]",
                    ["Deep.Protocol.Protobuf"] = $"[{ProtocolVersion}]"
                },
                "Deep.Protocol.MembershipRoutes" or "Deep.Protocol.ProfileCarrier" =>
                    new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["Deep.Protocol"] = $"[{ProtocolVersion}]"
                    },
                _ => new Dictionary<string, string>(StringComparer.Ordinal)
            };
            var actualInternal = metadata.Descendants(ns + "dependency")
                .Where(value => value.Attribute("id")!.Value.StartsWith(
                    "Deep.Protocol", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            Assert.Equal(requiredInternal.Count, actualInternal.Length);
            Assert.Equal(actualInternal.Length, actualInternal
                .Select(value => value.Attribute("id")!.Value)
                .Distinct(StringComparer.OrdinalIgnoreCase).Count());
            foreach (var dependency in actualInternal)
            {
                var id = dependency.Attribute("id")!.Value;
                Assert.True(requiredInternal.TryGetValue(id, out var requiredVersion));
                Assert.Equal(requiredVersion, dependency.Attribute("version")!.Value);
            }
        }

        Assert.Equal(ProtocolSource, CarrierSource);
    }

    [Fact]
    public void NuGetSourcesAreLocalAndDeepPackagesMapOnlyToSurvivalBeta()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "NuGet.Config"));
        Assert.Contains("<clear", text, StringComparison.Ordinal);
        Assert.Contains("production-protocol-closure", text, StringComparison.Ordinal);
        Assert.Contains("vendor\\production-1059184\\packages", text, StringComparison.Ordinal);
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
            root, "vendor", "production-1059184", "package-manifest.json"));
        var project = File.ReadAllText(Path.Combine(
            root, "src", "Deep.Client.Shared", "Deep.Client.Shared.csproj"));
        AssertPackagePin(manifest, project);
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(ProtocolVersion, "0.4.0-survival.invalid",
                StringComparison.Ordinal),
            project));
        foreach (var expected in ExpectedPackages)
        {
            Assert.Throws<InvalidDataException>(() => AssertPackagePin(
                manifest.Replace(
                    expected.Sha256,
                    new string('0', 64),
                    StringComparison.Ordinal),
                project));
        }
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(
                "\"id\":\"Deep.Protocol.Protobuf\"",
                "\"id\":\"Deep.Protocol.Protobuf.Drift\"",
                StringComparison.Ordinal),
            project));
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(ProtocolSource, new string('1', 40),
                StringComparison.Ordinal),
            project));
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(
                "3b03f0ee3e3491e849bea02fd4ef71882f44d3623f6039913bf7595b972cfa90",
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
        if (document.RootElement.GetProperty("sourceCommit").GetString()
                != ProtocolSource
            || packages.Length != ExpectedPackages.Length
            || ExpectedPackages.Any(expected =>
                packages.Count(value =>
                    value.GetProperty("id").GetString() == expected.Id) != 1 ||
                packages.Single(value =>
                        value.GetProperty("id").GetString() == expected.Id)
                    .GetProperty("version").GetString() != expected.Version ||
                packages.Single(value =>
                        value.GetProperty("id").GetString() == expected.Id)
                    .GetProperty("bytes").GetInt64() != expected.Bytes ||
                packages.Single(value =>
                        value.GetProperty("id").GetString() == expected.Id)
                    .GetProperty("sha256").GetString() != expected.Sha256 ||
                packages.Single(value =>
                        value.GetProperty("id").GetString() == expected.Id)
                    .GetProperty("sha512").GetString() != expected.Sha512 ||
                packages.Single(value =>
                        value.GetProperty("id").GetString() == expected.Id)
                    .GetProperty("contentHash").GetString() != expected.ContentHash)
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
            throw new InvalidDataException("Unified Survival Beta package pin validation failed.");
        }
    }

    private static void AssertResolved(
        JsonElement dependencies,
        ExpectedPackage expected)
    {
        var dependency = dependencies.GetProperty(expected.Id);
        Assert.Equal(expected.Version, dependency.GetProperty("resolved").GetString());
        Assert.Equal(expected.ContentHash, dependency.GetProperty("contentHash").GetString());
    }

    private static string Sha256(string path) =>
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

    private static string Sha512(string path) =>
        Convert.ToHexStringLower(SHA512.HashData(File.ReadAllBytes(path)));

    private sealed record ExpectedPackage(
        string Id,
        string Version,
        long Bytes,
        string Sha256,
        string Sha512,
        string ContentHash,
        string Source);

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
