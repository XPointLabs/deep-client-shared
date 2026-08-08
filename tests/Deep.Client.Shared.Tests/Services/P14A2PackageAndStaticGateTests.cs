using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.4.0-production.2024907";
    private const string CarrierVersion = "0.4.0-survival.2024907";
    private const string ProtocolSource =
        "20249077913abfd9ad69f957aa07e57ff55b5e24";
    private const string CarrierSource =
        "20249077913abfd9ad69f957aa07e57ff55b5e24";
    private static readonly ExpectedPackage[] ExpectedPackages =
    [
        new("Deep.Protocol", ProtocolVersion, 218_744,
            "00bfaf36679fc905c9c83b644d717367ce1f2a3864f0009ef998da714f3fddfc",
            "d53e0c854c73af57ae17fa4ed942cc7047825cf8ff1156df4b458656bae6bddce7159c38aadda44d41a38d595edea07399d33f7d8952f2549a8a8880227b1ebd",
            "4UtigGZqDJyCOaVEXa2GpK2cp/O2FVpGCO026O31qYzNIEh0tv1l725o2ItCITJh4ozRJP0tGa8FohppPqVmOQ==",
            ProtocolSource),
        new("Deep.Protocol.Abstractions", ProtocolVersion, 24_956,
            "b3790c2599be43ab593364dc57b558e97d36333a56c3b3b7cd6427e78629a9a2",
            "b73c4664a18354848dda9124c7ad88fa5310be39e9aa6d78297cd5a55223befc5844330c85efcbbcbdf571750691d06f8cacd6d5e7b179e7d737ac2a9dd59907",
            "a/shd1eEhiyPcy6XSwV5NfQcgTduNTdcLys7IF9jm6ZQQrF4AqqjJNJ0CxUbtBncp2RUcDwugg8Lyw9n9KZjnw==",
            ProtocolSource),
        new("Deep.Protocol.MembershipRoutes", ProtocolVersion, 48_182,
            "91698919918caba2e671dcef87d02f1fc6168d330fc852ab15e90cdb29c209d7",
            "e68f5ea66a23997541a507cbf6d1444632e8f8885233a0d639c9946a7a30664f0a3c392ef4bc046a8e0a13200374ddd647794704681e71dab16f0812ade2555b",
            "5o9epmojmXVBpQfL9tFERjLo+IhSM6DWOcmUanowZk8KPDku9LwEao4KEyADdN3WR3lHBGgecdqxbwgSreJVWw==",
            ProtocolSource),
        new("Deep.Protocol.ProfileCarrier", CarrierVersion, 72_713,
            "4eba47d1829f4613c1414590de825c9390e6d26f1301bf9edb2294c90838b522",
            "386e3c821f7fc4aeba1c3c75254c6254ec5098939565240e39db399e3a79b8b9417ddae6ccadb86feab667363dbb4ab0e6423a3ca7493b63914dd8de84b38cc9",
            "OG48gh9/xK66HDx1JUxiVOxQmJOVZSQOOds5njp5uLlBfdrmzK24b+q2ZzY9u0qw5kI6PKdJO2ORTdjehLOMyQ==",
            CarrierSource),
        new("Deep.Protocol.Protobuf", ProtocolVersion, 50_210,
            "c42b0463013d98a9c5d5200db5c875a6d320a2b6c80e1062b8c76ac5aac205a2",
            "ad318fc294e7986e7cd296d57b484d52a6c09dbcc39e2315aa2d403935bb5744c2c29ed0a9f68da1ef48bf3d649f53be675db34d1ccf42fd3b2a1078b389174f",
            "LJZWHPkNilHuBFS9EZYMvAtTk64dwfa8LfWgzvrK3j3qNFlevUIpBgVvll4ENY2nxYpsZTLjKYJlKaZURDFxdw==",
            ProtocolSource)
    ];

    [Fact]
    public void UnifiedSurvivalBetaPackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "production-2024907");
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
                "production-2024907",
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
        }

        Assert.Equal(ProtocolSource, CarrierSource);
    }

    [Fact]
    public void NuGetSourcesAreLocalAndDeepPackagesMapOnlyToSurvivalBeta()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "NuGet.Config"));
        Assert.Contains("<clear", text, StringComparison.Ordinal);
        Assert.Contains("production-protocol-closure", text, StringComparison.Ordinal);
        Assert.Contains("vendor\\production-2024907\\packages", text, StringComparison.Ordinal);
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
            root, "vendor", "production-2024907", "package-manifest.json"));
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
                "\"id\": \"Deep.Protocol.Protobuf\"",
                "\"id\": \"Deep.Protocol.Protobuf.Drift\"",
                StringComparison.Ordinal),
            project));
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(ProtocolSource, new string('1', 40),
                StringComparison.Ordinal),
            project));
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(
                "4eba47d1829f4613c1414590de825c9390e6d26f1301bf9edb2294c90838b522",
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
