using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.4.0-production.32b4d14";
    private const string CarrierVersion = "0.4.0-survival.32b4d14";
    private const string ProtocolSource =
        "32b4d145de6d6b008e95b3cfc6ac2943de7f78fc";
    private const string CarrierSource =
        "32b4d145de6d6b008e95b3cfc6ac2943de7f78fc";
    private static readonly ExpectedPackage[] ExpectedPackages =
    [
        new("Deep.Protocol", ProtocolVersion, 218_813,
            "9d49292fd16069dc13f4b669a8e17597eb38e533dbc2097905f4dc93a1d62b0b",
            "5f7bd2ef8b383dfbb5b691b52d1b8939113c8ceb59e86cf94652d28e1f9519add859a830f76238c1785c4539c18bd0fb28439d15314b34c4328915ccaf01d249",
            "X3vS74s4Pfu1tpG1LRuJORE8jOtZ6Gz5RlLSjh+VGa3YWagw92I4wXhcRTnBi9D7KEOdFTFLNMQyiRXMrwHSSQ==",
            ProtocolSource),
        new("Deep.Protocol.Abstractions", ProtocolVersion, 24_968,
            "1af4fe4d305ab555790cd976ca1fea5f94db611a854c675a11b608991a3c25fd",
            "5f6d9eb6c8224a99c3ad27f20eb8b0103b0191b3f1792df031732fe577d4d8b284752ef3bce564ad5bde136c2d0e33be0105cd0e196cc42fc76520f58268236f",
            "X22etsgiSpnDrSfyDriwEDsBkbPxeS3wMXMv5XfU2LKEdS7zvOVkrVveE2wtDjO+AQXNDhlsxC/HZSD1gmgjbw==",
            ProtocolSource),
        new("Deep.Protocol.MembershipRoutes", ProtocolVersion, 123_901,
            "e4d5feeb4e8b2634167f90634f76bc9d630087cf452876a48b6f3358f9b9e493",
            "0e1143b50af202e77969a9cf9ec0ba60702b8f1111936015b556c79648a6bd06d2b4123059cc300118331dae08ec60becbe1df90d893eabd1f80accf398b5b15",
            "DhFDtQryAud5aanPnsC6YHArjxERk2AVtVbHlkimvQbStBIwWcwwARgzHa4I7GC+y+HfkNiT6r0fgKzPOYtbFQ==",
            ProtocolSource),
        new("Deep.Protocol.ProfileCarrier", CarrierVersion, 49_710,
            "8b7c2b6146ef518304804b1818498537d4c6dc61a2d92060377f560290351009",
            "d369d0f7f04c5604273c5564b7b4901e8305f21c1f830b2b6d6ee87853d80582857e8ef45eed07a2818097bb0f67f9c1129e76bc1471806101f5e179b04e6c30",
            "02nQ9/BMVgQnPFVkt7SQHoMF8hwfgwsrbW7oeFPYBYKFfo70Xu0HooGAl7sPZ/nBEp52vBRxgGEB9eF5sE5sMA==",
            CarrierSource),
        new("Deep.Protocol.Protobuf", ProtocolVersion, 50_218,
            "f441a1875bc1d9a717e91dd2422bda1e9d08a7fa1eaeaa2b8024127689aca84e",
            "1c0b503a8025cee3e6a2db6d7d091617b25599bc9ca5355e1b52778accccc3c1627716d4afa4364b96450369114392e8dd09a520f8671ccd7065251ab5940959",
            "HAtQOoAlzuPmotttfQkWF7JVmbycpTVeG1J3iszMw8FidxbUr6Q2S5ZFA2kRQ5Lo3QmlIPhnHM1wZSUatZQJWQ==",
            ProtocolSource)
    ];

    [Fact]
    public void UnifiedSurvivalBetaPackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "production-32b4d14");
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
                "production-32b4d14",
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
        Assert.Contains("vendor\\production-32b4d14\\packages", text, StringComparison.Ordinal);
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
            root, "vendor", "production-32b4d14", "package-manifest.json"));
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
                "8b7c2b6146ef518304804b1818498537d4c6dc61a2d92060377f560290351009",
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
