using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.4.0-production.cc39def";
    private const string CarrierVersion = "0.4.0-survival.cc39def";
    private const string ProtocolSource =
        "cc39defbf9c24bf7d99f6346a86c7602379b62ea";
    private const string CarrierSource =
        "cc39defbf9c24bf7d99f6346a86c7602379b62ea";
    private static readonly ExpectedPackage[] ExpectedPackages =
    [
        new("Deep.Protocol", ProtocolVersion, 218_891,
            "6ae87c7b577b89aa42db9afdf41660c8ecd3ca5984c19b4290cb40fa53024f0d",
            "6f42b01c12d378db7d848fd41dc91b568b3a278c4e624365e03ca007b6fff1c150bfd9cc07ef5172900425600ae738bdf012548361c035e5ab2f90f387698b11",
            "b0KwHBLTeNt9hI/UHckbVos6J4xOYkNl4DygB7b/8cFQv9nMB+9RcpAEJWAK5zi98BJUg2HANeWrL5Dzh2mLEQ==",
            ProtocolSource),
        new("Deep.Protocol.Abstractions", ProtocolVersion, 25_036,
            "e26432a477df59da31afc5dc8ab1b67cd828942c5095b56d568f6897abc08043",
            "88b0f9ebdcb434dbb0ad97a6538e8f51bbb35368c1ea824c70307e4efc848e444060912d99f2c2346ef2c9a51da09cf77549b6e705d3df1421f7b46e0ebb183e",
            "iLD569y0NNuwrZemU46PUbuzU2jB6oJMcDB+TvyEjkRAYJEtmfLCNG7yyaUdoJz3dUm25wXT3xQh97RuDrsYPg==",
            ProtocolSource),
        new("Deep.Protocol.MembershipRoutes", ProtocolVersion, 134_217,
            "7d6338ca8330b5db3db31f0cbe23aa38a4796f16bb7affbcc042c32b4ce1144a",
            "2eccddefd293d0adce4681a2c0483fddaccb09a54a1c2e075889ebc2b7c48560ea7bb9021dc45843d61b075cc30955dd33456bf57e49c10969a525885e12bfcc",
            "Lszd79KT0K3ORoGiwEg/3azLCaVKHC4HWInrwrfEhWDqe7kCHcRYQ9YbB1zDCVXdM0Vr9X5JwQlppSWIXhK/zA==",
            ProtocolSource),
        new("Deep.Protocol.ProfileCarrier", CarrierVersion, 72_706,
            "683f46bcc789f1f4719c86b8be8e5bcfd428ac2f5a55302ee06a2142c8697d78",
            "e14ed9c076b3db22e27e48781c9afea26fb591bf3f0f21a8a95fa87b520086d0aeeae8495a6b70c92498dba9dfa8dc533e72f1fae326eda5f43da13be37e52ef",
            "4U7ZwHaz2yLifkh4HJr+om+1kb8/DyGoqV+oe1IAhtCu6uhJWmtwySSY26nfqNxTPnLx+uMm7aX0PaE7435S7w==",
            CarrierSource),
        new("Deep.Protocol.Protobuf", ProtocolVersion, 50_304,
            "999ff91b25a58662987c63824fcd4e0ce796ddc9de32c598efc22ce170c3bd25",
            "ab1c005d1d04d39ae40445b62e89649fae6ddaf992c8ba1aee6a18ef8cb57539d0054320c6574db42f6b88bfc799f6d2d53f6c2fe4c1c269538ca2a631b85b2f",
            "qxwAXR0E05rkBEW2Lolkn65t2vmSyLoa7moY74y1dTnQBUMgxldNtC9riL/HmfbS1T9sL+TBwmlTjKKmMbhbLw==",
            ProtocolSource)
    ];

    [Fact]
    public void UnifiedSurvivalBetaPackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "production-cc39def");
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
                "production-cc39def",
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
    public void RouteContinuitySliceCExposesOnlyBoundedHighLevelCapabilities()
    {
        var revocation = typeof(VerifiedProductionMailboxRouteContinuityRevocation);
        Assert.True(revocation.IsSealed);
        Assert.Empty(revocation.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        var verifyOwnerRevocation = Assert.Single(
            typeof(ProductionMailboxRouteContinuityVerifier).GetMethods(
                BindingFlags.Public | BindingFlags.Static),
            method => method.Name == "VerifyOwnerRevocation");
        Assert.Equal(revocation, verifyOwnerRevocation.ReturnType);

        var cacheClosure = typeof(VerifiedProductionMailboxNodeCacheClosure);
        Assert.True(cacheClosure.IsSealed);
        Assert.Empty(cacheClosure.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        var verifyCache = Assert.Single(
            typeof(ProductionMailboxNodeCacheVerifier).GetMethods(
                BindingFlags.Public | BindingFlags.Static),
            method => method.Name == "Verify");
        Assert.Equal(cacheClosure, verifyCache.ReturnType);
        Assert.DoesNotContain(
            cacheClosure.GetMethods(BindingFlags.Public | BindingFlags.Instance),
            method => method.ReturnType.Name.Contains("Activation", StringComparison.Ordinal));

        var protectedRestore = typeof(ProductionMailboxRouteHistoryProtectedRestoreContext);
        Assert.Equal(
            protectedRestore,
            typeof(VerifiedProductionMailboxRouteHistoryCursor)
                .GetMethod("ToProtectedRestoreContext")!.ReturnType);
        Assert.Equal(
            protectedRestore,
            typeof(ProductionMailboxRouteHistoryBatchCommitPlan)
                .GetMethod("ToProtectedRestoreContext")!.ReturnType);
    }

    [Fact]
    public void NuGetSourcesAreLocalAndDeepPackagesMapOnlyToSurvivalBeta()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "NuGet.Config"));
        Assert.Contains("<clear", text, StringComparison.Ordinal);
        Assert.Contains("production-protocol-closure", text, StringComparison.Ordinal);
        Assert.Contains("vendor\\production-cc39def\\packages", text, StringComparison.Ordinal);
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
            root, "vendor", "production-cc39def", "package-manifest.json"));
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
                "683f46bcc789f1f4719c86b8be8e5bcfd428ac2f5a55302ee06a2142c8697d78",
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
