using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.4.0-production.62fd84a";
    private const string CarrierVersion = "0.4.0-survival.62fd84a";
    private const string ProtocolSource =
        "62fd84a36580855a64307bf8020ce6a94d4ac741";
    private const string CarrierSource =
        "62fd84a36580855a64307bf8020ce6a94d4ac741";
    private static readonly ExpectedPackage[] ExpectedPackages =
    [
        new("Deep.Protocol", ProtocolVersion, 218_813,
            "a1620cd62f12bcf62052c666445be46e453312d4a50d13d2dd44dff0594a0e51",
            "a2d278d19de0e3b2fae77a2f4e290f178fa60853db92e23e774aa3e80da8c4b172da3b36afcd8ff892d105d12a1d01dea5a5e433f0513e5bc974ceb8f6526d3a",
            "otJ40Z3g47L653ovTikPF4+mCFPbkuI+d0qj6A2oxLFy2js2r82P+JLRBdEqHQHepaXkM/BRPlvJdM649lJtOg==",
            ProtocolSource),
        new("Deep.Protocol.Abstractions", ProtocolVersion, 24_968,
            "e0cffcf86d2340611a8c3fa68acb7d0d44f4cacd97be3c0059f528375108743c",
            "7797a5f499fe07dbed98c28be0283195afbeb518046dcaf85dcc30a6e76f9ccbf00bdc7106534257780e4dd747512e75e9af5811b49184b43d9aeb3d4907356d",
            "d5el9Jn+B9vtmMKL4Cgxla++tRgEbcr4XcwwpudvnMvwC9xxBlNCV3gOTddHUS516a9YEbSRhLQ9mus9SQc1bQ==",
            ProtocolSource),
        new("Deep.Protocol.MembershipRoutes", ProtocolVersion, 170_466,
            "e30511a9ec0541d957094a0be527c689cc6de4a7455bd81bd20b1bbb0082cafb",
            "c364563e2d3ca5cdbe8eaba10865a9fafd2fd3edfb25c05ef340a56553f54bbbaf9a94e18e1809b84e099eba531ca4ad1c7c751d837bf595745b6e3088651741",
            "w2RWPi08pc2+jquhCGWp+v0v0+37JcBe80ClZVP1S7uvmpThjhgJuE4JnrpTHKStHHx1HYN79ZV0W24wiGUXQQ==",
            ProtocolSource),
        new("Deep.Protocol.ProfileCarrier", CarrierVersion, 49_710,
            "cc2bbc8a28543451ab56af7b20b24a67fedda6da80d4565ae63282458347ed78",
            "bd9a8b0b892ce68a77aa381b7bde31ca4851f8f613b841144bae9ad2bdaeedd5a4a96f8ff62ee8b064521af504a101df4e1c458ad58ec462180455537b464b84",
            "vZqLC4ks5op3qjgbe94xykhR+PYTuEEUS66a0r2u7dWkqW+P9i7osGRSGvUEoQHfThxFitWOxGIYBFVTe0ZLhA==",
            CarrierSource),
        new("Deep.Protocol.Protobuf", ProtocolVersion, 50_216,
            "e10b612ea9913e18ae1f059de37fe9c9a67aadfa6bd4b2cd219a74749d5d403e",
            "2215aa681cc4f0f3c01593108a47f8db6d7890b23c399ede6705bea7f57c925e301430a691ebb76df1cb4d6e5cbb6436a2ef78afc8920a8f682cad9b8cb32071",
            "IhWqaBzE8PPAFZMQikf42214kLI8OZ7eZwW+p/V8kl4wFDCmkeu3bfHLTW5cu2Q2ou94r8iSCo9oLK2bjLMgcQ==",
            ProtocolSource)
    ];

    [Fact]
    public void UnifiedSurvivalBetaPackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "production-62fd84a");
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
                "production-62fd84a",
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
    public void RouteContinuitySliceDExposesOnlySealedCryptoCapabilities()
    {
        foreach (var capability in new[]
                 {
                     typeof(VerifiedProductionMailboxHistoricalRouteAnchor),
                     typeof(VerifiedProductionMailboxLiveTransition),
                     typeof(VerifiedProductionMailboxOwnerControlRequest),
                     typeof(VerifiedProductionMailboxOwnerControlResponse),
                     typeof(VerifiedProductionMailboxOwnerControlResponseHeader)
                 })
        {
            Assert.True(capability.IsSealed);
            Assert.Empty(capability.GetConstructors(
                BindingFlags.Public | BindingFlags.Instance));
        }

        var liveMethods = typeof(ProductionMailboxLiveTransitionAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        Assert.Equal(4, liveMethods.Length);
        Assert.All(liveMethods, method =>
        {
            Assert.DoesNotContain(method.GetParameters(), parameter =>
                parameter.ParameterType.Name.Contains("Committer", StringComparison.Ordinal)
                || parameter.ParameterType.IsInterface
                && parameter.ParameterType.Name.Contains("Verifier", StringComparison.Ordinal));
            Assert.DoesNotContain(method.GetParameters(), parameter =>
                parameter.ParameterType == typeof(ProductionMailboxSelectionSuccessorMode)
                || parameter.ParameterType ==
                typeof(ProductionMailboxRouteAuthorizationKind));
        });

        Assert.DoesNotContain(
            typeof(ProductionMailboxSelectionSuccessorAuthoring).GetMethods(
                BindingFlags.Public | BindingFlags.Static),
            method => method.Name is "AuthorDirectAsync" or "AuthorOfflineAsync");
        Assert.DoesNotContain(
            typeof(ProductionMailboxRouteIssuerAuthoring).GetMethods(
                BindingFlags.Public | BindingFlags.Static),
            method => method.Name == "CreateSelectionTransitionIntent");

        var transport = typeof(ProductionMailboxOwnerControlTransportCodec).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        Assert.DoesNotContain(transport, method =>
            method.Name is "ReadFinalActivationAsync" or "ReadHistoryPayloadAsync");
        Assert.Contains(transport, method =>
            method.Name == "ReadVerifiedResponsePayloadAsync"
            && method.GetParameters().Any(parameter =>
                parameter.ParameterType ==
                typeof(VerifiedProductionMailboxOwnerControlResponseHeader)));

        Assert.Equal(272,
            ProductionMailboxOwnerControlConstants.ResponderCertificateLength);
        Assert.Equal(344, ProductionMailboxOwnerControlConstants.RequestLength);
        Assert.Equal(384,
            ProductionMailboxOwnerControlConstants.ResponseHeaderLength);
        Assert.Equal(48,
            ProductionMailboxOwnerControlConstants.FinalActivationHeaderLength);
    }

    [Fact]
    public void NuGetSourcesAreLocalAndDeepPackagesMapOnlyToSurvivalBeta()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "NuGet.Config"));
        Assert.Contains("<clear", text, StringComparison.Ordinal);
        Assert.Contains("production-protocol-closure", text, StringComparison.Ordinal);
        Assert.Contains("vendor\\production-62fd84a\\packages", text, StringComparison.Ordinal);
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
            root, "vendor", "production-62fd84a", "package-manifest.json"));
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
                "cc2bbc8a28543451ab56af7b20b24a67fedda6da80d4565ae63282458347ed78",
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
