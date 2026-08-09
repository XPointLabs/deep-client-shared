using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.4.0-production.2eb8b1e";
    private const string CarrierVersion = "0.4.0-survival.2eb8b1e";
    private const string ProtocolSource =
        "2eb8b1eb4605216b239f63d1ad8e587a28918134";
    private const string CarrierSource =
        "2eb8b1eb4605216b239f63d1ad8e587a28918134";
    private static readonly ExpectedPackage[] ExpectedPackages =
    [
        new("Deep.Protocol", ProtocolVersion, 218_772,
            "247a90915853b274f95f2e2aa69b71689f666d95a29150f45152326988104a8b",
            "ee85f1aa2078221d4f8f91f73133004dbad997d10f736fdc39836a7696ec6d578959ee1b494b6345b57dd957ac95374618cb72e630412bb82431231304c5177b",
            "7oXxqiB4Ih1Pj5H3MTMATbrZl9EPc2/cOYNqdpbsbVeJWe4bSUtjRbV92VeslTdGGMty5jBBK7gkMSMTBMUXew==",
            ProtocolSource),
        new("Deep.Protocol.Abstractions", ProtocolVersion, 24_930,
            "66cd9b24bd441daaf9127700d52e577749cb67ed4ba9ab87ce416f1de65dac79",
            "a9de2f1fd7095f8f5b3ba9528ee7b075aab9b4e7116005e3a0cbf760ff0739ca91623600e7d40b19a9a9c6a435de315db65115cd1a29e9e726e068eb51215817",
            "qd4vH9cJX49bO6lSjuewdaq5tOcRYAXjoMv3YP8HOcqRYjYA59QLGampxqQ13jFdtlEVzRop6ecm4GjrUSFYFw==",
            ProtocolSource),
        new("Deep.Protocol.MembershipRoutes", ProtocolVersion, 175_350,
            "cf5651b70f66a0e18b43e40274021fa948414aa300c4ce8ba63889f5638dc5c3",
            "fdbf6581d9a8affad57ed4bd63d66c9d1759668f5e46de5d6d7138d18a090597761388cc72e72ac8c02b11bf9d1bb0c37297eeb5153a684e2034ed0b41398b38",
            "/b9lgdmor/rVftS9Y9ZsnRdZZo9eRt5dbXE40YoJBZd2E4jMcucqyMArEb+dG7DDcpfutRU6aE4gNO0LQTmLOA==",
            ProtocolSource),
        new("Deep.Protocol.ProfileCarrier", CarrierVersion, 49_708,
            "9aa96a224d8797be3436c998c8f8b1a8e06168323eb8aa09e1d2ea984182ab08",
            "9cf478761b9d9e2cbf8fff64e6a5ed750ebc86010dd752d5bd2e0d0a456ecef215fdcd893700008e0962d6f326d763d7952f495ac9d7c14140c9fa3c4888ec69",
            "nPR4dhudniy/j/9k5qXtdQ68hgEN11LVvS4NCkVuzvIV/c2JNwAAjgli1vMm12PXlS9JWsnXwUFAyfo8SIjsaQ==",
            CarrierSource),
        new("Deep.Protocol.Protobuf", ProtocolVersion, 50_183,
            "8f8fdd8e0fd7e09e55a7eec95ef190e50d9c7235a769b5407f85adee36d6cfb7",
            "7c3c10a1f5b25e21597eec44ab2d57fff1e17a83928e4b8e91e871af24ee83366cd8edce5c12aaf3f3d637002e2a0653da08ed0fd0bb27980ab0723a06e67b78",
            "fDwQofWyXiFZfuxEqy1X//HheoOSjkuOkehxryTugzZs2O3OXBKq8/PWNwAuKgZT2gjtD9C7J5gKsHI6BuZ7eA==",
            ProtocolSource)
    ];

    [Fact]
    public void UnifiedSurvivalBetaPackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "production-2eb8b1e");
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
                "production-2eb8b1e",
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
                     typeof(VerifiedProductionMailboxOwnerControlResponseHeader),
                     typeof(VerifiedProductionMailboxRouteContinuityGenesisIntent),
                     typeof(ProductionMailboxRouteContinuityGenesisCommitPlan)
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

        var issuer = typeof(ProductionMailboxRouteIssuerAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        Assert.Single(issuer, method => method.Name == "VerifyGenesisIntent");
        var authorGenesis = Assert.Single(
            issuer, method => method.Name == "AuthorGenesisAsync");
        Assert.DoesNotContain(authorGenesis.GetParameters(), parameter =>
            parameter.ParameterType.Name.Contains("Commit", StringComparison.Ordinal)
            || parameter.ParameterType.Name.Contains("Store", StringComparison.Ordinal));
        Assert.DoesNotContain(issuer, method => method.Name is
            "AcceptDelegationAsync"
            or "AuthorOwnerControlResponderCertificateAsync"
            or "CreateHistoricalAnchor");

        var history = typeof(ProductionMailboxRouteHistoryAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        Assert.DoesNotContain(history, method => method.Name == "CreateInitialCursor");
        var restoreCursor = Assert.Single(
            history, method => method.Name == "RestoreCursor");
        Assert.Contains(restoreCursor.GetParameters(), parameter =>
            parameter.ParameterType ==
            typeof(VerifiedProductionMailboxHistoricalRouteAnchor));
        Assert.DoesNotContain(
            typeof(ProductionMailboxRouteContinuityGenesisCommitPlan).GetMethods(
                BindingFlags.Public | BindingFlags.Instance),
            method => method.ReturnType.Name.StartsWith(
                          "Verified", StringComparison.Ordinal)
                      || method.Name.Contains("Publish", StringComparison.Ordinal)
                      || method.Name is "Commit" or "CommitAsync");

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
        Assert.Contains("vendor\\production-2eb8b1e\\packages", text, StringComparison.Ordinal);
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
            root, "vendor", "production-2eb8b1e", "package-manifest.json"));
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
                "9aa96a224d8797be3436c998c8f8b1a8e06168323eb8aa09e1d2ea984182ab08",
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
