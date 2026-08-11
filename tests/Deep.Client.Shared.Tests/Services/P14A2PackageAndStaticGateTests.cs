using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.4.0-production.bb4cd70";
    private const string CarrierVersion = "0.4.0-survival.bb4cd70";
    private const string ProtocolSource =
        "bb4cd70d6166b36c6a46d362c25cbc0f90583882";
    private const string CarrierSource =
        "bb4cd70d6166b36c6a46d362c25cbc0f90583882";
    private static readonly ExpectedPackage[] ExpectedPackages =
    [
        new("Deep.Protocol", ProtocolVersion, 218_896,
            "9ac1d6850574bf6a050633554894802f4d161151381a64e27b1c81105f6ae991",
            "c911d4fed0dd5b91e52d98958709f722a7fe0c1549e30b51cb542a0e6ef6d4367468583def62ed2208c9f12e4790fe69d8d8626d038f2051a0eb532f347672e7",
            "yRHU/tDdW5HlLZiVhwn3Iqf+DBVJ4wtRy1QqDm721DZ0aFg972LtIgjJ8S5HkP5p2NhibQOPIFGg61MvNHZy5w==",
            ProtocolSource),
        new("Deep.Protocol.Abstractions", ProtocolVersion, 24_965,
            "712a4ae4310413ac95678fe28f18f939cb18c755689d9bd32940a95cffd4954c",
            "37030423d9841fc9576d7637d6c0dde219dc314b076b9ee38237ceee1c5e47a02d37fe1fae5f19caf8207997c8b8360e9cb67ee30f93932ebdcdb32336dd0d4e",
            "NwMEI9mEH8lXbXY31sDd4hncMUsHa57jgjfO7hxeR6AtN/4frl8ZyvggeZfIuDYOnLZ+4w+Tky69zbMjNt0NTg==",
            ProtocolSource),
        new("Deep.Protocol.MembershipRoutes", ProtocolVersion, 183_958,
            "08ed475780e66a28905e79e5d5e2699a1dba2e07ca05976cdf2677a8a99fba9b",
            "fd6b4bd35aa4933137cb1859818dae5eae111f46545b6fcf8bf853540d46a111647eea715e0cb1dee268345babe96a3e1343074bf0500a2838ebac95996de1d5",
            "/WtL01qkkzE3yxhZgY2uXq4RH0ZUW2/Pi/hTVA1GoRFkfupxXgyx3uJoNFur6Wo+E0MHS/BQCig466yVmW3h1Q==",
            ProtocolSource),
        new("Deep.Protocol.ProfileCarrier", CarrierVersion, 50_789,
            "5ca9d552afce5bca287fa7c79075e4d029d9b38ae34050037f772794f7ae37db",
            "9cbdafd10bf73840b437f2907d5fc9a9e7352e56b3034ae3c313f4d21638f4c0896c9761de43fe362e1396643c1af08cb37589423b94f690c4a6c9fd1d8dcbe8",
            "nL2v0Qv3OEC0N/KQfV/Jqec1LlazA0rjwxP00hY49MCJbJdh3kP+Ni4TlmQ8GvCMs3WJQjuU9pDEpsn9HY3L6A==",
            CarrierSource),
        new("Deep.Protocol.Protobuf", ProtocolVersion, 50_217,
            "5dbd75fa3a59829c53f03a12f027deca2f9652ec0941644860ec5deaac4358f6",
            "290cb35525a984aef348e01d29f6f73aae79db9430eabc3de472af19b8dcc4774bca54ca7c426620237ce1bcddf4f5a89e3cef7e446455b980401f3cdfc1d3e6",
            "KQyzVSWphK7zSOAdKfb3Oq5525Qw6rw95HKvGbjcxHdLylTKfEJmICN84bzd9PWonjzvfkRkVbmAQB8838HT5g==",
            ProtocolSource)
    ];

    [Fact]
    public void UnifiedSurvivalBetaPackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "production-bb4cd70");
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
                "production-bb4cd70",
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
    public void RouteHistoryProtocolEExposesOnlyNextCommitPlanCapabilities()
    {
        foreach (var capability in new[]
                 {
                     typeof(VerifiedProductionMailboxRouteHistoryCursor),
                     typeof(ProductionMailboxRouteHistoryBatchCommitPlan),
                     typeof(ProductionMailboxRouteHistoryDurableRouteState),
                     typeof(ProductionMailboxRouteHistoryCumulativeState),
                     typeof(ProductionMailboxRouteHistoryFinalArtifacts)
                 })
        {
            Assert.True(capability.IsSealed);
            Assert.Empty(capability.GetConstructors(
                BindingFlags.Public | BindingFlags.Instance));
        }

        var methods = typeof(ProductionMailboxRouteHistoryAuthoring).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        var verify = Assert.Single(methods,
            method => method.Name == "VerifyNextBatchForCommit");
        Assert.Equal(typeof(ProductionMailboxRouteHistoryBatchCommitPlan),
            verify.ReturnType);
        Assert.Contains(verify.GetParameters(), parameter =>
            parameter.ParameterType ==
            typeof(VerifiedProductionMailboxRouteHistoryCursor));
        Assert.DoesNotContain(methods, method => method.Name == "VerifyBatch");
        Assert.DoesNotContain(methods.SelectMany(method => method.GetParameters()),
            parameter => parameter.ParameterType.IsInterface &&
                         parameter.ParameterType.Name.Contains(
                             "Verifier", StringComparison.Ordinal));

        var plan = typeof(ProductionMailboxRouteHistoryBatchCommitPlan);
        Assert.Equal(typeof(ProductionMailboxRouteHistoryDurableRouteState),
            plan.GetProperty("CurrentDurableRouteState")!.PropertyType);
        Assert.Equal(typeof(ProductionMailboxRouteHistoryDurableRouteState),
            plan.GetProperty("NextDurableRouteState")!.PropertyType);
        Assert.Equal(typeof(ProductionMailboxRouteHistoryCumulativeState),
            plan.GetProperty("CurrentCumulativeState")!.PropertyType);
        Assert.Equal(typeof(ProductionMailboxRouteHistoryCumulativeState),
            plan.GetProperty("NextCumulativeState")!.PropertyType);
        Assert.Equal(typeof(ProductionMailboxRouteHistoryFinalArtifacts),
            plan.GetProperty("FinalArtifacts")!.PropertyType);
        Assert.DoesNotContain(plan.GetMethods(
                BindingFlags.Public | BindingFlags.Instance),
            method => method.Name.Contains("Commit", StringComparison.Ordinal) ||
                      method.Name.Contains("Publish", StringComparison.Ordinal) ||
                      method.ReturnType.Name.Contains("Activation", StringComparison.Ordinal));
    }

    [Fact]
    public void OwnerControlProtocolFExposesOnlySegmentedHistoryResponsePlan()
    {
        var methods = typeof(ProductionMailboxOwnerControlTransportCodec).GetMethods(
            BindingFlags.Public | BindingFlags.Static);
        var author = Assert.Single(methods,
            method => method.Name == "AuthorHistoryResponseHeaderAsync");
        Assert.Equal(
            typeof(ValueTask<ProductionMailboxOwnerControlHistoryResponsePlan>),
            author.ReturnType);
        Assert.DoesNotContain(methods,
            method => method.Name == "AuthorHistoryResponseAsync");

        var plan = typeof(ProductionMailboxOwnerControlHistoryResponsePlan);
        Assert.True(plan.IsSealed);
        Assert.Empty(plan.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        var properties = plan.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Assert.Contains(properties,
            property => property.Name == "CanonicalRouteHistoryBatch");
        Assert.Contains(properties,
            property => property.Name == "CanonicalRouteHistoryCheckpoint");
        Assert.DoesNotContain(properties,
            property => property.Name is "CanonicalPayload" or "Payload");
        Assert.DoesNotContain(plan.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .Where(method => !method.IsSpecialName),
            method => method.Name.Contains("Commit", StringComparison.Ordinal)
                      || method.Name.Contains("Publish", StringComparison.Ordinal)
                      || method.ReturnType.Name.Contains("Activation", StringComparison.Ordinal));
    }

    [Fact]
    public void NuGetSourcesAreLocalAndDeepPackagesMapOnlyToSurvivalBeta()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "NuGet.Config"));
        Assert.Contains("<clear", text, StringComparison.Ordinal);
        Assert.Contains("production-protocol-closure", text, StringComparison.Ordinal);
        Assert.Contains("vendor\\production-bb4cd70\\packages", text, StringComparison.Ordinal);
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
            root, "vendor", "production-bb4cd70", "package-manifest.json"));
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
                "5ca9d552afce5bca287fa7c79075e4d029d9b38ae34050037f772794f7ae37db",
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
