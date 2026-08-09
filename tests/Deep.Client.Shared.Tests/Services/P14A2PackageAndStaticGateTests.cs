using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.4.0-production.588229f";
    private const string CarrierVersion = "0.4.0-survival.588229f";
    private const string ProtocolSource =
        "588229f6beed9266382b17ce3c8b9303e3d36b2a";
    private const string CarrierSource =
        "588229f6beed9266382b17ce3c8b9303e3d36b2a";
    private static readonly ExpectedPackage[] ExpectedPackages =
    [
        new("Deep.Protocol", ProtocolVersion, 218_899,
            "026b63904f04bf841348d37732208cc52e13199f6483492eb652c85ae496e498",
            "e3f0d235bc10b73740a3c8950d15f743fbe6c4c207e46ad2727304da24677488ca4d4ab2aea03427a57b9c71993e543ee762c57f3be0079655cda412646f6d94",
            "4/DSNbwQtzdAo8iVDRX3Q/vmxMIH5GrScnME2iRndIjKTUqyrqA0J6V7nHGZPlQ+52LFfzvgB5ZVzaQSZG9tlA==",
            ProtocolSource),
        new("Deep.Protocol.Abstractions", ProtocolVersion, 24_965,
            "1651c6b2bb84b8320fe795920d53cd64e9f0a8b684d97993739f9b107b0e1082",
            "07845043ddbdda11b88505dd9d35d7f5385977cc48ec026645a364da036210b5046cca844c256d57285257b250c62673db265ae8c9f22eaebcb4ebd34af28096",
            "B4RQQ9292hG4hQXdnTXX9ThZd8xI7AJmRaNk2gNiELUEbMqETCVtVyhSV7JQxiZz2yZa6MnyLq68tOvTSvKAlg==",
            ProtocolSource),
        new("Deep.Protocol.MembershipRoutes", ProtocolVersion, 181_181,
            "229a74b058be8a7a4278232833aa28b5afd56e2801f7e8ebef30173a676f8da3",
            "1297be1acf10384af118b4127aa8480228eda613c892709022643b1ba5dd24c5d7c23bec2d96fa49ba97c96d3dfaf5e0da3c32061f9cc1d2d5f9293a2a74ee97",
            "Epe+Gs8QOErxGLQSeqhIAijtphPIknCQImQ7G6XdJMXXwjvsLZb6SbqXyW09+vXg2jwyBh+cwdLV+Sk6KnTulw==",
            ProtocolSource),
        new("Deep.Protocol.ProfileCarrier", CarrierVersion, 49_853,
            "557991ea8a0bf6ffcbffdebfdccb8aebccbad6abc52bdafe25d55b4e534ed676",
            "ea2f21d8a1801503b7c7bba8c599a61522d7ed1b2a3e0ee25ec0cbb68a34be860b2901c912ac2ed4ef5b415b4391966806e06baea6bfbc3436214d7daee7e693",
            "6i8h2KGAFQO3x7uoxZmmFSLX7RsqPg7iXsDLtoo0voYLKQHJEqwu1O9bQVtDkZZoBuBrrqa/vDQ2IU19rufmkw==",
            CarrierSource),
        new("Deep.Protocol.Protobuf", ProtocolVersion, 50_211,
            "309ce298498311d2c3aa001f99a5a72c28fd687223c461402125c194dfe7e75b",
            "1e162b94047ac94a852b79d688f397fbfb7cb6b8a078a88e5aab7bfe4eac8f9ae1c014810e0c52a8b05234f680bbfc580cbcb058cdcf546349bea0712a8b599f",
            "HhYrlAR6yUqFK3nWiPOX+/t8trigeKiOWqt7/k6sj5rhwBSBDgxSqLBSNPaAu/xYDLywWM3PVGNJvqBxKotZnw==",
            ProtocolSource)
    ];

    [Fact]
    public void UnifiedSurvivalBetaPackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "production-588229f");
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
                "production-588229f",
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
    public void NuGetSourcesAreLocalAndDeepPackagesMapOnlyToSurvivalBeta()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "NuGet.Config"));
        Assert.Contains("<clear", text, StringComparison.Ordinal);
        Assert.Contains("production-protocol-closure", text, StringComparison.Ordinal);
        Assert.Contains("vendor\\production-588229f\\packages", text, StringComparison.Ordinal);
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
            root, "vendor", "production-588229f", "package-manifest.json"));
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
                "557991ea8a0bf6ffcbffdebfdccb8aebccbad6abc52bdafe25d55b4e534ed676",
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
