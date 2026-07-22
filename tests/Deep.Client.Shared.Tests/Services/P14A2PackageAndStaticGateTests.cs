using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string CarrierVersion = "0.2.0-p14.69a712a";
    private const string CarrierSource = "69a712a894b024a09859096025c2bb8fe68a642e";
    private const string CarrierSourceTree = "d83bbdd001b723738357689bbb2150a51357cb3b";
    private const string CarrierEvidence = "071b5b300bcba3796d621720fb8f21cfdd5eb882";
    private const string CarrierEvidenceTree = "ecbfc7747452709fb82aaf85fa912ba13b61d4ad";
    private const string CarrierSha256 =
        "fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498";
    private const string CarrierContentHash =
        "x9LZb8nAUE/XQWQS2ZGBGLbPt2FivGRVc9y1xvlsr02CKHaU6scklrBsOebxj/NiTG66QgFCK7Gd7qFEoRe5zw==";
    private const string CarrierNormalizedIdentity =
        "baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f";
    private const string CarrierDllSha256 =
        "20489ac15239af11207a0daa670545b975c03eaebb78297adf956af45daa7034";
    private const string CarrierPdbSha256 =
        "80f2210e6c61050e2a4edbbf1fa4181ca0d7285d124073fa0d9aa9a77307542a";
    private const string CarrierFile =
        "packages/Deep.Protocol.ProfileCarrier.0.2.0-p14.69a712a.nupkg";
    private const string CarrierStatus =
        "P14A2B1-SOURCE-REVIEW-PENDING / STAGED-BYTES-ONLY / " +
        "CLIENT-RUNTIME-REGISTRATION-NO-GO / PROFILE-ACTIVATION-NO-GO";

    [Fact]
    public void ExactCarrierPackageAndAcceptedProducerArePinned()
    {
        var root = RepositoryRoot();
        var vendor = Path.Combine(root, "vendor", "p14a2");
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(vendor, "profile-carrier-manifest.json")));
        var value = manifest.RootElement;
        Assert.Equal("deep-client-p14a2b1-profile-carrier-package.v1",
            value.GetProperty("schema").GetString());
        Assert.Equal(CarrierVersion, value.GetProperty("version").GetString());
        Assert.Equal(CarrierSource,
            value.GetProperty("sourceCommit").GetString());
        Assert.Equal(CarrierSourceTree, value.GetProperty("sourceTree").GetString());
        Assert.Equal(CarrierEvidence, value.GetProperty("evidenceCommit").GetString());
        Assert.Equal(CarrierEvidenceTree, value.GetProperty("evidenceTree").GetString());
        Assert.Equal(CarrierSha256, value.GetProperty("sha256").GetString());
        Assert.Equal(
            CarrierNormalizedIdentity,
            value.GetProperty("normalizedIdentity").GetString());
        Assert.Equal(CarrierDllSha256, value.GetProperty("dllSha256").GetString());
        Assert.Equal(CarrierPdbSha256, value.GetProperty("pdbSha256").GetString());
        Assert.Equal(CarrierStatus, value.GetProperty("status").GetString());
        Assert.Equal(
            new[]
            {
                ("Deep.Protocol", "[0.3.0-p04.b887fa0]"),
                ("Sodium.Core", "[1.4.1]"),
                ("libsodium", "[1.0.22]")
            },
            value.GetProperty("dependencies")
                .EnumerateArray()
                .Select(dependency => (
                    dependency.GetProperty("id").GetString()!,
                    dependency.GetProperty("version").GetString()!))
                .OrderBy(dependency => dependency.Item1, StringComparer.Ordinal)
                .ToArray());
        var package = Path.Combine(vendor, value.GetProperty("file").GetString()!);
        Assert.Equal(29_399, new FileInfo(package).Length);
        Assert.Equal(value.GetProperty("sha256").GetString(), Sha256(package));

        using var archive = ZipFile.OpenRead(package);
        var nuspec = Assert.Single(archive.Entries,
            entry => entry.FullName == "Deep.Protocol.ProfileCarrier.nuspec");
        using var stream = nuspec.Open();
        var xml = XDocument.Load(stream);
        XNamespace ns = xml.Root!.Name.Namespace;
        var metadata = xml.Root.Element(ns + "metadata")!;
        Assert.Equal(CarrierSource,
            metadata.Element(ns + "repository")!.Attribute("commit")!.Value);
        var dependencies = metadata.Descendants(ns + "dependency")
            .Select(dependency => (
                Id: dependency.Attribute("id")!.Value,
                Version: dependency.Attribute("version")!.Value))
            .OrderBy(dependency => dependency.Id, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            new[]
            {
                ("Deep.Protocol", "[0.3.0-p04.b887fa0]"),
                ("Sodium.Core", "[1.4.1]"),
                ("libsodium", "[1.0.22]")
            },
            dependencies);

        Assert.Equal(CarrierDllSha256, Sha256(ArchiveEntry(archive,
            "lib/net10.0/Deep.Protocol.ProfileCarrier.dll")));
        Assert.Equal(CarrierPdbSha256, Sha256(ArchiveEntry(archive,
            "lib/net10.0/Deep.Protocol.ProfileCarrier.pdb")));

        var project = File.ReadAllText(Path.Combine(root, "src", "Deep.Client.Shared", "Deep.Client.Shared.csproj"));
        Assert.Contains($"Deep.Protocol.ProfileCarrier\" Version=\"[{CarrierVersion}]", project);
        Assert.DoesNotContain("ProjectReference", project, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void VendorClosureIsExactHashAndContentHashBijection()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "p14a2");
        using var closureDocument = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(vendor, "offline-closure-manifest.json")));
        using var contentDocument = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(vendor, "package-content-hashes.json")));
        var packages = closureDocument.RootElement.GetProperty("packages")
            .EnumerateArray().ToArray();
        var content = contentDocument.RootElement.GetProperty("packages");
        var files = Directory.GetFiles(Path.Combine(vendor, "packages"), "*.nupkg")
            .Select(Path.GetFileName).Order(StringComparer.OrdinalIgnoreCase).ToArray();
        var manifestFiles = packages.Select(value =>
                Path.GetFileName(value.GetProperty("file").GetString()!))
            .Order(StringComparer.OrdinalIgnoreCase).ToArray();

        Assert.Equal(29, packages.Length);
        Assert.True(files.SequenceEqual(manifestFiles, StringComparer.OrdinalIgnoreCase));
        Assert.True(files.SequenceEqual(
            content.EnumerateObject().Select(value => value.Name)
                .Order(StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase));
        foreach (var package in packages)
        {
            var file = Path.GetFileName(package.GetProperty("file").GetString()!);
            var path = Path.Combine(vendor, "packages", file);
            Assert.Equal(package.GetProperty("bytes").GetInt64(), new FileInfo(path).Length);
            Assert.Equal(package.GetProperty("sha256").GetString(), Sha256(path));
            using var sha = SHA512.Create();
            using var stream = File.OpenRead(path);
            Assert.Equal(content.GetProperty(file).GetString(),
                Convert.ToBase64String(sha.ComputeHash(stream)));
        }
        Assert.Equal("cd9d20a8ec8346d171d4cd070dde170aa5f471d7",
            closureDocument.RootElement.GetProperty("acceptedP14C2SourceCommit").GetString());
        Assert.Equal(CarrierSource,
            closureDocument.RootElement.GetProperty("acceptedP14E2SourceCommit").GetString());
        Assert.Equal(CarrierSourceTree,
            closureDocument.RootElement.GetProperty("acceptedP14E2SourceTree").GetString());
        Assert.Equal(CarrierEvidence,
            closureDocument.RootElement.GetProperty("acceptedP14E2EvidenceCommit").GetString());
        Assert.Equal(CarrierEvidenceTree,
            closureDocument.RootElement.GetProperty("acceptedP14E2EvidenceTree").GetString());
        Assert.Equal(CarrierSha256,
            closureDocument.RootElement.GetProperty("acceptedP14E2PackageSha256").GetString());
        Assert.Equal(CarrierNormalizedIdentity,
            closureDocument.RootElement.GetProperty("acceptedP14E2NormalizedIdentity").GetString());
    }

    [Fact]
    public void CarrierLocksPinExactVersionAndNuGetContentHash()
    {
        var root = RepositoryRoot();
        foreach (var relativePath in new[]
                 {
                     Path.Combine("src", "Deep.Client.Shared", "packages.lock.json"),
                     Path.Combine("tests", "Deep.Client.Shared.Tests", "packages.lock.json")
                 })
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, relativePath)));
            var carrier = document.RootElement.GetProperty("dependencies").GetProperty("net10.0")
                .GetProperty("Deep.Protocol.ProfileCarrier");
            Assert.Equal(CarrierVersion, carrier.GetProperty("resolved").GetString());
            Assert.Equal(CarrierContentHash, carrier.GetProperty("contentHash").GetString());
            var dependencies = carrier.GetProperty("dependencies");
            Assert.Equal(3, dependencies.EnumerateObject().Count());
            Assert.Equal("[0.3.0-p04.b887fa0]",
                dependencies.GetProperty("Deep.Protocol").GetString());
            Assert.Equal("[1.4.1]", dependencies.GetProperty("Sodium.Core").GetString());
            Assert.Equal("[1.0.22]", dependencies.GetProperty("libsodium").GetString());
            if (carrier.GetProperty("type").GetString() == "Direct")
            {
                Assert.Equal($"[{CarrierVersion}, {CarrierVersion}]",
                    carrier.GetProperty("requested").GetString());
            }
        }
    }

    [Fact]
    public void SourceLockPinsOfflineWinArm64RuntimeClosure()
    {
        var projectText = File.ReadAllText(Path.Combine(
            RepositoryRoot(), "src", "Deep.Client.Shared", "Deep.Client.Shared.csproj"));
        Assert.Contains(
            "<RuntimeIdentifiers>win-arm64</RuntimeIdentifiers>",
            projectText,
            StringComparison.Ordinal);

        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(
            RepositoryRoot(), "src", "Deep.Client.Shared", "packages.lock.json")));
        var runtime = document.RootElement.GetProperty("dependencies")
            .GetProperty("net10.0/win-arm64");

        AssertRuntimePackage(
            runtime,
            "libsodium",
            "1.0.22",
            "KPD9SloJFclrsjnhABu7dzWrcyYkwPbvx5l1gRSPAX/0n+OBtSiVCKtGFv4n+ecWUHU0tCG9LSSwoZZx673zBQ==");
        AssertRuntimePackage(
            runtime,
            "SQLitePCLRaw.lib.e_sqlcipher",
            "2.1.11",
            "Cg6UPeDbH8jyaOs1vqXYIgeewH0wYrBnmbC5Ml3GYBo+GKzNmyxrWSO52JV68bfB7Addt/PZLMekJV1RH2ftWQ==");
        Assert.Equal(2, runtime.EnumerateObject().Count());
    }

    [Fact]
    public void CarrierPinNegativeControlsRejectAlteredVersionShaAndProjectReference()
    {
        var root = RepositoryRoot();
        var manifestText = File.ReadAllText(Path.Combine(
            root, "vendor", "p14a2", "profile-carrier-manifest.json"));
        var projectText = File.ReadAllText(Path.Combine(
            root, "src", "Deep.Client.Shared", "Deep.Client.Shared.csproj"));

        AssertCarrierPin(manifestText, projectText);
        Assert.Throws<InvalidDataException>(() => AssertCarrierPin(
            manifestText.Replace(CarrierVersion, "0.2.0-p14.invalid", StringComparison.Ordinal),
            projectText));
        Assert.Throws<InvalidDataException>(() => AssertCarrierPin(
            manifestText.Replace(
                CarrierSha256,
                new string('0', 64), StringComparison.Ordinal),
            projectText));
        Assert.Throws<InvalidDataException>(() => AssertCarrierPin(
            manifestText,
            projectText + "<ProjectReference Include=\"synthetic\" />"));
        foreach (var drifted in new[]
                 {
                     manifestText.Replace(CarrierFile, "packages/drift.nupkg",
                         StringComparison.Ordinal),
                     manifestText.Replace(CarrierContentHash, new string('A', 88),
                         StringComparison.Ordinal),
                     manifestText.Replace(CarrierNormalizedIdentity, new string('0', 64),
                         StringComparison.Ordinal),
                     manifestText.Replace(CarrierSource, new string('0', 40),
                         StringComparison.Ordinal),
                     manifestText.Replace(CarrierEvidence, new string('1', 40),
                         StringComparison.Ordinal),
                     manifestText.Replace(CarrierDllSha256, new string('2', 64),
                         StringComparison.Ordinal),
                     manifestText.Replace(CarrierPdbSha256, new string('3', 64),
                         StringComparison.Ordinal),
                     manifestText.Replace("[1.0.22]", "[1.0.0,2.0.0)",
                         StringComparison.Ordinal),
                     manifestText.Replace(
                         "\"id\": \"libsodium\"",
                         "\"id\": \"unexpected\"",
                         StringComparison.Ordinal),
                     manifestText.Replace(CarrierStatus, "PRODUCTION-READY",
                         StringComparison.Ordinal)
                 })
        {
            Assert.Throws<InvalidDataException>(() => AssertCarrierPin(drifted, projectText));
        }
    }

    [Fact]
    public void OfflineGateIsClientNamedAndContainsNoXNodePath()
    {
        var root = RepositoryRoot();
        foreach (var path in Directory.GetFiles(Path.Combine(root, "eng", "scripts"), "*P14A2*"))
            Assert.DoesNotContain("xnode", File.ReadAllText(path), StringComparison.OrdinalIgnoreCase);
        foreach (var path in Directory.GetFiles(Path.Combine(root, "vendor", "p14a2"), "*.json"))
            Assert.DoesNotContain("xnode", File.ReadAllText(path), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProductionGraphIsDormantAndUsesOnlySharedVerifier()
    {
        var root = RepositoryRoot();
        var path = Path.Combine(root, "src", "Deep.Client.Shared", "Services",
            "DormantSelfHostedProfileVerificationService.cs");
        var source = File.ReadAllText(path);
        Assert.Contains("ProfileCarrierVerifier.VerifyExact", source);
        foreach (var forbidden in new[]
                 {
                     "MembershipContractVerifier", "ImportSelfHostedGenesis", "DSIG",
                     "ClientRuntime", "HttpClient", "ILogger", "Console.", "wallet",
                     "billing", "subscription", "entitlement", "XPNT", "endpoint"
                 })
        {
            Assert.DoesNotContain(forbidden, source, StringComparison.OrdinalIgnoreCase);
        }
        var runtime = File.ReadAllText(Path.Combine(root, "src", "Deep.Client.Shared", "State", "ClientRuntime.cs"));
        Assert.DoesNotContain("DormantSelfHostedProfileVerification", runtime);
    }

    private static string Sha256(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    private static void AssertCarrierPin(string manifestText, string projectText)
    {
        using var document = JsonDocument.Parse(manifestText);
        var manifest = document.RootElement;
        var dependencies = manifest.GetProperty("dependencies")
            .EnumerateArray()
            .Select(dependency => (
                Id: dependency.GetProperty("id").GetString()!,
                Version: dependency.GetProperty("version").GetString()!))
            .OrderBy(dependency => dependency.Id, StringComparer.Ordinal)
            .ToArray();
        var expectedDependencies = new[]
        {
            (Id: "Deep.Protocol", Version: "[0.3.0-p04.b887fa0]"),
            (Id: "Sodium.Core", Version: "[1.4.1]"),
            (Id: "libsodium", Version: "[1.0.22]")
        };
        if (manifest.GetProperty("version").GetString() != CarrierVersion
            || manifest.GetProperty("file").GetString() != CarrierFile
            || manifest.GetProperty("bytes").GetInt64() != 29_399
            || manifest.GetProperty("sha256").GetString() != CarrierSha256
            || manifest.GetProperty("nugetContentHash").GetString() != CarrierContentHash
            || manifest.GetProperty("normalizedIdentity").GetString()
                != CarrierNormalizedIdentity
            || manifest.GetProperty("sourceCommit").GetString() != CarrierSource
            || manifest.GetProperty("sourceTree").GetString() != CarrierSourceTree
            || manifest.GetProperty("evidenceCommit").GetString() != CarrierEvidence
            || manifest.GetProperty("evidenceTree").GetString() != CarrierEvidenceTree
            || manifest.GetProperty("dllSha256").GetString() != CarrierDllSha256
            || manifest.GetProperty("pdbSha256").GetString() != CarrierPdbSha256
            || manifest.GetProperty("status").GetString() != CarrierStatus
            || !dependencies.SequenceEqual(expectedDependencies)
            || !projectText.Contains(
                $"Deep.Protocol.ProfileCarrier\" Version=\"[{CarrierVersion}]",
                StringComparison.Ordinal)
            || projectText.Contains("ProjectReference", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Carrier pin validation failed.");
        }
    }

    private static byte[] ArchiveEntry(ZipArchive archive, string name)
    {
        var entry = Assert.Single(archive.Entries, value => value.FullName == name);
        using var stream = entry.Open();
        using var memory = new MemoryStream((int)entry.Length);
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    private static string Sha256(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static void AssertRuntimePackage(
        JsonElement runtime,
        string id,
        string version,
        string contentHash)
    {
        var package = runtime.GetProperty(id);
        Assert.Equal("Transitive", package.GetProperty("type").GetString());
        Assert.Equal(version, package.GetProperty("resolved").GetString());
        Assert.Equal(contentHash, package.GetProperty("contentHash").GetString());
    }

    internal static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Deep.Client.Shared.slnx")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Repository root missing.");
    }
}
