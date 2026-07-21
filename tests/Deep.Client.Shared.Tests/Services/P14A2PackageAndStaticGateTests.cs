using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    [Fact]
    public void ExactCarrierPackageAndAcceptedProducerArePinned()
    {
        var root = RepositoryRoot();
        var vendor = Path.Combine(root, "vendor", "p14a2");
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(vendor, "profile-carrier-manifest.json")));
        var value = manifest.RootElement;
        Assert.Equal("deep-client-p14a2-profile-carrier-package.v1",
            value.GetProperty("schema").GetString());
        Assert.Equal("0.1.0-p14.faa598f", value.GetProperty("version").GetString());
        Assert.Equal("faa598ff32913470cf85d6f2c8a8921cbf2aa287",
            value.GetProperty("sourceCommit").GetString());
        Assert.Equal("5b895ced820d678e6957482989f74621322a7bb0661ede13dcb3184e4f3e960e",
            value.GetProperty("sha256").GetString());
        var package = Path.Combine(vendor, value.GetProperty("file").GetString()!);
        Assert.Equal(24_597, new FileInfo(package).Length);
        Assert.Equal(value.GetProperty("sha256").GetString(), Sha256(package));

        using var archive = ZipFile.OpenRead(package);
        var nuspec = Assert.Single(archive.Entries,
            entry => entry.FullName == "Deep.Protocol.ProfileCarrier.nuspec");
        using var stream = nuspec.Open();
        var xml = XDocument.Load(stream);
        XNamespace ns = xml.Root!.Name.Namespace;
        var metadata = xml.Root.Element(ns + "metadata")!;
        Assert.Equal("faa598ff32913470cf85d6f2c8a8921cbf2aa287",
            metadata.Element(ns + "repository")!.Attribute("commit")!.Value);
        var dependency = Assert.Single(metadata.Descendants(ns + "dependency"));
        Assert.Equal("Deep.Protocol", dependency.Attribute("id")!.Value);
        Assert.Equal("[0.3.0-p04.b887fa0]", dependency.Attribute("version")!.Value);

        var project = File.ReadAllText(Path.Combine(root, "src", "Deep.Client.Shared", "Deep.Client.Shared.csproj"));
        Assert.Contains("Deep.Protocol.ProfileCarrier\" Version=\"[0.1.0-p14.faa598f]", project);
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
            Assert.Equal("0.1.0-p14.faa598f", carrier.GetProperty("resolved").GetString());
            Assert.Equal(
                "XV6HBDrOAQKVp9jQDirlxIO1QrdWIFhMuF5ij8HGavGPCMhIvOTHwTwn/bDuSTsMfmQ0BJDDC+RH+VE8BtqR5Q==",
                carrier.GetProperty("contentHash").GetString());
            if (carrier.GetProperty("type").GetString() == "Direct")
            {
                Assert.Equal("[0.1.0-p14.faa598f, 0.1.0-p14.faa598f]",
                    carrier.GetProperty("requested").GetString());
            }
        }
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
            manifestText.Replace("0.1.0-p14.faa598f", "0.1.0-p14.invalid", StringComparison.Ordinal),
            projectText));
        Assert.Throws<InvalidDataException>(() => AssertCarrierPin(
            manifestText.Replace(
                "5b895ced820d678e6957482989f74621322a7bb0661ede13dcb3184e4f3e960e",
                new string('0', 64), StringComparison.Ordinal),
            projectText));
        Assert.Throws<InvalidDataException>(() => AssertCarrierPin(
            manifestText,
            projectText + "<ProjectReference Include=\"synthetic\" />"));
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
        if (manifest.GetProperty("version").GetString() != "0.1.0-p14.faa598f"
            || manifest.GetProperty("sha256").GetString()
                != "5b895ced820d678e6957482989f74621322a7bb0661ede13dcb3184e4f3e960e"
            || !projectText.Contains(
                "Deep.Protocol.ProfileCarrier\" Version=\"[0.1.0-p14.faa598f]",
                StringComparison.Ordinal)
            || projectText.Contains("ProjectReference", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Carrier pin validation failed.");
        }
    }

    internal static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Deep.Client.Shared.slnx")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Repository root missing.");
    }
}
