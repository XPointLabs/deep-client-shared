using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2B1ActivationTrustRebindTests
{
    private const string AcceptedVersion = "0.2.0-p14.69a712a";
    private const string AcceptedSource = "69a712a894b024a09859096025c2bb8fe68a642e";
    private const string AcceptedSha256 =
        "fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498";
    private const string AcceptedContentHash =
        "x9LZb8nAUE/XQWQS2ZGBGLbPt2FivGRVc9y1xvlsr02CKHaU6scklrBsOebxj/NiTG66QgFCK7Gd7qFEoRe5zw==";
    private const string AcceptedNormalizedIdentity =
        "baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f";
    private const string OldVersion = "0.1.0-p14.faa598f";

    [Fact]
    public void AcceptedCarrierIsTheOnlyCarrierInTheOfflineClosure()
    {
        var root = P14A2PackageAndStaticGateTests.RepositoryRoot();
        var vendor = Path.Combine(root, "vendor", "p14a2");
        var packageDirectory = Path.Combine(vendor, "packages");
        var acceptedFile = $"Deep.Protocol.ProfileCarrier.{AcceptedVersion}.nupkg";
        var packages = Directory.GetFiles(
                packageDirectory,
                "Deep.Protocol.ProfileCarrier.*.nupkg")
            .Select(Path.GetFileName)
            .ToArray();

        Assert.Equal(new[] { acceptedFile }, packages);

        var packagePath = Path.Combine(packageDirectory, acceptedFile);
        Assert.Equal(29_399, new FileInfo(packagePath).Length);
        Assert.Equal(AcceptedSha256, Sha256(packagePath));
        using var sha512 = SHA512.Create();
        using var packageStream = File.OpenRead(packagePath);
        Assert.Equal(
            AcceptedContentHash,
            Convert.ToBase64String(sha512.ComputeHash(packageStream)));

        using var archive = ZipFile.OpenRead(packagePath);
        var nuspec = Assert.Single(
            archive.Entries,
            entry => entry.FullName == "Deep.Protocol.ProfileCarrier.nuspec");
        using var nuspecStream = nuspec.Open();
        var xml = XDocument.Load(nuspecStream);
        XNamespace ns = xml.Root!.Name.Namespace;
        var metadata = xml.Root.Element(ns + "metadata")!;
        Assert.Equal(AcceptedVersion, metadata.Element(ns + "version")!.Value);
        Assert.Equal(
            AcceptedSource,
            metadata.Element(ns + "repository")!.Attribute("commit")!.Value);
    }

    [Fact]
    public void ProjectLocksAndManifestsBindOnlyTheAcceptedCarrier()
    {
        var root = P14A2PackageAndStaticGateTests.RepositoryRoot();
        var project = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Deep.Client.Shared",
            "Deep.Client.Shared.csproj"));
        Assert.Contains(
            $"Deep.Protocol.ProfileCarrier\" Version=\"[{AcceptedVersion}]",
            project,
            StringComparison.Ordinal);
        Assert.DoesNotContain(OldVersion, project, StringComparison.Ordinal);

        foreach (var relativePath in new[]
                 {
                     Path.Combine("src", "Deep.Client.Shared", "packages.lock.json"),
                     Path.Combine("tests", "Deep.Client.Shared.Tests", "packages.lock.json")
                 })
        {
            var text = File.ReadAllText(Path.Combine(root, relativePath));
            Assert.DoesNotContain(OldVersion, text, StringComparison.Ordinal);
            using var document = JsonDocument.Parse(text);
            var carrier = document.RootElement.GetProperty("dependencies")
                .GetProperty("net10.0")
                .GetProperty("Deep.Protocol.ProfileCarrier");
            Assert.Equal(AcceptedVersion, carrier.GetProperty("resolved").GetString());
            Assert.Equal(AcceptedContentHash, carrier.GetProperty("contentHash").GetString());
        }

        var manifestPath = Path.Combine(
            root,
            "vendor",
            "p14a2",
            "profile-carrier-manifest.json");
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(manifestPath));
        var value = manifest.RootElement;
        Assert.Equal(AcceptedVersion, value.GetProperty("version").GetString());
        Assert.Equal(AcceptedSource, value.GetProperty("sourceCommit").GetString());
        Assert.Equal(AcceptedSha256, value.GetProperty("sha256").GetString());
        Assert.Equal(AcceptedContentHash, value.GetProperty("nugetContentHash").GetString());
        Assert.Equal(
            AcceptedNormalizedIdentity,
            value.GetProperty("normalizedIdentity").GetString());

        var closure = File.ReadAllText(Path.Combine(
            root,
            "vendor",
            "p14a2",
            "offline-closure-manifest.json"));
        Assert.DoesNotContain(OldVersion, closure, StringComparison.Ordinal);
        Assert.Contains(AcceptedVersion, closure, StringComparison.Ordinal);

        var hashes = File.ReadAllText(Path.Combine(
            root,
            "vendor",
            "p14a2",
            "package-content-hashes.json"));
        Assert.DoesNotContain(OldVersion, hashes, StringComparison.Ordinal);
        Assert.Contains(AcceptedContentHash, hashes, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("0.2.0-p14.invalid", AcceptedSha256, AcceptedContentHash)]
    [InlineData(AcceptedVersion,
        "0000000000000000000000000000000000000000000000000000000000000000",
        AcceptedContentHash)]
    [InlineData(AcceptedVersion, AcceptedSha256,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")]
    public void AcceptedBindingRejectsSyntheticVersionOrHashDrift(
        string version,
        string sha256,
        string contentHash)
    {
        Assert.Throws<InvalidDataException>(() => AssertAcceptedBinding(
            version,
            sha256,
            contentHash,
            AcceptedNormalizedIdentity,
            AcceptedSource));
    }

    private static void AssertAcceptedBinding(
        string version,
        string sha256,
        string contentHash,
        string normalizedIdentity,
        string source)
    {
        if (!string.Equals(version, AcceptedVersion, StringComparison.Ordinal)
            || !string.Equals(sha256, AcceptedSha256, StringComparison.Ordinal)
            || !string.Equals(contentHash, AcceptedContentHash, StringComparison.Ordinal)
            || !string.Equals(
                normalizedIdentity,
                AcceptedNormalizedIdentity,
                StringComparison.Ordinal)
            || !string.Equals(source, AcceptedSource, StringComparison.Ordinal))
        {
            throw new InvalidDataException("P14A2B1 carrier binding is not exact.");
        }
    }

    private static string Sha256(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
}
