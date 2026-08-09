using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2B1ActivationTrustRebindTests
{
    private const string AcceptedVersion = "0.4.0-survival.588229f";
    private const string AcceptedSource = "588229f6beed9266382b17ce3c8b9303e3d36b2a";
    private const string AcceptedSha256 =
        "557991ea8a0bf6ffcbffdebfdccb8aebccbad6abc52bdafe25d55b4e534ed676";
    private const string AcceptedContentHash =
        "6i8h2KGAFQO3x7uoxZmmFSLX7RsqPg7iXsDLtoo0voYLKQHJEqwu1O9bQVtDkZZoBuBrrqa/vDQ2IU19rufmkw==";
    private const string OldVersion = "0.2.0-p10j.2886880";

    [Fact]
    public void AcceptedCarrierIsTheOnlyCarrierInTheOfflineClosure()
    {
        var root = P14A2PackageAndStaticGateTests.RepositoryRoot();
        var vendor = Path.Combine(root, "vendor", "production-588229f");
        var packageDirectory = Path.Combine(vendor, "packages");
        var acceptedFile = $"Deep.Protocol.ProfileCarrier.{AcceptedVersion}.nupkg";
        var packages = Directory.GetFiles(
                packageDirectory,
                "Deep.Protocol.ProfileCarrier.*.nupkg")
            .Select(Path.GetFileName)
            .ToArray();

        Assert.Equal(new[] { acceptedFile }, packages);

        var packagePath = Path.Combine(packageDirectory, acceptedFile);
        Assert.Equal(49_853, new FileInfo(packagePath).Length);
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
            "production-588229f",
            "package-manifest.json");
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(manifestPath));
        var value = manifest.RootElement;
        Assert.Equal(
            AcceptedSource,
            value.GetProperty("sourceCommit").GetString());
        var carrierPackage = Assert.Single(
            value.GetProperty("packages").EnumerateArray(),
            package => package.GetProperty("id").GetString() ==
                "Deep.Protocol.ProfileCarrier");
        Assert.Equal(
            AcceptedVersion,
            carrierPackage.GetProperty("version").GetString());
        Assert.Equal(
            AcceptedSha256,
            carrierPackage.GetProperty("sha256").GetString());
    }

    [Theory]
    [InlineData("0.4.0-survival.invalid", AcceptedSha256, AcceptedContentHash)]
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
            AcceptedSource));
    }

    private static void AssertAcceptedBinding(
        string version,
        string sha256,
        string contentHash,
        string source)
    {
        if (!string.Equals(version, AcceptedVersion, StringComparison.Ordinal)
            || !string.Equals(sha256, AcceptedSha256, StringComparison.Ordinal)
            || !string.Equals(contentHash, AcceptedContentHash, StringComparison.Ordinal)
            || !string.Equals(source, AcceptedSource, StringComparison.Ordinal))
        {
            throw new InvalidDataException("P14A2B1 carrier binding is not exact.");
        }
    }

    private static string Sha256(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
}
