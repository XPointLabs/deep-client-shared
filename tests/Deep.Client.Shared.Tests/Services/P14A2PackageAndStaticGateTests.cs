using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.3.0-p10i.a9b7a10";
    private const string CarrierVersion = "0.2.0-p10i.a9b7a10";
    private const string ProtocolSource =
        "a9b7a10a555758d4b2e30707a70d271f010b6c30";
    private const string CarrierSource =
        "a9b7a10a555758d4b2e30707a70d271f010b6c30";
    private static readonly ExpectedPackage[] ExpectedPackages =
    [
        new("Deep.Protocol", ProtocolVersion, 153_855,
            "925106e6098fe03a9fc247c5be519a13783318bb349b3b8f3cebaa299b8d0a78",
            "5a9e615092944e6a09702d8d4c999b411f129545e13a4f02bb3d90720090bfe47d6be2e5eb5eb2553057bfbac319465234bc8d308f68bfa6aeda06725c71bcc3",
            "Wp5hUJKUTmoJcC2NTJmbQR8SlUXhOk8Cuz2QcgCQv+R9a+Ll616yVTBXv7rDGUZSNLyNMI9ov6au2gZyXHG8ww==",
            ProtocolSource),
        new("Deep.Protocol.Abstractions", ProtocolVersion, 25_666,
            "0daa36393ff1e048186ae90883d7e5aaef18bab345e7c1219fa770a1e17776a6",
            "88a8665085b06dca908ce428c4374afde489ac7466cc8ff365084350ec8ab6f0b8fbbfb8d884f96b9a924a11651069fd401351517f3afece7035560b806ba843",
            "iKhmUIWwbcqQjOQoxDdK/eSJrHRmzI/zZQhDUOyKtvC4+7+42IT5a5qSShFlEGn9QBNRUX86/s5wNVYLgGuoQw==",
            ProtocolSource),
        new("Deep.Protocol.MembershipRoutes", ProtocolVersion, 13_280,
            "cb7cf4b4319349fb8eea81ea700b411f6b3d81ba580aef6a44c4dd141f6dee7e",
            "60438b1f616ca6cd3d98eeac204a47f61f4835111a6d47f4d82d0eb8478c73646ccc7d0f06630d30f20456377dd6d95a207f4919b0e64c7f5bc95cb8f927729f",
            "YEOLH2Fsps09mO6sIEpH9h9INREabUf02C0OuEeMc2RszH0PBmMNMPIEVjd91tlaIH9JGbDmTH9byVy4+Sdynw==",
            ProtocolSource),
        new("Deep.Protocol.ProfileCarrier", CarrierVersion, 28_904,
            "ccae562846602d99115e2de75ddf5b9e3290d17461a8eaa6a9ac0860b231da31",
            "e2e411ab7c6d3caaaca2728bb28d166a0bf619740900dd930b449fe068e46fffbf1f46a74938c66f86059585d8142d1b3c8c98a95d73ce806085d573875f888d",
            "4uQRq3xtPKqsonKLso0Wagv2GXQJAN2TC0Sf4Gjkb/+/H0anSTjGb4YFlYXYFC0bPIyYqV1zzoBghdVzh1+IjQ==",
            CarrierSource),
        new("Deep.Protocol.Protobuf", ProtocolVersion, 51_186,
            "5583ede034a85cf514840c8db325a4cffb7cdb0ab840af8c6df7d34fb0c1bade",
            "2e85e6e3f7dc27346034d64ba04b01c6a61cbc74042a594bd418427e2c288cf5a00fc36015ea383830371345fc3fc1218eff910827375e6aca28b55bb0c2a344",
            "LoXm4/fcJzRgNNZLoEsBxqYcvHQEKllL1BhCfiwojPWgD8NgFeo4ODA3E0X8P8Ehjv+RCCc3XmrKKLVbsMKjRA==",
            ProtocolSource)
    ];

    [Fact]
    public void UnifiedP10iPackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "p10i");
        using var document = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(vendor, "package-provenance.json")));
        var root = document.RootElement;
        Assert.Equal("deep-client-p10i-offline-package-set.v1",
            root.GetProperty("schema").GetString());
        Assert.Equal(ProtocolSource,
            root.GetProperty("protocolSourceCommit").GetString());
        Assert.Equal(CarrierSource,
            root.GetProperty("profileCarrierSourceCommit").GetString());
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
            Assert.Equal(expected.ContentHash, ContentHash(path));
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
            AssertResolved(dependencies, "Deep.Protocol", ProtocolVersion);
            AssertResolved(dependencies, "Deep.Protocol.Abstractions", ProtocolVersion);
            AssertResolved(dependencies, "Deep.Protocol.MembershipRoutes", ProtocolVersion);
            AssertResolved(dependencies, "Deep.Protocol.ProfileCarrier", CarrierVersion);
            AssertResolved(dependencies, "Deep.Protocol.Protobuf", ProtocolVersion);
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
                "p10i",
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
        }

        Assert.Equal(ProtocolSource, CarrierSource);
    }

    [Fact]
    public void NuGetSourcesAreLocalAndDeepPackagesMapOnlyToP10i()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "NuGet.Config"));
        Assert.Contains("<clear", text, StringComparison.Ordinal);
        Assert.Contains("p10i-protocol-local-pinned", text, StringComparison.Ordinal);
        Assert.Contains("vendor\\p10i\\packages", text, StringComparison.Ordinal);
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
            root, "vendor", "p10i", "package-provenance.json"));
        var project = File.ReadAllText(Path.Combine(
            root, "src", "Deep.Client.Shared", "Deep.Client.Shared.csproj"));
        AssertPackagePin(manifest, project);
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(ProtocolVersion, "0.3.0-p10i.invalid",
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
                "\"id\": \"Deep.Protocol.Protobuf\"",
                "\"id\": \"Deep.Protocol.Protobuf.Drift\"",
                StringComparison.Ordinal),
            project));
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(ProtocolSource, new string('1', 40),
                StringComparison.Ordinal),
            project));
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(
                "ccae562846602d99115e2de75ddf5b9e3290d17461a8eaa6a9ac0860b231da31",
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
        if (document.RootElement.GetProperty("protocolSourceCommit").GetString()
                != ProtocolSource
            || document.RootElement.GetProperty("profileCarrierSourceCommit").GetString()
                != CarrierSource
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
            throw new InvalidDataException("Unified P10I package pin validation failed.");
        }
    }

    private static void AssertResolved(
        JsonElement dependencies,
        string id,
        string version) =>
        Assert.Equal(version, dependencies.GetProperty(id).GetProperty("resolved").GetString());

    private static string Sha256(string path) =>
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

    private static string Sha512(string path) =>
        Convert.ToHexStringLower(SHA512.HashData(File.ReadAllBytes(path)));

    private static string ContentHash(string path) =>
        Convert.ToBase64String(SHA512.HashData(File.ReadAllBytes(path)));

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
