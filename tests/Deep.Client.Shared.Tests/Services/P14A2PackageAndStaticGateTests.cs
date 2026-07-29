using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.3.0-p10j.2886880";
    private const string CarrierVersion = "0.2.0-p10j.2886880";
    private const string ProtocolSource =
        "2886880d4c2060cd819765c53c77a02e1c475ea8";
    private const string CarrierSource =
        "2886880d4c2060cd819765c53c77a02e1c475ea8";
    private static readonly ExpectedPackage[] ExpectedPackages =
    [
        new("Deep.Protocol", ProtocolVersion, 193_439,
            "a41c79124f1c62c2889e7b2ea4695956272aa16de1700206cade8993c1b44abe",
            "f2792da79b55f683f13996eaf60f580ead08f2d9a492a63899d5cff616600449d98b5c657cfaba8fa23fb35c5416dd3ee3f32874c946bfd5ff454d2227fbc56f",
            "8nktp5tV9oPxOZbq9g9YDq0I8tmkkqY4mdXP9hZgBEnZi1xlfPq6j6I/s1xUFt0+4/ModMlGv9X/RU0iJ/vFbw==",
            ProtocolSource),
        new("Deep.Protocol.Abstractions", ProtocolVersion, 34_415,
            "4508e67aba983e91c174c8ce796df654c06892680d65e14ff78bda4d553d542c",
            "4c849430fc3511da9d32e060e3412d77670910858345de864ef3965ea2a131d54db0db2a7d039362a37c8707c997dd5b9a6d3ccf0b11060829536ee01b93206c",
            "TISUMPw1EdqdMuBg40Etd2cJEIWDRd6GTvOWXqKhMdVNsNsqfQOTYqN8hwfJl91bmm08zwsRBggpU27gG5MgbA==",
            ProtocolSource),
        new("Deep.Protocol.MembershipRoutes", ProtocolVersion, 21_799,
            "cdb3eb8a8b2889567a25e6db437a287fb12db86d29e0819c13c9adb5fbc02327",
            "62a3040abf990d523deecbfd2f2d77ad2ad8c7a6b3bbdc7046119c0f85f8cdce0017179011c338bcfc6d0376c837da8e2aa34093efca959c7eb9658b553bc2f7",
            "YqMECr+ZDVI97sv9Ly13rSrYx6azu9xwRhGcD4X4zc4AFxeQEcM4vPxtA3bIN9qOKqNAk+/KlZx+uWWLVTvC9w==",
            ProtocolSource),
        new("Deep.Protocol.ProfileCarrier", CarrierVersion, 28_944,
            "a4b13bd32d6dac2999dd997e567a3760af20b5697a5fd1045cca910cde2a1f36",
            "8f1ecda8da537ea92516e368658232af0ba7c07e6afdad1a8f97e03a57fbacba5a394f99ec81a867a1fea8a6c7c8b3ad5349473196117b59782184065d204adf",
            "jx7NqNpTfqklFuNoZYIyrwunwH5q/a0aj5fgOlf7rLpaOU+Z7IGoZ6H+qKbHyLOtU0lHMZYRe1l4IYQGXSBK3w==",
            CarrierSource),
        new("Deep.Protocol.Protobuf", ProtocolVersion, 73_289,
            "c97025f5d1b44fd7a955e7b69614ea2c6cca499656ccf7930029cc740208eab7",
            "8a63e142f25ed4dc67e0f7d1e37abee076ca9e80409935a7c8ca2a14bb01bc28962a097c003c8e84ad01b930a1bbc8f5e6940675a51654fed70353078305eacc",
            "imPhQvJe1Nxn4PfR43q+4HbKnoBAmTWnyMoqFLsBvCiWKgl8ADyOhK0BuTChu8j15pQGdaUWVP7XA1MHgwXqzA==",
            ProtocolSource)
    ];

    [Fact]
    public void UnifiedP10jPackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "p10j");
        using var document = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(vendor, "package-provenance.json")));
        var root = document.RootElement;
        Assert.Equal("deep-client-p10j-offline-package-set.v1",
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
                "p10j",
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
    public void NuGetSourcesAreLocalAndDeepPackagesMapOnlyToP10j()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "NuGet.Config"));
        Assert.Contains("<clear", text, StringComparison.Ordinal);
        Assert.Contains("p10j-protocol-local-pinned", text, StringComparison.Ordinal);
        Assert.Contains("vendor\\p10j\\packages", text, StringComparison.Ordinal);
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
            root, "vendor", "p10j", "package-provenance.json"));
        var project = File.ReadAllText(Path.Combine(
            root, "src", "Deep.Client.Shared", "Deep.Client.Shared.csproj"));
        AssertPackagePin(manifest, project);
        Assert.Throws<InvalidDataException>(() => AssertPackagePin(
            manifest.Replace(ProtocolVersion, "0.3.0-p10j.invalid",
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
                "a4b13bd32d6dac2999dd997e567a3760af20b5697a5fd1045cca910cde2a1f36",
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
            throw new InvalidDataException("Unified P10J package pin validation failed.");
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
