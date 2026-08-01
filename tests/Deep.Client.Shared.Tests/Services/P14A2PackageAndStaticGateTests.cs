using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2PackageAndStaticGateTests
{
    private const string ProtocolVersion = "0.4.0-survival.e570512";
    private const string CarrierVersion = ProtocolVersion;
    private const string ProtocolSource =
        "e5705123836b32060ec4392e813d5b8c44635e2e";
    private const string CarrierSource =
        "e5705123836b32060ec4392e813d5b8c44635e2e";
    private static readonly ExpectedPackage[] ExpectedPackages =
    [
        new("Deep.Protocol", ProtocolVersion, 200_240,
            "c331f55662985dc4837c50c9b0c5f2c6c4f5c6b66427e2ac2eb4c8565862b06e",
            "ed367db8b36d550584a8a86ee51fabdb7cb1188ccd7e1b4c634549f17ece3d381bb0de852697f40d9eff3c2823a9371479c67105271227bc85c5f2dbfa8cc90b",
            "7TZ9uLNtVQWEqKhu5R+r23yxGIzNfhtMY0VJ8X7OPTgbsN6FJpf0DZ7/PCgjqTcUecZxBScSJ7yFxfLb+ozJCw==",
            ProtocolSource),
        new("Deep.Protocol.Abstractions", ProtocolVersion, 25_677,
            "138ace62ea38dc800f6fc392ed70c1e1860a0a2a73c7585091a66173f7012628",
            "736ad1c71ece82b236a667e4cded854b798977a46bbbce17f1bc17eff14b251f588133b42fe81097252ea17a5728e985416f949b87e3c04fdda7eefdb08724a3",
            "c2rRxx7OgrI2pmfkze2FS3mJd6Rru84X8bwX7/FLJR9YgTO0L+gQlyUuoXpXKOmFQW+Um4fjwE/dp+79sIckow==",
            ProtocolSource),
        new("Deep.Protocol.MembershipRoutes", ProtocolVersion, 13_290,
            "455fa53e2c95e9d8cabab1d13ffe4b8fd6133735898a9eae9bf5b67021bf58f1",
            "ff7e681bb98203b02da0ae5f189fd2825b5ca82bedf07e280203fcd33cebc90c84953d358a2af0027631da65660e924ab65c33994bd48ac0917be4c601593d68",
            "/35oG7mCA7AtoK5fGJ/SgltcqCvt8H4oAgP80zzryQyElT01iirwAnYx2mVmDpJKtlwzmUvUisCRe+TGAVk9aA==",
            ProtocolSource),
        new("Deep.Protocol.ProfileCarrier", CarrierVersion, 30_360,
            "48b64474f9b46e9c6e4017e20586a940ed138a8a28365195326a31d56e664ff3",
            "7e4ca29fd95c2d73f64ed13850fb76b7dc74bb9e644cfd9eca6cc4800c9d6d533cd69ac07abbebb79c8cf1e1f4a7bc7266ce51ab448981ca32f7dff630a9029d",
            "fkyin9lcLXP2TtE4UPt2t9x0u55kTP2eymzEgAydbVM81prAervrt5yM8eH0p7xyZs5Rq0SJgcoy99/2MKkCnQ==",
            CarrierSource),
        new("Deep.Protocol.Protobuf", ProtocolVersion, 51_192,
            "0d334cf3312727648a8dd05d430a33e0cb81e1b8aae8d31ec8a748866c5bcc76",
            "eb270413d4bd6514dd29c838391f3c87458fe0ea6ac766f337fa7649bf31862e9a9abee018e2f9724fa8ca1169e8ddec4e0e6012913d60d43d2aa49921c956bd",
            "6ycEE9S9ZRTdKcg4OR88h0WP4Opqx2bzN/p2Sb8xhi6amr7gGOL5ck+oyhFp6N3sTg5gEpE9YNQ9KqSZIclWvQ==",
            ProtocolSource)
    ];

    [Fact]
    public void UnifiedSurvivalBetaPackageSetIsExactAndLocallyPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "survival-beta-e570512");
        using var document = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(vendor, "package-provenance.json")));
        var root = document.RootElement;
        Assert.Equal("deep-survival-beta-protocol-closure.v1",
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
                "survival-beta-e570512",
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
    public void NuGetSourcesAreLocalAndDeepPackagesMapOnlyToSurvivalBeta()
    {
        var text = File.ReadAllText(Path.Combine(RepositoryRoot(), "NuGet.Config"));
        Assert.Contains("<clear", text, StringComparison.Ordinal);
        Assert.Contains("survival-beta-protocol-closure", text, StringComparison.Ordinal);
        Assert.Contains("vendor\\survival-beta-e570512\\packages", text, StringComparison.Ordinal);
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
            root, "vendor", "survival-beta-e570512", "package-provenance.json"));
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
                "48b64474f9b46e9c6e4017e20586a940ed138a8a28365195326a31d56e664ff3",
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
            throw new InvalidDataException("Unified Survival Beta package pin validation failed.");
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
