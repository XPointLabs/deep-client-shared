using System.Security.Cryptography;
using System.Text.Json;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Client.Shared.Tests.Services;

internal static class P14A2TestSupport
{
    public const ulong VerificationTime = 1_100;
    public const uint ClockSkew = 30;
    public const ushort Protocol = 2;
    public const string Fingerprint =
        "sha256:f297fde558e06fb88b83ab638e7bd85113a5d0cf617e3d4fe20d8e77a9b18fe2";

    public static DormantSelfHostedProfileVerificationParameters Parameters() =>
        new(VerificationTime, ClockSkew, Protocol);

    public static byte[] Fixture(string name) => File.ReadAllBytes(Path.Combine(
        AppContext.BaseDirectory,
        "Fixtures",
        "p14a2",
        name));

    public static P14A2FixtureManifest Manifest()
    {
        var bytes = Fixture("p14a2-fixtures.json");
        return JsonSerializer.Deserialize<P14A2FixtureManifest>(
            bytes,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
    }

    public static SelfHostedProfileStagingAccountScope Scope(byte value) =>
        SelfHostedProfileStagingAccountScope.FromBytes(
            Enumerable.Repeat(value, StagedSelfHostedProfileLimits.AccountScopeBytes).ToArray());
}

internal sealed class P14A2DeterministicVerifier : IMembershipSignatureVerifier
{
    public bool Verify(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature)
    {
        var input = new byte[signerId.Length + publicKey.Length + signingBytes.Length];
        signerId.CopyTo(input);
        publicKey.CopyTo(input.AsSpan(signerId.Length));
        signingBytes.CopyTo(input.AsSpan(signerId.Length + publicKey.Length));
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(input), signature);
    }
}

internal sealed record P14A2FixtureManifest(
    string AcceptedP14C2SourceCommit,
    string AcceptedP14C2SourceTree,
    string AcceptedP14C2EvidenceCarrier,
    string OriginalVectorSourceCommit,
    string Fingerprint,
    ushort MinimumProtocol,
    ushort MaximumProtocol,
    ulong VerificationTimeUnixSeconds,
    uint AllowedClockSkewSeconds,
    ushort Protocol,
    P14A2FixtureVector[] Vectors);

internal sealed record P14A2FixtureVector(
    string File,
    int Bytes,
    string Sha256,
    int ComponentCount,
    int BridgeCount);
