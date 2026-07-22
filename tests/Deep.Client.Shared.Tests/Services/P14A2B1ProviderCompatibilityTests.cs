using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class P14A2B1ProviderCompatibilityTests
{
    // RFC 8032 section 7.1 test 1 public key. The second signature is an
    // immutable test-only signature over a P04 Genesis-tagged statement.
    private static readonly byte[] RfcPublicKey = Convert.FromHexString(
        "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");
    private static readonly byte[] RfcSignature = Convert.FromHexString(
        "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155" +
        "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");
    private static readonly byte[] TaggedMessage = Convert.FromHexString(
        "444545502D47454E2D56310000000000" +
        "73796E7468657469632D63616E6F6E6963616C2D73746174656D656E742D7631");
    private static readonly byte[] TaggedSignature = Convert.FromHexString(
        "CD1C153F2688C5C846A9063C7C10C951A0707A28E10EBA41FAFC14401192FBBE" +
        "94D4D17811C6BA7B15EAA1D63591EBB8D8B5B2AC77EB3F55D5F14EC720823B0C");

    [Fact]
    public void AcceptedProviderVerifiesRfc8032AndExactP04TaggedKats()
    {
        Assert.True(PublicKeyAuth.VerifyDetached(RfcSignature, [], RfcPublicKey));
        var corruptedRfcSignature = RfcSignature.ToArray();
        corruptedRfcSignature[0] ^= 0x80;
        Assert.False(PublicKeyAuth.VerifyDetached(
            corruptedRfcSignature,
            [],
            RfcPublicKey));

        var tag = MembershipSigningDomains.GetFixedTag(MembershipSignatureDomain.Genesis);
        Assert.Equal(MembershipSigningDomains.FixedTagLength, tag.Length);
        Assert.True(TaggedMessage.AsSpan(0, tag.Length).SequenceEqual(tag.Span));
        Assert.True(PublicKeyAuth.VerifyDetached(
            TaggedSignature,
            TaggedMessage,
            RfcPublicKey));

        var verifier = new SodiumEd25519MembershipSignatureVerifier();
        var signerId = new byte[MembershipLimits.SignerIdLength];
        Assert.True(verifier.Verify(
            signerId,
            RfcPublicKey,
            MembershipSignatureDomain.Genesis,
            TaggedMessage,
            TaggedSignature));

        var corruptedSignature = TaggedSignature.ToArray();
        corruptedSignature[0] ^= 0x80;
        Assert.False(verifier.Verify(
            signerId,
            RfcPublicKey,
            MembershipSignatureDomain.Genesis,
            TaggedMessage,
            corruptedSignature));
        Assert.False(verifier.Verify(
            signerId,
            RfcPublicKey,
            MembershipSignatureDomain.Bridge,
            TaggedMessage,
            TaggedSignature));

        var wrongTag = TaggedMessage.ToArray();
        wrongTag[0] ^= 0x80;
        Assert.False(verifier.Verify(
            signerId,
            RfcPublicKey,
            MembershipSignatureDomain.Genesis,
            wrongTag,
            TaggedSignature));
        Assert.False(verifier.Verify(
            signerId.AsSpan(1),
            RfcPublicKey,
            MembershipSignatureDomain.Genesis,
            TaggedMessage,
            TaggedSignature));
    }

    [Fact]
    public void NewProviderRemainsTestOnlyAndProductConstructionRemainsManual()
    {
        var root = P14A2PackageAndStaticGateTests.RepositoryRoot();
        var productSource = string.Join(
            "\n",
            Directory.GetFiles(
                    Path.Combine(root, "src", "Deep.Client.Shared"),
                    "*.cs",
                    SearchOption.AllDirectories)
                .Select(File.ReadAllText));

        Assert.DoesNotContain(
            nameof(SodiumEd25519MembershipSignatureVerifier),
            productSource,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "DormantSelfHostedProfileVerificationService>(",
            productSource,
            StringComparison.Ordinal);
        Assert.DoesNotContain("AddSingleton", productSource, StringComparison.Ordinal);
        Assert.DoesNotContain("AddScoped", productSource, StringComparison.Ordinal);
        Assert.DoesNotContain("AddTransient", productSource, StringComparison.Ordinal);
    }
}
