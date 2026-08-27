using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ContactMailboxInvitationServiceTests
{
    private const string AlicePhrase =
        "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed";
    private const string BobPhrase =
        "update vague zinger boxes ornament renting glass gained island nabbing afield calamity nabbing";
    private const ulong Now = 1_800_000_000;

    [Fact]
    public void RoundTrip_ReturnsFrozenAuthenticatedRouteWithoutAuthorityClaim()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        var route = CreateRoute();
        var text = ContactMailboxInvitationService.Create(
            alice,
            route.Owner.PublicKey,
            route.CanonicalAdvertisement,
            DateTimeOffset.FromUnixTimeSeconds(checked((long)(Now + 1_800))),
            new FixedTimeProvider(Now));

        var verified = ContactMailboxInvitationService.ParseAndVerify(
            text,
            new FixedTimeProvider(Now));

        Assert.StartsWith(ContactMailboxInvitationCodec.TextPrefix, text, StringComparison.Ordinal);
        Assert.Equal(ContactMailboxInvitationCodec.CanonicalTextLength, text.Length);
        Assert.Equal(alice.SessionId, verified.SessionId);
        Assert.Equal(alice.GetEd25519PublicKey(), verified.SessionEd25519PublicKey.ToArray());
        Assert.Equal(route.Owner.PublicKey, verified.MailboxOwnerEd25519PublicKey.ToArray());
        Assert.Equal(route.CanonicalAdvertisement, verified.CanonicalRouteAdvertisement.ToArray());
        Assert.Equal(Now, verified.IssuedAtUnixSeconds);
        Assert.Equal(Now + 1_800, verified.ExpiresAtUnixSeconds);
        Assert.Equal(7UL, verified.RouteSequence);
        Assert.Equal(32, verified.RouteDomainHash.Length);
        Assert.Equal(SHA256.HashData(route.CanonicalAdvertisement),
            verified.CanonicalRouteAdvertisementHash.ToArray());

        var firstCopy = verified.CanonicalRouteAdvertisement.ToArray();
        firstCopy[0] ^= 1;
        Assert.Equal(route.CanonicalAdvertisement, verified.CanonicalRouteAdvertisement.ToArray());
    }

    [Theory]
    [InlineData(ContactMailboxInvitationCodec.SessionEd25519Offset)]
    [InlineData(ContactMailboxInvitationCodec.MailboxOwnerEd25519Offset)]
    [InlineData(ContactMailboxInvitationCodec.RouteAdvertisementOffset + 200)]
    [InlineData(ContactMailboxInvitationCodec.IssuedAtOffset + 7)]
    [InlineData(ContactMailboxInvitationCodec.ExpiresAtOffset + 7)]
    [InlineData(ContactMailboxInvitationCodec.SignatureOffset + 10)]
    public void TamperingAnyAuthenticatedRegion_IsRejected(int offset)
    {
        var fixture = CreateInvitation();
        var bytes = DecodeTextBytes(fixture.Text);
        bytes[offset] ^= 1;
        var tampered = EncodeTextBytes(bytes);

        Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.ParseAndVerify(
                tampered,
                new FixedTimeProvider(Now)));
    }

    [Fact]
    public void ResignedWrongSessionId_IsRejectedByEd25519ToSessionBinding()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var route = CreateRoute();
        var envelope = UnsignedEnvelope(alice, route) with
        {
            SessionId = Convert.FromHexString(bob.SessionId.Value)
        };
        var text = SignAndEncode(envelope, alice);

        var error = Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.ParseAndVerify(
                text,
                new FixedTimeProvider(Now)));

        Assert.Equal(ContactMailboxInvitationError.SessionBindingMismatch, error.Error);
    }

    [Fact]
    public void SignatureFromWrongSessionKey_IsRejected()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var route = CreateRoute();
        var text = SignAndEncode(UnsignedEnvelope(alice, route), bob);

        var error = Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.ParseAndVerify(
                text,
                new FixedTimeProvider(Now)));

        Assert.Equal(ContactMailboxInvitationError.InvalidSessionSignature, error.Error);
    }

    [Fact]
    public void ResignedEnvelopeWithWrongMailboxOwner_IsRejected()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        var route = CreateRoute();
        var wrongOwner = PublicKeyAuth.GenerateKeyPair(Bytes(0xd1, 32));
        var envelope = UnsignedEnvelope(alice, route) with
        {
            MailboxOwnerEd25519PublicKey = wrongOwner.PublicKey
        };
        var text = SignAndEncode(envelope, alice);

        var error = Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.ParseAndVerify(
                text,
                new FixedTimeProvider(Now)));

        Assert.Equal(ContactMailboxInvitationError.RouteOwnerMismatch, error.Error);
    }

    [Fact]
    public void ResignedEnvelopeWithTamperedPra1OwnerSignature_IsRejected()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        var route = CreateRoute();
        var advertisement = ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(
            route.CanonicalAdvertisement);
        var ownerSignature = advertisement.OwnerSignature.ToArray();
        ownerSignature[^1] ^= 1;
        var changed = advertisement with { OwnerSignature = ownerSignature };
        var envelope = UnsignedEnvelope(alice, route) with
        {
            CanonicalRouteAdvertisement =
                ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(changed)
        };
        var text = SignAndEncode(envelope, alice);

        var error = Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.ParseAndVerify(
                text,
                new FixedTimeProvider(Now)));

        Assert.Equal(ContactMailboxInvitationError.InvalidRouteOwnerSignature, error.Error);
    }

    [Fact]
    public void ResignedEnvelopeWithTamperedPra1IssuerSignature_IsRejected()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        var route = CreateRoute();
        var advertisement = ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(
            route.CanonicalAdvertisement);
        var issuerSignature = advertisement.Certificate.IssuerSignature.ToArray();
        issuerSignature[^1] ^= 1;
        var changed = advertisement with
        {
            Certificate = advertisement.Certificate with
            {
                IssuerSignature = issuerSignature
            }
        };
        changed = changed with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec.GetAdvertisementSigningBytes(changed),
                route.Owner.PrivateKey)
        };
        var envelope = UnsignedEnvelope(alice, route) with
        {
            CanonicalRouteAdvertisement =
                ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(changed)
        };
        var text = SignAndEncode(envelope, alice);

        var error = Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.ParseAndVerify(
                text,
                new FixedTimeProvider(Now)));

        Assert.Equal(ContactMailboxInvitationError.InvalidRouteIssuerSignature, error.Error);
    }

    [Fact]
    public void ExpiredInvitation_IsRejected()
    {
        var fixture = CreateInvitation();

        var error = Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.ParseAndVerify(
                fixture.Text,
                new FixedTimeProvider(Now + 2_101)));

        Assert.Equal(ContactMailboxInvitationError.Expired, error.Error);
    }

    [Fact]
    public void NonCanonicalBinaryReservedByte_IsRejectedBeforeVerification()
    {
        var fixture = CreateInvitation();
        var bytes = DecodeTextBytes(fixture.Text);
        bytes[5] = 1;

        var error = Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.ParseAndVerify(
                EncodeTextBytes(bytes),
                new FixedTimeProvider(Now)));

        Assert.Equal(ContactMailboxInvitationError.ReservedFieldNotZero, error.Error);
    }

    [Fact]
    public void NonCanonicalPra1_IsRejectedEvenWhenSessionResignsIt()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        var route = CreateRoute();
        var malformed = route.CanonicalAdvertisement.ToArray();
        malformed[5] = 1;
        var text = SignAndEncode(
            UnsignedEnvelope(alice, route) with
            {
                CanonicalRouteAdvertisement = malformed
            },
            alice);

        var error = Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.ParseAndVerify(
                text,
                new FixedTimeProvider(Now)));

        Assert.Equal(ContactMailboxInvitationError.InvalidRoute, error.Error);
    }

    [Fact]
    public void OversizeText_IsRejectedBeforeBase64Decode()
    {
        var fixture = CreateInvitation();

        var error = Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.ParseAndVerify(
                fixture.Text + "A",
                new FixedTimeProvider(Now)));

        Assert.Equal(ContactMailboxInvitationError.Oversize, error.Error);
    }

    [Theory]
    [InlineData("prefix")]
    [InlineData("alphabet")]
    public void NonCanonicalText_IsRejected(string mutation)
    {
        var fixture = CreateInvitation();
        var changed = mutation switch
        {
            "prefix" => "Deep" + fixture.Text[4..],
            "alphabet" => fixture.Text[..^1] + "=",
            _ => throw new ArgumentOutOfRangeException(nameof(mutation))
        };

        var error = Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.ParseAndVerify(
                changed,
                new FixedTimeProvider(Now)));

        Assert.True(error.Error is ContactMailboxInvitationError.InvalidTextPrefix or
            ContactMailboxInvitationError.InvalidTextEncoding);
    }

    [Fact]
    public void InvitationOutsidePra1Window_IsRejectedAtAuthoring()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        var route = CreateRoute();

        var error = Assert.Throws<ContactMailboxInvitationException>(() =>
            ContactMailboxInvitationService.Create(
                alice,
                route.Owner.PublicKey,
                route.CanonicalAdvertisement,
                DateTimeOffset.FromUnixTimeSeconds(checked((long)(Now + 4_000))),
                new FixedTimeProvider(Now)));

        Assert.Equal(ContactMailboxInvitationError.InvalidValidityWindow, error.Error);
    }

    private static InvitationFixture CreateInvitation()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        var route = CreateRoute();
        return new InvitationFixture(
            ContactMailboxInvitationService.Create(
                alice,
                route.Owner.PublicKey,
                route.CanonicalAdvertisement,
                DateTimeOffset.FromUnixTimeSeconds(checked((long)(Now + 1_800))),
                new FixedTimeProvider(Now)));
    }

    private static ContactMailboxInvitationEnvelope UnsignedEnvelope(
        SessionIdentityProvider identity,
        RouteFixture route) => new(
            Convert.FromHexString(identity.SessionId.Value),
            identity.GetEd25519PublicKey(),
            route.Owner.PublicKey,
            route.CanonicalAdvertisement,
            Now,
            Now + 1_800,
            new byte[ContactMailboxInvitationCodec.SignatureLength]);

    private static string SignAndEncode(
        ContactMailboxInvitationEnvelope envelope,
        SessionIdentityProvider signer)
    {
        var signingBytes = ContactMailboxInvitationCodec.GetSigningBytes(envelope);
        return ContactMailboxInvitationCodec.EncodeText(envelope with
        {
            Signature = signer.SignDetached(signingBytes)
        });
    }

    private static RouteFixture CreateRoute()
    {
        var issuer = PublicKeyAuth.GenerateKeyPair(Bytes(0x21, 32));
        var owner = PublicKeyAuth.GenerateKeyPair(Bytes(0x51, 32));
        var placement = Bytes(0x81, 32);
        var certificate = new ProductionMailboxRouteCertificate
        {
            NetworkId = Bytes(0x01, 16),
            AuthorityGeneration = 4,
            CanonicalAuthorityHash = Bytes(0x11, 32),
            IssuerEd25519PublicKey = issuer.PublicKey,
            MailboxOwnerEd25519PublicKey = owner.PublicKey,
            BlindedMailboxId = Bytes(0x61, 32),
            BlindedPlacementId = placement,
            SelectionInputCommitment = ProductionMailboxReplicaSelection
                .ComputeSelectionInputCommitment(new BlindedPlacementId(placement)),
            IssuedAtUnixSeconds = Now - 120,
            ExpiresAtUnixSeconds = Now + 3_600,
            IssuerSignature = new byte[64]
        };
        certificate = certificate with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(certificate),
                issuer.PrivateKey)
        };
        var advertisement = new ProductionMailboxRouteAdvertisement
        {
            Certificate = certificate,
            Sequence = 7,
            PublishedAtUnixSeconds = Now - 60,
            ExpiresAtUnixSeconds = Now + 3_600,
            OwnerSignature = new byte[64]
        };
        advertisement = advertisement with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec.GetAdvertisementSigningBytes(advertisement),
                owner.PrivateKey)
        };
        return new RouteFixture(
            owner,
            ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(advertisement));
    }

    private static byte[] DecodeTextBytes(string text) => Convert.FromBase64String(
        text[ContactMailboxInvitationCodec.TextPrefix.Length..]
            .Replace('-', '+')
            .Replace('_', '/'));

    private static string EncodeTextBytes(byte[] bytes) =>
        ContactMailboxInvitationCodec.TextPrefix + Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static byte[] Bytes(byte seed, int length) => Enumerable.Range(0, length)
        .Select(index => unchecked((byte)(seed + index)))
        .ToArray();

    private sealed class FixedTimeProvider(ulong now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() =>
            DateTimeOffset.FromUnixTimeSeconds(checked((long)now));
    }

    private sealed record RouteFixture(KeyPair Owner, byte[] CanonicalAdvertisement);
    private sealed record InvitationFixture(string Text);
}
