using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Services;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class E2eeEnvelopeCodecTests
{
    private const string AlicePhrase = "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade";
    private const string BobPhrase = "cactus canyon cedar circle cloud comet coral crystal dawn delta dune ember";
    private const string CharliePhrase = "fabric feather fern flame forest frost galaxy garden glacier grove harbor hazel";

    private const int SenderSessionIdOffset = 8;
    private const int SenderEd25519Offset = 41;
    private const int RecipientSessionIdOffset = 73;
    private const int NonceOffset = 106;
    private const int WrappedLengthOffset = 118;
    private const int CiphertextLengthOffset = 120;
    private const int WrappedCekOffset = 124;
    private const int CiphertextOffset = 204;

    [Fact]
    public void MessageEnvelope_RoundTripsAuthenticatedMetadataPlaintextAndDigest()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var plaintext = "DPE1 confidential marker"u8.ToArray();

        var envelope = alice.CreateEnvelopeCodec().Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, plaintext);
        var decoded = bob.CreateEnvelopeCodec().Decrypt(envelope);

        Assert.Equal(E2eeEnvelopeKind.Message, decoded.Kind);
        Assert.Equal(alice.SessionId, decoded.Sender);
        Assert.Equal(bob.SessionId, decoded.Recipient);
        Assert.Equal(plaintext, decoded.Plaintext.ToArray());
        Assert.Equal(SHA256.HashData(envelope), decoded.EnvelopeDigest.ToArray());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(envelope)), decoded.EnvelopeDigestHex);
    }

    [Fact]
    public void Ciphertext_DoesNotContainMarkerPlaintext()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var marker = Encoding.UTF8.GetBytes("plaintext-marker-that-must-not-leak-92841");

        var envelope = alice.CreateEnvelopeCodec().Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, marker);

        Assert.False(ContainsSequence(envelope, marker));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(SenderSessionIdOffset)]
    [InlineData(SenderEd25519Offset)]
    [InlineData(RecipientSessionIdOffset)]
    [InlineData(NonceOffset)]
    [InlineData(WrappedCekOffset)]
    [InlineData(CiphertextOffset)]
    public void Decrypt_RejectsTamperInMajorAuthenticatedFields(int offset)
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var envelope = alice.CreateEnvelopeCodec().Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, "authenticated"u8);
        envelope[offset] ^= 0x01;

        Assert.Throws<E2eeProtocolException>(() => bob.CreateEnvelopeCodec().Decrypt(envelope));
    }

    [Fact]
    public void Decrypt_RejectsCiphertextAndTagTamperEvenWhenResignedAndRejectsSignatureTamper()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var codec = bob.CreateEnvelopeCodec();
        var envelope = alice.CreateEnvelopeCodec().Encrypt(E2eeEnvelopeKind.Reaction, bob.SessionId, "reaction"u8);

        var ciphertextTamper = envelope.ToArray();
        ciphertextTamper[CiphertextOffset] ^= 0x01;
        ResignAsAlice(ciphertextTamper);
        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt(ciphertextTamper));

        var tagTamper = envelope.ToArray();
        tagTamper[^(E2eeEnvelopeCodec.SignatureSize + 1)] ^= 0x01;
        ResignAsAlice(tagTamper);
        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt(tagTamper));

        var signatureTamper = envelope.ToArray();
        signatureTamper[^1] ^= 0x01;
        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt(signatureTamper));
    }

    [Fact]
    public void Decrypt_RejectsWrongRecipientWithoutPlaintextFallback()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        using var charlie = new SessionIdentityProvider(CharliePhrase);
        var envelope = alice.CreateEnvelopeCodec().Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, "for Bob"u8);

        Assert.Throws<E2eeProtocolException>(() => charlie.CreateEnvelopeCodec().Decrypt(envelope));
        Assert.Throws<E2eeProtocolException>(() => bob.CreateEnvelopeCodec().Decrypt("plaintext"u8));
    }

    [Fact]
    public void Decrypt_RejectsValidSignatureWhenSenderKeyDoesNotBindToSenderSessionId()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        using var charlie = new SessionIdentityProvider(CharliePhrase);
        var envelope = alice.CreateEnvelopeCodec().Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, "binding"u8);
        Convert.FromHexString(charlie.SessionId.Value).CopyTo(envelope, SenderSessionIdOffset);
        ResignAsAlice(envelope);

        var exception = Assert.Throws<E2eeProtocolException>(() => bob.CreateEnvelopeCodec().Decrypt(envelope));
        Assert.Contains("bound", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Decrypt_RejectsUnknownVersionKindAndFlags()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var codec = bob.CreateEnvelopeCodec();
        var valid = alice.CreateEnvelopeCodec().Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, "fields"u8);

        var unknownVersion = valid.ToArray();
        unknownVersion[4] = 2;
        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt(unknownVersion));

        var unknownKind = valid.ToArray();
        unknownKind[5] = 0xff;
        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt(unknownKind));

        var unknownFlags = valid.ToArray();
        unknownFlags[7] = 1;
        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt(unknownFlags));
    }

    [Fact]
    public void Decrypt_RejectsInvalidLengthFieldsTruncationTrailingBytesAndOversize()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var codec = bob.CreateEnvelopeCodec();
        var valid = alice.CreateEnvelopeCodec().Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, "lengths"u8);

        var wrappedLength = valid.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(wrappedLength.AsSpan(WrappedLengthOffset, 2), 79);
        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt(wrappedLength));

        var ciphertextLength = valid.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(ciphertextLength.AsSpan(CiphertextLengthOffset, 4), uint.MaxValue);
        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt(ciphertextLength));

        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt(valid[..^1]));
        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt(valid[..100]));
        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt([.. valid, 0]));
        Assert.Throws<E2eeProtocolException>(() => codec.Decrypt(new byte[E2eeEnvelopeCodec.MaxEnvelopeBytes + 1]));
    }

    [Fact]
    public void Encrypt_RejectsUnknownKindInvalidSessionAndPlaintextLimits()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var codec = alice.CreateEnvelopeCodec();

        Assert.Throws<ArgumentOutOfRangeException>(() => codec.Encrypt((E2eeEnvelopeKind)99, bob.SessionId, "x"u8));
        Assert.Throws<ArgumentException>(() => codec.Encrypt(E2eeEnvelopeKind.Message, new("15" + new string('a', 64)), "x"u8));
        Assert.Throws<ArgumentOutOfRangeException>(() => codec.Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, []));
        Assert.Throws<ArgumentOutOfRangeException>(() => codec.Encrypt(
            E2eeEnvelopeKind.Message,
            bob.SessionId,
            new byte[E2eeEnvelopeCodec.MaxPlaintextBytes + 1]));
    }

    [Fact]
    public void Envelope_AcceptsExactMaximumAndProduces512KiBWireSize()
    {
        using var alice = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var plaintext = new byte[E2eeEnvelopeCodec.MaxPlaintextBytes];
        RandomNumberGenerator.Fill(plaintext);

        var envelope = alice.CreateEnvelopeCodec().Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, plaintext);
        var decoded = bob.CreateEnvelopeCodec().Decrypt(envelope);

        Assert.Equal(E2eeEnvelopeCodec.MaxEnvelopeBytes, envelope.Length);
        Assert.Equal(plaintext, decoded.Plaintext.ToArray());
    }

    [Fact]
    public void DisposedIdentity_RefusesPrivateKeyOperations()
    {
        var identity = new SessionIdentityProvider(AlicePhrase);
        using var bob = new SessionIdentityProvider(BobPhrase);
        var codec = identity.CreateEnvelopeCodec();
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => codec.Encrypt(E2eeEnvelopeKind.Message, bob.SessionId, "x"u8));
    }

    private static void ResignAsAlice(byte[] envelope)
    {
        var normalized = SessionIdentityMaterialRecoveryPhrase(AlicePhrase);
        var seed = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(normalized.Normalize(NormalizationForm.FormKD)),
            Encoding.UTF8.GetBytes("mnemonic"),
            2048,
            HashAlgorithmName.SHA512,
            32);
        var keyPair = PublicKeyAuth.GenerateKeyPair(seed);
        try
        {
            var signature = PublicKeyAuth.SignDetached(envelope[..^E2eeEnvelopeCodec.SignatureSize], keyPair.PrivateKey);
            signature.CopyTo(envelope, envelope.Length - E2eeEnvelopeCodec.SignatureSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(keyPair.PrivateKey);
        }
    }

    private static string SessionIdentityMaterialRecoveryPhrase(string phrase) =>
        string.Join(' ', phrase
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(static word => word.ToLowerInvariant()));

    private static bool ContainsSequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        for (var index = 0; index <= haystack.Length - needle.Length; index++)
        {
            if (haystack.Slice(index, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }
}
