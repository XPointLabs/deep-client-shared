using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Bounded enrollment-only proof of work. It must never run from polling/background sync and
/// deliberately rejects server costs that could turn anonymous enrollment into a battery DoS.
/// </summary>
public static class ProductionMailboxProofOfWork
{
    public const int MinimumLeadingZeroBits = 8;
    public const int MaximumMobileLeadingZeroBits = 22;
    private static ReadOnlySpan<byte> Domain =>
        "Deep/production-mailbox/pow/v1"u8;

    public static Task<ulong> SolveAsync(
        ReadOnlyMemory<byte> challengeId,
        ReadOnlyMemory<byte> challenge,
        int leadingZeroBits,
        CancellationToken cancellationToken = default)
    {
        Validate(challengeId.Span, challenge.Span, leadingZeroBits);
        var frozenId = challengeId.ToArray();
        var frozenChallenge = challenge.ToArray();
        return Task.Run(
            () => Solve(frozenId, frozenChallenge, leadingZeroBits, cancellationToken),
            cancellationToken);
    }

    public static bool Verify(
        ReadOnlySpan<byte> challengeId,
        ReadOnlySpan<byte> challenge,
        ulong nonce,
        int leadingZeroBits)
    {
        Validate(challengeId, challenge, leadingZeroBits);
        Span<byte> transcript = stackalloc byte[Domain.Length + 16 + 32 + 8];
        WriteTranscript(transcript, challengeId, challenge, nonce);
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(transcript, digest);
        return HasLeadingZeroBits(digest, leadingZeroBits);
    }

    private static ulong Solve(
        byte[] challengeId,
        byte[] challenge,
        int leadingZeroBits,
        CancellationToken cancellationToken)
    {
        try
        {
            Span<byte> transcript = stackalloc byte[Domain.Length + 16 + 32 + 8];
            Domain.CopyTo(transcript);
            challengeId.CopyTo(transcript[Domain.Length..]);
            challenge.CopyTo(transcript[(Domain.Length + 16)..]);
            Span<byte> digest = stackalloc byte[32];
            for (ulong nonce = 0; ; nonce++)
            {
                if ((nonce & 0x3ff) == 0)
                    cancellationToken.ThrowIfCancellationRequested();
                BinaryPrimitives.WriteUInt64BigEndian(transcript[^8..], nonce);
                SHA256.HashData(transcript, digest);
                if (HasLeadingZeroBits(digest, leadingZeroBits)) return nonce;
                if (nonce == ulong.MaxValue)
                    throw new InvalidOperationException(
                        "Production mailbox proof-of-work nonce space was exhausted.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challengeId);
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    private static void WriteTranscript(
        Span<byte> destination,
        ReadOnlySpan<byte> challengeId,
        ReadOnlySpan<byte> challenge,
        ulong nonce)
    {
        Domain.CopyTo(destination);
        challengeId.CopyTo(destination[Domain.Length..]);
        challenge.CopyTo(destination[(Domain.Length + 16)..]);
        BinaryPrimitives.WriteUInt64BigEndian(destination[^8..], nonce);
    }

    private static bool HasLeadingZeroBits(ReadOnlySpan<byte> digest, int bits)
    {
        var fullBytes = bits / 8;
        if (digest[..fullBytes].IndexOfAnyExcept((byte)0) >= 0) return false;
        var remaining = bits % 8;
        return remaining == 0 || (digest[fullBytes] >> (8 - remaining)) == 0;
    }

    private static void Validate(
        ReadOnlySpan<byte> challengeId,
        ReadOnlySpan<byte> challenge,
        int leadingZeroBits)
    {
        if (challengeId.Length != 16 ||
            challengeId.IndexOfAnyExcept((byte)0) < 0 ||
            challenge.Length != 32 ||
            challenge.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException(
                "Production mailbox challenge is invalid.");
        if (leadingZeroBits is < MinimumLeadingZeroBits or > MaximumMobileLeadingZeroBits)
            throw new InvalidDataException(
                "Production mailbox proof-of-work cost exceeds the mobile safety policy.");
    }
}
