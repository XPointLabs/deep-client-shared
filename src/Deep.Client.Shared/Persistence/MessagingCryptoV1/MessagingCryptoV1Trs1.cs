using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Client.Shared.Persistence.MessagingCryptoV1;

internal sealed record MessagingCryptoV1Trs1Facts(
    ulong Generation,
    byte[] StateCommitment,
    byte[] ExactHash,
    bool TerminallyLatched);

internal static class MessagingCryptoV1Trs1
{
    private const int PrefixSize = 12;
    private const int BindingSize = 240;
    private const int ScalarSize = 284;
    private const int SkippedEntrySize = 185;
    private const int StateCommitmentSize = 32;
    private const int ChecksumSize = 32;
    private const int MinimumSize = PrefixSize + BindingSize + ScalarSize + StateCommitmentSize + ChecksumSize;
    private const int GenerationOffset = PrefixSize + BindingSize;
    private const int ComponentLengthOffset = GenerationOffset + 8 + 32 + 8 + 32 + 8 + 4 + 4 + 56 + 56 + 32 + 32 + 4;
    private const string ChecksumDomain = "Deep/LocalState/V1/triple-ratchet-state-checksum";

    internal static MessagingCryptoV1Trs1Facts Validate(
        ReadOnlySpan<byte> encoded,
        MessagingCryptoV1StoreScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (encoded.Length < MinimumSize || encoded.Length > MessagingCryptoV1Limits.MaximumTrs1Bytes)
            throw new FormatException("TRS1 is outside the closed 2 MiB persistence bound.");
        if (!encoded[..4].SequenceEqual("TRS1"u8) || encoded[4] != 1 ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded[5..]) != 0x0201 || (encoded[7] & ~1) != 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(encoded[8..]) != encoded.Length)
            throw new FormatException("TRS1 prefix, suite, flags, or exact length is invalid.");

        var session = encoded.Slice(PrefixSize, 32);
        var localDevice = encoded.Slice(PrefixSize + 96, 32);
        var localDeviceGeneration = BinaryPrimitives.ReadUInt64BigEndian(encoded[(PrefixSize + 128)..]);
        if (!Fixed(session, scope.SessionId) || !Fixed(localDevice, scope.LocalDeviceId) ||
            localDeviceGeneration != scope.DeviceGeneration)
            throw new MessagingCryptoV1StoreOpenException(
                MessagingCryptoV1StoreOpenFailure.ScopeMismatch,
                "TRS1 session or local-device binding differs from the store scope.");

        var generation = BinaryPrimitives.ReadUInt64BigEndian(encoded[GenerationOffset..]);
        if (generation == 0) throw new FormatException("TRS1 storage generation must be nonzero.");
        var componentLength = BinaryPrimitives.ReadUInt32BigEndian(encoded[ComponentLengthOffset..]);
        var skippedCount = BinaryPrimitives.ReadUInt32BigEndian(encoded[(ComponentLengthOffset + 4)..]);
        if (componentLength > MessagingCryptoV1Limits.MaximumTrs1Bytes || skippedCount > 2048)
            throw new FormatException("TRS1 variable cardinality exceeds its closed bound.");
        var expected = checked((long)MinimumSize + componentLength + (long)skippedCount * SkippedEntrySize);
        if (expected != encoded.Length)
            throw new FormatException("TRS1 variable fields do not match its exact length.");
        var terminal = encoded[7] == 1;
        if (terminal ? componentLength != 0 || skippedCount != 0 : componentLength == 0)
            throw new FormatException("TRS1 terminal/provider state shape is invalid.");

        var commitmentOffset = checked((int)(PrefixSize + BindingSize + ScalarSize +
            componentLength + (long)skippedCount * SkippedEntrySize));
        var stateCommitment = encoded.Slice(commitmentOffset, StateCommitmentSize);
        if (stateCommitment.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("TRS1 state commitment is zero.");

        var checksumOffset = encoded.Length - ChecksumSize;
        var expectedChecksum = Sha256Domain(ChecksumDomain, encoded[..checksumOffset]);
        try
        {
            if (!Fixed(expectedChecksum, encoded[checksumOffset..]))
                throw new FormatException("TRS1 checksum does not match its exact bytes.");
        }
        finally { CryptographicOperations.ZeroMemory(expectedChecksum); }

        return new MessagingCryptoV1Trs1Facts(
            generation,
            stateCommitment.ToArray(),
            SHA256.HashData(encoded),
            terminal);
    }

    internal static byte[] Sha256Domain(string label, ReadOnlySpan<byte> value)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(labelBytes);
        hash.AppendData([0]);
        hash.AppendData(length);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    internal static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
