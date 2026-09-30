using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Completed local initial-session custody, not delivery or ACK.
/// Only ciphertext/identifiers are public; ratchet state stays inside Shared.</summary>
public sealed class DeepIdV2InitialSessionCommit : IDisposable
{
    internal const int HeaderBytes = 180, MaximumDphBytes = 65536, MaximumInitialTrsBytes = 131072;
    internal const int MaximumPayloadBytes = HeaderBytes + 1476 + MaximumDphBytes + MaximumInitialTrsBytes;
    private byte[]? payload;
    private readonly int dphOffset, dphLength, trsOffset, trsLength;
    internal readonly CurrentDmd1Evidence Directory;
    internal readonly LocalDeviceAgreementBinding Device;
    internal readonly Dph2Record Record;
    internal string Fingerprint => Convert.ToHexString(Bytes.Slice(12, 32));
    internal ReadOnlySpan<byte> CanonicalSpan => Bytes;
    internal ReadOnlySpan<byte> ExactTrsSpan => Bytes.Slice(trsOffset, trsLength);
    internal ReadOnlySpan<byte> EventHashSpan => Bytes.Slice(76, 32);
    internal ReadOnlySpan<byte> IntentSpan => Bytes.Slice(108, 32);
    internal ReadOnlySpan<byte> AgreementPeerSpan => Bytes.Slice(148, 32);
    public ReadOnlyMemory<byte> ExactDph2 => Bytes.Slice(dphOffset, dphLength).ToArray();
    public ReadOnlyMemory<byte> SessionId => Record.SessionId;
    public ReadOnlyMemory<byte> ClaimOperationId => Record.ClaimOperationId;
    public ReadOnlyMemory<byte> ExactClaimReplayHash => Bytes.Slice(44, 32).ToArray();
    private ReadOnlySpan<byte> Bytes => payload ?? throw new ObjectDisposedException(GetType().Name);

    private DeepIdV2InitialSessionCommit(byte[] owned)
    {
        payload = owned;
        try
        {
            if (owned.Length < HeaderBytes || owned.Length > MaximumPayloadBytes || owned[0] != 1 || owned[1] != 0)
                throw new InvalidDataException("The completed initial-session record has no closed local shape.");
            var dmdLength = BinaryPrimitives.ReadUInt16BigEndian(owned.AsSpan(2, 2));
            var drs = BinaryPrimitives.ReadUInt64BigEndian(owned.AsSpan(4, 8));
            var dph = BinaryPrimitives.ReadUInt32BigEndian(owned.AsSpan(140, 4));
            var trs = BinaryPrimitives.ReadUInt32BigEndian(owned.AsSpan(144, 4));
            if (dmdLength is < 426 or > 1476 || dph is 0 or > MaximumDphBytes ||
                trs is 0 or > MaximumInitialTrsBytes || owned.Length != (long)HeaderBytes + dmdLength + dph + trs)
                throw new InvalidDataException("The completed initial-session lengths are invalid.");
            foreach (var offset in new[] { 12, 44, 76, 108, 148 })
                if (owned.AsSpan(offset, 32).IndexOfAnyExcept((byte)0) < 0)
                    throw new InvalidDataException("The completed initial-session binding is zero.");
            Directory = CurrentDmd1Evidence.RestoreProtected(false, owned.AsSpan(HeaderBytes, dmdLength), drs);
            dphOffset = HeaderBytes + dmdLength; dphLength = checked((int)dph);
            trsOffset = dphOffset + dphLength; trsLength = checked((int)trs);
            Record = Dph2Codec.Decode(owned.AsSpan(dphOffset, dphLength));
            Device = LocalDeviceAgreementBinding.FromCompletedRecord(Directory, Record);
            var expected = DeviceV1.ProtectedCurrentDmd1Validation.FingerprintAgreement(Directory, Device,
                Deep.Protocol.Identity.LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                Record.ClaimOperationId.Span, AgreementPeerSpan);
            if (Fingerprint != expected) throw new CryptographicException("The completed agreement fingerprint differs.");
            var facts = MessagingCryptoV1Trs1.ValidateDeviceBinding(ExactTrsSpan, Record.SessionId.Span,
                Record.InitiatorDeviceId.Span, Record.InitiatorDeviceGeneration);
            MessagingCryptoV1Trs1.RequireResponderContactBinding(ExactTrsSpan, Record.ResponderDeviceId.Span,
                Record.ResponderDeviceGeneration);
            if (facts.Generation != 1 || facts.TerminallyLatched)
                throw new CryptographicException("The initial ratchet is not an active first generation.");
        }
        catch { Dispose(); throw; }
    }

    internal static DeepIdV2InitialSessionCommit Capture(InitiatorInitialSessionCommitCapability capability,
        CurrentDmd1Evidence directory, string fingerprint, ReadOnlySpan<byte> claimReplayHash,
        ReadOnlySpan<byte> eventHash, ReadOnlySpan<byte> intent, ReadOnlySpan<byte> agreementPeer)
    {
        using var transferred = capability.ConsumeForAtomicStore();
        if (transferred.ExactDph2Length > MaximumDphBytes || transferred.ExactTrs1Length > MaximumInitialTrsBytes)
            throw new InvalidDataException("The initial-session payload exceeds its local custody bound.");
        if (claimReplayHash.Length != 32 || eventHash.Length != 32 || intent.Length != 32 || agreementPeer.Length != 32)
            throw new ArgumentException("Exact initial-session hashes and intent are required.");
        // These accessors already return owned copies. Do not create an
        // abandoned second copy of secret ratchet state.
        var dph = transferred.ExactDph2; var trs = transferred.ExactTrs1;
        byte[]? result = null;
        try
        {
            result = new byte[HeaderBytes + directory.Canonical.Length + dph.Length + trs.Length]; result[0] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2, 2), checked((ushort)directory.Canonical.Length));
            BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(4, 8), directory.DrsRevision);
            Convert.FromHexString(fingerprint).CopyTo(result, 12);
            claimReplayHash.CopyTo(result.AsSpan(44)); eventHash.CopyTo(result.AsSpan(76)); intent.CopyTo(result.AsSpan(108));
            agreementPeer.CopyTo(result.AsSpan(148));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(140, 4), checked((uint)dph.Length));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(144, 4), checked((uint)trs.Length));
            directory.Canonical.Span.CopyTo(result.AsSpan(HeaderBytes));
            dph.Span.CopyTo(result.AsSpan(HeaderBytes + directory.Canonical.Length));
            trs.Span.CopyTo(result.AsSpan(HeaderBytes + directory.Canonical.Length + dph.Length));
            var commit = new DeepIdV2InitialSessionCommit(result); result = null; return commit;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(dph).Span);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(trs).Span);
            if (result is not null) CryptographicOperations.ZeroMemory(result);
        }
    }

    // Only called after authenticating the exact checkpoint/hash-chain owner;
    // never a public raw-byte parser or a Protocol capability constructor.
    internal static DeepIdV2InitialSessionCommit RestoreCustody(ReadOnlySpan<byte> exact) => new(exact.ToArray());
    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }
    ~DeepIdV2InitialSessionCommit() => DisposeCore();
    private void DisposeCore()
    {
        var value = Interlocked.Exchange(ref payload, null);
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}
