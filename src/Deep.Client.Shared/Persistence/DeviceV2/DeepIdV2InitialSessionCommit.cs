using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Completed local initial-session custody, not delivery or ACK.
/// Only ciphertext/identifiers are public; ratchet state stays inside Shared.</summary>
public sealed class DeepIdV2InitialSessionCommit : IDisposable
{
    internal const int HeaderBytes = 212, MaximumDphBytes = 65536, MaximumInitialTrsBytes = 131072;
    internal const int MaximumPayloadBytes = HeaderBytes + 1476 + MaximumDphBytes;
    internal const int MaximumPendingBytes = MaximumPayloadBytes + MaximumInitialTrsBytes;
    private byte[]? payload, initialState;
    private readonly int dphOffset, dphLength;
    internal readonly CurrentDmd1Evidence Directory;
    internal readonly LocalDeviceAgreementBinding Device;
    internal readonly Dph2Record Record;
    internal string Fingerprint => Convert.ToHexString(Bytes.Slice(12, 32));
    internal ReadOnlySpan<byte> CanonicalSpan => Bytes;
    internal ReadOnlySpan<byte> ExactTrsSpan { get { _ = Bytes; return initialState is { Length: > 0 } state ? state : throw new InvalidOperationException("Initial sender keys have been transferred and retired."); } }
    internal bool HasInitialState { get { _ = Bytes; return initialState is { Length: > 0 }; } }
    internal ReadOnlySpan<byte> InitialStateHashSpan => Bytes.Slice(180, 32);
    internal ReadOnlySpan<byte> EventHashSpan => Bytes.Slice(76, 32);
    internal ReadOnlySpan<byte> IntentSpan => Bytes.Slice(108, 32);
    internal ReadOnlySpan<byte> AgreementPeerSpan => Bytes.Slice(148, 32);
    public ReadOnlyMemory<byte> ExactDph2 => Bytes.Slice(dphOffset, dphLength).ToArray();
    public ReadOnlyMemory<byte> SessionId => Record.SessionId;
    public ReadOnlyMemory<byte> ClaimOperationId => Record.ClaimOperationId;
    public ReadOnlyMemory<byte> ExactClaimReplayHash => Bytes.Slice(44, 32).ToArray();
    private ReadOnlySpan<byte> Bytes => payload ?? throw new ObjectDisposedException(GetType().Name);

    private DeepIdV2InitialSessionCommit(byte[] owned, byte[]? state = null)
    {
        payload = owned; initialState = state;
        try
        {
            if (owned.Length < HeaderBytes || owned.Length > MaximumPayloadBytes || owned[0] != 2 || owned[1] != 0)
                throw new InvalidDataException("The completed initial-session record has no closed local shape.");
            var dmdLength = BinaryPrimitives.ReadUInt16BigEndian(owned.AsSpan(2, 2));
            var drs = BinaryPrimitives.ReadUInt64BigEndian(owned.AsSpan(4, 8));
            var dph = BinaryPrimitives.ReadUInt32BigEndian(owned.AsSpan(140, 4));
            var trs = BinaryPrimitives.ReadUInt32BigEndian(owned.AsSpan(144, 4));
            if (dmdLength is < 426 or > 1476 || dph is 0 or > MaximumDphBytes ||
                trs is 0 or > MaximumInitialTrsBytes || owned.Length != (long)HeaderBytes + dmdLength + dph)
                throw new InvalidDataException("The completed initial-session lengths are invalid.");
            foreach (var offset in new[] { 12, 44, 76, 108, 148, 180 })
                if (owned.AsSpan(offset, 32).IndexOfAnyExcept((byte)0) < 0)
                    throw new InvalidDataException("The completed initial-session binding is zero.");
            Directory = CurrentDmd1Evidence.RestoreProtected(false, owned.AsSpan(HeaderBytes, dmdLength), drs);
            dphOffset = HeaderBytes + dmdLength; dphLength = checked((int)dph);
            Record = Dph2Codec.Decode(owned.AsSpan(dphOffset, dphLength));
            Device = LocalDeviceAgreementBinding.FromCompletedRecord(Directory, Record);
            var expected = DeviceV1.ProtectedCurrentDmd1Validation.FingerprintAgreement(Directory, Device,
                Deep.Protocol.Identity.LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
                Record.ClaimOperationId.Span, AgreementPeerSpan);
            if (Fingerprint != expected) throw new CryptographicException("The completed agreement fingerprint differs.");
            if (!HasInitialState) return; // Key-free historical metadata grants no initial seed.
            if (state!.Length != trs || !DeviceInitialSessionCheckpoint.Fixed(SHA256.HashData(state), InitialStateHashSpan))
                throw new CryptographicException("The live sender state differs from its immutable commitment.");
            var facts = MessagingCryptoV1Trs1.ValidateDeviceBinding(state, Record.SessionId.Span,
                Record.InitiatorDeviceId.Span, Record.InitiatorDeviceGeneration);
            MessagingCryptoV1Trs1.RequireResponderContactBinding(ExactTrsSpan, Record.ResponderDeviceId.Span,
                Record.ResponderDeviceGeneration);
            MessagingCryptoV1Trs1.RequireLocalDirectoryBinding(ExactTrsSpan, Directory.DirectoryHash.Span);
            if (facts.Generation != 1 || facts.TerminallyLatched)
                throw new CryptographicException("The initial ratchet is not an active first generation.");
        }
        catch { Dispose(); throw; }
    }

    // A conversation is not present in the public DPH2/TRS1 header. Derive
    // it only from the exact events authenticated by this custody record,
    // never from a caller-supplied messaging-store scope. No payload escapes.
    internal byte[] RequireInitialConversation(ReadOnlySpan<byte> exactInit, ReadOnlySpan<byte> exactFirst)
    {
        if (exactInit.IsEmpty || exactInit.Length > 32768 || exactFirst.Length > 32768)
            throw new InvalidDataException("The retained initial events exceed their custody bound.");
        var hash = DeviceInitialSessionCheckpoint.EventHash(exactInit, exactFirst);
        try
        {
            if (!DeviceInitialSessionCheckpoint.Fixed(hash, EventHashSpan))
                throw new CryptographicException("The initial events differ from their durable completion.");
        }
        finally { CryptographicOperations.ZeroMemory(hash); }

        var init = ApplicationCoreCodec.DecodeDmc2(exactInit);
        if (init.ContentKind != Dmc2ContentKind.SessionInit ||
            !DeviceInitialSessionCheckpoint.Fixed(init.NetworkId.Span, Record.NetworkId.Span) ||
            !DeviceInitialSessionCheckpoint.Fixed(init.SenderAccountId.Span, Record.InitiatorAccountId.Span) ||
            !DeviceInitialSessionCheckpoint.Fixed(init.SenderDeviceId.Span, Record.InitiatorDeviceId.Span))
            throw new CryptographicException("The initial conversation differs from its retained device authority.");

        // DecodeDmc2 has already checked the canonical SessionInit grammar,
        // directory hash and embedded sender entry; close over our exact DMD1.
        var payload = init.PayloadBytes;
        if (payload.Length != Directory.Canonical.Length + 72 ||
            !DeviceInitialSessionCheckpoint.Fixed(payload.Span.Slice(32, 32), Directory.DirectoryHash.Span) ||
            !DeviceInitialSessionCheckpoint.Fixed(payload.Span.Slice(68, Directory.Canonical.Length), Directory.Canonical.Span))
            throw new CryptographicException("The initial conversation contains a different retained directory.");
        if (!exactFirst.IsEmpty)
        {
            var first = ApplicationCoreCodec.DecodeDmc2(exactFirst);
            if (first.ContentKind == Dmc2ContentKind.SessionInit ||
                !DeviceInitialSessionCheckpoint.Fixed(first.NetworkId.Span, init.NetworkId.Span) ||
                !DeviceInitialSessionCheckpoint.Fixed(first.SenderAccountId.Span, init.SenderAccountId.Span) ||
                !DeviceInitialSessionCheckpoint.Fixed(first.SenderDeviceId.Span, init.SenderDeviceId.Span) ||
                !DeviceInitialSessionCheckpoint.Fixed(first.ConversationId.Span, init.ConversationId.Span) ||
                DeviceInitialSessionCheckpoint.Fixed(first.LogicalMessageId.Span, init.LogicalMessageId.Span) ||
                first.SenderClientSequence <= init.SenderClientSequence ||
                first.CreatedAtUnixMilliseconds < init.CreatedAtUnixMilliseconds)
                throw new CryptographicException("The retained first event belongs to a different conversation stream.");
        }
        return init.ConversationId.ToArray();
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
            result = new byte[HeaderBytes + directory.Canonical.Length + dph.Length]; result[0] = 2;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2, 2), checked((ushort)directory.Canonical.Length));
            BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(4, 8), directory.DrsRevision);
            Convert.FromHexString(fingerprint).CopyTo(result, 12);
            claimReplayHash.CopyTo(result.AsSpan(44)); eventHash.CopyTo(result.AsSpan(76)); intent.CopyTo(result.AsSpan(108));
            agreementPeer.CopyTo(result.AsSpan(148));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(140, 4), checked((uint)dph.Length));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(144, 4), checked((uint)trs.Length));
            SHA256.HashData(trs.Span).CopyTo(result.AsSpan(180));
            directory.Canonical.Span.CopyTo(result.AsSpan(HeaderBytes));
            dph.Span.CopyTo(result.AsSpan(HeaderBytes + directory.Canonical.Length));
            if (!MemoryMarshal.TryGetArray(trs, out var state) || state.Array is null || state.Offset != 0 || state.Count != state.Array.Length)
                throw new InvalidOperationException("The owned initial TRS accessor changed its ownership contract.");
            var commit = new DeepIdV2InitialSessionCommit(result, state.Array); result = null; trs = default; return commit;
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
    internal static DeepIdV2InitialSessionCommit RestoreCustody(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> state = default) =>
        new(exact.ToArray(), state.IsEmpty ? null : state.ToArray());
    internal byte[] SerializePending()
    {
        var state = ExactTrsSpan; var result = new byte[Bytes.Length + state.Length];
        Bytes.CopyTo(result); state.CopyTo(result.AsSpan(Bytes.Length)); return result;
    }
    internal static int PendingMetadataLength(ReadOnlySpan<byte> pending)
    {
        if (pending.Length < HeaderBytes || pending.Length > MaximumPendingBytes || pending[0] != 2)
            throw new InvalidDataException("Sender pending custody has a different closed generation.");
        var dmd = BinaryPrimitives.ReadUInt16BigEndian(pending[2..]);
        var dph = BinaryPrimitives.ReadUInt32BigEndian(pending[140..]); var trs = BinaryPrimitives.ReadUInt32BigEndian(pending[144..]);
        var metadata = (long)HeaderBytes + dmd + dph;
        if (dmd is < 426 or > 1476 || dph is 0 or > MaximumDphBytes || trs is 0 or > MaximumInitialTrsBytes ||
            pending.Length != metadata + trs || !DeviceInitialSessionCheckpoint.Fixed(SHA256.HashData(pending[checked((int)metadata)..]), pending.Slice(180, 32)))
            throw new InvalidDataException("Sender pending custody lengths or state digest differ.");
        return checked((int)metadata);
    }
    internal static DeepIdV2InitialSessionCommit RestorePending(ReadOnlySpan<byte> exact)
    { var metadata = PendingMetadataLength(exact); return RestoreCustody(exact[..metadata], exact[metadata..]); }
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
        var state = Interlocked.Exchange(ref initialState, null);
        if (state is not null) CryptographicOperations.ZeroMemory(state);
    }
}
