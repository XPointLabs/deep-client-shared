using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Stable local initial-contact receiver custody, not acceptance or
/// ACK. Exact authenticated events and ratchet state stay inside Shared.</summary>
public sealed class DeepIdV2InitialContactSessionCommit : IDisposable
{
    internal const int HeaderBytes = 168, MaximumDphBytes = 65536, MaximumTrsBytes = 131072, MaximumEventBytes = 32768;
    internal const int MaximumPayloadBytes = HeaderBytes + 1476 + MaximumDphBytes + 2 * MaximumEventBytes;
    internal const int MaximumPendingBytes = MaximumPayloadBytes + MaximumTrsBytes;
    private byte[]? payload, initialState;
    private readonly int initOffset, initLength, helloOffset, helloLength;
    internal readonly Dph2Record Record;
    internal readonly ParsedDmd1 Directory;
    private readonly byte[] conversationId, relationshipId;
    internal ReadOnlySpan<byte> CanonicalSpan => Bytes;
    internal ReadOnlySpan<byte> ExactTrsSpan { get { _ = Bytes; return initialState is { Length: > 0 } state ? state : throw new InvalidOperationException("Initial receiver keys have been transferred and retired."); } }
    internal bool HasInitialState { get { _ = Bytes; return initialState is { Length: > 0 }; } }
    internal ReadOnlySpan<byte> InitialStateHashSpan => Bytes.Slice(136, 32);
    internal ReadOnlySpan<byte> ExactInitSpan => Bytes.Slice(initOffset, initLength);
    internal ReadOnlySpan<byte> ExactHelloSpan => Bytes.Slice(helloOffset, helloLength);
    internal ReadOnlySpan<byte> ExactClaimReplayHashSpan => Bytes.Slice(24, 32);
    internal ReadOnlySpan<byte> OneTimeKeyIdSpan => Bytes.Slice(72, 32);
    internal ReadOnlySpan<byte> MlKemKeyIdSpan => Bytes.Slice(104, 32);
    internal Dpk2PrekeyKind Kind => (Dpk2PrekeyKind)Bytes[1];
    internal ushort Counter => BinaryPrimitives.ReadUInt16BigEndian(Bytes.Slice(2, 2));
    public ReadOnlyMemory<byte> SessionId => Record.SessionId;
    public ReadOnlyMemory<byte> ClaimOperationId => Record.ClaimOperationId;
    public ReadOnlyMemory<byte> ConversationId => conversationId.ToArray();
    public ReadOnlyMemory<byte> RelationshipId => relationshipId.ToArray();
    private ReadOnlySpan<byte> Bytes => payload ?? throw new ObjectDisposedException(GetType().Name);

    private DeepIdV2InitialContactSessionCommit(byte[] owned, byte[]? state = null)
    {
        payload = owned; initialState = state;
        try
        {
            if (owned.Length < HeaderBytes || owned.Length > MaximumPayloadBytes || owned[0] != 2 ||
                owned[1] is not (1 or 2) || owned[6] != 0 || owned[7] != 0)
                throw new InvalidDataException("Initial contact receiver custody has no closed shape.");
            var dmdLength = BinaryPrimitives.ReadUInt16BigEndian(Bytes.Slice(4, 2));
            var dphLength = BinaryPrimitives.ReadUInt32BigEndian(Bytes.Slice(8, 4));
            var trs = BinaryPrimitives.ReadUInt32BigEndian(Bytes.Slice(12, 4));
            var init = BinaryPrimitives.ReadUInt32BigEndian(Bytes.Slice(16, 4));
            var hello = BinaryPrimitives.ReadUInt32BigEndian(Bytes.Slice(20, 4));
            if (dmdLength is < 426 or > 1476 || dphLength is 0 or > MaximumDphBytes || trs is 0 or > MaximumTrsBytes ||
                init is 0 or > MaximumEventBytes || hello is 0 or > MaximumEventBytes ||
                owned.Length != (long)HeaderBytes + dmdLength + dphLength + init + hello ||
                ExactClaimReplayHashSpan.IndexOfAnyExcept((byte)0) < 0 || MlKemKeyIdSpan.IndexOfAnyExcept((byte)0) < 0 || InitialStateHashSpan.IndexOfAnyExcept((byte)0) < 0)
                throw new InvalidDataException("Initial contact receiver lengths or commitments are invalid.");
            Directory = ApplicationCoreCodec.DecodeDmd1(Bytes.Slice(HeaderBytes, dmdLength));
            var dphOffset = HeaderBytes + dmdLength;
            Record = Dph2Codec.Decode(Bytes.Slice(dphOffset, checked((int)dphLength)));
            initOffset = dphOffset + checked((int)dphLength); initLength = checked((int)init);
            helloOffset = initOffset + initLength; helloLength = checked((int)hello);
            if (Kind != Record.SelectedPrekey.Kind || Counter != Record.LastResortUseCounter ||
                !Fixed(OneTimeKeyIdSpan, Record.SelectedPrekey.OneTimeX25519PrekeyIdOrZero.Span) ||
                !Fixed(MlKemKeyIdSpan, Record.SelectedPrekey.MlKemPrekeyId.Span) ||
                !Fixed(Directory.NetworkId.Span, Record.NetworkId.Span) ||
                !Fixed(Directory.DeepAccountId.Span, Record.ResponderAccountId.Span) ||
                Directory.AccountGeneration != BinaryPrimitives.ReadUInt64BigEndian(Bytes.Slice(56, 8)) ||
                Record.ResponderDeviceGeneration != BinaryPrimitives.ReadUInt64BigEndian(Bytes.Slice(64, 8)))
                throw new CryptographicException("Initial receiver custody has different reservation or local directory bindings.");
            var localId = Record.ResponderDeviceId.ToArray();
            var entry = Directory.ActiveDevices.SingleOrDefault(candidate => Fixed(candidate.DeviceId.Span, localId));
            if (entry is null)
                throw new CryptographicException("Initial receiver custody has no matching local directory device.");
            if (HasInitialState)
            {
                if (state!.Length != trs || !Fixed(SHA256.HashData(state), InitialStateHashSpan))
                    throw new CryptographicException("The live receiver state differs from its immutable commitment.");
                var facts = MessagingCryptoV1Trs1.ValidateDeviceBinding(state, Record.SessionId.Span,
                    Record.ResponderDeviceId.Span, Record.ResponderDeviceGeneration);
                MessagingCryptoV1Trs1.RequireResponderContactBinding(ExactTrsSpan, Record.InitiatorDeviceId.Span, Record.InitiatorDeviceGeneration);
                MessagingCryptoV1Trs1.RequireLocalDirectoryBinding(ExactTrsSpan, Directory.RecordHash.Span);
                if (facts.Generation != 1 || facts.TerminallyLatched)
                    throw new CryptographicException("Initial receiver ratchet is not an active first generation.");
            }
            var parsedInit = ApplicationCoreCodec.DecodeDmc2(ExactInitSpan);
            var helloEvent = ApplicationCoreCodec.DecodeDmc2(ExactHelloSpan);
            if (parsedInit.ParsedPayload is not SessionInitDmc2Payload initial || helloEvent.ParsedPayload is not ContactHelloDmc2Payload contact ||
                !Fixed(parsedInit.NetworkId.Span, Record.NetworkId.Span) ||
                !Fixed(parsedInit.SenderAccountId.Span, Record.InitiatorAccountId.Span) ||
                !Fixed(parsedInit.SenderDeviceId.Span, Record.InitiatorDeviceId.Span) ||
                !Fixed(initial.SenderDirectory.DeepAccountId.Span, Record.InitiatorAccountId.Span) ||
                !Fixed(initial.SenderDirectory.NetworkId.Span, Record.NetworkId.Span) ||
                !Fixed(initial.SenderDmd1Hash.Span, initial.SenderDirectory.RecordHash.Span) ||
                !Fixed(contact.InitiatorDmd1Hash.Span, initial.SenderDmd1Hash.Span) ||
                !Fixed(helloEvent.NetworkId.Span, parsedInit.NetworkId.Span) ||
                !Fixed(helloEvent.SenderAccountId.Span, parsedInit.SenderAccountId.Span) ||
                !Fixed(helloEvent.SenderDeviceId.Span, parsedInit.SenderDeviceId.Span) ||
                !Fixed(helloEvent.ConversationId.Span, parsedInit.ConversationId.Span) ||
                Fixed(helloEvent.LogicalMessageId.Span, parsedInit.LogicalMessageId.Span) ||
                helloEvent.SenderClientSequence <= parsedInit.SenderClientSequence ||
                helloEvent.CreatedAtUnixMilliseconds < parsedInit.CreatedAtUnixMilliseconds ||
                !Fixed(helloEvent.ConversationId.Span, ApplicationCoreVerifier.ComputeContactConversationId(Record.NetworkId.Span,
                    contact.RelationshipId.Span, Record.InitiatorAccountId.Span, Record.ResponderAccountId.Span)))
                throw new CryptographicException("Initial receiver events differ from their exact authenticated conversation stream.");
            if (HasInitialState) MessagingCryptoV1Trs1.RequireRemoteDirectoryBinding(ExactTrsSpan, initial.SenderDmd1Hash.Span);
            var remoteId = Record.InitiatorDeviceId.ToArray();
            var remoteEntry = initial.SenderDirectory.ActiveDevices.SingleOrDefault(candidate => Fixed(candidate.DeviceId.Span, remoteId));
            if (remoteEntry is null || !Fixed(remoteEntry.Dpd1Reference.CanonicalHash.Span, Record.InitiatorDpd1Ref.Span[6..]))
                throw new CryptographicException("Initial receiver events have a different initiating directory certificate.");
            // Retain identifiers, not another long-lived parsed plaintext copy.
            conversationId = helloEvent.ConversationId.ToArray(); relationshipId = contact.RelationshipId.ToArray();
        }
        catch { Dispose(); throw; }
    }

    internal static DeepIdV2InitialContactSessionCommit Capture(ResponderInitialSessionCommitCapability capability,
        VerifiedDph2InitialClaim claim, ParsedDmd1 recipientDirectory)
    {
        using var transfer = capability.ConsumeForAtomicStore();
        var reservation = transfer.Reservation;
        var dph = Own(claim.Initiation.ExactBytes); byte[]? trs = Own(transfer.ExactTrs1);
        var init = Own(transfer.SessionInitDmc2); var hello = Own(transfer.FirstApplicationDmc2);
        byte[]? result = null;
        try
        {
            if (dph.Length > MaximumDphBytes || trs.Length > MaximumTrsBytes || init.Length > MaximumEventBytes || hello.Length > MaximumEventBytes)
                throw new InvalidDataException("Initial receiver preparation exceeds its local custody bound.");
            if (!Fixed(reservation.SessionId.Span, claim.Initiation.SessionId.Span) ||
                !Fixed(reservation.OperationId.Span, claim.Claim.OperationId.Span) ||
                !Fixed(reservation.Dph2FullReplayHash.Span, claim.Initiation.FullReplayHash.Span) ||
                !Fixed(reservation.ExactDpk2Hash.Span, claim.Claim.ExactDpk2Hash.Span) ||
                !Fixed(reservation.Xpc1FullReplayHash.Span, claim.Claim.ExactReplayHash.Span))
                throw new CryptographicException("Initial receiver preparation differs from its verified exact claim.");
            result = new byte[HeaderBytes + recipientDirectory.CanonicalBytes.Length + dph.Length + init.Length + hello.Length];
            result[0] = 2; result[1] = (byte)reservation.Kind;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2, 2), reservation.LastResortUseCounter);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4, 2), checked((ushort)recipientDirectory.CanonicalBytes.Length));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8, 4), checked((uint)dph.Length));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(12, 4), checked((uint)trs.Length));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(16, 4), checked((uint)init.Length));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(20, 4), checked((uint)hello.Length));
            reservation.Xpc1FullReplayHash.Span.CopyTo(result.AsSpan(24));
            BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(56, 8), recipientDirectory.AccountGeneration);
            BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(64, 8), Dph2Codec.Decode(dph).ResponderDeviceGeneration);
            reservation.X25519PreKeyId.Span.CopyTo(result.AsSpan(72));
            reservation.MlKemPreKeyId.Span.CopyTo(result.AsSpan(104));
            SHA256.HashData(trs).CopyTo(result.AsSpan(136));
            var offset = HeaderBytes;
            recipientDirectory.CanonicalBytes.Span.CopyTo(result.AsSpan(offset)); offset += recipientDirectory.CanonicalBytes.Length;
            foreach (var exact in new[] { dph, init, hello }) { exact.CopyTo(result, offset); offset += exact.Length; }
            var commit = new DeepIdV2InitialContactSessionCommit(result, trs); result = null; trs = null; return commit;
        }
        finally
        {
            foreach (var secret in new[] { trs, init, hello, result }) if (secret is not null) CryptographicOperations.ZeroMemory(secret);
        }
    }

    internal static DeepIdV2InitialContactSessionCommit RestoreCustody(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> state = default) =>
        new(exact.ToArray(), state.IsEmpty ? null : state.ToArray());
    internal byte[] SerializePending()
    {
        var state = ExactTrsSpan; var result = new byte[Bytes.Length + state.Length];
        Bytes.CopyTo(result); state.CopyTo(result.AsSpan(Bytes.Length)); return result;
    }
    internal static int PendingMetadataLength(ReadOnlySpan<byte> pending)
    {
        if (pending.Length < HeaderBytes || pending.Length > MaximumPendingBytes || pending[0] != 2)
            throw new InvalidDataException("Receiver pending custody has a different closed generation.");
        var dmd = BinaryPrimitives.ReadUInt16BigEndian(pending[4..]);
        var dph = BinaryPrimitives.ReadUInt32BigEndian(pending[8..]); var trs = BinaryPrimitives.ReadUInt32BigEndian(pending[12..]);
        var init = BinaryPrimitives.ReadUInt32BigEndian(pending[16..]); var hello = BinaryPrimitives.ReadUInt32BigEndian(pending[20..]);
        var metadata = (long)HeaderBytes + dmd + dph + init + hello;
        if (dmd is < 426 or > 1476 || dph is 0 or > MaximumDphBytes || trs is 0 or > MaximumTrsBytes ||
            init is 0 or > MaximumEventBytes || hello is 0 or > MaximumEventBytes || pending.Length != metadata + trs ||
            !Fixed(SHA256.HashData(pending[checked((int)metadata)..]), pending.Slice(136, 32)))
            throw new InvalidDataException("Receiver pending custody lengths or state digest differ.");
        return checked((int)metadata);
    }
    internal static DeepIdV2InitialContactSessionCommit RestorePending(ReadOnlySpan<byte> exact)
    { var metadata = PendingMetadataLength(exact); return RestoreCustody(exact[..metadata], exact[metadata..]); }
    // Protocol accessors return owned array-backed copies. Do not abandon
    // their plaintext/ratchet copy by allocating and erasing only a second one.
    private static byte[] Own(ReadOnlyMemory<byte> value) =>
        MemoryMarshal.TryGetArray(value, out var segment) && segment.Array is not null && segment.Offset == 0 && segment.Count == segment.Array.Length
            ? segment.Array : value.ToArray();
    internal static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    public void Dispose()
    {
        var owned = Interlocked.Exchange(ref payload, null); if (owned is not null) CryptographicOperations.ZeroMemory(owned);
        var state = Interlocked.Exchange(ref initialState, null); if (state is not null) CryptographicOperations.ZeroMemory(state);
        GC.SuppressFinalize(this);
    }
    ~DeepIdV2InitialContactSessionCommit() => Dispose();
}
