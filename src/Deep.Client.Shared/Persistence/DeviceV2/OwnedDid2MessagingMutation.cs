using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Closed owned capture of initial custody or a Protocol-sealed
/// transition. Restored protected pending bytes are only exact crash recovery;
/// neither form grants retirement, dispatch or ACK permission.</summary>
internal sealed class OwnedDid2MessagingMutation : IDisposable
{
    private readonly byte[] bytes = [];
    private readonly int[] lengths;
    private int disposed;
    internal Did2MessagingSessionScope Scope { get; }
    internal Did2MessagingFloor Predecessor { get; }
    internal Did2MessagingFloor Successor { get; }
    internal ReadOnlyMemory<byte> Exact { get { RequireLive(); return bytes; } }
    internal ReadOnlySpan<byte> Header { get { RequireLive(); return bytes.AsSpan(0, Did2MessagingFloor.MetadataBytes); } }
    internal byte Kind => Header[5];
    internal byte Direction => Header[6];
    internal ReadOnlySpan<byte> Operation => Header.Slice(268, 32);
    internal ReadOnlySpan<byte> EventCommitment => Header.Slice(300, 32);
    internal ReadOnlySpan<byte> EnvelopeCommitment => Header.Slice(332, 32);
    internal ReadOnlySpan<byte> NextTrs => Body(0);
    internal ReadOnlySpan<byte> Envelope => Body(1);
    internal ReadOnlySpan<byte> AuthenticatedDmc2 => Body(2);
    internal ReadOnlySpan<byte> SessionInit => Body(3);
    internal ReadOnlySpan<byte> ContactHello => Body(4);

    private OwnedDid2MessagingMutation(Did2MessagingSessionScope scope, ReadOnlySpan<byte> exact)
    {
        Scope = scope;
        ValidateHeader(exact);
        // No allocation based on untrusted length until every length and sum
        // passes the closed kind-specific bound.
        lengths = new int[5];
        for (var index = 0; index < 5; index++) lengths[index] = checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact[(588 + 4 * index)..]));
        bytes = exact.ToArray();
        try
        {
            Predecessor = Did2MessagingFloor.Decode(Header.Slice(8, Did2MessagingFloor.Bytes), scope);
            ValidateBodies();
            Successor = Did2MessagingFloor.Pending(scope, Predecessor, Header[7],
                BinaryPrimitives.ReadUInt64BigEndian(Header[196..]), Header.Slice(204, 32), Header.Slice(236, 32), Header, bytes);
        }
        catch { Dispose(); throw; }
    }

    internal static OwnedDid2MessagingMutation Import(OwnedInitialMessagingSeed seed, Did2MessagingFloor empty)
    {
        var scope = Did2MessagingSessionScope.FromSeed(seed);
        _ = Did2MessagingFloor.Decode(empty.Exact.Span, scope);
        if (empty.Phase != 1 || empty.Ordinal != 0) throw new InvalidDataException("DID2 messaging import requires its registered empty floor.");
        var trs = seed.ExactTrs; var facts = Facts(trs, scope);
        var envelope = Dph2Codec.Encode(seed.Initiation);
        var header = HeaderFor(1, 0, 0, empty, facts.Generation, facts.StateCommitment, facts.ExactHash,
            seed.Initiation.ClaimOperationId.Span, DeviceInitialSessionCheckpoint.EventHash(seed.ExactSessionInit, seed.ExactContactHello),
            SHA256.HashData(envelope));
        return Encode(scope, header, trs, envelope, [], seed.ExactSessionInit, seed.ExactContactHello);
    }

    internal static OwnedDid2MessagingMutation Activate(Did2InitialKeyRetirementReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        var transfer = receipt.Transfer; var prior = transfer.ImportedFloor;
        var header = HeaderFor(3, 0, 1, prior, prior.RatchetGeneration, prior.RatchetCommitment,
            prior.RatchetHash, receipt.Operation, receipt.Commitment, new byte[32]);
        return Encode(transfer.Scope, header, [], [], [], [], []);
    }

    internal static OwnedDid2MessagingMutation LatchOwnedSend(Did2OwnedSendConflict conflict)
    {
        ArgumentNullException.ThrowIfNull(conflict);
        var prior = conflict.Floor;
        if (prior.Phase != 1 || prior.Status != 1)
            throw new CryptographicException("Owned-send latching requires the verified active stable predecessor.");
        var header = HeaderFor(4, 0, 2, prior, prior.RatchetGeneration, new byte[32], new byte[32],
            conflict.Operation, conflict.Commitment, new byte[32]);
        return Encode(conflict.Scope, header, [], [], [], [], []);
    }

    internal static OwnedDid2MessagingMutation Ratchet(Did2MessagingSessionScope scope, Did2MessagingFloor stable,
        ExactDpe2DurablePersistencePlan plan, ReadOnlySpan<byte> exactSendEventHash)
    {
        ArgumentNullException.ThrowIfNull(plan);
        _ = Did2MessagingFloor.Decode(stable.Exact.Span, scope);
        using var owned = ExactDpe2ProtocolPlanSnapshot.Capture(plan);
        if (stable.Phase != 1 || stable.Status != 1 || !owned.HasStateMutation || !owned.MessageKeyDeleted ||
            owned.PriorStateGeneration != stable.RatchetGeneration || owned.NextStateGeneration != checked(stable.RatchetGeneration + 1) ||
            owned.CheckpointPriorGeneration != stable.RatchetGeneration || owned.ExpectedJournalGeneration != stable.Ordinal ||
            !Fixed(owned.PriorStateCommitment, stable.RatchetCommitment) || !Fixed(owned.CheckpointPriorCommitment, stable.RatchetCommitment) ||
            !Fixed(owned.JournalPredecessor, stable.Head) || !Fixed(SHA256.HashData(owned.PriorTrs1), stable.RatchetHash))
            throw new CryptographicException("DID2 sealed transition has a different protected predecessor.");
        var priorFacts = Facts(owned.PriorTrs1, scope);
        if (priorFacts.Generation != stable.RatchetGeneration || !Fixed(priorFacts.StateCommitment, stable.RatchetCommitment))
            throw new CryptographicException("DID2 sealed transition prior TRS differs.");
        var direction = owned.Direction == MessagingCryptoV1Direction.Send ? (byte)1 : (byte)2;
        if (direction == 1 && (exactSendEventHash.Length != 32 || Zero(exactSendEventHash) || owned.AuthenticatedDmc2.Length != 0) ||
            direction == 2 && (!exactSendEventHash.IsEmpty || owned.AuthenticatedDmc2.Length == 0))
            throw new CryptographicException("DID2 sealed transition event ownership differs.");
        var eventHash = direction == 1 ? exactSendEventHash.ToArray() : SHA256.HashData(owned.AuthenticatedDmc2);
        var header = HeaderFor(2, direction, 1, stable, owned.NextStateGeneration, owned.NextStateCommitment,
            SHA256.HashData(owned.NextTrs1), owned.OperationId, eventHash, owned.ExactEnvelopeHash);
        Put(header, 364, owned.ExactHeaderHash); Put(header, 396, owned.DeletionManifestCommitment);
        Put(header, 428, owned.MessageKeyDeletionEvidence); Put(header, 460, owned.ReplayEvidenceCommitment);
        PutOptional(header, 492, owned.DeduplicationMutationCommitment); PutOptional(header, 524, owned.PqFenceMutationCommitment);
        PutOptional(header, 556, owned.TerminalStateCommitment);
        return Encode(scope, header, owned.NextTrs1, owned.ExactEnvelope, owned.AuthenticatedDmc2, [], []);
    }

    internal static OwnedDid2MessagingMutation RecoverProtectedPending(Did2MessagingSessionScope scope,
        Did2MessagingFloor protectedPending, ReadOnlySpan<byte> exact)
    {
        _ = Did2MessagingFloor.Decode(protectedPending.Exact.Span, scope);
        if (protectedPending.Phase != 2 || exact.Length != protectedPending.PendingBytes ||
            !Fixed(SHA256.HashData(exact), protectedPending.PendingHash))
            throw new CryptographicException("DID2 mutation recovery lacks its exact protected pending payload.");
        var restored = new OwnedDid2MessagingMutation(scope, exact);
        if (Fixed(restored.Successor.Exact.Span, protectedPending.Exact.Span)) return restored;
        restored.Dispose(); throw new CryptographicException("DID2 mutation successor differs from its protected pending floor.");
    }

    private static byte[] HeaderFor(byte kind, byte direction, byte status, Did2MessagingFloor predecessor,
        ulong generation, ReadOnlySpan<byte> commitment, ReadOnlySpan<byte> trsHash, ReadOnlySpan<byte> operation,
        ReadOnlySpan<byte> eventHash, ReadOnlySpan<byte> envelopeHash)
    {
        var header = new byte[Did2MessagingFloor.MetadataBytes]; "MSP2"u8.CopyTo(header);
        header[4] = 1; header[5] = kind; header[6] = direction; header[7] = status; predecessor.Exact.Span.CopyTo(header.AsSpan(8));
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(196), generation);
        Put(header, 204, commitment); Put(header, 236, trsHash); Put(header, 268, operation);
        Put(header, 300, eventHash); Put(header, 332, envelopeHash); return header;
    }
    private static OwnedDid2MessagingMutation Encode(Did2MessagingSessionScope scope, byte[] header,
        ReadOnlySpan<byte> trs, ReadOnlySpan<byte> envelope, ReadOnlySpan<byte> dmc, ReadOnlySpan<byte> init, ReadOnlySpan<byte> hello)
    {
        int[] sizes = [trs.Length, envelope.Length, dmc.Length, init.Length, hello.Length];
        long total = Did2MessagingFloor.MetadataBytes + sizes.Sum(static length => (long)length);
        if (total > Did2MessagingFloor.MaximumPendingBytes) throw new InvalidDataException("DID2 mutation exceeds its closed payload bound.");
        for (var index = 0; index < 5; index++) BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(588 + index * 4), checked((uint)sizes[index]));
        var bytes = new byte[checked((int)total)];
        try
        {
            header.CopyTo(bytes, 0); var offset = Did2MessagingFloor.MetadataBytes;
            trs.CopyTo(bytes.AsSpan(offset)); offset += trs.Length; envelope.CopyTo(bytes.AsSpan(offset)); offset += envelope.Length;
            dmc.CopyTo(bytes.AsSpan(offset)); offset += dmc.Length; init.CopyTo(bytes.AsSpan(offset)); offset += init.Length; hello.CopyTo(bytes.AsSpan(offset));
            return new(scope, bytes);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static void ValidateHeader(ReadOnlySpan<byte> exact)
    {
        if (exact.Length < Did2MessagingFloor.MetadataBytes || exact.Length > Did2MessagingFloor.MaximumPendingBytes)
            throw new InvalidDataException("DID2 mutation has a different closed payload size.");
        ValidateMetadata(exact[..Did2MessagingFloor.MetadataBytes]);
        long total = Did2MessagingFloor.MetadataBytes;
        for (var index = 0; index < 5; index++) total += BinaryPrimitives.ReadUInt32BigEndian(exact[(588 + index * 4)..]);
        if (total != exact.Length) throw new InvalidDataException("DID2 mutation exact body lengths differ.");
    }
    internal static void ValidateMetadata(ReadOnlySpan<byte> exact)
    {
        if (exact.Length != Did2MessagingFloor.MetadataBytes || !exact[..4].SequenceEqual("MSP2"u8) ||
            exact[4] != 1 || exact[5] is not (1 or 2 or 3 or 4) || exact[6] > 2 || exact[7] > 2)
            throw new InvalidDataException("DID2 mutation has an unknown closed header.");
        Span<uint> sizes = stackalloc uint[5]; long total = Did2MessagingFloor.MetadataBytes;
        for (var index = 0; index < 5; index++) { sizes[index] = BinaryPrimitives.ReadUInt32BigEndian(exact[(588 + index * 4)..]); total += sizes[index]; }
        if (total > Did2MessagingFloor.MaximumPendingBytes || Zero(exact.Slice(268, 32)) || Zero(exact.Slice(300, 32)))
            throw new InvalidDataException("DID2 mutation lengths or operation/event binding are invalid.");
        if (exact[5] == 1)
        {
            if (exact[6] != 0 || exact[7] != 0 || sizes[0] is 0 or > 131072 || sizes[1] is 0 or > 65536 || sizes[2] != 0 ||
                sizes[3] is 0 or > 32768 || sizes[4] is 0 or > 32768 || Zero(exact.Slice(332, 32)) || !Zero(exact.Slice(364, 224)))
                throw new InvalidDataException("DID2 import mutation has a different closed shape.");
        }
        else if (exact[5] == 2)
        {
            if (exact[6] is not (1 or 2) || exact[7] != 1 || sizes[0] is 0 or > 2097152 || sizes[1] is 0 or > 65536 ||
                (exact[6] == 1 ? sizes[2] != 0 : sizes[2] is 0 or > 33082) || sizes[3] != 0 || sizes[4] != 0)
                throw new InvalidDataException("DID2 ratchet mutation has a different closed shape.");
            foreach (var offset in new[] { 332, 364, 396, 428, 460 })
                if (Zero(exact.Slice(offset, 32))) throw new InvalidDataException("DID2 ratchet mutation lacks closed evidence.");
            if (exact[6] == 1 ? !Zero(exact.Slice(492, 32)) : Zero(exact.Slice(492, 32)))
                throw new InvalidDataException("DID2 ratchet deduplication evidence has a different direction.");
        }
        else if (exact[6] != 0 || sizes.IndexOfAnyExcept(0U) >= 0 || !Zero(exact.Slice(332, 256)) ||
                 exact[7] != (exact[5] == 3 ? 1 : 2))
            throw new InvalidDataException("DID2 control mutation has a different closed shape.");
    }
    internal static void ValidateMetadataTransition(ReadOnlySpan<byte> header, Did2MessagingSessionScope scope, Did2MessagingFloor predecessor)
    {
        ValidateMetadata(header);
        var retained = Did2MessagingFloor.Decode(header.Slice(8, Did2MessagingFloor.Bytes), scope);
        var generation = BinaryPrimitives.ReadUInt64BigEndian(header[196..]); var kind = header[5];
        if (!Fixed(predecessor.Exact.Span, retained.Exact.Span) || retained.Phase != 1 || retained.Status == 2 || generation == 0 ||
            (kind == 1 ? retained.Ordinal != 0 || generation != 1 :
                kind == 2 ? retained.Status != 1 || retained.RatchetGeneration == ulong.MaxValue || generation != retained.RatchetGeneration + 1 :
                retained.Ordinal == 0 || generation != retained.RatchetGeneration || kind == 3 && retained.Status != 0))
            throw new InvalidDataException("DID2 mutation metadata predecessor or transition is invalid.");
        if (kind == 3 ? !Fixed(header.Slice(204, 32), retained.RatchetCommitment) || !Fixed(header.Slice(236, 32), retained.RatchetHash) :
            kind == 4 && !Zero(header.Slice(204, 64)))
            throw new CryptographicException("DID2 control metadata changed retained key-state commitments.");
    }
    private void ValidateBodies()
    {
        var generation = BinaryPrimitives.ReadUInt64BigEndian(Header[196..]);
        if (Predecessor.Phase != 1 || Predecessor.Status == 2 || generation == 0)
            throw new InvalidDataException("DID2 mutation predecessor cannot advance.");
        if (Kind == 1 ? Predecessor.Ordinal != 0 || generation != 1 :
            Kind == 2 ? Predecessor.Status != 1 || generation != checked(Predecessor.RatchetGeneration + 1) :
            Predecessor.Ordinal == 0 || generation != Predecessor.RatchetGeneration || Kind == 3 && Predecessor.Status != 0)
            throw new InvalidDataException("DID2 mutation generation/status transition is invalid.");
        if (Kind is 3 or 4)
        {
            if (Kind == 3 ? !Fixed(Header.Slice(204, 32), Predecessor.RatchetCommitment) || !Fixed(Header.Slice(236, 32), Predecessor.RatchetHash) :
                !Zero(Header.Slice(204, 64))) throw new CryptographicException("DID2 control mutation changed retained key-state commitments.");
            return;
        }
        var facts = Facts(NextTrs, Scope);
        if (generation != facts.Generation || !Fixed(Header.Slice(204, 32), facts.StateCommitment) || !Fixed(Header.Slice(236, 32), facts.ExactHash))
            throw new CryptographicException("DID2 next TRS differs from the exact mutation commitments.");
        if (Kind == 1)
        {
            if (facts.TerminallyLatched) throw new CryptographicException("DID2 import has terminal key state.");
            var record = Dph2Codec.Decode(Envelope);
            if (!Fixed(record.NetworkId.Span, Scope.Network) || !Fixed(record.SessionId.Span, Scope.Session) ||
                !Fixed(record.ClaimOperationId.Span, Operation) || !Fixed(SHA256.HashData(Envelope), EnvelopeCommitment) ||
                !Fixed(record.InitiatorAccountId.Span, Scope.IsInitiator ? Scope.LocalAccount : Scope.RemoteAccount) ||
                !Fixed(record.ResponderAccountId.Span, Scope.IsInitiator ? Scope.RemoteAccount : Scope.LocalAccount) ||
                !Fixed(record.InitiatorDeviceId.Span, Scope.IsInitiator ? Scope.LocalDevice : Scope.RemoteDevice) ||
                !Fixed(record.ResponderDeviceId.Span, Scope.IsInitiator ? Scope.RemoteDevice : Scope.LocalDevice) ||
                record.InitiatorDeviceGeneration != (Scope.IsInitiator ? Scope.LocalDeviceGeneration : Scope.RemoteDeviceGeneration) ||
                record.ResponderDeviceGeneration != (Scope.IsInitiator ? Scope.RemoteDeviceGeneration : Scope.LocalDeviceGeneration) ||
                !Fixed(DeviceInitialSessionCheckpoint.EventHash(SessionInit, ContactHello), EventCommitment))
                throw new CryptographicException("DID2 import differs from its exact initial custody.");
            var initial = ApplicationCoreCodec.DecodeDmc2(SessionInit); var hello = ApplicationCoreCodec.DecodeDmc2(ContactHello);
            RequireEvent(initial, Scope.IsInitiator); RequireEvent(hello, Scope.IsInitiator);
            if (initial.ParsedPayload is not SessionInitDmc2Payload session || hello.ParsedPayload is not ContactHelloDmc2Payload contact ||
                !Fixed(contact.RelationshipId.Span, Scope.Relationship) ||
                !Fixed(session.SenderDmd1Hash.Span, Scope.IsInitiator ? Scope.LocalDirectory : Scope.RemoteDirectory) ||
                !Fixed(contact.InitiatorDmd1Hash.Span, session.SenderDmd1Hash.Span) ||
                hello.SenderClientSequence <= initial.SenderClientSequence || hello.CreatedAtUnixMilliseconds < initial.CreatedAtUnixMilliseconds ||
                Fixed(hello.LogicalMessageId.Span, initial.LogicalMessageId.Span) ||
                !Fixed(ApplicationCoreVerifier.ComputeContactConversationId(Scope.Network, Scope.Relationship, Scope.LocalAccount, Scope.RemoteAccount), Scope.Conversation))
                throw new CryptographicException("DID2 import's authenticated events are inconsistent.");
        }
        else
        {
            var envelope = Dpe2Codec.Decode(Envelope);
            if (!Fixed(envelope.NetworkId.Span, Scope.Network) || !Fixed(envelope.SessionId.Span, Scope.Session) ||
                !Fixed(envelope.SenderDeviceId.Span, Direction == 1 ? Scope.LocalDevice : Scope.RemoteDevice) ||
                !Fixed(envelope.RecipientDeviceId.Span, Direction == 1 ? Scope.RemoteDevice : Scope.LocalDevice) ||
                !Fixed(envelope.OperationId.Span, Operation) ||
                !Fixed(MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(envelope), EnvelopeCommitment) ||
                !Fixed(MessagingWireCryptographicInputs.ComputeDtr2HeaderHash(envelope.RatchetHeader), Header.Slice(364, 32)))
                throw new CryptographicException("DID2 ratchet envelope differs from the exact mutation.");
            if (Direction == 2)
            {
                RequireEvent(ApplicationCoreCodec.DecodeDmc2(AuthenticatedDmc2), false, initialConversation: false);
                if (!Fixed(SHA256.HashData(AuthenticatedDmc2), EventCommitment)) throw new CryptographicException("DID2 receive event commitment differs.");
            }
            if (facts.TerminallyLatched && Zero(Header.Slice(556, 32)))
                throw new CryptographicException("DID2 terminal successor lacks its sealed terminal commitment.");
        }
    }
    private void RequireEvent(ParsedDmc2 record, bool localSender, bool initialConversation = true)
    {
        if (!Fixed(record.NetworkId.Span, Scope.Network) || initialConversation && !Fixed(record.ConversationId.Span, Scope.Conversation) ||
            !Fixed(record.SenderAccountId.Span, localSender ? Scope.LocalAccount : Scope.RemoteAccount) ||
            !Fixed(record.SenderDeviceId.Span, localSender ? Scope.LocalDevice : Scope.RemoteDevice))
            throw new CryptographicException("DID2 authenticated event has a different session scope.");
    }
    private static MessagingCryptoV1Trs1Facts Facts(ReadOnlySpan<byte> trs, Did2MessagingSessionScope scope)
    {
        var facts = MessagingCryptoV1Trs1.ValidateDeviceBinding(trs, scope.Session, scope.LocalDevice, scope.LocalDeviceGeneration);
        MessagingCryptoV1Trs1.RequireResponderContactBinding(trs, scope.RemoteDevice, scope.RemoteDeviceGeneration);
        MessagingCryptoV1Trs1.RequireLocalDirectoryBinding(trs, scope.LocalDirectory);
        MessagingCryptoV1Trs1.RequireRemoteDirectoryBinding(trs, scope.RemoteDirectory); return facts;
    }
    private ReadOnlySpan<byte> Body(int index)
    {
        RequireLive(); var offset = Did2MessagingFloor.MetadataBytes;
        for (var prior = 0; prior < index; prior++) offset += lengths[prior];
        return bytes.AsSpan(offset, lengths[index]);
    }
    private static void Put(byte[] header, int offset, ReadOnlySpan<byte> value)
    { if (value.Length != 32) throw new InvalidDataException("DID2 mutation commitment has a different width."); value.CopyTo(header.AsSpan(offset, 32)); }
    private static void PutOptional(byte[] header, int offset, ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty) { header.AsSpan(offset, 32).Clear(); return; }
        if (Zero(value)) throw new InvalidDataException("DID2 optional commitment is present but zero.");
        Put(header, offset, value);
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => Did2MessagingSessionScope.Fixed(a, b);
    private static bool Zero(ReadOnlySpan<byte> value) => Did2MessagingSessionScope.Zero(value);
    private void RequireLive() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) != 0) return; CryptographicOperations.ZeroMemory(bytes); GC.SuppressFinalize(this); }
    ~OwnedDid2MessagingMutation() => Dispose();
}
