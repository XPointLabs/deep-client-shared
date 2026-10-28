using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Synchronous derivation over independently qualified native/authored originals.
// It is never an admission path: the owner authenticates source roots, exact SQL
// and outgoing authored counters before supplying bytes, then rechecks them after
// every external edge. Selected consumers still verify actual originals on use.
internal sealed class Did2MessagingArchiveSemanticReplay
{
    private readonly Did2MessagingSessionScope scope;
    private readonly Did2MessagingArchiveBuilder builder;
    private readonly Func<Did2MessagingArchiveReference, ReadOnlyMemory<byte>> original;
    private readonly byte[] reducer, helloHash;
    private readonly Dictionary<ulong, ReadOnlyMemory<byte>> observed = [];

    internal Did2MessagingArchiveSemanticReplay(Did2MessagingSessionScope scope, Did2MessagingFloor target,
        Did2MessagingArchiveReducer before, Did2MessagingArchiveBuilder builder,
        ReadOnlySpan<byte> initialMetadata, ReadOnlyMemory<byte> exactHello,
        Func<Did2MessagingArchiveReference, ReadOnlyMemory<byte>> original)
    {
        this.scope = scope; this.builder = builder; this.original = original;
        if (target.Ordinal < before.Basis.Ordinal) throw Bad();
        reducer = before.Exact.ToArray(); target.Exact.Span.CopyTo(reducer.AsSpan(36));
        helloHash = SHA256.HashData(exactHello.Span);
        if (target.Ordinal == 0) { _ = Did2MessagingArchiveReducer.Decode(reducer, scope); return; }
        var hello = ApplicationCoreCodec.DecodeDmc2(exactHello.Span);
        if (hello.ParsedPayload is not ContactHelloDmc2Payload greeting || hello.SenderClientSequence != 2 ||
            !Fixed(hello.NetworkId.Span, scope.Network) || !Fixed(hello.ConversationId.Span, scope.Conversation) ||
            !Fixed(greeting.RelationshipId.Span, scope.Relationship) ||
            !Fixed(hello.SenderAccountId.Span, scope.IsInitiator ? scope.LocalAccount : scope.RemoteAccount) ||
            !Fixed(hello.SenderDeviceId.Span, scope.IsInitiator ? scope.LocalDevice : scope.RemoteDevice)) throw Bad();
        var metadataHash = SHA256.HashData(initialMetadata);
        if (before.Basis.Ordinal == 0)
        {
            metadataHash.CopyTo(reducer.AsSpan(224));
            BinaryPrimitives.WriteUInt32BigEndian(reducer.AsSpan(896), (uint)greeting.Policy);
            var reference = Did2MessagingArchiveReference.Initial(metadataHash);
            Set(scope.IsInitiator ? Did2MessagingArchiveReducer.ReferenceKind.OwnHead : Did2MessagingArchiveReducer.ReferenceKind.PeerHead, reference);
            SetSequence(scope.IsInitiator, 2);
            if (!scope.IsInitiator) QualifiedPeer(reference, greeting.MailboxRoute.Route.ExactBytes.Span, 0, new byte[32], 2);
        }
        else if (!Fixed(before.InitialMetadataHash, metadataHash)) throw Bad();
        observed.Add(1, exactHello);
        _ = Did2MessagingArchiveReducer.Decode(reducer, scope);
    }

    internal void Observe(Did2MessagingArchiveOriginal native, ReadOnlyMemory<byte> exactAuthored)
    {
        var reference = native.Reference;
        if (reference.Kind != 2 || !Fixed(reference.MetadataHash, SHA256.HashData(native.Metadata))) throw Bad();
        builder.Add(Did2MessagingArchiveFamily.Operation, reference.Operation, reference.Exact.Span);
        Span<byte> number = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(number, reference.Ordinal);
        builder.Add(Did2MessagingArchiveFamily.Ordinal, number, reference.Exact.Span);
        if (reference.Direction is 3 or 4) return;
        var exact = reference.Direction == 2 ? (ReadOnlyMemory<byte>)native.Plaintext : exactAuthored;
        if (exact.IsEmpty || !Fixed(SHA256.HashData(exact.Span), native.Metadata.AsSpan(300, 32))) throw Bad();
        var message = ApplicationCoreCodec.DecodeDmc2(exact.Span);
        try
        {
            if (!Fixed(message.NetworkId.Span, scope.Network) || !Fixed(message.ConversationId.Span, scope.Conversation) ||
                !Fixed(message.SenderAccountId.Span, reference.Direction == 1 ? scope.LocalAccount : scope.RemoteAccount) ||
                !Fixed(message.SenderDeviceId.Span, reference.Direction == 1 ? scope.LocalDevice : scope.RemoteDevice)) throw Bad();
            observed[reference.Ordinal] = exact;
            if (reference.Direction == 2)
            {
                builder.Add(Did2MessagingArchiveFamily.FirstIncomingEvent, native.Metadata.AsSpan(300, 32), reference.Exact.Span);
                var position = new byte[40]; scope.Conversation.CopyTo(position);
                BinaryPrimitives.WriteUInt64BigEndian(position.AsSpan(32), message.SenderClientSequence);
                var value = new byte[240]; reference.Exact.Span.CopyTo(value); native.Metadata.AsSpan(300, 32).CopyTo(value.AsSpan(88));
                builder.Add(Did2MessagingArchiveFamily.PeerAuthoredPosition, position, value);
                var attachment = new byte[64]; message.LogicalMessageId.Span.CopyTo(attachment); message.SenderDeviceId.Span.CopyTo(attachment.AsSpan(32));
                value = new byte[176]; reference.Exact.Span.CopyTo(value);
                builder.Add(Did2MessagingArchiveFamily.IncomingAttachment, attachment, value);
                var envelope = Dpe2Codec.Decode(native.Envelope);
                if (envelope.RatchetHeader.SckaSendingEpoch > U64(872) || Get(Did2MessagingArchiveReducer.ReferenceKind.MaximumPeerEpoch).IsAbsent)
                { Set(Did2MessagingArchiveReducer.ReferenceKind.MaximumPeerEpoch, reference); SetU64(872, envelope.RatchetHeader.SckaSendingEpoch); }
            }
            if (message.ParsedPayload is ContactAcceptDmc2Payload consent)
            {
                if (reference.Direction != (scope.IsInitiator ? 2 : 1) ||
                    !Fixed(consent.RelationshipId.Span, scope.Relationship) || !Fixed(consent.ContactHelloHash.Span, helloHash)) throw Bad();
                var prior = Get(Did2MessagingArchiveReducer.ReferenceKind.Consent);
                if (!prior.IsAbsent)
                {
                    if (!Fixed(Source(prior).Span, exact.Span)) throw Bad();
                    return;
                }
                Set(Did2MessagingArchiveReducer.ReferenceKind.Consent, reference);
                BinaryPrimitives.WriteUInt32BigEndian(reducer.AsSpan(900), (uint)consent.Policy);
                Set(reference.Direction == 1 ? Did2MessagingArchiveReducer.ReferenceKind.OwnHead : Did2MessagingArchiveReducer.ReferenceKind.PeerHead, reference);
                SetSequence(reference.Direction == 1, message.SenderClientSequence);
                if (reference.Direction == 2) QualifiedPeer(reference, consent.MailboxRoute.Route.ExactBytes.Span,
                    reference.Ordinal, new byte[32], message.SenderClientSequence);
            }
            else if (message.ParsedPayload is ContactRouteUpdateDmc2Payload update) Promote(native, message, update);
        }
        finally { if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
    }

    private void Promote(Did2MessagingArchiveOriginal native, ParsedDmc2 message, ContactRouteUpdateDmc2Payload update)
    {
        var reference = native.Reference; var own = reference.Direction == 1;
        if (!Fixed(update.RelationshipId.Span, scope.Relationship)) throw Bad();
        if (!own)
        {
            Did2RouteProcessingMetadata.RequireReceivedEvent(native.Metadata.AsSpan(608, 64), message);
            if (native.Metadata[608] == 2)
            {
                if (Get(Did2MessagingArchiveReducer.ReferenceKind.FirstFault).IsAbsent)
                    Set(Did2MessagingArchiveReducer.ReferenceKind.FirstFault, reference);
                return;
            }
        }
        var consent = Get(Did2MessagingArchiveReducer.ReferenceKind.Consent);
        if (consent.IsAbsent || reference.Ordinal <= consent.Ordinal ||
            ((BinaryPrimitives.ReadUInt32BigEndian(reducer.AsSpan(896)) & BinaryPrimitives.ReadUInt32BigEndian(reducer.AsSpan(900))) &
                (uint)ContactPolicy.AllowRouteUpdates) == 0) throw Bad();
        var headKind = own ? Did2MessagingArchiveReducer.ReferenceKind.OwnHead : Did2MessagingArchiveReducer.ReferenceKind.PeerHead;
        var previousKind = own ? Did2MessagingArchiveReducer.ReferenceKind.OwnPrevious : Did2MessagingArchiveReducer.ReferenceKind.PeerPrevious;
        var prior = Get(headKind); if (prior.IsAbsent) throw Bad();
        var previousBytes = Source(prior); var previousHash = SHA256.HashData(previousBytes.Span);
        if (Fixed(previousHash, native.Metadata.AsSpan(300, 32))) return;
        var previous = ApplicationCoreCodec.DecodeDmc2(previousBytes.Span);
        try
        {
            var route = previous.ParsedPayload switch
            {
                ContactHelloDmc2Payload hello => hello.MailboxRoute.Route,
                ContactAcceptDmc2Payload accept => accept.MailboxRoute.Route,
                ContactRouteUpdateDmc2Payload control => ContactRouteClosureCodec.Decode(control.ExactRouteClosure.Span),
                _ => throw Bad()
            };
            var generation = BinaryPrimitives.ReadUInt64BigEndian(route.Reachability.Field(3).Span);
            if (!own && update.RouteGeneration <= generation)
            {
                var first = builder.Read(Did2MessagingArchiveFamily.FirstIncomingEvent, native.Metadata.AsSpan(300, 32));
                if (first is not null && Did2MessagingArchiveReference.Decode(first, false).Ordinal < reference.Ordinal) return;
                throw Bad();
            }
            if (generation == ulong.MaxValue || update.RouteGeneration != generation + 1 ||
                !Fixed(update.PredecessorRouteUpdateHash.Span, previousHash) ||
                message.SenderClientSequence <= U64(own ? 880 : 888) ||
                !Get(Did2MessagingArchiveReducer.ReferenceKind.FirstFault).IsAbsent) throw Bad();
            Set(previousKind, prior); Set(headKind, reference); SetSequence(own, message.SenderClientSequence);
            if (!own) QualifiedPeer(reference, update.ExactRouteClosure.Span, consent.Ordinal, previousHash, message.SenderClientSequence);
        }
        finally { if (previous.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
    }

    private void QualifiedPeer(Did2MessagingArchiveReference reference, ReadOnlySpan<byte> closure,
        ulong consentOrdinal, ReadOnlySpan<byte> predecessorHash, ulong sequence)
    {
        var value = new byte[136]; reference.Exact.Span.CopyTo(value);
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(88), consentOrdinal); predecessorHash.CopyTo(value.AsSpan(96));
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(128), sequence);
        builder.Add(Did2MessagingArchiveFamily.QualifiedPeerRoute, SHA256.HashData(closure), value);
    }
    internal Did2MessagingArchiveReducer Complete() => Did2MessagingArchiveReducer.Decode(reducer, scope);
    private ReadOnlyMemory<byte> Source(Did2MessagingArchiveReference reference) => observed.TryGetValue(reference.Ordinal, out var exact) ? exact : original(reference);
    private Did2MessagingArchiveReference Get(Did2MessagingArchiveReducer.ReferenceKind kind) => Did2MessagingArchiveReference.Decode(reducer.AsSpan(256 + (int)kind * 88, 88));
    private void Set(Did2MessagingArchiveReducer.ReferenceKind kind, Did2MessagingArchiveReference reference) => reference.Exact.Span.CopyTo(reducer.AsSpan(256 + (int)kind * 88));
    private void SetSequence(bool own, ulong value) => SetU64(own ? 880 : 888, value);
    private ulong U64(int offset) => BinaryPrimitives.ReadUInt64BigEndian(reducer.AsSpan(offset));
    private void SetU64(int offset, ulong value) => BinaryPrimitives.WriteUInt64BigEndian(reducer.AsSpan(offset), value);
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => Did2MessagingSessionScope.Fixed(a, b);
    private static CryptographicException Bad() => new("Messaging archive semantic replay differs from its qualified native/authored originals.");
}
