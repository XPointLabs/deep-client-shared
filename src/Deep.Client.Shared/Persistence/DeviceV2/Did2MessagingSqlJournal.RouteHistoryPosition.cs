using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    private (Did2MessagingArchiveReference? Related, byte[] Fact) ReadRoutePositionConflict(
        Did2MessagingArchiveOriginal selected, IReadOnlyList<byte[]> headers, SqliteTransaction tx)
    {
        if (selected.Reference.Kind != 2 || selected.Reference.Direction != 2 || selected.Metadata[608] != 3)
            throw new CryptographicException("Native position conflict requires its actual incoming staged control.");
        var message = ApplicationCoreCodec.DecodeDmc2(selected.Plaintext);
        if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload || !Fixed(message.ConversationId.Span, scope.Conversation))
            throw new CryptographicException("Native position conflict has another actual control scope.");
        var selector = new byte[40]; scope.Conversation.CopyTo(selector);
        BinaryPrimitives.WriteUInt64BigEndian(selector.AsSpan(32), message.SenderClientSequence);
        var fact = ReadArchiveFact(Did2MessagingArchiveFamily.PeerAuthoredPosition, selector, tx);
        for (var index = 0; index < headers.Count; index++)
        {
            var header = headers[index]; if (header[5] != 2 || header[6] != 2) continue;
            var reference = CaptureNativeReference(checked(WorkingBasis.Ordinal + (ulong)index + 1), header, tx);
            using var original = ReadArchiveOriginal(reference, tx);
            var candidate = ApplicationCoreCodec.DecodeDmc2(original.Plaintext);
            try
            {
                if (!Fixed(candidate.ConversationId.Span, scope.Conversation) || candidate.SenderClientSequence != message.SenderClientSequence) continue;
                var observation = new byte[240]; reference.Exact.Span.CopyTo(observation); header.AsSpan(300, 32).CopyTo(observation.AsSpan(88));
                fact = fact is null ? observation : Did2MessagingArchiveBuilder.Merge(Did2MessagingArchiveFamily.PeerAuthoredPosition, selector, fact, observation);
            }
            finally { if (candidate.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
        }
        if (fact is null) throw new CryptographicException("A selected native control lost its complete authored-position membership.");
        for (var index = 0; index < 2; index++)
        {
            var reference = Did2MessagingArchiveReference.Decode(fact.AsSpan(index == 0 ? 0 : 120, 88));
            if (reference.IsAbsent || Fixed(fact.AsSpan(index == 0 ? 88 : 208, 32), selected.Metadata.AsSpan(300, 32))) continue;
            RequireNativeReference(reference, tx); using var other = ReadArchiveOriginal(reference, tx);
            var actual = ApplicationCoreCodec.DecodeDmc2(other.Plaintext);
            try
            {
                if (actual.SenderClientSequence != message.SenderClientSequence || !Fixed(actual.ConversationId.Span, message.ConversationId.Span) ||
                    !Fixed(actual.SenderAccountId.Span, message.SenderAccountId.Span) || !Fixed(actual.SenderDeviceId.Span, message.SenderDeviceId.Span) ||
                    !Fixed(SHA256.HashData(other.Plaintext), fact.AsSpan(index == 0 ? 88 : 208, 32)))
                    throw new CryptographicException("Native authored-position conflict changed its actual independently authenticated witness.");
                return (reference, fact);
            }
            finally { if (actual.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
        }
        return (null, fact);
    }
}
