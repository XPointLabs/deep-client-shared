using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    private ParsedContactRouteClosure ReadQualifiedDecisionClosure(Did2RouteHistoryStoredDecision decision, SqliteTransaction tx)
    {
        var body = decision.Body;
        if (body.Subject != 2 || body.Action != Did2RouteHistoryDecision.ActionKind.Promotion || body.L.Kind != 2 || body.L.Direction != 2)
            throw new CryptographicException("A selected peer closure requires its actual local promotion decision.");
        RequireNativeReference(body.L, tx); using var announcement = ReadArchiveOriginal(body.L, tx);
        var message = ApplicationCoreCodec.DecodeDmc2(announcement.Plaintext);
        Did2RouteProcessingMetadata.RequireReceivedEvent(announcement.Metadata.AsSpan(608, 64), message);
        if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload page || page.Mode is not (DeepIdV2ContactRouteHistoryMode.Announcement or DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement))
            throw new CryptographicException("A selected peer promotion lost its original announcement.");
        var selector = Did2MessagingArchiveRouteFacts.HistorySelector(2, 1, BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span));
        var initial = ReadArchiveInitialSource(tx); var selectedOriginals = new Dictionary<string, Did2MessagingArchiveOriginal>(StringComparer.Ordinal);
        byte[]? fact;
        try
        {
            var headers = ReadJournal(out var tip, tx);
            fact = ReadRouteFactAtStable(new(Did2MessagingArchiveFamily.RouteHistory, selector), tip, ReadArchiveReducer(tx), headers,
                null, initial, tx, sourcesOnly: false, current: true, Did2RouteHistorySnapshot.MaximumCurrentAuthoredOriginals, selectedOriginals);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(initial.Metadata); CryptographicOperations.ZeroMemory(initial.Hello);
            foreach (var original in selectedOriginals.Values) original.Dispose();
        }
        if (fact is null) throw new CryptographicException("A selected peer endpoint lost its independently verified C fact.");
        var first = Did2MessagingArchiveReference.Decode(fact.AsSpan(0, 88), false); RequireNativeReference(first, tx);
        using var verified = ReadRouteHistoryDecision(first, tx);
        var originals = new List<Did2MessagingArchiveOriginal>();
        try
        {
            var completed = Did2MessagingArchiveRouteSource.Completed(verified.Body.C, Resolve);
            if (!Fixed(completed.Route.Reachability.CoreHash.Span, page.RightCursor.Span.Slice(8, 32)) ||
                !Fixed(SHA256.HashData(completed.Route.ExactBytes.Span), body.EndpointHash))
                throw new CryptographicException("A selected peer endpoint changes its independently verified exact C source.");
            return completed.Route;
            ReadOnlyMemory<byte> Resolve(Did2MessagingArchiveReference reference)
            {
                if (reference.Kind == 2 && reference.Direction != 2) throw new CryptographicException("A peer C source has another native author.");
                RequireNativeReference(reference, tx); var original = ReadArchiveOriginal(reference, tx); originals.Add(original); return original.Plaintext;
            }
        }
        finally { foreach (var original in originals) original.Dispose(); }
    }
}
