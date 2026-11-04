using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private sealed class NativeRouteSnapshot(Did2MessagingSqlJournal.ArchiveRouteSources archive,
        Did2MessagingOwnedEventBatch suffix, Dictionary<ulong, byte[]> authored) : IDisposable
    {
        internal Did2MessagingSqlJournal.ArchiveRouteSources Archive { get; } = archive;
        internal Did2MessagingOwnedEventBatch Suffix { get; } = suffix;
        internal Dictionary<ulong, byte[]> Authored { get; } = authored;
        internal byte[]? Head(bool own) => Source(Archive.Reducer.Reference(own ? Did2MessagingArchiveReducer.ReferenceKind.OwnHead : Did2MessagingArchiveReducer.ReferenceKind.PeerHead));
        internal byte[]? Previous(bool own) => Source(Archive.Reducer.Reference(own ? Did2MessagingArchiveReducer.ReferenceKind.OwnPrevious : Did2MessagingArchiveReducer.ReferenceKind.PeerPrevious));
        private byte[]? Source(Did2MessagingArchiveReference reference) => reference.Kind != 2 ? null :
            reference.Direction == 1 ? Authored[reference.Ordinal] : Archive.Originals.Single(row => row.Reference.Ordinal == reference.Ordinal).Plaintext;
        public void Dispose()
        { Archive.Dispose(); Suffix.Dispose(); foreach (var bytes in Authored.Values) CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task<NativeRouteSnapshot> ReadNativeRouteSnapshotAsync(OwnedDid2MessagingStorage opened,
        Did2MessagingFloor stable, bool own, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var originals = await opened.WithSqlAsync(sql => sql.ReadRouteAuthoredSources(stable, own), ct).ConfigureAwait(false);
        try
        {
            using var qualified = await QualifyArchiveAuthoredAsync(opened.Scope, originals, held, ct).ConfigureAwait(false);
            return await opened.WithPairedSqlAsync(qualified.PairedRead, sql =>
            {
                var archive = sql.ReadArchiveRouteSources(stable, own);
                try { return new NativeRouteSnapshot(archive, sql.ReadVerifiedWorkingEvents(stable, own ? 1 : 2, routeOnly: !own),
                    qualified.Events.ToDictionary(pair => pair.Key, pair => pair.Value.ToArray())); }
                catch { archive.Dispose(); throw; }
            }, ct).ConfigureAwait(false);
        }
        finally { foreach (var row in originals) row.Dispose(); }
    }

    private static ParsedContactRouteClosure ArchiveRouteClosure(ReadOnlySpan<byte> exact)
    {
        var message = ApplicationCoreCodec.DecodeDmc2(exact);
        return message.ParsedPayload switch
        {
            ContactHelloDmc2Payload hello => hello.MailboxRoute.Route,
            ContactAcceptDmc2Payload accept => accept.MailboxRoute.Route,
            ContactRouteUpdateDmc2Payload update => ContactRouteClosureCodec.Decode(update.ExactRouteClosure.Span),
            _ => throw new CryptographicException("Archive selected route head has no exact route source.")
        };
    }
}
