using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private sealed class QualifiedArchiveAuthored(Did2MessagingSessionScope scope) : IDisposable
    {
        internal readonly Dictionary<ulong, ReadOnlyMemory<byte>> Values = [];
        internal readonly Dictionary<string, byte[]?> Roots = new(StringComparer.Ordinal);
        internal readonly List<Did2MessagingArchiveOriginal> Originals = [];
        internal byte[] OrdinaryExact = [], AcceptExact = [];
        internal readonly Dictionary<ulong, byte[]> Groups = [];
        internal IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> Events => Values;
        internal Did2MessagingArchiveAuthoredRead PairedRead => new(Roots, connection =>
        {
            using var ordinary = ProtectedDid2DirectTextJournal.Decode(OrdinaryExact, scope.Network, scope.LocalAccount, scope.Instance);
            using var accepts = ProtectedDid2ContactAcceptJournal.Decode(AcceptExact, scope.Network, scope.LocalAccount, scope.Instance);
            foreach (var row in Originals)
            {
                var actual = SqliteDeepMailboxStore.ReadArchiveAuthoredOriginal(connection, scope, row, ordinary, accepts.FindScope(scope), Groups.GetValueOrDefault(row.Reference.Ordinal));
                try { if (!Values.TryGetValue(row.Reference.Ordinal, out var expected) || !Did2MessagingSessionScope.Fixed(actual, expected.Span)) throw new CryptographicException("Final paired selected application original changed."); }
                finally { CryptographicOperations.ZeroMemory(actual); }
            }
        }, Originals.Count != 0);
        public void Dispose()
        {
            foreach (var bytes in Values.Values) if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(bytes, out var array)) CryptographicOperations.ZeroMemory(array.AsSpan());
            foreach (var root in Roots.Values) if (root is not null) CryptographicOperations.ZeroMemory(root);
            foreach (var original in Originals) original.Dispose();
            CryptographicOperations.ZeroMemory(OrdinaryExact); CryptographicOperations.ZeroMemory(AcceptExact);
            foreach (var bytes in Groups.Values) CryptographicOperations.ZeroMemory(bytes);
            Values.Clear(); Roots.Clear(); Originals.Clear();
        }
    }

    private async Task<QualifiedArchiveAuthored> QualifyArchiveAuthoredAsync(Did2MessagingSessionScope scope,
        IReadOnlyList<Did2MessagingArchiveOriginal> originals, HeldDeepIdV2AccountLease held, CancellationToken ct,
        int maximumOriginals = Did2RouteHistorySnapshot.MaximumCurrentAuthoredOriginals)
    {
        held.RequireOwner(lease);
        if (maximumOriginals is not (Did2RouteHistorySnapshot.MaximumCurrentAuthoredOriginals or Did2RouteHistorySnapshot.MaximumCatchupAuthoredOriginals) ||
            originals.Count > maximumOriginals ||
            originals.Any(row => row.Reference.Kind != 2 || row.Reference.Direction != 1))
            throw new InvalidDataException("Authored qualification requires bounded outgoing actual originals.");
        var result = new QualifiedArchiveAuthored(scope);
        try
        {
            using var actual = await storage.ReadOwnedBatchAsync(ArchiveAuthoredSlots, ct).ConfigureAwait(false);
            ProtectedDid2DirectTextJournal.State? ordinary = null;
            ProtectedDid2ContactAcceptJournal.State? accepts = null;
            var groups = new Dictionary<ulong, byte[]>();
            try
            {
                for (var i = 0; i < ArchiveAuthoredSlots.Length; i++)
                {
                    var slot = ArchiveAuthoredSlots[i]; var raw = actual[i];
                    result.Roots[slot] = raw?.Use(bytes => SHA256.HashData(bytes));
                    if (slot == ProtectedDid2DirectTextJournal.Slot)
                    {
                        ordinary = raw?.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance)) ??
                            throw new InvalidDataException("Actual protected authored counters are absent.");
                        result.OrdinaryExact = raw!.Use(bytes => bytes.ToArray());
                    }
                    else if (slot == ProtectedDid2ContactAcceptJournal.Slot)
                    {
                        accepts = raw?.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance)) ??
                            throw new InvalidDataException("Actual protected explicit-consent custody is absent.");
                        result.AcceptExact = raw!.Use(bytes => bytes.ToArray());
                    }
                    else if (raw is not null)
                    {
                        using var parsed = raw.Use(bytes => ProtectedDid2GroupJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                        foreach (var native in originals)
                        {
                            var exact = RequireGroupAuthoredEvent(parsed, scope, native.Reference.Operation, native.Metadata.AsSpan(300, 32));
                            if (exact is not null) groups.Add(native.Reference.Ordinal, exact);
                        }
                    }
                    else throw new InvalidDataException("Actual protected group authored custody is absent.");
                }
                actual.Dispose(); // In particular, dispose every copied group key before application-key acquisition.
                var commands = ordinary ?? throw new InvalidDataException("Authored counter custody is absent.");
                var acceptance = accepts?.FindScope(scope);
                if (originals.Count == 0) return result;
                var values = await SqliteDeepIdV2AccountGeneration.ReadArchiveAuthoredSqlUnderLeaseAsync(storage, sqlStatePath,
                    scope, held, lease, result.Roots, connection =>
                    {
                        var output = new Dictionary<ulong, byte[]>();
                        try
                        {
                            foreach (var native in originals)
                            {
                                ct.ThrowIfCancellationRequested();
                                if (output.ContainsKey(native.Reference.Ordinal)) continue;
                                output.Add(native.Reference.Ordinal, SqliteDeepMailboxStore.ReadArchiveAuthoredOriginal(connection, scope,
                                    native, commands, acceptance, groups.GetValueOrDefault(native.Reference.Ordinal)));
                            }
                            return output;
                        }
                        catch { foreach (var bytes in output.Values) CryptographicOperations.ZeroMemory(bytes); throw; }
                    }, ct).ConfigureAwait(false);
                foreach (var item in values) result.Values.Add(item.Key, item.Value);
                foreach (var item in groups) result.Groups.Add(item.Key, item.Value.ToArray());
                foreach (var native in originals.GroupBy(row => row.Reference.Ordinal).Select(group => group.First()))
                    result.Originals.Add(new(native.Reference, native.Metadata.ToArray(), native.Envelope.ToArray(), native.Plaintext.ToArray()));
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                return result;
            }
            finally
            {
                ordinary?.Dispose(); accepts?.Dispose();
                foreach (var bytes in groups.Values) CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch { result.Dispose(); throw; }
    }

    private async Task RequireArchiveAuthoredCurrentAsync(QualifiedArchiveAuthored expected,
        Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var actual = await QualifyArchiveAuthoredAsync(scope, expected.Originals, held, ct).ConfigureAwait(false);
        if (actual.Roots.Count != expected.Roots.Count || actual.Values.Count != expected.Values.Count ||
            expected.Roots.Any(pair => !actual.Roots.TryGetValue(pair.Key, out var value) ||
                (pair.Value is null ? value is not null : value is null || !Did2MessagingSessionScope.Fixed(pair.Value, value))) ||
            expected.Values.Any(pair => !actual.Values.TryGetValue(pair.Key, out var value) || !Did2MessagingSessionScope.Fixed(pair.Value.Span, value.Span)))
            throw new CryptographicException("Authored source changed across actual native SQL callbacks.");
    }

    private async Task<Did2MessagingSqlJournal.ArchivePrefixEffects> CaptureArchivePrefixEffectsAsync(
        OwnedDid2MessagingStorage opened, Did2MessagingFloor stable, int prefixRows,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var rows = await opened.WithSqlAsync(sql => sql.ReadArchivePrefixAuthoredSources(stable, prefixRows), ct).ConfigureAwait(false);
        try
        {
            using var qualified = await QualifyArchiveAuthoredAsync(opened.Scope, rows, held, ct).ConfigureAwait(false);
            var effects = await opened.WithPairedSqlAsync(qualified.PairedRead, sql => sql.CaptureArchivePrefixEffects(stable, prefixRows, qualified.Events), ct).ConfigureAwait(false);
            await RequireArchiveAuthoredCurrentAsync(qualified, opened.Scope, held, ct).ConfigureAwait(false);
            var final = await opened.WithPairedSqlAsync(qualified.PairedRead, sql => sql.CaptureArchivePrefixEffects(stable, prefixRows, qualified.Events), ct).ConfigureAwait(false);
            if (!Did2MessagingSessionScope.Fixed(effects.Before.Span, final.Before.Span) || !Did2MessagingSessionScope.Fixed(effects.After.Span, final.After.Span))
                throw new CryptographicException("Native prefix changed across paired authored-source readback.");
            return final;
        }
        finally { foreach (var row in rows) row.Dispose(); }
    }
    private static readonly string[] ArchiveAuthoredSlots =
        [ProtectedDid2ContactAcceptJournal.Slot, ProtectedDid2DirectTextJournal.Slot, ProtectedDid2GroupJournal.Slot];

    // Exact source framing: domain00 || actualAccount32 || scope32 || each
    // ordinal-sorted literal slot name(LP-u16 UTF8) || typed NULL(0) or
    // blob(2 || length:u64 || exact protected bytes), followed by the existing
    // canonical complete application schema/table/row/cell stream. Literal names:
    // deep.store.v2.contact-accept-journal, deep.store.v2.direct-text-journal,
    // deep.store.v2.groups. Only the
    // incremental hash state survives the SQL/key acquisition callback; no
    // private Group/Accept/DirectText root bytes enter SQL or artifact output.
    private async Task<(byte[] SqlHash, byte[] DirectRootHash)> CaptureArchiveAuthoredSourceAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/archive-enrollment-authored"u8); hash.AppendData([0]);
        hash.AppendData(current.AccountId.Span); hash.AppendData(scope.Hash);
        var before = await AppendArchiveAuthoredRootsAsync(hash, scope, ct).ConfigureAwait(false);
        byte[] sqlHash;
        using (var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
            storage, sqlStatePath, current, held, ct).ConfigureAwait(false))
            sqlHash = await application.CaptureMessagingArchiveAuthoredSourceAsync(hash, scope, ct).ConfigureAwait(false);
        using var comparison = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var after = await AppendArchiveAuthoredRootsAsync(comparison, scope, ct).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(before.FramesHash, after.FramesHash) ||
            !Did2MessagingSessionScope.Fixed(before.DirectRootHash, after.DirectRootHash))
            throw new CryptographicException("Actual authored source roots changed across enrollment SQL acquisition.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        return (sqlHash, before.DirectRootHash);
    }

    private async Task<(byte[] FramesHash, byte[] DirectRootHash)> AppendArchiveAuthoredRootsAsync(
        IncrementalHash target, Did2MessagingSessionScope scope, CancellationToken ct)
    {
        var slots = ArchiveAuthoredSlots.OrderBy(static slot => slot, StringComparer.Ordinal).ToArray();
        using var actual = await storage.ReadOwnedBatchAsync(slots, ct).ConfigureAwait(false);
        using var frames = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[]? direct = null;
        for (var i = 0; i < slots.Length; i++)
        {
            var slot = slots[i]; var name = Encoding.UTF8.GetBytes(slot); var length = new byte[8];
            BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)name.Length));
            target.AppendData(length.AsSpan(0, 2)); target.AppendData(name);
            frames.AppendData(length.AsSpan(0, 2)); frames.AppendData(name);
            var owned = actual[i];
            if (owned is null)
            {
                throw new InvalidDataException("An actual mandatory protected authored root is absent.");
            }
            owned.Use(raw =>
            {
                if (slot == ProtectedDid2DirectTextJournal.Slot)
                { using var parsed = ProtectedDid2DirectTextJournal.Decode(raw, scope.Network, scope.LocalAccount, scope.Instance); direct = SHA256.HashData(raw); }
                else if (slot == ProtectedDid2ContactAcceptJournal.Slot)
                { using var parsed = ProtectedDid2ContactAcceptJournal.Decode(raw, scope.Network, scope.LocalAccount, scope.Instance); }
                else
                { using var parsed = ProtectedDid2GroupJournal.Decode(raw, scope.Network, scope.LocalAccount, scope.Instance); }
                BinaryPrimitives.WriteUInt64BigEndian(length, checked((ulong)raw.Length));
                target.AppendData([2]); target.AppendData(length); target.AppendData(raw);
                frames.AppendData([2]); frames.AppendData(length); frames.AppendData(raw);
            });
        }
        return (frames.GetHashAndReset(), direct ?? throw new InvalidDataException("The actual authored root was not selected."));
    }
}
