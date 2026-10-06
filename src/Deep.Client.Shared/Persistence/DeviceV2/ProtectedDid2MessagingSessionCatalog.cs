using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Account-owned current DMS2 key inventory. Metadata does not grant
/// endpoint freshness, initial-state import, retirement, messaging or ACK authority.
/// All mutations require the enclosing process-independent account lease.</summary>
internal sealed class ProtectedDid2MessagingSessionCatalog
{
    internal const string Slot = "deep.store.v2.messaging-session-catalog";
    internal const int HeaderBytes = 92, EntryBytes = 440, MaximumSessions = 512;
    private readonly IDeepSecureStorage storage;
    private readonly byte[] network, account, instance;

    internal ProtectedDid2MessagingSessionCatalog(IDeepSecureStorage storage,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        this.storage = storage ?? throw new ArgumentNullException(nameof(storage));
        RequireOwner(network, account, instance);
        this.network = network.ToArray(); this.account = account.ToArray(); this.instance = instance.ToArray();
    }

    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireOwner(network, account, instance);
        var bytes = new byte[HeaderBytes]; bytes[0] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(4), 1);
        network.CopyTo(bytes.AsSpan(12)); account.CopyTo(bytes.AsSpan(28)); instance.CopyTo(bytes.AsSpan(60));
        return bytes;
    }

    internal async Task<Snapshot> ReadAsync(CancellationToken ct)
    {
        using var owned = await storage.ReadOwnedAsync(Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("The protected DID2 messaging catalog is absent; explicit reset is required.");
        return owned.Use(bytes => Decode(bytes, network, account, instance));
    }

    internal static Snapshot Decode(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireOwner(network, account, instance);
        if (bytes.Length < HeaderBytes || bytes.Length > HeaderBytes + MaximumSessions * EntryBytes ||
            bytes[0] != 1 || bytes[1] != 0 ||
            !Fixed(bytes.Slice(12, 16), network) || !Fixed(bytes.Slice(28, 32), account) || !Fixed(bytes.Slice(60, 32), instance))
            throw new CryptographicException("Protected messaging catalog owner/shape differs.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
        if (count > MaximumSessions || bytes.Length != HeaderBytes + count * EntryBytes)
            throw new InvalidDataException("Protected messaging catalog count/length differs.");
        var scopes = new List<Did2MessagingSessionScope>(count);
        var sessions = new HashSet<string>(StringComparer.Ordinal);
        var bases = new HashSet<string>(StringComparer.Ordinal);
        // Compare key digests, never allocate private-key strings.
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var initialized = 0;
        byte[]? previous = null;
        for (var index = 0; index < count; index++)
        {
            var entry = bytes.Slice(HeaderBytes + index * EntryBytes, EntryBytes);
            if (entry[0] is not (1 or 2) || entry.Slice(1, 3).IndexOfAnyExcept((byte)0) >= 0 ||
                Did2MessagingSessionScope.Zero(entry.Slice(408, 32)))
                throw new InvalidDataException("Protected messaging catalog entry is not canonical.");
            var scope = Did2MessagingSessionScope.RestoreMetadata(entry.Slice(4, Did2MessagingSessionScope.Bytes));
            if (!Fixed(scope.Network, network) || !Fixed(scope.LocalAccount, account) || !Fixed(scope.Instance, instance))
                throw new CryptographicException("Protected messaging catalog entry has a different owner.");
            if (previous is not null && previous.AsSpan().SequenceCompareTo(scope.Hash) >= 0 ||
                !sessions.Add(Convert.ToHexString(scope.Session)) || !bases.Add(Convert.ToHexString(scope.InitialBasis)) ||
                !keys.Add(Convert.ToHexString(SHA256.HashData(entry.Slice(408, 32)))))
                throw new InvalidDataException("Protected messaging catalog is unordered or repeats a scope/session/basis/key.");
            previous = scope.Hash.ToArray(); scopes.Add(scope);
            if (entry[0] == 2) initialized++;
        }
        if (BinaryPrimitives.ReadUInt64BigEndian(bytes[4..]) != 1UL + (ulong)count + (ulong)initialized)
            throw new InvalidDataException("Protected messaging catalog revision differs from its exact phases.");
        return new Snapshot(bytes.ToArray(), scopes);
    }

    internal async Task<Did2MessagingSessionScope> RegisterAsync(OwnedInitialMessagingSeed seed, CancellationToken ct)
    {
        // No restored scope or caller-selected SQL key can authorize registration.
        var scope = Did2MessagingSessionScope.FromSeed(seed);
        RequireScopeOwner(scope);
        using var before = await ReadAsync(ct).ConfigureAwait(false);
        var existing = before.FindExact(scope);
        if (existing >= 0)
        {
            // A registered floor is never recreated or overwritten on retry.
            _ = await new Did2MessagingProtectedCheckpoint(storage, scope).ReadAsync(ct).ConfigureAwait(false);
            _ = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
            var peer = await ReadPeerCredentialAsync(scope, ct).ConfigureAwait(false);
            if (!Fixed(peer.CanonicalBytes.Span, seed.ExactPeerCredential))
                throw new CryptographicException("The registered peer credential differs from its verified seed.");
            return scope;
        }
        if (before.Count == MaximumSessions) throw new InvalidOperationException("DID2 messaging catalog capacity requires verified rollover.");
        var raw = new byte[EntryBytes]; raw[0] = 1; scope.Exact.CopyTo(raw.AsSpan(4));
        RandomNumberGenerator.Fill(raw.AsSpan(408, 32));
        byte[]? replacement = null;
        byte[]? bootstrap = null;
        try
        {
            bootstrap = ProtectedDid2MessagingPeerBootstrap.FromSeed(seed);
            replacement = before.WithInserted(raw, scope);
            // Validate new random key uniqueness and every closed codec constraint
            // before publishing either the registration or its empty floor.
            using var validated = Decode(replacement, network, account, instance);
            if (!await storage.CompareExchangeAndInsertAsync(Slot, before.Exact, replacement,
                [new(scope.FloorSlot, Did2MessagingFloor.Empty(scope).Exact),
                 new(Did2MessagingHistoryCheckpoint.Slot(scope), Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact),
                 new(ProtectedDid2MessagingPeerBootstrap.Slot(scope), bootstrap)], ct).ConfigureAwait(false))
                throw new CryptographicException("Protected messaging registration CAS/insert conflicted; no repair is permitted.");
            return scope;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
            if (bootstrap is not null) CryptographicOperations.ZeroMemory(bootstrap);
            if (replacement is not null) CryptographicOperations.ZeroMemory(replacement);
        }
    }

    internal async Task<Deep.Protocol.ApplicationCore.ParsedDid2> ReadPeerCredentialAsync(
        Did2MessagingSessionScope scope, CancellationToken ct)
    {
        RequireScopeOwner(scope);
        using var registered = await ReadAsync(ct).ConfigureAwait(false);
        if (registered.FindExact(scope) < 0)
            throw new CryptographicException("Peer lookup requires an exact registered messaging scope.");
        using var bootstrap = await storage.ReadOwnedAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope), ct).ConfigureAwait(false) ??
            throw new InvalidDataException("The mandatory messaging peer bootstrap is absent; explicit reset is required.");
        return bootstrap.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope));
    }

    internal async Task MarkSqlInitializedAsync(Did2MessagingSessionScope scope,
        Did2MessagingSqlJournal sql, CancellationToken ct)
    {
        RequireScopeOwner(scope);
        using var before = await ReadAsync(ct).ConfigureAwait(false);
        var index = before.FindExact(scope);
        if (index < 0) throw new InvalidDataException("SQL cannot initialize an unregistered DID2 session.");
        var checkpoint = new Did2MessagingProtectedCheckpoint(storage, scope);
        var floor = await checkpoint.ReadAsync(ct).ConfigureAwait(false);
        var sqlTip = sql.VerifyTip();
        if (before.Phase(index) == 2)
        {
            // Reconciliation belongs to phase2 owner, not this phase1 initializer.
            if (floor.Phase == 1 && !Fixed(floor.Exact.Span, sqlTip.Exact.Span))
                throw new CryptographicException("Initialized messaging SQL differs from its protected floor.");
            return;
        }
        var empty = Did2MessagingFloor.Empty(scope);
        if (!Fixed(floor.Exact.Span, empty.Exact.Span) || !Fixed(sqlTip.Exact.Span, empty.Exact.Span))
            throw new CryptographicException("Phase1 messaging initialization requires exact empty SQL/floor.");
        var replacement = before.WithInitialized(index);
        try
        {
            using var validated = Decode(replacement, network, account, instance);
            if (!await storage.CompareExchangeAsync(Slot, before.Exact, replacement, ct).ConfigureAwait(false))
                throw new CryptographicException("Messaging catalog initialization CAS conflicted.");
        }
        finally { CryptographicOperations.ZeroMemory(replacement); }
    }

    private void RequireScopeOwner(Did2MessagingSessionScope scope)
    {
        if (!Fixed(scope.Network, network) || !Fixed(scope.LocalAccount, account) || !Fixed(scope.Instance, instance))
            throw new CryptographicException("Messaging registration belongs to a different account instance.");
    }
    private static void RequireOwner(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (network.Length != 16 || account.Length != 32 || instance.Length != 32 ||
            Did2MessagingSessionScope.Zero(network) || Did2MessagingSessionScope.Zero(account) || Did2MessagingSessionScope.Zero(instance))
            throw new ArgumentException("Messaging catalog requires a nonzero exact account owner.");
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => Did2MessagingSessionScope.Fixed(a, b);

    internal sealed class Snapshot : IDisposable
    {
        private byte[]? exact;
        private readonly IReadOnlyList<Did2MessagingSessionScope> scopes;
        internal Snapshot(byte[] exact, IReadOnlyList<Did2MessagingSessionScope> scopes)
        { this.exact = exact; this.scopes = scopes; }
        internal int Count { get { _ = Live(); return scopes.Count; } }
        internal ReadOnlyMemory<byte> Exact => Live();
        internal Did2MessagingSessionScope Scope(int index) { _ = Live(); return scopes[index]; }
        internal byte Phase(int index) => Live()[HeaderBytes + index * EntryBytes];
        internal OwnedDeepSecret ReadKey(int index) => new(Live().AsSpan(HeaderBytes + index * EntryBytes + 408, 32));
        internal int FindExact(Did2MessagingSessionScope scope)
        {
            _ = Live();
            for (var index = 0; index < scopes.Count; index++)
            {
                var stored = scopes[index];
                if (Fixed(stored.Exact, scope.Exact)) return index;
                if (Fixed(stored.Session, scope.Session) || Fixed(stored.InitialBasis, scope.InitialBasis))
                    throw new CryptographicException("Existing messaging session/basis cannot register a different scope.");
            }
            return -1;
        }
        internal Did2MessagingSessionScope? FindSource(ReadOnlySpan<byte> session, ReadOnlySpan<byte> basis)
        {
            _ = Live();
            foreach (var scope in scopes)
            {
                var sameSession = Fixed(scope.Session, session);
                var sameBasis = Fixed(scope.InitialBasis, basis);
                if (sameSession && sameBasis) return scope;
                if (sameSession || sameBasis)
                    throw new CryptographicException("Existing messaging source has a different session/basis.");
            }
            return null;
        }
        // Selection metadata only; not endpoint freshness, ratchet or ACK authority.
        internal Did2MessagingSessionScope? FindIncoming(ReadOnlySpan<byte> network,
            ReadOnlySpan<byte> session, ReadOnlySpan<byte> sender, ReadOnlySpan<byte> recipient)
        {
            _ = Live();
            if (network.Length != 16 || session.Length != 32 || sender.Length != 32 || recipient.Length != 32 ||
                Did2MessagingSessionScope.Zero(network) || Did2MessagingSessionScope.Zero(session) ||
                Did2MessagingSessionScope.Zero(sender) || Did2MessagingSessionScope.Zero(recipient))
                throw new InvalidDataException("Incoming session metadata exceeds its closed shape.");
            for (var index = 0; index < scopes.Count; index++)
            {
                var scope = scopes[index];
                if (!Fixed(scope.Session, session)) continue;
                if (!Fixed(scope.Network, network) || !Fixed(scope.RemoteDevice, sender) || !Fixed(scope.LocalDevice, recipient))
                    throw new CryptographicException("Incoming envelope aliases a retained session with different endpoints.");
                if (Phase(index) != 2)
                    throw new InvalidOperationException("An uninitialized owned session cannot receive an ordinary envelope.");
                return scope;
            }
            return null;
        }

        internal byte[] WithInserted(ReadOnlySpan<byte> entry, Did2MessagingSessionScope scope)
        {
            var current = Live(); var output = new byte[current.Length + EntryBytes];
            current.AsSpan(0, HeaderBytes).CopyTo(output);
            var insertion = 0;
            while (insertion < scopes.Count && scopes[insertion].Hash.SequenceCompareTo(scope.Hash) < 0) insertion++;
            var offset = HeaderBytes + insertion * EntryBytes;
            current.AsSpan(HeaderBytes, offset - HeaderBytes).CopyTo(output.AsSpan(HeaderBytes));
            entry.CopyTo(output.AsSpan(offset)); current.AsSpan(offset).CopyTo(output.AsSpan(offset + EntryBytes));
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(2), checked((ushort)(scopes.Count + 1)));
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(4), checked(BinaryPrimitives.ReadUInt64BigEndian(current.AsSpan(4)) + 1));
            return output;
        }
        internal byte[] WithInitialized(int index)
        {
            if (Phase(index) != 1) throw new InvalidOperationException("Only phase1 may initialize SQL.");
            var output = Live().ToArray(); output[HeaderBytes + index * EntryBytes] = 2;
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(4), checked(BinaryPrimitives.ReadUInt64BigEndian(output.AsSpan(4)) + 1));
            return output;
        }
        private byte[] Live() => exact ?? throw new ObjectDisposedException(nameof(Snapshot));
        public void Dispose()
        {
            var bytes = Interlocked.Exchange(ref exact, null);
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
            GC.SuppressFinalize(this);
        }
        ~Snapshot() => Dispose();
    }
}
