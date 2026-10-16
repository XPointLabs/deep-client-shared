using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// DR-0130. Internal custody only: no currentness, publication/claim authority,
// secret retirement or independent receiver ledger is created here.
internal static class ProtectedPreKeyInventoryChain
{
    internal const string TipSlot = "deep.store.v2.prekey-inventory-tip";
    private const string EntryPrefix = "deep.store.v2.prekey-inventory/";
    internal const int HeaderBytes = 108;

    internal sealed class Entry : IDisposable
    {
        private byte[]? exact;
        private bool authoredCandidate;
        private readonly (int Offset, int Length)[] secrets;
        private readonly int publicationLength;
        private Entry(byte[] exact, int publicationLength, (int, int)[] secrets)
        { this.exact = exact; this.publicationLength = publicationLength; this.secrets = secrets; }
        private ReadOnlySpan<byte> Bytes => exact ?? throw new ObjectDisposedException(nameof(Entry));
        internal ReadOnlySpan<byte> ScopeHash => Bytes.Slice(4, 32);
        internal ReadOnlySpan<byte> PredecessorHash => Bytes.Slice(36, 32);
        internal ReadOnlySpan<byte> PublicationHash => Bytes.Slice(68, 32);
        internal byte[] CopyExact() => Bytes.ToArray();
        internal byte[] CopyService() => Bytes.Slice(HeaderBytes, DeepIdV2PreKeyServiceCodec.CanonicalLength).ToArray();
        internal byte[] CopyPublication() => Bytes.Slice(HeaderBytes + DeepIdV2PreKeyServiceCodec.CanonicalLength, publicationLength).ToArray();
        internal int SecretCount { get { _ = Bytes; return secrets.Length; } }
        internal bool HasAllSecrets { get { _ = Bytes; return secrets.All(value => value.Length > 0); } }
        internal bool IsAuthoredCandidate { get { _ = Bytes; return authoredCandidate; } }

        // Sealed data only. Restoring it still requires the existing private
        // protector, exact DPK2/scope and independent current admission checks.
        internal byte[] CopySealedSecret(int index) => Bytes.Slice(secrets[index].Offset, secrets[index].Length).ToArray();

        internal static Entry Create(ReadOnlySpan<byte> scopeHash, ReadOnlySpan<byte> predecessorHash,
            AuthoredDeepIdV2PreKeyService service, AuthoredDpk2InventoryV2 inventory,
            Dpk2PreKeyPersistenceProtector protector, Dpk2PreKeyPersistenceScope scope)
        {
            ArgumentNullException.ThrowIfNull(service); ArgumentNullException.ThrowIfNull(inventory);
            ArgumentNullException.ThrowIfNull(protector); ArgumentNullException.ThrowIfNull(scope);
            RequiredHash(scopeHash); RequiredHash(predecessorHash);
            var publication = DeepIdV2PreKeyPublicationCodec.Decode(inventory.ExactXpp1.Span);
            var xps = DeepIdV2PreKeyServiceCodec.Decode(service.ExactXps1.Span);
            RequireServiceBinding(xps, publication);
            var publicationHash = SHA256.HashData(inventory.ExactXpp1.Span);
            if (Fixed(publicationHash, predecessorHash))
                throw new CryptographicException("Prekey successor cannot name itself as predecessor.");
            var members = publication.OneTimeMembers.Append(publication.LastResortMember).ToArray();
            var offerings = inventory.OneTimeOfferings.Append(inventory.LastResortOffering).ToArray();
            if (members.Length != offerings.Length || !Fixed(publication.Manifest.CanonicalBytes.Span, inventory.ExactXpi1.Span) ||
                !Fixed(xps.Field(1).Span, scope.NetworkId.Span) || !Fixed(xps.Field(3).Span, scope.DeviceId.Span) ||
                !Fixed(xps.Field(4).Span, scope.ExactDpd1Reference.Span) ||
                !Fixed(publication.Manifest.Field(2).Span, xps.Field(2).Span) ||
                !Fixed(publication.Manifest.Field(5).Span, xps.Field(5).Span) ||
                !Fixed(publication.Manifest.Field(6).Span[6..], SHA256.HashData(service.ExactXps1.Span)))
                throw new CryptographicException("Prekey successor custody has different authored service support.");
            // Validate every public/private correspondence and the worst-case
            // slot budget BEFORE transferring the first single-use capability.
            for (var index = 0; index < members.Length; index++)
                if (!Fixed(members[index].CanonicalBytes.Span, offerings[index].ExactDpk2.Span) ||
                    !Fixed(members[index].ExactHash.Span, offerings[index].ExactDpk2Hash.Span) ||
                    !Fixed(members[index].NetworkId.Span, scope.NetworkId.Span) ||
                    !Fixed(members[index].ResponderAccountId.Span, scope.AccountId.Span) ||
                    !Fixed(members[index].ResponderDeviceId.Span, scope.DeviceId.Span) ||
                    members[index].ResponderDeviceGeneration != scope.DeviceGeneration ||
                    !Fixed(members[index].ResponderDpd1Reference.Span, scope.ExactDpd1Reference.Span))
                    throw new CryptographicException("Prekey successor custody contains a different private member.");
            var maximum = checked((long)HeaderBytes + DeepIdV2PreKeyServiceCodec.CanonicalLength +
                inventory.ExactXpp1.Length + members.Length * (4L + Dpk2PreKeyPersistenceBlob.MaximumCanonicalBytes));
            if (maximum > DeepSecureStorageRegistration.MaximumValueBytes)
                throw new InvalidOperationException("Prekey successor custody exceeds protected slot capacity.");
            var blobs = new List<byte[]>(members.Length);
            byte[]? encoded = null;
            try
            {
                foreach (var offering in offerings)
                    blobs.Add(offering.SealSecretForPersistence(protector, scope).CanonicalBytes.ToArray());
                encoded = new byte[checked(HeaderBytes + DeepIdV2PreKeyServiceCodec.CanonicalLength +
                    inventory.ExactXpp1.Length + blobs.Sum(value => 4 + value.Length))];
                encoded[0] = 1; scopeHash.CopyTo(encoded.AsSpan(4)); predecessorHash.CopyTo(encoded.AsSpan(36));
                SHA256.HashData(inventory.ExactXpp1.Span, encoded.AsSpan(68, 32));
                BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(100), checked((uint)inventory.ExactXpp1.Length));
                BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(104), checked((ushort)blobs.Count));
                service.ExactXps1.Span.CopyTo(encoded.AsSpan(HeaderBytes));
                inventory.ExactXpp1.Span.CopyTo(encoded.AsSpan(HeaderBytes + DeepIdV2PreKeyServiceCodec.CanonicalLength));
                var cursor = HeaderBytes + DeepIdV2PreKeyServiceCodec.CanonicalLength + inventory.ExactXpp1.Length;
                foreach (var blob in blobs)
                {
                    BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(cursor), checked((uint)blob.Length));
                    blob.CopyTo(encoded, cursor + 4); cursor += 4 + blob.Length;
                }
                var candidate = Decode(encoded, scopeHash, publicationHash);
                candidate.authoredCandidate = true;
                return candidate;
            }
            finally
            {
                foreach (var blob in blobs) CryptographicOperations.ZeroMemory(blob);
                if (encoded is not null) CryptographicOperations.ZeroMemory(encoded);
            }
        }

        // Parsed protected custody is not a verified offering or a capability.
        internal static Entry Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> expectedScope,
            ReadOnlySpan<byte> expectedPublicationHash)
        {
            RequiredHash(expectedScope); RequiredHash(expectedPublicationHash);
            if (exact.Length < HeaderBytes + DeepIdV2PreKeyServiceCodec.CanonicalLength + DeepIdV2PreKeyPublicationCodec.MinimumTotalBytes ||
                exact.Length > DeepSecureStorageRegistration.MaximumValueBytes || exact[0] != 1 ||
                exact.Slice(1, 3).IndexOfAnyExcept((byte)0) >= 0 || exact[106] != 0 || exact[107] != 0 ||
                !Fixed(exact.Slice(4, 32), expectedScope) || !Fixed(exact.Slice(68, 32), expectedPublicationHash) ||
                exact.Slice(36, 32).IndexOfAnyExcept((byte)0) < 0 || Fixed(exact.Slice(36, 32), expectedPublicationHash))
                throw new InvalidDataException("Prekey successor custody has an invalid exact header.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(100, 4));
            var count = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(104, 2));
            var start = HeaderBytes + DeepIdV2PreKeyServiceCodec.CanonicalLength;
            if (length < DeepIdV2PreKeyPublicationCodec.MinimumTotalBytes || length > DeepIdV2PreKeyPublicationCodec.MaximumTotalBytes ||
                count is < 33 or > 4097 || (long)start + length + count * 4L > exact.Length)
                throw new InvalidDataException("Prekey successor custody has invalid bounded lengths.");
            var publicationBytes = exact.Slice(start, checked((int)length));
            if (!Fixed(SHA256.HashData(publicationBytes), expectedPublicationHash))
                throw new CryptographicException("Prekey successor custody names a different publication.");
            var publication = DeepIdV2PreKeyPublicationCodec.Decode(publicationBytes);
            RequireServiceBinding(DeepIdV2PreKeyServiceCodec.Decode(exact.Slice(HeaderBytes,
                DeepIdV2PreKeyServiceCodec.CanonicalLength)), publication);
            if (count != publication.OneTimeMembers.Count + 1)
                throw new InvalidDataException("Prekey successor custody has a different secret count.");
            var slices = new (int, int)[count];
            var cursor = checked(start + (int)length);
            for (var index = 0; index < slices.Length; index++)
            {
                if (cursor > exact.Length - 4) throw new InvalidDataException("Prekey successor secret prefix is truncated.");
                var bytes = BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(cursor, 4)); cursor += 4;
                if (bytes > Dpk2PreKeyPersistenceBlob.MaximumCanonicalBytes || bytes > exact.Length - cursor)
                    throw new InvalidDataException("Prekey successor sealed secret exceeds its bound.");
                slices[index] = (cursor, checked((int)bytes));
                if (bytes != 0) _ = Dpk2PreKeyPersistenceBlob.Decode(exact.Slice(cursor, (int)bytes).ToArray());
                cursor += (int)bytes;
            }
            if (cursor != exact.Length) throw new InvalidDataException("Prekey successor custody has trailing bytes.");
            return new(exact.ToArray(), checked((int)length), slices);
        }

        public void Dispose()
        {
            var owned = Interlocked.Exchange(ref exact, null);
            if (owned is not null) CryptographicOperations.ZeroMemory(owned);
        }
    }

    internal sealed class Snapshot : IDisposable
    {
        private byte[]? tip;
        private readonly Entry[] entries;
        internal Snapshot(byte[] tip, Entry[] entries) { this.tip = tip; this.entries = entries; }
        internal IReadOnlyList<Entry> Entries { get { _ = Tip; return Array.AsReadOnly(entries); } }
        internal ReadOnlySpan<byte> Tip => tip ?? throw new ObjectDisposedException(nameof(Snapshot));
        public void Dispose()
        {
            var owned = Interlocked.Exchange(ref tip, null);
            foreach (var entry in entries) entry.Dispose();
            if (owned is not null) CryptographicOperations.ZeroMemory(owned);
        }
    }

    internal static string EntrySlot(ReadOnlySpan<byte> publicationHash)
    { RequiredHash(publicationHash); return EntryPrefix + Convert.ToHexString(publicationHash).ToLowerInvariant(); }

    // Caller holds the actual account lease. Capacity enforcement is delegated
    // to the one atomic backend, never implemented with sequential writes.
    internal static async Task<bool> StageAsync(IDeepSecureStorage storage, Entry candidate, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(storage); ArgumentNullException.ThrowIfNull(candidate);
        ct.ThrowIfCancellationRequested();
        if (!candidate.IsAuthoredCandidate) throw new CryptographicException("Parsed prekey custody cannot author a new protected successor.");
        if (!candidate.HasAllSecrets) throw new CryptographicException("New prekey custody cannot omit a private member.");
        var previous = Tip(candidate.ScopeHash, candidate.PredecessorHash);
        var next = Tip(candidate.ScopeHash, candidate.PublicationHash);
        var exact = candidate.CopyExact(); var slot = EntrySlot(candidate.PublicationHash);
        try
        {
            if (await storage.CompareExchangeAndInsertAsync(TipSlot, previous, next, [new(slot, exact)], ct).ConfigureAwait(false))
                return true;
            // A lost response may already have installed exactly this candidate.
            // Read root+entry in ONE actual snapshot, not two mixed reads.
            using var replay = await storage.ReadOwnedBatchAsync([TipSlot, slot], ct).ConfigureAwait(false);
            return replay[0]?.Use(value => Fixed(value, next)) == true &&
                replay[1]?.Use(value => Fixed(value, exact)) == true;
        }
        finally
        { CryptographicOperations.ZeroMemory(previous); CryptographicOperations.ZeroMemory(next); CryptographicOperations.ZeroMemory(exact); }
    }

    internal static async Task<Snapshot> ReadAsync(IDeepSecureStorage storage, ReadOnlyMemory<byte> scopeHash,
        ReadOnlyMemory<byte> initialPublicationHash, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(storage); RequiredHash(scopeHash.Span); RequiredHash(initialPublicationHash.Span);
        // Own caller inputs before the first asynchronous storage callback.
        var scope = scopeHash.ToArray(); var initial = initialPublicationHash.ToArray();
        byte[]? first = null;
        var entries = new List<Entry>();
        try
        {
            using (var root = await storage.ReadOwnedAsync(TipSlot, ct).ConfigureAwait(false))
                first = root?.Use(value => value.ToArray()) ?? throw new InvalidDataException("Prekey inventory pointer is absent.");
            if (first.Length != 64 || !Fixed(first.AsSpan(0, 32), scope) || first.AsSpan(32, 32).IndexOfAnyExcept((byte)0) < 0)
                throw new CryptographicException("Prekey inventory pointer has a different owner scope.");
            var current = first.AsSpan(32, 32).ToArray();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (!Fixed(current, initial))
            {
                ct.ThrowIfCancellationRequested();
                if (entries.Count >= DeepSecureStorageRegistration.MaximumEntries || !seen.Add(Convert.ToHexString(current)))
                    throw new InvalidDataException("Prekey inventory custody is cyclic or exceeds its bound.");
                using var stored = await storage.ReadOwnedAsync(EntrySlot(current), ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("An exact noninitial prekey inventory is missing.");
                var entry = stored.Use(value => Entry.Decode(value, scope, current));
                entries.Add(entry); current = entry.PredecessorHash.ToArray();
            }
            using var final = await storage.ReadOwnedAsync(TipSlot, ct).ConfigureAwait(false);
            if (final?.Use(value => Fixed(value, first)) != true)
                throw new CryptographicException("Prekey inventory pointer changed during custody read.");
            ct.ThrowIfCancellationRequested();
            entries.Reverse(); var result = new Snapshot(first, entries.ToArray()); first = null; entries.Clear(); return result;
        }
        finally
        {
            foreach (var entry in entries) entry.Dispose();
            CryptographicOperations.ZeroMemory(scope); CryptographicOperations.ZeroMemory(initial);
            if (first is not null) CryptographicOperations.ZeroMemory(first);
        }
    }

    private static byte[] Tip(ReadOnlySpan<byte> scope, ReadOnlySpan<byte> hash)
    { RequiredHash(scope); RequiredHash(hash); var value = new byte[64]; scope.CopyTo(value); hash.CopyTo(value.AsSpan(32)); return value; }
    private static void RequiredHash(ReadOnlySpan<byte> value)
    { if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("An exact nonzero custody hash is required."); }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);

    private static void RequireServiceBinding(ParsedXps1V2 service, ParsedXpp1V2 publication)
    {
        var manifest = publication.Manifest;
        foreach (var tag in new[] { 1, 2, 3, 4, 5 })
            if (!Fixed(service.Field(tag).Span, manifest.Field(tag).Span))
                throw new CryptographicException("Protected prekey inventory has different service scope.");
        if (!Fixed(SHA256.HashData(service.CanonicalBytes.Span), manifest.Field(6).Span[6..]) ||
            BinaryPrimitives.ReadUInt16BigEndian(service.Field(8).Span) > publication.OneTimeMembers.Count ||
            BinaryPrimitives.ReadUInt64BigEndian(manifest.Field(14).Span) < BinaryPrimitives.ReadUInt64BigEndian(service.Field(10).Span) ||
            BinaryPrimitives.ReadUInt64BigEndian(manifest.Field(15).Span) > BinaryPrimitives.ReadUInt64BigEndian(service.Field(11).Span))
            throw new CryptographicException("Protected prekey inventory has different signed service support.");
    }
}
