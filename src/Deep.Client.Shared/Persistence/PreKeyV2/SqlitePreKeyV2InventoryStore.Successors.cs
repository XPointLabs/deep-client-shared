using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;
using Sodium;

namespace Deep.Client.Shared.Persistence.PreKeyV2;

internal sealed partial class SqlitePreKeyV2InventoryStore
{
    internal async Task StageSuccessorAsync(IDeepSecureStorage storage, ReadOnlyMemory<byte> scopeHash,
        AuthoredDeepIdV2PreKeyService service, AuthoredDpk2InventoryV2 inventory, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); RequireReceiverStorage();
            await ReconcileReceiverUnderGateAsync(ct).ConfigureAwait(false);
            ValidateStagedRows(restoreSecrets: true);
            var prior = DeepIdV2PreKeyPublicationCodec.Decode(ReadStagedPublication() ??
                throw new InvalidDataException("A prekey successor requires its exact initial anchor."));
            var priorService = ReadStagedService() ?? throw new InvalidDataException("Prekey predecessor service is missing.");
            var next = DeepIdV2PreKeyPublicationCodec.Decode(inventory.ExactXpp1.Span);
            ValidateInventory(inventory, next, service.ExactXps1.Span);
            RequirePublicSuccessor(prior, priorService, next, service.ExactXps1.Span);
            using (var ledger = ReadReceiverLedger())
                if (IsOwnedPreKeyExhausted(ledger, next.LastResortMember, OwnedPublicMembers()))
                    throw new CryptographicException("A replenished inventory cannot reset an exhausted last-resort service counter.");
            using var candidate = ProtectedPreKeyInventoryChain.Entry.Create(scopeHash.Span,
                SHA256.HashData(prior.CanonicalBytes.Span), service, inventory, protector, PersistenceScope());
            if (!await ProtectedPreKeyInventoryChain.StageAsync(storage, candidate, ct).ConfigureAwait(false))
                throw new CryptographicException("Prekey successor lost its exact protected predecessor.");
        }
        finally { gate.Release(); }
    }

    private Dpk2PreKeyPersistenceScope PersistenceScope() =>
        new(network, account, accountGeneration, device, deviceGeneration, dpd1);

    private IEnumerable<ParsedXpp1V2> SuccessorPublications() => successorPublicRecords;

    // One private store instance under its actual account lease. These local
    // receive counts trigger maintenance; they do not report remote stock.
    internal (int OneTimeRemaining, bool ServiceLastResortExhausted) ReadOwnedReplenishmentState()
    {
        ThrowIfDisposed(); RequireReceiverStorage();
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(ReadStagedPublication()!);
        var service = DeepIdV2PreKeyServiceCodec.Decode(ReadStagedService()!);
        var reuseLimit = BinaryPrimitives.ReadUInt16BigEndian(service.Field(9).Span);
        using var ledger = ReadReceiverLedger(); var members = OwnedPublicMembers();
        var uses = ledger.Entries.Count(value => value.Commit.Kind == Dpk2PrekeyKind.LastResort &&
            value.Commit.Counter <= reuseLimit && RequireOwnedMember(members, value.Commit.Record.ExactDpk2Hash.Span)
                .PrekeyServiceGeneration == U64(service.Field(5).Span));
        return (publication.OneTimeMembers.Count(member => !IsOwnedPreKeyExhausted(ledger, member, members)),
            IsReceiverPreKeyExhausted(Dpk2PrekeyKind.LastResort, reuseLimit, uses));
    }

    private ParsedDpk2V2[] OwnedPublicMembers(SqliteTransaction? transaction = null) => new[] {
        DeepIdV2PreKeyPublicationCodec.Decode(ReadInitialPublication(transaction) ??
            throw new CryptographicException("Receiver history has no exact initial inventory.")) }
        .Concat(SuccessorPublications()).SelectMany(value => value.OneTimeMembers.Append(value.LastResortMember)).ToArray();

    private static ParsedDpk2V2 RequireOwnedMember(ParsedDpk2V2[] members, ReadOnlySpan<byte> hash)
    {
        // No generation search/fallback: the authenticated session names one
        // exact member, including when its private value has been destroyed.
        foreach (var member in members) if (Fixed(member.ExactHash.Span, hash)) return member;
        throw new CryptographicException("Receiver session has no exact owned public prekey.");
    }

    private static bool IsOwnedPreKeyExhausted(Ledger ledger, ParsedDpk2V2 member,
        ParsedDpk2V2[] members, DeepIdV2InitialContactSessionCommit? appended = null)
    {
        var commits = ledger.Entries.Select(value => value.Commit);
        if (appended is not null) commits = commits.Append(appended);
        var uses = member.Kind == Dpk2PrekeyKind.OneTime
            ? commits.Count(value => Fixed(value.Record.ExactDpk2Hash.Span, member.ExactHash.Span))
            : commits.Count(value => value.Kind == Dpk2PrekeyKind.LastResort && value.Counter <= member.ReuseLimit &&
                RequireOwnedMember(members, value.Record.ExactDpk2Hash.Span).PrekeyServiceGeneration == member.PrekeyServiceGeneration);
        // LR counters belong to XPS, not to XPI or an individual key. Destroy
        // only after every admissible counter has arrived, not the highest:
        // a lower-counter Hello can still be in flight across an epoch change.
        return IsReceiverPreKeyExhausted(member.Kind, member.ReuseLimit, uses);
    }

    private (ProtectedPreKeyInventoryChain.Entry Entry, int Index, ParsedDpk2V2 Member)?
        FindSuccessorMember(ReadOnlySpan<byte> exactHash)
    {
        if (successorCustody is null) return null;
        for (var ordinal = 0; ordinal < successorCustody.Entries.Count; ordinal++)
        {
            var entry = successorCustody.Entries[ordinal]; var publication = successorPublicRecords[ordinal];
            var members = publication.OneTimeMembers.Append(publication.LastResortMember).ToArray();
            for (var index = 0; index < members.Length; index++)
                if (Fixed(members[index].ExactHash.Span, exactHash)) return (entry, index, members[index]);
        }
        return null;
    }

    private void ValidateSuccessorPublicHistory(ParsedXpp1V2 initial, ReadOnlySpan<byte> initialService)
    {
        if (successorCustody is null) return;
        var previous = initial; var service = initialService.ToArray();
        var seen = new HashSet<string>(initial.OneTimeMembers.Append(initial.LastResortMember)
            .Select(value => Convert.ToHexString(value.ExactHash.Span)), StringComparer.Ordinal);
        for (var ordinal = 0; ordinal < successorCustody.Entries.Count; ordinal++)
        {
            var entry = successorCustody.Entries[ordinal]; var next = successorPublicRecords[ordinal];
            var nextService = entry.CopyService();
            if (!Fixed(entry.PredecessorHash, SHA256.HashData(previous.CanonicalBytes.Span)) ||
                !Fixed(next.NetworkId.Span, network) || !Fixed(next.Manifest.Field(3).Span, device) ||
                !Fixed(next.Manifest.Field(4).Span, dpd1) || !PublicKeyAuth.VerifyDetached(next.Manifest.Field(16).ToArray(),
                    next.Manifest.SignatureInput.ToArray(), signer))
                throw new CryptographicException("Protected prekey history differs from its signed local inventory.");
            ValidateService(next, nextService);
            RequirePublicSuccessor(previous, service, next, nextService);
            foreach (var member in next.OneTimeMembers.Append(next.LastResortMember))
            {
                if (!seen.Add(Convert.ToHexString(member.ExactHash.Span)) ||
                    !Fixed(member.ResponderAccountId.Span, account) || !Fixed(member.ResponderDeviceId.Span, device) ||
                    member.ResponderDeviceGeneration != deviceGeneration || !Fixed(member.ResponderDpd1Reference.Span, dpd1) ||
                    member.PrekeyServiceGeneration != U64(next.Manifest.Field(5).Span) || member.InventoryEpoch != U64(next.Manifest.Field(7).Span) ||
                    !Fixed(member.DeviceDirectoryHeadHash.Span, next.Manifest.Field(12).Span) ||
                    member.NotBefore != U64(next.Manifest.Field(14).Span) || member.ExpiresAt != U64(next.Manifest.Field(15).Span))
                    throw new CryptographicException("Protected prekey history has a duplicate or foreign member.");
            }
            previous = next; service = nextService;
        }
    }

    private void RequirePublicSuccessor(ParsedXpp1V2 prior, ReadOnlySpan<byte> priorService,
        ParsedXpp1V2 next, ReadOnlySpan<byte> nextService)
    {
        ValidateService(next, nextService);
        if (U64(next.Manifest.Field(14).Span) < U64(prior.Manifest.Field(14).Span))
            throw new CryptographicException("Prekey inventory issue time cannot roll back.");
        if (Fixed(priorService, nextService))
        {
            DeepIdV2PreKeyLineageVerifier.VerifySuccessor(next.Manifest, prior.Manifest);
            return;
        }
        var old = DeepIdV2PreKeyServiceCodec.Decode(priorService);
        var current = DeepIdV2PreKeyServiceCodec.Decode(nextService);
        DeepIdV2PreKeyLineageVerifier.VerifyServiceTransition(current, old, signer);
        DeepIdV2PreKeyLineageVerifier.VerifySuccessor(next.Manifest, null);
    }

    private void ValidateSuccessorSecrets(Ledger ledger, bool restore)
    {
        if (successorCustody is null) return;
        var ownedMembers = OwnedPublicMembers();
        for (var ordinal = 0; ordinal < successorCustody.Entries.Count; ordinal++)
        {
            var entry = successorCustody.Entries[ordinal]; var publication = successorPublicRecords[ordinal];
            var members = publication.OneTimeMembers.Append(publication.LastResortMember).ToArray();
            for (var index = 0; index < members.Length; index++)
            {
                var member = members[index];
                var consumed = IsOwnedPreKeyExhausted(ledger, member, ownedMembers);
                var blob = entry.CopySealedSecret(index);
                try
                {
                    if ((blob.Length == 0) != consumed)
                        throw new CryptographicException("Protected prekey destruction differs from authenticated receiver history.");
                    if (restore && blob.Length > 0)
                    { using var restored = protector.Restore(Dpk2PreKeyPersistenceBlob.Decode(blob), member.CanonicalBytes, PersistenceScope()); }
                }
                finally { CryptographicOperations.ZeroMemory(blob); }
            }
        }
    }

    // Runs only for a protected pending receiver transition, after its exact
    // SQL transaction and before stabilization. A lost CAS response is resolved
    // on the next pending reopen; no private key is copied back into SQL.
    private async Task CompleteSuccessorConsumptionAsync(Ledger ledger, CancellationToken ct)
    {
        if (successorCustody is null) return;
        var ownedMembers = OwnedPublicMembers();
        for (var ordinal = 0; ordinal < successorCustody.Entries.Count; ordinal++)
        {
            var entry = successorCustody.Entries[ordinal];
            var publication = successorPublicRecords[ordinal];
            var members = publication.OneTimeMembers.Append(publication.LastResortMember).ToArray();
            var erase = new HashSet<int>();
            for (var index = 0; index < members.Length; index++)
            {
                var member = members[index];
                var consumed = IsOwnedPreKeyExhausted(ledger, member, ownedMembers);
                var blob = entry.CopySealedSecret(index);
                try
                {
                    if (blob.Length == 0 && !consumed) throw new CryptographicException("A protected unconsumed prekey disappeared.");
                    if (blob.Length > 0 && consumed) erase.Add(index);
                }
                finally { CryptographicOperations.ZeroMemory(blob); }
            }
            if (erase.Count == 0) continue;
            var replacement = entry.WithoutSecrets(erase);
            var expected = entry.CopyExact(); var next = replacement.CopyExact();
            try
            {
                if (!await RequireReceiverStorage().CompareExchangeAsync(ProtectedPreKeyInventoryChain.EntrySlot(entry.PublicationHash),
                    expected, next, ct).ConfigureAwait(false))
                    throw new CryptographicException("Consumed prekey custody lost its exact protected predecessor.");
                successorCustody.ReplaceConsumedEntry(ordinal, replacement); replacement = null!;
            }
            finally
            { replacement?.Dispose(); CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(next); }
        }
        ValidateSuccessorSecrets(ledger, restore: false);
    }

    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
}
