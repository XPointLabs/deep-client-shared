using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;

namespace Deep.Client.Shared.Persistence.ContactV1;

public sealed partial class InMemoryContactStateStore : IContactStateStore, IContactResolveOperationStore
{
    public const int DefaultMaximumPendingAddresses = 10_000;

    private readonly object gate = new();
    private readonly int maximumPendingAddresses;
    private readonly Dictionary<string, PendingContactAddress> pending = new(StringComparer.Ordinal);

    public InMemoryContactStateStore(
        ContactStoreScope scope,
        int maximumPendingAddresses = DefaultMaximumPendingAddresses)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        if (scope.StoreGeneration != ContactStoreScope.CurrentStoreGeneration)
            throw new ArgumentException("Only the current ContactV1 store generation is supported.", nameof(scope));
        if (maximumPendingAddresses is <= 0 or > DefaultMaximumPendingAddresses)
            throw new ArgumentOutOfRangeException(nameof(maximumPendingAddresses));
        this.maximumPendingAddresses = maximumPendingAddresses;
    }

    public ContactStoreScope Scope { get; }

    public ValueTask<PendingContactAddressWriteResult> PutPendingAddressAsync(
        PendingContactAddress address,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(address);
        cancellationToken.ThrowIfCancellationRequested();
        var candidate = ContactStatePersistenceValidation.CloneAndValidate(address);
        var key = Key(candidate.Address.Kind, candidate.Address.CanonicalBytes.Span);
        lock (gate)
        {
            if (pending.TryGetValue(key, out var existing))
            {
                if (!existing.Address.Equals(candidate.Address))
                    throw new ArgumentException("The canonical address is already bound to another network.", nameof(address));
                return ValueTask.FromResult(new PendingContactAddressWriteResult(
                    PendingContactAddressWriteDisposition.Idempotent,
                    ContactStatePersistenceValidation.CloneAndValidate(existing)));
            }
            if (pending.Count >= maximumPendingAddresses)
                return ValueTask.FromResult(new PendingContactAddressWriteResult(
                    PendingContactAddressWriteDisposition.CapacityExceeded, null));
            pending.Add(key, candidate);
            return ValueTask.FromResult(new PendingContactAddressWriteResult(
                PendingContactAddressWriteDisposition.Added,
                ContactStatePersistenceValidation.CloneAndValidate(candidate)));
        }
    }

    public ValueTask<PendingContactAddress?> ReadPendingAddressAsync(
        ContactAddressKind kind,
        ReadOnlyMemory<byte> exactCanonicalAddress,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ContactStatePersistenceValidation.ValidateLookup(kind, exactCanonicalAddress.Span);
        lock (gate)
        {
            pending.TryGetValue(Key(kind, exactCanonicalAddress.Span), out var address);
            return ValueTask.FromResult(address is null
                ? null
                : ContactStatePersistenceValidation.CloneAndValidate(address));
        }
    }

    public ValueTask<IReadOnlyList<PendingContactAddress>> ReadPendingAddressesAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            IReadOnlyList<PendingContactAddress> snapshot = pending.Values
                .OrderBy(static item => item.ImportedAt)
                .ThenBy(static item => item.Address.Kind)
                .ThenBy(static item => Convert.ToHexString(item.Address.CanonicalBytes.Span), StringComparer.Ordinal)
                .Select(ContactStatePersistenceValidation.CloneAndValidate)
                .ToArray();
            return ValueTask.FromResult(snapshot);
        }
    }

    private static string Key(ContactAddressKind kind, ReadOnlySpan<byte> canonical) =>
        $"{KindNumber(kind)}:{Digest(canonical)}";

    private static int KindNumber(ContactAddressKind kind) => kind switch
    {
        ContactAddressKind.PermanentDeepId => (int)kind,
        ContactAddressKind.OneTimeInvitation => (int)kind,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static string Digest(ReadOnlySpan<byte> canonical)
    {
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(canonical, digest);
        return Convert.ToHexString(digest);
    }
}
