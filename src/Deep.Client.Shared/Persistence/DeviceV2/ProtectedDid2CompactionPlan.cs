using System.Globalization;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Protected exact plan/successor staging under the actual account
/// lock. Neither staging nor reading grants SQL deletion, terminal evidence,
/// native fence or checkpoint authority. Selection/SQL adoption remain owned
/// operations, not callbacks into this storage component.</summary>
internal sealed class ProtectedDid2CompactionPlan
{
    private readonly IDeepSecureStorage storage;
    private readonly DeepIdV2AccountFileLease lease;
    private readonly byte[] network, account, instance;

    internal ProtectedDid2CompactionPlan(IDeepSecureStorage storage,
        DeepIdV2AccountFileLease lease, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        this.storage = storage ?? throw new ArgumentNullException(nameof(storage));
        this.lease = lease ?? throw new ArgumentNullException(nameof(lease));
        using var validated = Did2CompactionPlan.RegisteredEmpty(network, account, instance);
        this.network = network.ToArray(); this.account = account.ToArray(); this.instance = instance.ToArray();
    }

    internal static string PartSlot(int index)
    {
        if (index is < 0 or >= Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes)
            throw new ArgumentOutOfRangeException(nameof(index));
        return Did2CompactionPlan.Slot + ".successor." + index.ToString(CultureInfo.InvariantCulture);
    }

    // Read-only registration check. The existing account registration producer
    // creates the empty slot; a reader must never synthesize it when absent.
    internal static async Task<Did2CompactionPlan> ReadRegisteredAsync(IDeepSecureStorage storage,
        ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account,
        ReadOnlyMemory<byte> instance, CancellationToken ct)
    {
        using var raw = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot, ct).ConfigureAwait(false)
            ?? throw new InvalidDataException("Protected compaction registration is absent; explicit reset is required.");
        return raw.Use(bytes => Did2CompactionPlan.Decode(bytes, network.Span, account.Span, instance.Span));
    }

    internal async Task<Did2CompactionPlan> ReadAsync(HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(held);
        using var borrowed = held.BorrowFor(lease);
        var result = await ReadRegisteredAsync(storage, network, account, instance, ct).ConfigureAwait(false);
        try { ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return result; }
        catch { result.Dispose(); throw; }
    }

    internal async Task StageAsync(Did2CompactionPlan predecessor,
        Did2CompactionPlan.Preparation preparation, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(predecessor); ArgumentNullException.ThrowIfNull(preparation);
        ArgumentNullException.ThrowIfNull(held);
        using var borrowed = held.BorrowFor(lease);
        // Capture all caller-owned values before the first await. The component
        // never retains a caller buffer across a storage operation.
        using var original = Did2CompactionPlan.Decode(predecessor.Exact.Span, network, account, instance);
        using var pending = Did2CompactionPlan.Decode(preparation.Plan.Exact.Span, network, account, instance);
        using var successors = preparation.Successors.Use(bytes => new OwnedDeepSecret(bytes));
        if (original.Phase != 0 || pending.Phase != 1 || pending.Revision != checked(original.Revision + 1))
            throw new InvalidDataException("Compaction staging has another predecessor or phase.");
        successors.Use(bytes => pending.ValidateSuccessors(bytes));
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        using var current = await ReadAsync(held, ct).ConfigureAwait(false);
        if (Fixed(current.Exact.Span, pending.Exact.Span))
        {
            using var retained = await ReadSuccessorsAsync(pending, held, ct).ConfigureAwait(false);
            return; // Exact retry; no re-creation of missing or changed parts.
        }
        if (!Fixed(current.Exact.Span, original.Exact.Span))
            throw new CryptographicException("Compaction predecessor changed; no plan overwrite is permitted.");
        await RequireNoPartsAsync(ct).ConfigureAwait(false);
        var parts = successors.Use(bytes => Split(bytes));
        try
        {
            var insertions = parts.Select((part, index) => new DeepSecureStorageWrite(PartSlot(index), part)).ToArray();
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            // Existing storage primitive atomically publishes the plan and every
            // insert-only part. Capacity/protection/conflicts leave no half-plan.
            if (!await storage.CompareExchangeAndInsertAsync(Did2CompactionPlan.Slot,
                    original.Exact, pending.Exact, insertions, ct).ConfigureAwait(false))
                throw new CryptographicException("Compaction plan/part publication conflicted; no repair is permitted.");
            using var published = await ReadAsync(held, ct).ConfigureAwait(false);
            if (!Fixed(published.Exact.Span, pending.Exact.Span))
                throw new CryptographicException("Protected compaction publication read-back differs.");
            using var readback = await ReadSuccessorsAsync(published, held, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        }
        finally { foreach (var part in parts) CryptographicOperations.ZeroMemory(part); }
    }

    internal async Task<OwnedDeepSecret> ReadSuccessorsAsync(Did2CompactionPlan expected,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(expected); ArgumentNullException.ThrowIfNull(held);
        using var borrowed = held.BorrowFor(lease);
        using var plan = Did2CompactionPlan.Decode(expected.Exact.Span, network, account, instance);
        if (plan.Phase == 0) throw new InvalidDataException("An idle compaction plan has no successor custody.");
        using var before = await ReadAsync(held, ct).ConfigureAwait(false);
        if (!Fixed(before.Exact.Span, plan.Exact.Span))
            throw new CryptographicException("Protected compaction plan differs before successor read-back.");
        var bytes = new byte[plan.SuccessorBytes];
        try
        {
            for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
            {
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                using var part = await storage.ReadOwnedAsync(PartSlot(index), ct).ConfigureAwait(false);
                if (index >= plan.PartCount)
                { if (part is not null) throw new InvalidDataException("Compaction staging has an unexpected extra part."); continue; }
                var offset = index * Did2CompactionPlan.PartBytes;
                var length = Math.Min(Did2CompactionPlan.PartBytes, bytes.Length - offset);
                if (part is null || part.Length != length)
                    throw new InvalidDataException("Compaction staging lost an exact successor part.");
                part.CopyTo(bytes.AsSpan(offset, length));
            }
            plan.ValidateSuccessors(bytes);
            using var after = await ReadAsync(held, ct).ConfigureAwait(false);
            if (!Fixed(after.Exact.Span, plan.Exact.Span))
                throw new CryptographicException("Protected compaction plan changed during successor read-back.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return new(bytes);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task RequireNoPartsAsync(CancellationToken ct)
    {
        for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
        {
            using var part = await storage.ReadOwnedAsync(PartSlot(index), ct).ConfigureAwait(false);
            if (part is not null) throw new InvalidDataException("Idle compaction has unexplained successor custody; no deletion is permitted.");
        }
    }

    private static byte[][] Split(ReadOnlySpan<byte> bytes)
    {
        var count = (bytes.Length + Did2CompactionPlan.PartBytes - 1) / Did2CompactionPlan.PartBytes;
        var result = new byte[count][];
        try
        {
            for (var index = 0; index < count; index++)
            {
                var offset = index * Did2CompactionPlan.PartBytes;
                result[index] = bytes.Slice(offset, Math.Min(Did2CompactionPlan.PartBytes, bytes.Length - offset)).ToArray();
            }
            return result;
        }
        catch { foreach (var part in result) if (part is not null) CryptographicOperations.ZeroMemory(part); throw; }
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
