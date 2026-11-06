using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.Identity;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<IReadOnlyDictionary<string, DeepPermanentIdV2>> KnownContactAddressesAsync(
        ulong seconds, IDeepMlDsa65Verifier verifier,
        IReadOnlyDictionary<string, DeepPermanentIdV2>? supplied, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage,
            networkId, current.AccountId, ct).ConfigureAwait(false);
        using var raw = await storage.ReadOwnedAsync(ProtectedKnownContactAddresses.Slot, ct).ConfigureAwait(false);
        var exact = raw?.Use(bytes => bytes.ToArray()); byte[]? next = null;
        try
        {
            var addresses = exact is null ? new Dictionary<string, DeepPermanentIdV2>(StringComparer.OrdinalIgnoreCase) :
                ProtectedKnownContactAddresses.Decode(exact, networkId, current.AccountId.Span, instance);
            if (supplied is not null)
            {
                foreach (var item in supplied) addresses[item.Key] = item.Value;
                next = ProtectedKnownContactAddresses.Encode(addresses, networkId, current.AccountId.Span, instance);
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                if (exact is null)
                {
                    // Enrollment is atomic with an unchanged existing account
                    // guard; CompareExchange deliberately cannot insert slots.
                    using var guard = await storage.ReadOwnedAsync(CurrentAccountSlot, ct).ConfigureAwait(false) ??
                        throw new InvalidDataException("Known-contact enrollment lost its current account.");
                    var predecessor = guard.Use(bytes => bytes.ToArray());
                    try
                    {
                        if (!await storage.CompareExchangeAndInsertAsync(CurrentAccountSlot, predecessor, predecessor,
                            [new(ProtectedKnownContactAddresses.Slot, next)], ct).ConfigureAwait(false))
                            throw new IOException("Known-contact enrollment changed its account guard.");
                    }
                    finally { CryptographicOperations.ZeroMemory(predecessor); }
                }
                else if (!exact.AsSpan().SequenceEqual(next))
                    if (!await storage.CompareExchangeAsync(ProtectedKnownContactAddresses.Slot, exact, next, ct).ConfigureAwait(false))
                        throw new IOException("Protected known-contact data changed during commit.");
            }
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return addresses;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance);
            if (exact is not null) CryptographicOperations.ZeroMemory(exact);
            if (next is not null) CryptographicOperations.ZeroMemory(next);
        }
    }
}
