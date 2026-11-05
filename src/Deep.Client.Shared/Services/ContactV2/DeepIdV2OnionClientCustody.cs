using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.ContactV2;

/// <summary>Account-owned local ONION guards and entropy reservations. It
/// contains no device agreement scalar or node receive-key authority and
/// grants no current network, publication or messaging authority.</summary>
public sealed class DeepIdV2OnionClientCustody
{
    private readonly CancellationToken lifetime;

    internal DeepIdV2OnionClientCustody(DeepIdV2AccountService owner,
        IProtectedEntryGuardStore guards, IOnionEntropyUniquenessLedger entropy)
    {
        Owner = owner;
        Guards = guards;
        Entropy = entropy;
    }

    private DeepIdV2OnionClientCustody(DeepIdV2OnionClientCustody original, CancellationToken lifetime)
    {
        Owner = original.Owner;
        this.lifetime = lifetime;
        Guards = new ScopedGuards(original.Guards, lifetime);
        Entropy = new ScopedEntropy(original.Entropy, lifetime);
    }

    // Restricts the actual borrowed stores as well as the transport context.
    // It conveys no fresh authority and cannot extend the underlying owner loan.
    internal DeepIdV2OnionClientCustody RestrictToLifetime(CancellationToken scope)
    {
        RequireActive(); scope.ThrowIfCancellationRequested();
        if (lifetime.CanBeCanceled || !scope.CanBeCanceled)
            throw new InvalidOperationException("ONION custody requires one cancellable transport lifetime.");
        return new(this, scope);
    }

    internal void RequireActive() => lifetime.ThrowIfCancellationRequested();

    internal DeepIdV2AccountService Owner { get; }
    internal IProtectedEntryGuardStore Guards { get; }
    internal IOnionEntropyUniquenessLedger Entropy { get; }

    private sealed class ScopedGuards(IProtectedEntryGuardStore inner, CancellationToken lifetime) : IProtectedEntryGuardStore
    {
        public async ValueTask<EntryGuardState?> ReadAsync(CancellationToken cancellationToken)
        {
            using var scope = CancellationTokenSource.CreateLinkedTokenSource(lifetime, cancellationToken);
            scope.Token.ThrowIfCancellationRequested();
            var result = await inner.ReadAsync(scope.Token).ConfigureAwait(false);
            scope.Token.ThrowIfCancellationRequested(); return result;
        }

        public async ValueTask<EntryGuardStoreWriteResult> CompareExchangeAsync(ulong? expectedRevision,
            EntryGuardState replacement, CancellationToken cancellationToken)
        {
            using var scope = CancellationTokenSource.CreateLinkedTokenSource(lifetime, cancellationToken);
            scope.Token.ThrowIfCancellationRequested();
            var result = await inner.CompareExchangeAsync(expectedRevision, replacement, scope.Token).ConfigureAwait(false);
            scope.Token.ThrowIfCancellationRequested(); return result;
        }
    }

    private sealed class ScopedEntropy(IOnionEntropyUniquenessLedger inner, CancellationToken lifetime) : IOnionEntropyUniquenessLedger
    {
        public async ValueTask<OnionEntropyCommitOutcome> CommitAsync(OnionEntropyCommitmentBatch batch,
            CancellationToken cancellationToken)
        {
            using var scope = CancellationTokenSource.CreateLinkedTokenSource(lifetime, cancellationToken);
            scope.Token.ThrowIfCancellationRequested();
            var result = await inner.CommitAsync(batch, scope.Token).ConfigureAwait(false);
            scope.Token.ThrowIfCancellationRequested(); return result;
        }
    }
}
