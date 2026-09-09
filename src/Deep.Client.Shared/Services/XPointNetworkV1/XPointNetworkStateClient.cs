using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.XPointNetworkV1;

public enum XPointNetworkAdvanceDisposition
{
    Applied = 1,
    Idempotent = 2,
    StaleCapability = 3,
    ForkLatched = 4,
}

public sealed record XPointNetworkAdvanceResult(
    XPointNetworkAdvanceDisposition Disposition,
    XPointNetworkStateSnapshot Snapshot);

internal interface IXPointNetworkVerifiedAdvance
{
    XPointNetworkProtectedLkg? Prior { get; }
    XPointNetworkProtectedLkg Next { get; }
}

internal sealed class ForwardCheckpointAdvance : IXPointNetworkVerifiedAdvance
{
    private readonly VerifiedXPointNetworkForwardCheckpoint checkpoint;

    internal ForwardCheckpointAdvance(VerifiedXPointNetworkForwardCheckpoint checkpoint)
    {
        this.checkpoint = checkpoint
            ?? throw new ArgumentNullException(nameof(checkpoint));
        this.checkpoint.EnsureCurrent();
    }

    public XPointNetworkProtectedLkg? Prior => checkpoint.PriorProtectedLkg;
    public XPointNetworkProtectedLkg Next => checkpoint.NextProtectedLkg;
}

internal sealed class VerifiedNetworkContextAdvance : IXPointNetworkVerifiedAdvance
{
    internal VerifiedNetworkContextAdvance(VerifiedOnionNetworkContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.EnsureCurrent();
        Next = context.ProtectedLkg
            ?? throw new InvalidOperationException(
                "The verified network context has no protected-LKG projection.");
        Prior = context.PriorProtectedLkg;
    }

    public XPointNetworkProtectedLkg? Prior { get; }
    public XPointNetworkProtectedLkg Next { get; }
}

/// <summary>
/// Serializes verified public-network trust advances into the protected store.
/// It never accepts raw network records or a caller-authored replacement LKG.
/// </summary>
public sealed class XPointNetworkStateClient
{
    private const int MaximumCasAttempts = 8;
    private readonly IXPointNetworkStateStore store;

    public XPointNetworkStateClient(IXPointNetworkStateStore store) =>
        this.store = store ?? throw new ArgumentNullException(nameof(store));

    public async ValueTask<XPointNetworkProtectedLkg?> RestoreProtectedLkgAsync(
        CancellationToken cancellationToken = default)
    {
        var snapshot = await store.ReadAsync(cancellationToken).ConfigureAwait(false);
        return snapshot is null
            ? null
            : XPointNetworkStateSnapshot.Clone(snapshot.ProtectedLkg);
    }

    public ValueTask<XPointNetworkAdvanceResult> ApplyForwardCheckpointAsync(
        VerifiedXPointNetworkForwardCheckpoint checkpoint,
        CancellationToken cancellationToken = default) =>
        ApplyAsync(new ForwardCheckpointAdvance(checkpoint), cancellationToken);

    public ValueTask<XPointNetworkAdvanceResult> ApplyVerifiedNetworkContextAsync(
        VerifiedOnionNetworkContext context,
        CancellationToken cancellationToken = default) =>
        ApplyAsync(new VerifiedNetworkContextAdvance(context), cancellationToken);

    internal async ValueTask<XPointNetworkAdvanceResult> ApplyAsync(
        IXPointNetworkVerifiedAdvance advance,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(advance);
        for (var attempt = 0; attempt < MaximumCasAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await store.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (current is null)
            {
                if (advance.Prior is not null)
                    throw new InvalidOperationException(
                        "A successor capability cannot initialize an empty protected network store.");
                var bootstrap = new XPointNetworkStateSnapshot(
                    1,
                    advance.Next,
                    forkLatched: false);
                var firstWrite = await store.CompareExchangeAsync(
                    null,
                    bootstrap,
                    cancellationToken).ConfigureAwait(false);
                if (firstWrite.Disposition == XPointNetworkStoreWriteDisposition.Applied)
                    return new(XPointNetworkAdvanceDisposition.Applied, firstWrite.Snapshot!);
                continue;
            }
            if (current.ForkLatched)
                return new(XPointNetworkAdvanceDisposition.ForkLatched, current);
            if (Same(current.ProtectedLkg, advance.Next))
                return new(XPointNetworkAdvanceDisposition.Idempotent, current);
            if (advance.Prior is null || !Same(current.ProtectedLkg, advance.Prior))
                return new(XPointNetworkAdvanceDisposition.StaleCapability, current);

            var next = advance.Next;
            if (!Fixed(current.ProtectedLkg.NetworkId.Span, next.NetworkId.Span)
                || next.ViewGeneration <= current.ProtectedLkg.ViewGeneration
                || next.HeadTreeSize <= current.ProtectedLkg.HeadTreeSize
                || (current.ProtectedLkg.LastForwardCheckpointGeneration.HasValue
                    && (!next.LastForwardCheckpointGeneration.HasValue
                        || next.LastForwardCheckpointGeneration.Value
                        < current.ProtectedLkg.LastForwardCheckpointGeneration.Value)))
                throw new CryptographicException(
                    "A verified forward checkpoint attempted a non-monotonic protected-LKG transition.");

            var replacement = new XPointNetworkStateSnapshot(
                checked(current.Revision + 1),
                next,
                forkLatched: false);
            var write = await store.CompareExchangeAsync(
                current.Revision,
                replacement,
                cancellationToken).ConfigureAwait(false);
            if (write.Disposition == XPointNetworkStoreWriteDisposition.Applied)
                return new(XPointNetworkAdvanceDisposition.Applied, write.Snapshot!);
        }

        throw new IOException("Protected XPoint network state remained contended.");
    }

    private static bool Same(
        XPointNetworkProtectedLkg left,
        XPointNetworkProtectedLkg right)
    {
        var leftBytes = XPointNetworkProtectedLkgCodec.Encode(left);
        var rightBytes = XPointNetworkProtectedLkgCodec.Encode(right);
        try
        {
            return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}
