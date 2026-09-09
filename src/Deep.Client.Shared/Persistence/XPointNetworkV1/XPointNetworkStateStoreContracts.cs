using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.XPointNetworkV1;

public sealed class XPointNetworkStateSnapshot
{
    public XPointNetworkStateSnapshot(
        ulong revision,
        XPointNetworkProtectedLkg protectedLkg,
        bool forkLatched)
    {
        if (revision == 0) throw new ArgumentOutOfRangeException(nameof(revision));
        Revision = revision;
        ProtectedLkg = Clone(protectedLkg);
        ForkLatched = forkLatched;
    }

    public ulong Revision { get; }
    public XPointNetworkProtectedLkg ProtectedLkg { get; }
    public bool ForkLatched { get; }

    internal static XPointNetworkProtectedLkg Clone(XPointNetworkProtectedLkg value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return XPointNetworkProtectedLkgCodec.Decode(
            XPointNetworkProtectedLkgCodec.Encode(value));
    }
}

public enum XPointNetworkStoreWriteDisposition
{
    Applied = 1,
    Conflict = 2,
}

public sealed record XPointNetworkStoreWriteResult(
    XPointNetworkStoreWriteDisposition Disposition,
    XPointNetworkStateSnapshot? Snapshot);

public interface IXPointNetworkStateStore
{
    ValueTask<XPointNetworkStateSnapshot?> ReadAsync(CancellationToken cancellationToken);

    ValueTask<XPointNetworkStoreWriteResult> CompareExchangeAsync(
        ulong? expectedRevision,
        XPointNetworkStateSnapshot replacement,
        CancellationToken cancellationToken);
}

internal static class XPointNetworkStateCloner
{
    internal static XPointNetworkStateSnapshot? Clone(XPointNetworkStateSnapshot? snapshot) =>
        snapshot is null
            ? null
            : new XPointNetworkStateSnapshot(
                snapshot.Revision,
                snapshot.ProtectedLkg,
                snapshot.ForkLatched);
}
