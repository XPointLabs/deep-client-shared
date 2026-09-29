using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Local authenticated custody, not a caller-mintable network capability.
internal sealed class DeepIdV2NetworkHistorySnapshot(
    XPointNetworkStateSnapshot snapshot, ReadOnlySpan<byte> exactHistory)
{
    private readonly byte[] history = exactHistory.ToArray();
    internal XPointNetworkStateSnapshot Snapshot { get; } = new(snapshot.Revision,
        snapshot.ProtectedLkg, snapshot.ForkLatched);
    internal ReadOnlyMemory<byte> ExactHistory => history.ToArray();
}

internal interface IDeepIdV2NetworkHistoryStore
{
    void RequireAccountScope(ReadOnlyMemory<byte> accountId);

    ValueTask<DeepIdV2NetworkHistorySnapshot?> ReadHistoryAsync(CancellationToken cancellationToken);

    ValueTask<XPointNetworkAdvanceResult> ApplyVerifiedHistoryAsync(
        DeepIdV2NetworkHistorySnapshot? expected,
        VerifiedOnionNetworkContext verified,
        CancellationToken cancellationToken);
}
