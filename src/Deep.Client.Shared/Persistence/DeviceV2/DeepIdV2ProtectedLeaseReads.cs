using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Internal closed storage readers, never trust-authoring/fetch/initialization APIs.
internal interface IDeepIdV2DirectoryProtectedLeaseRead
{
    ValueTask<AccountDirectoryProtectedLkg> ReadExistingUnderLeaseAsync(
        VerifiedXPointNetworkAuthority authority, HeldDeepIdV2AccountLease held, CancellationToken ct);
}
internal interface IDeepIdV2NetworkHistoryLeaseRead
{
    ValueTask<DeepIdV2NetworkHistorySnapshot?> ReadHistoryUnderLeaseAsync(HeldDeepIdV2AccountLease held, CancellationToken ct);
}
