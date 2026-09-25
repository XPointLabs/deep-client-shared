using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static class DeepIdV2GenesisDmd1Custody
{
    internal static ValueTask<ProtectedCurrentDmd1CommitResult> CommitAsync(
        VerifiedDeepIdV2CurrentAccount current,
        SqliteDeviceStateStore deviceStore,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(deviceStore);
        var directory = current.Verified.PublicEvidence.Directory;
        var lineage = ApplicationCoreVerifier.StartDmd1Lineage(directory).Next;
        ReadOnlySpan<byte> domain =
            "Deep/STORE-V2/install-genesis-DMD1"u8;
        var operationInput = new byte[domain.Length + 32 + 32];
        domain.CopyTo(operationInput);
        current.AccountId.Span.CopyTo(operationInput.AsSpan(domain.Length));
        directory.Record.RecordHash.Span.CopyTo(
            operationInput.AsSpan(domain.Length + 32));
        try
        {
            var operationId = DeviceOperationId32.FromBytes(
                SHA256.HashData(operationInput));
            return deviceStore.CommitCurrentDmd1Async(operationId,
                lineage, cancellationToken);
        }
        finally { CryptographicOperations.ZeroMemory(operationInput); }
    }
}
