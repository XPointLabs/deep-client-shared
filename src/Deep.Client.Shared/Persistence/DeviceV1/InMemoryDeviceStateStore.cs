using Deep.Client.Shared.Domain.DeviceV1;

namespace Deep.Client.Shared.Persistence.DeviceV1;

public sealed partial class InMemoryDeviceStateStore : IDeviceStateStore, IProtectedCurrentDmd1Store
{
    private readonly object gate = new();
    private readonly Dictionary<string, DeviceAccountStateSnapshot> states = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> operations = new(StringComparer.Ordinal);

    public ValueTask<DeviceStoreReadResult> ReadAsync(DeviceAccountId32 accountId, ulong accountGeneration,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accountId); cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            states.TryGetValue(Key(accountId, accountGeneration), out var snapshot);
            return ValueTask.FromResult(new DeviceStoreReadResult(snapshot));
        }
    }

    public ValueTask<DeviceCommitResult> CommitAsync(DeviceTransactionPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan); cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            var stateKey = Key(plan.AccountId, plan.AccountGeneration);
            var operationKey = $"{stateKey}:{Convert.ToHexString(plan.OperationId.Span)}";
            var fingerprint = plan.Fingerprint();
            if (operations.TryGetValue(operationKey, out var prior))
            {
                states.TryGetValue(stateKey, out var replay);
                return ValueTask.FromResult(new DeviceCommitResult(
                    CryptographicEquals(prior, fingerprint) ? DeviceCommitDisposition.Idempotent : DeviceCommitDisposition.Conflict,
                    replay));
            }
            states.TryGetValue(stateKey, out var current);
            var result = DeviceStateMachine.Apply(current, plan);
            if (result.Snapshot is not null && result.Disposition is DeviceCommitDisposition.Applied
                or DeviceCommitDisposition.ForkLatched or DeviceCommitDisposition.Idempotent)
            {
                states[stateKey] = result.Snapshot; operations.Add(operationKey, fingerprint);
            }
            return ValueTask.FromResult(result);
        }
    }

    private static string Key(DeviceAccountId32 accountId, ulong generation) =>
        $"{Convert.ToHexString(accountId.Span)}:{generation}";
    private static bool CryptographicEquals(string left, string right) =>
        System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left), Convert.FromHexString(right));
}
