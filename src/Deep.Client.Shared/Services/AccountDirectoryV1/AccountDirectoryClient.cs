using Deep.Client.Shared.Domain.AccountDirectoryV1;
using Deep.Client.Shared.Persistence.AccountDirectoryV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Services.AccountDirectoryV1;

public sealed class AccountDirectoryClient
{
    private readonly IAccountDirectoryStateStore store;
    public AccountDirectoryClient(IAccountDirectoryStateStore store) => this.store = store ?? throw new ArgumentNullException(nameof(store));

    public ValueTask<AccountDirectoryStateSnapshot?> ReadAsync(CancellationToken cancellationToken) => store.ReadAsync(cancellationToken);

    public Task<AccountDirectoryStateSnapshot> ApplyVerifiedAsync(VerifiedAccountDirectoryFreshness verified,
        AccountDirectoryAuthorizationId32? selectedAuthorizationId,
        AccountDirectoryDeviceId32? selectedDeviceId, CancellationToken cancellationToken)
    {
        var update = AccountDirectoryVerifiedUpdate.FromVerified(verified, selectedAuthorizationId, selectedDeviceId);
        return MutateAsync(current => AccountDirectoryStateMachine.ApplyVerified(current, update), cancellationToken);
    }

    public async Task<AccountDirectoryStateSnapshot> VerifyAndApplyAsync(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactDtt1,
        ReadOnlyMemory<byte> exactAdp1,
        ReadOnlyMemory<byte> callerNonce32,
        ReadOnlyMemory<byte> queriedDirectoryLeafKey32,
        AccountDirectoryMonotonicRequestWindow monotonic,
        AccountDirectoryProtectedLkg? liveProtectedLkg,
        VerifiedAccountDirectoryCheckpoint? currentCheckpoint,
        ushort supportedReader,
        AccountDirectoryAuthorizationId32? selectedAuthorizationId,
        AccountDirectoryDeviceId32? selectedDeviceId,
        CancellationToken cancellationToken)
    {
        var protectedState = (await store.ReadAsync(cancellationToken).ConfigureAwait(false))?.ProtectedLkg;
        EnsureLiveCapabilityMatchesProtectedState(protectedState, liveProtectedLkg);
        var verified = AccountDirectoryCurrentProofVerifier.Verify(authority, exactAdh1, exactDtt1, exactAdp1,
            callerNonce32.Span, queriedDirectoryLeafKey32.Span, monotonic, liveProtectedLkg,
            currentCheckpoint, supportedReader);
        return await ApplyVerifiedAsync(verified, selectedAuthorizationId, selectedDeviceId, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<AccountDirectoryProtectedLkg> RestoreProtectedLkgAsync(
        VerifiedXPointNetworkAuthority authority, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var snapshot = await store.ReadAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Protected account-directory state is missing; null-LKG fallback is forbidden.");
        var persisted = snapshot.ProtectedLkg
            ?? throw new InvalidOperationException("Protected account-directory LKG is missing; null-LKG fallback is forbidden.");
        var restored = AccountDirectoryProtectedLkgFactory.Restore(
            authority, persisted.ExactAdh1, persisted.CoreHash.Span);
        EnsureLiveCapabilityMatchesProtectedState(persisted, restored);
        return restored;
    }

    public async Task<AccountDirectoryStateSnapshot> RestoreVerifyAndApplyAsync(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactDtt1,
        ReadOnlyMemory<byte> exactAdp1,
        ReadOnlyMemory<byte> callerNonce32,
        ReadOnlyMemory<byte> queriedDirectoryLeafKey32,
        AccountDirectoryMonotonicRequestWindow monotonic,
        VerifiedAccountDirectoryCheckpoint? currentCheckpoint,
        ushort supportedReader,
        AccountDirectoryAuthorizationId32? selectedAuthorizationId,
        AccountDirectoryDeviceId32? selectedDeviceId,
        CancellationToken cancellationToken)
    {
        var restored = await RestoreProtectedLkgAsync(authority, cancellationToken).ConfigureAwait(false);
        return await VerifyAndApplyAsync(authority, exactAdh1, exactDtt1, exactAdp1,
            callerNonce32, queriedDirectoryLeafKey32, monotonic, restored, currentCheckpoint,
            supportedReader, selectedAuthorizationId, selectedDeviceId, cancellationToken).ConfigureAwait(false);
    }

    public Task<AccountDirectoryStateSnapshot> RequireRefreshAsync(AccountDirectoryLeafKey32 leafKey,
        AccountDirectoryRefreshReason reason, CancellationToken cancellationToken) =>
        MutateAsync(current => AccountDirectoryStateMachine.MarkRefreshRequired(current, leafKey, reason), cancellationToken);

    public async Task EnsureMutationAllowedAsync(AccountDirectoryLeafKey32 leafKey,
        AccountDirectoryMutationKind mutation, ReadOnlyMemory<byte> currentBootId,
        ulong currentMonotonicSample, CancellationToken cancellationToken)
    {
        var snapshot = await store.ReadAsync(cancellationToken).ConfigureAwait(false);
        AccountDirectoryMutationFence.EnsureAllowed(snapshot, leafKey, mutation, currentBootId.Span, currentMonotonicSample);
    }

    private async Task<AccountDirectoryStateSnapshot> MutateAsync(
        Func<AccountDirectoryStateSnapshot?, AccountDirectoryStateSnapshot> transition,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await store.ReadAsync(cancellationToken).ConfigureAwait(false);
            var replacement = transition(current);
            if (ReferenceEquals(replacement, current)) return current!;
            var result = await store.CompareExchangeAsync(current?.Revision, replacement, cancellationToken).ConfigureAwait(false);
            if (result.Disposition == AccountDirectoryStoreWriteDisposition.Applied) return result.Snapshot!;
        }
    }

    private static void EnsureLiveCapabilityMatchesProtectedState(AccountDirectoryProtectedLkgState? state,
        AccountDirectoryProtectedLkg? capability)
    {
        if (state is null)
        {
            if (capability is not null) throw new InvalidOperationException("A live LKG capability exists without protected local state.");
            return;
        }
        if (capability is null || capability.LogGeneration != state.LogGeneration
            || capability.TreeSize != state.TreeSize
            || !Fixed(capability.CoreHash.Span, state.CoreHash.Span)
            || !Fixed(capability.ExactAdh1.Span, state.ExactAdh1.Span))
            throw new InvalidOperationException("The live protocol LKG capability does not match protected local state.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
