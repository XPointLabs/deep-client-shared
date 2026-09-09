using Deep.Client.Shared.Domain.AccountDirectoryV1;

namespace Deep.Client.Shared.Services.AccountDirectoryV1;

public enum AccountDirectoryMutationKind
{
    ReadLocalHistory = 1,
    SaveLocalDraft = 2,
    RetainCiphertextWithoutAcknowledgement = 3,
    EmitOutboundEnvelope = 4,
    EstablishPreKeyOrRatchet = 5,
    AcceptContact = 6,
    EmitRemoteStateReceipt = 7,
    ChangeGroupMembershipOrDevice = 8
}

public sealed class AccountDirectoryMutationDeniedException(AccountDirectoryClientState state)
    : InvalidOperationException($"Account-directory mutation is blocked in {state} state.")
{
    public AccountDirectoryClientState State { get; } = state;
}

public static class AccountDirectoryMutationFence
{
    public static AccountDirectoryClientState Evaluate(AccountDirectoryStateSnapshot? snapshot,
        AccountDirectoryLeafKey32 leafKey, AccountDirectoryMutationKind mutation,
        ReadOnlySpan<byte> currentBootId, ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(leafKey);
        if (!Enum.IsDefined(mutation)) throw new ArgumentOutOfRangeException(nameof(mutation));
        if (mutation is AccountDirectoryMutationKind.ReadLocalHistory or AccountDirectoryMutationKind.SaveLocalDraft
            or AccountDirectoryMutationKind.RetainCiphertextWithoutAcknowledgement)
            return AccountDirectoryClientState.Current;
        if (snapshot?.ForkLatched == true) return AccountDirectoryClientState.DirectoryForkBlocked;
        return snapshot?.Find(leafKey)?.EffectiveState(currentBootId, currentMonotonicSample)
            ?? AccountDirectoryClientState.RevocationRefreshRequired;
    }

    public static void EnsureAllowed(AccountDirectoryStateSnapshot? snapshot, AccountDirectoryLeafKey32 leafKey,
        AccountDirectoryMutationKind mutation, ReadOnlySpan<byte> currentBootId, ulong currentMonotonicSample)
    {
        var state = Evaluate(snapshot, leafKey, mutation, currentBootId, currentMonotonicSample);
        if (state != AccountDirectoryClientState.Current) throw new AccountDirectoryMutationDeniedException(state);
    }
}
