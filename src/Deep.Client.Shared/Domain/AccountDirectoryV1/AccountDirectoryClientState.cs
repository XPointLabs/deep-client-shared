using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Client.Shared.Domain.AccountDirectoryV1;

public enum AccountDirectoryClientState
{
    Current = 1,
    RevocationRefreshRequired = 2,
    DirectoryForkBlocked = 3,
    RevokedAuthorization = 4
}

public enum AccountDirectoryRefreshReason
{
    None = 0,
    DeadlineReached = 1,
    SecureTimeContinuityLost = 2,
    HigherGossipFloorObserved = 3,
    ProofUnavailable = 4,
    NonMembership = 5
}

public sealed class AccountDirectoryProtectedLkgState
{
    private readonly byte[] exactAdh1;
    private readonly byte[] coreHash;

    private AccountDirectoryProtectedLkgState(ReadOnlySpan<byte> exactAdh1, ReadOnlySpan<byte> coreHash,
        ulong logGeneration, ulong treeSize)
    {
        if (exactAdh1.IsEmpty) throw new ArgumentException("Exact ADH1 may not be empty.", nameof(exactAdh1));
        var parsed = AccountDirectoryAdh1Codec.Decode(exactAdh1);
        if (parsed.LogGeneration != logGeneration || parsed.TreeSize != treeSize)
            throw new ArgumentException("Persisted LKG tuple does not match exact ADH1.", nameof(exactAdh1));
        this.exactAdh1 = exactAdh1.ToArray();
        this.coreHash = AccountDirectoryHash32.FromBytes(coreHash).ToArray();
        LogGeneration = logGeneration;
        TreeSize = treeSize;
    }

    public ReadOnlyMemory<byte> ExactAdh1 => exactAdh1.ToArray();
    public AccountDirectoryHash32 CoreHash => AccountDirectoryHash32.FromBytes(coreHash);
    public ulong LogGeneration { get; }
    public ulong TreeSize { get; }

    internal static AccountDirectoryProtectedLkgState FromVerified(VerifiedAccountDirectoryFreshness verified) =>
        new(verified.NextProtectedLkg.ExactAdh1.Span, verified.NextProtectedLkg.CoreHash.Span,
            verified.NextProtectedLkg.LogGeneration, verified.NextProtectedLkg.TreeSize);

    internal static AccountDirectoryProtectedLkgState RestorePersisted(ReadOnlySpan<byte> exactAdh1,
        ReadOnlySpan<byte> coreHash, ulong logGeneration, ulong treeSize) =>
        new(exactAdh1, coreHash, logGeneration, treeSize);
}

public sealed class AccountDirectorySubjectState
{
    private readonly byte[] exactAdc1Reference;
    private readonly byte[] bootId;

    internal AccountDirectorySubjectState(AccountDirectoryLeafKey32 leafKey, AccountDirectoryClientState state,
        AccountDirectoryRefreshReason refreshReason, ReadOnlySpan<byte> exactAdc1Reference,
        ulong accountGeneration, ulong directoryGeneration, ReadOnlySpan<byte> bootId,
        ulong verifiedAtMonotonic, ulong freshnessDeadlineMonotonic,
        AccountDirectoryAuthorizationId32? authorizationId, AccountDirectoryDeviceId32? deviceId)
    {
        ArgumentNullException.ThrowIfNull(leafKey);
        if (!Enum.IsDefined(state) || !Enum.IsDefined(refreshReason)) throw new ArgumentOutOfRangeException(nameof(state));
        if (state == AccountDirectoryClientState.Current && refreshReason != AccountDirectoryRefreshReason.None)
            throw new ArgumentException("Current state cannot carry a refresh reason.");
        if (state == AccountDirectoryClientState.RevocationRefreshRequired && refreshReason == AccountDirectoryRefreshReason.None)
            throw new ArgumentException("Refresh-required state needs a reason.");
        if (state is AccountDirectoryClientState.DirectoryForkBlocked or AccountDirectoryClientState.RevokedAuthorization
            && refreshReason != AccountDirectoryRefreshReason.None)
            throw new ArgumentException("Terminal directory states cannot carry a refresh reason.");
        if (exactAdc1Reference.Length is not (0 or 38)) throw new ArgumentException("ADC1 reference must be empty or 38 bytes.", nameof(exactAdc1Reference));
        if (bootId.Length != 16 || bootId.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("Boot ID must be 16 non-zero bytes.", nameof(bootId));
        if (freshnessDeadlineMonotonic < verifiedAtMonotonic) throw new ArgumentOutOfRangeException(nameof(freshnessDeadlineMonotonic));
        if (state == AccountDirectoryClientState.Current && freshnessDeadlineMonotonic == verifiedAtMonotonic)
            throw new ArgumentException("Current state needs a non-empty monotonic freshness interval.");
        LeafKey = AccountDirectoryLeafKey32.FromBytes(leafKey.Span);
        State = state; RefreshReason = refreshReason; this.exactAdc1Reference = exactAdc1Reference.ToArray();
        AccountGeneration = accountGeneration; DirectoryGeneration = directoryGeneration;
        this.bootId = bootId.ToArray(); VerifiedAtMonotonic = verifiedAtMonotonic;
        FreshnessDeadlineMonotonic = freshnessDeadlineMonotonic;
        AuthorizationId = authorizationId is null ? null : AccountDirectoryAuthorizationId32.FromBytes(authorizationId.Span);
        DeviceId = deviceId is null ? null : AccountDirectoryDeviceId32.FromBytes(deviceId.Span);
    }

    public AccountDirectoryLeafKey32 LeafKey { get; }
    public AccountDirectoryClientState State { get; }
    public AccountDirectoryRefreshReason RefreshReason { get; }
    public ReadOnlyMemory<byte> ExactAdc1Reference => exactAdc1Reference.ToArray();
    public ulong AccountGeneration { get; }
    public ulong DirectoryGeneration { get; }
    public ReadOnlyMemory<byte> BootId => bootId.ToArray();
    public ulong VerifiedAtMonotonic { get; }
    public ulong FreshnessDeadlineMonotonic { get; }
    public AccountDirectoryAuthorizationId32? AuthorizationId { get; }
    public AccountDirectoryDeviceId32? DeviceId { get; }

    public AccountDirectoryClientState EffectiveState(ReadOnlySpan<byte> currentBootId, ulong currentSample)
    {
        if (State != AccountDirectoryClientState.Current) return State;
        return currentBootId.Length == 16
            && CryptographicOperations.FixedTimeEquals(bootId, currentBootId)
            && currentSample >= VerifiedAtMonotonic
            && currentSample < FreshnessDeadlineMonotonic
            ? AccountDirectoryClientState.Current
            : AccountDirectoryClientState.RevocationRefreshRequired;
    }

    internal AccountDirectorySubjectState WithState(AccountDirectoryClientState state, AccountDirectoryRefreshReason reason) =>
        new(LeafKey, state, reason, exactAdc1Reference, AccountGeneration, DirectoryGeneration, bootId,
            VerifiedAtMonotonic, FreshnessDeadlineMonotonic, AuthorizationId, DeviceId);
}

public sealed class AccountDirectoryStateSnapshot
{
    private readonly AccountDirectorySubjectState[] subjects;
    internal AccountDirectoryStateSnapshot(ulong revision, AccountDirectoryProtectedLkgState? lkg,
        bool forkLatched, IEnumerable<AccountDirectorySubjectState> subjects)
    {
        if (revision == 0) throw new ArgumentOutOfRangeException(nameof(revision));
        Revision = revision; ProtectedLkg = lkg; ForkLatched = forkLatched;
        this.subjects = subjects.OrderBy(static item => item.LeafKey).ToArray();
        if (this.subjects.Select(static item => Convert.ToHexString(item.LeafKey.ToArray())).Distinct(StringComparer.Ordinal).Count() != this.subjects.Length)
            throw new ArgumentException("Directory subjects must be unique.", nameof(subjects));
        if (forkLatched && this.subjects.Any(static item => item.State != AccountDirectoryClientState.DirectoryForkBlocked))
            throw new ArgumentException("A fork-latched snapshot must block every subject.", nameof(subjects));
    }
    public ulong Revision { get; }
    public AccountDirectoryProtectedLkgState? ProtectedLkg { get; }
    public bool ForkLatched { get; }
    public IReadOnlyList<AccountDirectorySubjectState> Subjects => Array.AsReadOnly(subjects.ToArray());
    public AccountDirectorySubjectState? Find(AccountDirectoryLeafKey32 leafKey) => subjects.SingleOrDefault(item => item.LeafKey.Equals(leafKey));
}
