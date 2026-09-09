namespace Deep.Client.Shared.Domain.DeviceV1;

public enum DeviceDirectoryTransitionDisposition
{
    AcceptedGenesis = 1, AcceptedSuccessor = 2, ExactReplay = 3, StaleCandidate = 4,
    InvalidLineage = 5, ForkLatched = 6, RevokedDeviceReuse = 7
}

public sealed class DeviceDirectoryState
{
    private readonly DeviceLocalRevocationFloorEntry[] floor;

    internal DeviceDirectoryState(VerifiedDeviceDirectoryFacts head, bool forkLatched,
        IEnumerable<DeviceLocalRevocationFloorEntry> floor)
    {
        ArgumentNullException.ThrowIfNull(head); ArgumentNullException.ThrowIfNull(floor);
        Head = head; ForkLatched = forkLatched; this.floor = floor.OrderBy(static x => x.DeviceId).ToArray();
        if (this.floor.Any(x => !x.AccountId.Equals(head.AccountId) || x.AccountGeneration != head.AccountGeneration)
            || this.floor.Select(static x => x.DeviceId).Distinct().Count() != this.floor.Length)
            throw new ArgumentException("The local revocation floor must contain unique entries for one exact account generation.", nameof(floor));
    }

    public VerifiedDeviceDirectoryFacts Head { get; }
    public bool ForkLatched { get; }
    public IReadOnlyList<DeviceLocalRevocationFloorEntry> LocalRevocationFloor => Array.AsReadOnly(floor.ToArray());
    public bool IsLocallyRevoked(DeviceIdentifier32 deviceId)
    { ArgumentNullException.ThrowIfNull(deviceId); return floor.Any(x => x.DeviceId.Equals(deviceId)); }

    public static DeviceDirectoryTransition Start(VerifiedDeviceDirectoryFacts genesis)
    {
        ArgumentNullException.ThrowIfNull(genesis);
        if (genesis.DirectoryGeneration != 1 || genesis.PredecessorSpan.IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidOperationException("A verified DMD1 lineage starts at generation one with a zero predecessor.");
        var state = new DeviceDirectoryState(genesis, false, []);
        return new(state, state, DeviceDirectoryTransitionDisposition.AcceptedGenesis);
    }

    internal static DeviceDirectoryState Restore(VerifiedDeviceDirectoryFacts head, bool forkLatched,
        IEnumerable<DeviceLocalRevocationFloorEntry> floor) => new(head, forkLatched, floor);

    public DeviceDirectoryTransition PrepareTransition(VerifiedDeviceDirectoryFacts candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        if (ForkLatched) return new(this, this, DeviceDirectoryTransitionDisposition.ForkLatched);
        if (!Head.AccountId.Equals(candidate.AccountId) || Head.AccountGeneration != candidate.AccountGeneration)
            return new(this, this, DeviceDirectoryTransitionDisposition.InvalidLineage);
        // A peer may legitimately remain offline with an older directory that predates a local
        // revoke.  It has no authority to revive the device, but it is not equivocation and must
        // not permanently wedge this account.  Reuse is a fork only at the current/newer lineage.
        if (candidate.DirectoryGeneration < Head.DirectoryGeneration)
            return new(this, this, DeviceDirectoryTransitionDisposition.StaleCandidate);
        if (candidate.ActiveDevices.Any(x => IsLocallyRevoked(x.DeviceId)))
        {
            var latched = new DeviceDirectoryState(Head, true, floor);
            return new(this, latched, DeviceDirectoryTransitionDisposition.RevokedDeviceReuse);
        }
        if (candidate.DirectoryGeneration == Head.DirectoryGeneration)
        {
            if (candidate.DirectoryHash.Equals(Head.DirectoryHash))
                return new(this, this, DeviceDirectoryTransitionDisposition.ExactReplay);
            var latched = new DeviceDirectoryState(Head, true, floor);
            return new(this, latched, DeviceDirectoryTransitionDisposition.ForkLatched);
        }
        if (Head.DirectoryGeneration != ulong.MaxValue
            && candidate.DirectoryGeneration == Head.DirectoryGeneration + 1
            && !candidate.PredecessorSpan.SequenceEqual(Head.DirectoryHash.Span))
        {
            var latched = new DeviceDirectoryState(Head, true, floor);
            return new(this, latched, DeviceDirectoryTransitionDisposition.ForkLatched);
        }
        if (Head.DirectoryGeneration == ulong.MaxValue || candidate.DirectoryGeneration != Head.DirectoryGeneration + 1)
            return new(this, this, DeviceDirectoryTransitionDisposition.InvalidLineage);
        var accepted = new DeviceDirectoryState(candidate, false, floor);
        return new(this, accepted, DeviceDirectoryTransitionDisposition.AcceptedSuccessor);
    }

    internal DeviceDirectoryState CommitRevocation(VerifiedDeviceDirectoryFacts exactSuccessor,
        DeviceLocalRevocationFloorEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (IsLocallyRevoked(entry.DeviceId)) throw new InvalidOperationException("A revoked device ID can never be reused.");
        var transition = PrepareTransition(exactSuccessor);
        if (transition.Disposition != DeviceDirectoryTransitionDisposition.AcceptedSuccessor || exactSuccessor.Contains(entry.DeviceId))
            throw new InvalidOperationException("The exact verified successor must remove the revoked device.");
        return new DeviceDirectoryState(exactSuccessor, false, floor.Append(entry));
    }
}

public sealed class DeviceDirectoryTransition
{
    internal DeviceDirectoryTransition(DeviceDirectoryState previous, DeviceDirectoryState next,
        DeviceDirectoryTransitionDisposition disposition)
    { Previous = previous; Next = next; Disposition = disposition; }
    public DeviceDirectoryState Previous { get; }
    public DeviceDirectoryState Next { get; }
    public DeviceDirectoryTransitionDisposition Disposition { get; }
}
