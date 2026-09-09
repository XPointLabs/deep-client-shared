namespace Deep.Client.Shared.Domain.DeviceV1;

public enum DeviceTargetSelectionOutcome
{ Ready = 1, NoTargets = 2, StaleDirectory = 3, ForkLatched = 4, RevokedTarget = 5, DirectoryAdvanced = 6 }

public sealed class DeviceDirectoryObservation
{
    public DeviceDirectoryObservation(DeviceAccountId32 accountId, ulong accountGeneration, ulong generation,
        DeviceDirectoryHash32 hash)
    {
        ArgumentNullException.ThrowIfNull(accountId);
        if (accountGeneration == 0 || generation == 0) throw new ArgumentOutOfRangeException(nameof(generation));
        AccountId = DeviceAccountId32.FromBytes(accountId.Span); AccountGeneration = accountGeneration;
        Generation = generation; Hash = DeviceDirectoryHash32.FromBytes(hash.Span);
    }
    public DeviceAccountId32 AccountId { get; }
    public ulong AccountGeneration { get; }
    public ulong Generation { get; }
    public DeviceDirectoryHash32 Hash { get; }
}

public sealed class DeviceDeliveryTarget : IEquatable<DeviceDeliveryTarget>, IComparable<DeviceDeliveryTarget>
{
    internal DeviceDeliveryTarget(DeviceAccountId32 accountId, ulong accountGeneration, DeviceIdentifier32 deviceId)
    {
        if (accountGeneration == 0) throw new ArgumentOutOfRangeException(nameof(accountGeneration));
        AccountId = DeviceAccountId32.FromBytes(accountId.Span); AccountGeneration = accountGeneration;
        DeviceId = DeviceIdentifier32.FromBytes(deviceId.Span);
    }
    public DeviceAccountId32 AccountId { get; }
    public ulong AccountGeneration { get; }
    public DeviceIdentifier32 DeviceId { get; }
    public bool Equals(DeviceDeliveryTarget? other) => other is not null && AccountId.Equals(other.AccountId)
        && AccountGeneration == other.AccountGeneration && DeviceId.Equals(other.DeviceId);
    public override bool Equals(object? obj) => Equals(obj as DeviceDeliveryTarget);
    public override int GetHashCode() => HashCode.Combine(AccountId, AccountGeneration, DeviceId);
    public int CompareTo(DeviceDeliveryTarget? other)
    { ArgumentNullException.ThrowIfNull(other); var c = AccountId.CompareTo(other.AccountId); if (c != 0) return c;
      c = AccountGeneration.CompareTo(other.AccountGeneration); return c != 0 ? c : DeviceId.CompareTo(other.DeviceId); }
    public override string ToString() => "[opaque-device-delivery-target]";
}

public sealed class DeviceFanoutPlan
{
    private readonly DeviceDeliveryTarget[] targets;
    internal DeviceFanoutPlan(DeviceTargetSelectionOutcome outcome, VerifiedDeviceDirectoryFacts directory,
        IEnumerable<DeviceDeliveryTarget> targets, DeviceIdentifier32? requestedTarget = null)
    {
        Outcome = outcome; AccountId = DeviceAccountId32.FromBytes(directory.AccountId.Span);
        AccountGeneration = directory.AccountGeneration; DirectoryGeneration = directory.DirectoryGeneration;
        DirectoryHash = DeviceDirectoryHash32.FromBytes(directory.DirectoryHash.Span);
        RevocationHash = DeviceRevocationHash32.FromBytes(directory.RevocationHash.Span);
        this.targets = targets.OrderBy(static x => x).ToArray();
        RequestedTarget = requestedTarget is null ? null : DeviceIdentifier32.FromBytes(requestedTarget.Span);
    }
    public DeviceTargetSelectionOutcome Outcome { get; }
    public DeviceAccountId32 AccountId { get; }
    public ulong AccountGeneration { get; }
    public ulong DirectoryGeneration { get; }
    public DeviceDirectoryHash32 DirectoryHash { get; }
    public DeviceRevocationHash32 RevocationHash { get; }
    public DeviceIdentifier32? RequestedTarget { get; }
    public IReadOnlyList<DeviceDeliveryTarget> Targets => Array.AsReadOnly(targets.ToArray());
}

public static class DeviceTargetSelector
{
    public static DeviceFanoutPlan SelectAllActive(DeviceDirectoryState directory,
        DeviceDirectoryObservation? observedDirectory = null, DeviceIdentifier32? excludeDevice = null)
    {
        ArgumentNullException.ThrowIfNull(directory); var preflight = Preflight(directory, observedDirectory);
        if (preflight != DeviceTargetSelectionOutcome.Ready) return new(preflight, directory.Head, []);
        if (directory.Head.ActiveDevices.Any(x => directory.IsLocallyRevoked(x.DeviceId)))
            return new(DeviceTargetSelectionOutcome.ForkLatched, directory.Head, []);
        var targets = directory.Head.ActiveDevices.Where(x => excludeDevice is null || !x.DeviceId.Equals(excludeDevice))
            .Select(x => new DeviceDeliveryTarget(directory.Head.AccountId, directory.Head.AccountGeneration, x.DeviceId)).ToArray();
        return new(targets.Length == 0 ? DeviceTargetSelectionOutcome.NoTargets : DeviceTargetSelectionOutcome.Ready,
            directory.Head, targets);
    }

    public static DeviceFanoutPlan SelectExact(DeviceDirectoryState directory, DeviceIdentifier32 target,
        DeviceDirectoryObservation? observedDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(directory); ArgumentNullException.ThrowIfNull(target);
        var preflight = Preflight(directory, observedDirectory);
        if (preflight != DeviceTargetSelectionOutcome.Ready) return new(preflight, directory.Head, [], target);
        if (directory.IsLocallyRevoked(target) || !directory.Head.Contains(target))
            return new(DeviceTargetSelectionOutcome.RevokedTarget, directory.Head, [], target);
        return new(DeviceTargetSelectionOutcome.Ready, directory.Head,
            [new DeviceDeliveryTarget(directory.Head.AccountId, directory.Head.AccountGeneration, target)], target);
    }

    public static DeviceTargetSelectionOutcome Revalidate(DeviceFanoutPlan plan, DeviceDirectoryState current)
    {
        ArgumentNullException.ThrowIfNull(plan); ArgumentNullException.ThrowIfNull(current);
        if (current.ForkLatched) return DeviceTargetSelectionOutcome.ForkLatched;
        if (!plan.AccountId.Equals(current.Head.AccountId) || plan.AccountGeneration != current.Head.AccountGeneration)
            return DeviceTargetSelectionOutcome.StaleDirectory;
        if (plan.Targets.Any(x => x.AccountGeneration != current.Head.AccountGeneration
                || current.IsLocallyRevoked(x.DeviceId) || !current.Head.Contains(x.DeviceId))
            || (plan.RequestedTarget is not null && current.IsLocallyRevoked(plan.RequestedTarget)))
            return DeviceTargetSelectionOutcome.RevokedTarget;
        return plan.DirectoryHash.Equals(current.Head.DirectoryHash) ? plan.Outcome : DeviceTargetSelectionOutcome.DirectoryAdvanced;
    }

    private static DeviceTargetSelectionOutcome Preflight(DeviceDirectoryState directory, DeviceDirectoryObservation? observed)
    {
        if (directory.ForkLatched) return DeviceTargetSelectionOutcome.ForkLatched;
        if (observed is null) return DeviceTargetSelectionOutcome.Ready;
        if (!observed.AccountId.Equals(directory.Head.AccountId) || observed.AccountGeneration != directory.Head.AccountGeneration
            || observed.Generation > directory.Head.DirectoryGeneration) return DeviceTargetSelectionOutcome.StaleDirectory;
        if (observed.Generation == directory.Head.DirectoryGeneration && !observed.Hash.Equals(directory.Head.DirectoryHash))
            return DeviceTargetSelectionOutcome.ForkLatched;
        return DeviceTargetSelectionOutcome.Ready;
    }
}
