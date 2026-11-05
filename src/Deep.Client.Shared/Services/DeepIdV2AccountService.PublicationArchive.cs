using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Services;

/// <summary>Count-only local publication custody status. No authority or private original is released.</summary>
public sealed record DeepIdV2PublicationArchiveStatus(int WorkingEntries, int ArchivedEntries, int WorkingBytes,
    int ReservedWorkingBytes, int ArchivedBytes, bool CanReservePublication)
{
    /// <summary>Unchanged secure storage per-slot bound.</summary>
    public int MaximumWorkingBytes => ProtectedDid2ContactRouteJournal.MaximumBytes;
    /// <summary>Explicit publication archive aggregate bound, within the secure inventory quota.</summary>
    public int MaximumArchivedBytes => ProtectedDid2ContactRouteJournal.MaximumArchivedBytes;
    /// <summary>Combined working and archived intent bound.</summary>
    public int MaximumIntents => ProtectedDid2ContactRouteJournal.MaximumIntents;
}

public sealed partial class DeepIdV2AccountService
{
    /// <summary>Explicitly enrolls authenticated local publication custody without replacing the account or address.
    /// Completed permanent predecessors enter exact immutable protected custody atomically with the working root.</summary>
    public async Task<DeepIdV2PublicationArchiveStatus> EnrollPublicationArchiveAsync(CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        return await owner.EnrollPublicationArchiveAsync(TrustedUnixSeconds(), verifier, cancellationToken).ConfigureAwait(false);
    }
}
