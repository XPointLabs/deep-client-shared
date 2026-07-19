using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

public static class StagedSelfHostedProfileLimits
{
    public const int SchemaVersion = 1;
    public const int AccountScopeBytes = 32;
    public const int CandidateIdBytes = 16;
    public const int FingerprintBytes = 32;
    public const int MaxCandidatesPerAccount = 16;
    public const int MaxCandidateBytes = 64 * 1024;
    public const int MaxAccountCandidateBytes = 512 * 1024;
    public const int MaxDisplayHintUtf8Bytes = 64;
    public const int MaxDisplayHintCharacters = 256;
    internal const int MaximumCasAttempts = 16;
}

public abstract class StagedSelfHostedProfileOpaqueValue :
    IEquatable<StagedSelfHostedProfileOpaqueValue>
{
    private readonly byte[] value;
    private readonly string redactedName;

    private protected StagedSelfHostedProfileOpaqueValue(
        ReadOnlySpan<byte> value,
        int requiredLength,
        string redactedName)
    {
        if (value.Length != requiredLength)
        {
            throw new ArgumentException("Opaque staging value has an invalid length.", nameof(value));
        }
        if (value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("Opaque staging value must not be all zero.", nameof(value));
        }

        this.value = value.ToArray();
        this.redactedName = redactedName;
    }

    internal ReadOnlySpan<byte> Value => value;

    public bool Equals(StagedSelfHostedProfileOpaqueValue? other) =>
        other is not null
        && other.GetType() == GetType()
        && CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) =>
        Equals(obj as StagedSelfHostedProfileOpaqueValue);

    public override int GetHashCode() => GetType().GetHashCode();

    public override string ToString() => $"[opaque-{redactedName}]";
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class SelfHostedProfileStagingAccountScope :
    StagedSelfHostedProfileOpaqueValue
{
    private SelfHostedProfileStagingAccountScope(ReadOnlySpan<byte> value)
        : base(
            value,
            StagedSelfHostedProfileLimits.AccountScopeBytes,
            "self-hosted-staging-account-scope")
    {
    }

    public static SelfHostedProfileStagingAccountScope FromBytes(ReadOnlySpan<byte> value) =>
        new(value);
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class StagedSelfHostedProfileCandidateId :
    StagedSelfHostedProfileOpaqueValue
{
    private StagedSelfHostedProfileCandidateId(ReadOnlySpan<byte> value)
        : base(
            value,
            StagedSelfHostedProfileLimits.CandidateIdBytes,
            "staged-self-hosted-profile-candidate")
    {
    }

    internal static StagedSelfHostedProfileCandidateId FromBytes(ReadOnlySpan<byte> value) =>
        new(value);
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class StagedSelfHostedProfileCandidate :
    IEquatable<StagedSelfHostedProfileCandidate>
{
    internal StagedSelfHostedProfileCandidate(
        StagedSelfHostedProfileCandidateId id,
        int schemaVersion,
        int candidateByteLength)
    {
        Id = StagedSelfHostedProfileCandidateId.FromBytes(id.Value);
        SchemaVersion = schemaVersion;
        CandidateByteLength = candidateByteLength;
    }

    public StagedSelfHostedProfileCandidateId Id { get; }

    public int SchemaVersion { get; }

    public int CandidateByteLength { get; }

    public bool Equals(StagedSelfHostedProfileCandidate? other) =>
        other is not null
        && Id.Equals(other.Id)
        && SchemaVersion == other.SchemaVersion
        && CandidateByteLength == other.CandidateByteLength;

    public override bool Equals(object? obj) =>
        Equals(obj as StagedSelfHostedProfileCandidate);

    public override int GetHashCode() => typeof(StagedSelfHostedProfileCandidate).GetHashCode();

    public override string ToString() => "[staged-unverified-self-hosted-profile-candidate]";
}

public enum StagedSelfHostedProfileSaveResult
{
    Saved,
    Idempotent,
    InvalidCandidate,
    CapacityExceeded,
    Corrupt,
    DependencyFailure,
    OutcomeUnknown
}

public enum StagedSelfHostedProfileListResult
{
    Success,
    Corrupt,
    DependencyFailure
}

public enum StagedSelfHostedProfileReadResult
{
    Missing,
    Found,
    Corrupt,
    DependencyFailure
}

public enum StagedSelfHostedProfileExportResult
{
    Missing,
    Exported,
    Corrupt,
    DependencyFailure
}

public enum StagedSelfHostedProfileDeleteResult
{
    Missing,
    Deleted,
    Corrupt,
    DependencyFailure,
    OutcomeUnknown
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class StagedSelfHostedProfileSaveOutcome
{
    internal StagedSelfHostedProfileSaveOutcome(
        StagedSelfHostedProfileSaveResult result,
        StagedSelfHostedProfileCandidate? candidate = null)
    {
        Result = result;
        Candidate = candidate;
    }

    public StagedSelfHostedProfileSaveResult Result { get; }

    public StagedSelfHostedProfileCandidate? Candidate { get; }

    public override string ToString() => "[staged-self-hosted-profile-save-outcome]";
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class StagedSelfHostedProfileListOutcome
{
    internal StagedSelfHostedProfileListOutcome(
        StagedSelfHostedProfileListResult result,
        IReadOnlyList<StagedSelfHostedProfileCandidate>? candidates = null)
    {
        Result = result;
        Candidates = candidates ?? Array.Empty<StagedSelfHostedProfileCandidate>();
    }

    public StagedSelfHostedProfileListResult Result { get; }

    public IReadOnlyList<StagedSelfHostedProfileCandidate> Candidates { get; }

    public override string ToString() => "[staged-self-hosted-profile-list-outcome]";
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class StagedSelfHostedProfileReadOutcome
{
    internal StagedSelfHostedProfileReadOutcome(
        StagedSelfHostedProfileReadResult result,
        StagedSelfHostedProfileCandidate? candidate = null)
    {
        Result = result;
        Candidate = candidate;
    }

    public StagedSelfHostedProfileReadResult Result { get; }

    public StagedSelfHostedProfileCandidate? Candidate { get; }

    public override string ToString() => "[staged-self-hosted-profile-read-outcome]";
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class StagedSelfHostedProfileExportOutcome
{
    private readonly byte[] candidateBytes;

    internal StagedSelfHostedProfileExportOutcome(
        StagedSelfHostedProfileExportResult result,
        ReadOnlySpan<byte> candidateBytes = default)
    {
        Result = result;
        this.candidateBytes = candidateBytes.ToArray();
    }

    public StagedSelfHostedProfileExportResult Result { get; }

    public byte[] GetCandidateBytesCopy() => candidateBytes.ToArray();

    public override string ToString() => "[staged-self-hosted-profile-export-outcome]";
}

public sealed class StagedSelfHostedProfilePersistenceException : IOException
{
    public StagedSelfHostedProfilePersistenceException()
        : base("Staged self-hosted profile persistence failed.")
    {
    }
}

internal interface IStagedSelfHostedProfileProviders
{
    byte[] CreateCandidateId();

    byte[] ComputeFingerprint(ReadOnlySpan<byte> value);
}

internal sealed class SystemStagedSelfHostedProfileProviders :
    IStagedSelfHostedProfileProviders
{
    public byte[] CreateCandidateId() =>
        RandomNumberGenerator.GetBytes(StagedSelfHostedProfileLimits.CandidateIdBytes);

    public byte[] ComputeFingerprint(ReadOnlySpan<byte> value) =>
        SHA256.HashData(value);
}

/// <summary>
/// Stores bounded opaque profile candidates as staged and unverified local data.
/// This boundary is non-activating: it does not parse, verify, select, or connect a profile.
/// </summary>
public sealed class StagedSelfHostedProfileService
{
    private const string SettingsPrefix = "account.self-hosted-staging.v1.";
    private static ReadOnlySpan<byte> SettingsScopeDomain =>
        "deep.staged-self-hosted-profile.settings-scope/v1"u8;
    private readonly IAtomicBoundedSettingsRepository settings;
    private readonly IStagedSelfHostedProfileProviders providers;

    public StagedSelfHostedProfileService(IAtomicBoundedSettingsRepository settings)
        : this(settings, new SystemStagedSelfHostedProfileProviders())
    {
    }

    internal StagedSelfHostedProfileService(
        IAtomicBoundedSettingsRepository settings,
        IStagedSelfHostedProfileProviders providers)
    {
        this.settings = settings ?? throw new ArgumentNullException(nameof(settings));
        this.providers = providers ?? throw new ArgumentNullException(nameof(providers));
    }

    public async Task<StagedSelfHostedProfileSaveOutcome> SaveAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        int schemaVersion,
        ReadOnlyMemory<byte> canonicalEnvelopeCandidate,
        string? displayHint = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        cancellationToken.ThrowIfCancellationRequested();
        if (schemaVersion != StagedSelfHostedProfileLimits.SchemaVersion
            || canonicalEnvelopeCandidate.Length is 0
                or > StagedSelfHostedProfileLimits.MaxCandidateBytes
            || displayHint?.Length > StagedSelfHostedProfileLimits.MaxDisplayHintCharacters
            || !TryNormalizeDisplayHint(displayHint, out var normalizedHint))
        {
            return new(StagedSelfHostedProfileSaveResult.InvalidCandidate);
        }

        byte[] candidateBytes;
        byte[] fingerprint;
        byte[] candidateId;
        string key;
        try
        {
            candidateBytes = canonicalEnvelopeCandidate.ToArray();
            fingerprint = providers.ComputeFingerprint(candidateBytes);
            candidateId = providers.CreateCandidateId();
            key = SettingsKey(accountScope);
            if (fingerprint.Length != StagedSelfHostedProfileLimits.FingerprintBytes
                || candidateId.Length != StagedSelfHostedProfileLimits.CandidateIdBytes
                || candidateId.AsSpan().IndexOfAnyExcept((byte)0) < 0
                || key.Length != SettingsPrefix.Length
                    + StagedSelfHostedProfileLimits.FingerprintBytes * 2)
            {
                return new(StagedSelfHostedProfileSaveResult.DependencyFailure);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw SanitizedCancellation(cancellationToken);
        }
        catch
        {
            return new(StagedSelfHostedProfileSaveResult.DependencyFailure);
        }

        var observedExistingCatalog = false;
        for (var attempt = 0;
             attempt < StagedSelfHostedProfileLimits.MaximumCasAttempts;
             attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var loaded = await LoadCatalogAsync(key, cancellationToken).ConfigureAwait(false);
            if (loaded.Result == CatalogLoadResult.DependencyFailure)
            {
                return new(StagedSelfHostedProfileSaveResult.DependencyFailure);
            }
            if (loaded.Result == CatalogLoadResult.Corrupt)
            {
                return new(StagedSelfHostedProfileSaveResult.Corrupt);
            }
            if (loaded.Revision is not null)
            {
                observedExistingCatalog = true;
            }
            else if (observedExistingCatalog)
            {
                return new(StagedSelfHostedProfileSaveResult.OutcomeUnknown);
            }

            var duplicate = loaded.Catalog.Items.SingleOrDefault(item =>
                CryptographicOperations.FixedTimeEquals(item.Fingerprint, fingerprint)
                && item.CandidateBytes.AsSpan().SequenceEqual(candidateBytes));
            if (duplicate is not null)
            {
                return new(
                    StagedSelfHostedProfileSaveResult.Idempotent,
                    ToCandidate(duplicate));
            }
            if (loaded.Catalog.Items.Count
                    >= StagedSelfHostedProfileLimits.MaxCandidatesPerAccount
                || loaded.Catalog.Items.Sum(static item => item.CandidateBytes.Length)
                    + candidateBytes.Length
                    > StagedSelfHostedProfileLimits.MaxAccountCandidateBytes)
            {
                return new(StagedSelfHostedProfileSaveResult.CapacityExceeded);
            }
            if (loaded.Catalog.Items.Any(item => item.Id.AsSpan().SequenceEqual(candidateId)))
            {
                try
                {
                    candidateId = providers.CreateCandidateId();
                }
                catch (OperationCanceledException) when (
                    cancellationToken.IsCancellationRequested)
                {
                    throw SanitizedCancellation(cancellationToken);
                }
                catch
                {
                    return new(StagedSelfHostedProfileSaveResult.DependencyFailure);
                }
                if (candidateId.Length != StagedSelfHostedProfileLimits.CandidateIdBytes
                    || candidateId.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                {
                    return new(StagedSelfHostedProfileSaveResult.DependencyFailure);
                }
                continue;
            }

            var item = new CatalogItem
            {
                Id = candidateId.ToArray(),
                Fingerprint = fingerprint.ToArray(),
                CandidateBytes = candidateBytes.ToArray(),
                DisplayHint = normalizedHint
            };
            loaded.Catalog.Items.Add(item);
            SortItems(loaded.Catalog.Items);
            if (!TrySerializeCatalog(loaded.Catalog, out var serialized))
            {
                return new(StagedSelfHostedProfileSaveResult.Corrupt);
            }

            var mutation = await MutateSaveCatalogAsync(
                key,
                loaded.Revision,
                serialized,
                cancellationToken).ConfigureAwait(false);
            switch (mutation)
            {
                case AtomicBoundedSettingMutationResult.Applied:
                    return new(StagedSelfHostedProfileSaveResult.Saved, ToCandidate(item));
                case AtomicBoundedSettingMutationResult.Conflict:
                    continue;
                case AtomicBoundedSettingMutationResult.Missing:
                    observedExistingCatalog = true;
                    continue;
                case AtomicBoundedSettingMutationResult.DependencyFailure:
                    return new(StagedSelfHostedProfileSaveResult.DependencyFailure);
                case AtomicBoundedSettingMutationResult.TooLarge:
                    return new(StagedSelfHostedProfileSaveResult.Corrupt);
                case AtomicBoundedSettingMutationResult.OutcomeUnknown:
                    return await ReconcileSaveAsync(
                        key,
                        item,
                        cancellationToken).ConfigureAwait(false);
            }
        }

        return new(StagedSelfHostedProfileSaveResult.OutcomeUnknown);
    }

    public async Task<StagedSelfHostedProfileListOutcome> ListAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        cancellationToken.ThrowIfCancellationRequested();
        if (!TrySettingsKey(accountScope, cancellationToken, out var key))
        {
            return new(StagedSelfHostedProfileListResult.DependencyFailure);
        }
        var loaded = await LoadCatalogAsync(key, cancellationToken).ConfigureAwait(false);
        if (loaded.Result == CatalogLoadResult.DependencyFailure)
        {
            return new(StagedSelfHostedProfileListResult.DependencyFailure);
        }
        if (loaded.Result == CatalogLoadResult.Corrupt)
        {
            return new(StagedSelfHostedProfileListResult.Corrupt);
        }

        return new(
            StagedSelfHostedProfileListResult.Success,
            Array.AsReadOnly(loaded.Catalog.Items.Select(ToCandidate).ToArray()));
    }

    public async Task<StagedSelfHostedProfileReadOutcome> ReadAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        StagedSelfHostedProfileCandidateId candidateId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(candidateId);
        cancellationToken.ThrowIfCancellationRequested();
        if (!TrySettingsKey(accountScope, cancellationToken, out var key))
        {
            return new(StagedSelfHostedProfileReadResult.DependencyFailure);
        }
        var loaded = await LoadCatalogAsync(key, cancellationToken).ConfigureAwait(false);
        if (loaded.Result == CatalogLoadResult.DependencyFailure)
        {
            return new(StagedSelfHostedProfileReadResult.DependencyFailure);
        }
        if (loaded.Result == CatalogLoadResult.Corrupt)
        {
            return new(StagedSelfHostedProfileReadResult.Corrupt);
        }
        var item = FindById(loaded.Catalog.Items, candidateId);
        return item is null
            ? new(StagedSelfHostedProfileReadResult.Missing)
            : new(StagedSelfHostedProfileReadResult.Found, ToCandidate(item));
    }

    public async Task<StagedSelfHostedProfileExportOutcome> ExportAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        StagedSelfHostedProfileCandidateId candidateId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(candidateId);
        cancellationToken.ThrowIfCancellationRequested();
        if (!TrySettingsKey(accountScope, cancellationToken, out var key))
        {
            return new(StagedSelfHostedProfileExportResult.DependencyFailure);
        }
        var loaded = await LoadCatalogAsync(key, cancellationToken).ConfigureAwait(false);
        if (loaded.Result == CatalogLoadResult.DependencyFailure)
        {
            return new(StagedSelfHostedProfileExportResult.DependencyFailure);
        }
        if (loaded.Result == CatalogLoadResult.Corrupt)
        {
            return new(StagedSelfHostedProfileExportResult.Corrupt);
        }
        var item = FindById(loaded.Catalog.Items, candidateId);
        return item is null
            ? new(StagedSelfHostedProfileExportResult.Missing)
            : new(StagedSelfHostedProfileExportResult.Exported, item.CandidateBytes);
    }

    public async Task<StagedSelfHostedProfileDeleteResult> DeleteAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        StagedSelfHostedProfileCandidateId candidateId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(candidateId);
        cancellationToken.ThrowIfCancellationRequested();
        if (!TrySettingsKey(accountScope, cancellationToken, out var key))
        {
            return StagedSelfHostedProfileDeleteResult.DependencyFailure;
        }

        for (var attempt = 0;
             attempt < StagedSelfHostedProfileLimits.MaximumCasAttempts;
             attempt++)
        {
            var loaded = await LoadCatalogAsync(key, cancellationToken).ConfigureAwait(false);
            if (loaded.Result == CatalogLoadResult.DependencyFailure)
            {
                return StagedSelfHostedProfileDeleteResult.DependencyFailure;
            }
            if (loaded.Result == CatalogLoadResult.Corrupt)
            {
                return StagedSelfHostedProfileDeleteResult.Corrupt;
            }
            if (loaded.Revision is null)
            {
                return StagedSelfHostedProfileDeleteResult.Missing;
            }
            var item = FindById(loaded.Catalog.Items, candidateId);
            if (item is null)
            {
                return StagedSelfHostedProfileDeleteResult.Missing;
            }

            loaded.Catalog.Items.Remove(item);
            AtomicBoundedSettingMutationResult mutation;
            if (loaded.Catalog.Items.Count == 0)
            {
                mutation = await DeleteCatalogAsync(
                    key,
                    loaded.Revision,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                if (!TrySerializeCatalog(loaded.Catalog, out var serialized))
                {
                    return StagedSelfHostedProfileDeleteResult.Corrupt;
                }
                mutation = await ReplaceCatalogAsync(
                    key,
                    loaded.Revision,
                    serialized,
                    cancellationToken).ConfigureAwait(false);
            }

            switch (mutation)
            {
                case AtomicBoundedSettingMutationResult.Applied:
                    return StagedSelfHostedProfileDeleteResult.Deleted;
                case AtomicBoundedSettingMutationResult.Conflict:
                    continue;
                case AtomicBoundedSettingMutationResult.Missing:
                    return StagedSelfHostedProfileDeleteResult.Deleted;
                case AtomicBoundedSettingMutationResult.DependencyFailure:
                    return StagedSelfHostedProfileDeleteResult.DependencyFailure;
                case AtomicBoundedSettingMutationResult.TooLarge:
                    return StagedSelfHostedProfileDeleteResult.Corrupt;
                case AtomicBoundedSettingMutationResult.OutcomeUnknown:
                    return await ReconcileDeleteAsync(
                        key,
                        candidateId,
                        cancellationToken).ConfigureAwait(false);
            }
        }

        return StagedSelfHostedProfileDeleteResult.OutcomeUnknown;
    }

    private async Task<AtomicBoundedSettingMutationResult> MutateSaveCatalogAsync(
        string key,
        AtomicBoundedSettingRevision? revision,
        ReadOnlyMemory<byte> serialized,
        CancellationToken cancellationToken)
    {
        try
        {
            return revision is null
                ? await settings.CreateAtomicBoundedSettingAsync(
                    key,
                    serialized,
                    AtomicBoundedSettingsLimits.MaximumValueUtf8Bytes,
                    cancellationToken).ConfigureAwait(false)
                : await settings.ReplaceAtomicBoundedSettingAsync(
                    key,
                    revision,
                    serialized,
                    AtomicBoundedSettingsLimits.MaximumValueUtf8Bytes,
                    cancellationToken).ConfigureAwait(false);
        }
        catch (AccountGenerationMutationCanceledException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw SanitizedCancellation(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return AtomicBoundedSettingMutationResult.OutcomeUnknown;
        }
        catch
        {
            return AtomicBoundedSettingMutationResult.DependencyFailure;
        }
    }

    private async Task<AtomicBoundedSettingMutationResult> ReplaceCatalogAsync(
        string key,
        AtomicBoundedSettingRevision revision,
        ReadOnlyMemory<byte> serialized,
        CancellationToken cancellationToken)
    {
        try
        {
            return await settings.ReplaceAtomicBoundedSettingAsync(
                key,
                revision,
                serialized,
                AtomicBoundedSettingsLimits.MaximumValueUtf8Bytes,
                cancellationToken).ConfigureAwait(false);
        }
        catch (AccountGenerationMutationCanceledException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw SanitizedCancellation(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return AtomicBoundedSettingMutationResult.OutcomeUnknown;
        }
        catch
        {
            return AtomicBoundedSettingMutationResult.DependencyFailure;
        }
    }

    private async Task<AtomicBoundedSettingMutationResult> DeleteCatalogAsync(
        string key,
        AtomicBoundedSettingRevision revision,
        CancellationToken cancellationToken)
    {
        try
        {
            return await settings.DeleteAtomicBoundedSettingAsync(
                key,
                revision,
                AtomicBoundedSettingsLimits.MaximumValueUtf8Bytes,
                cancellationToken).ConfigureAwait(false);
        }
        catch (AccountGenerationMutationCanceledException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw SanitizedCancellation(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return AtomicBoundedSettingMutationResult.OutcomeUnknown;
        }
        catch
        {
            return AtomicBoundedSettingMutationResult.DependencyFailure;
        }
    }

    private async Task<StagedSelfHostedProfileSaveOutcome> ReconcileSaveAsync(
        string key,
        CatalogItem expected,
        CancellationToken cancellationToken)
    {
        var loaded = await LoadCatalogAsync(key, cancellationToken).ConfigureAwait(false);
        if (loaded.Result == CatalogLoadResult.DependencyFailure)
        {
            return new(StagedSelfHostedProfileSaveResult.OutcomeUnknown);
        }
        if (loaded.Result == CatalogLoadResult.Corrupt)
        {
            return new(StagedSelfHostedProfileSaveResult.Corrupt);
        }
        var applied = loaded.Catalog.Items.SingleOrDefault(item =>
            item.Id.AsSpan().SequenceEqual(expected.Id)
            && item.CandidateBytes.AsSpan().SequenceEqual(expected.CandidateBytes));
        return applied is null
            ? new(StagedSelfHostedProfileSaveResult.OutcomeUnknown)
            : new(StagedSelfHostedProfileSaveResult.Saved, ToCandidate(applied));
    }

    private async Task<StagedSelfHostedProfileDeleteResult> ReconcileDeleteAsync(
        string key,
        StagedSelfHostedProfileCandidateId candidateId,
        CancellationToken cancellationToken)
    {
        var loaded = await LoadCatalogAsync(key, cancellationToken).ConfigureAwait(false);
        if (loaded.Result == CatalogLoadResult.DependencyFailure)
        {
            return StagedSelfHostedProfileDeleteResult.OutcomeUnknown;
        }
        if (loaded.Result == CatalogLoadResult.Corrupt)
        {
            return StagedSelfHostedProfileDeleteResult.Corrupt;
        }
        return FindById(loaded.Catalog.Items, candidateId) is null
            ? StagedSelfHostedProfileDeleteResult.Deleted
            : StagedSelfHostedProfileDeleteResult.OutcomeUnknown;
    }

    private async Task<CatalogLoadOutcome> LoadCatalogAsync(
        string key,
        CancellationToken cancellationToken)
    {
        AtomicBoundedSettingReadOutcome read;
        try
        {
            read = await settings.ReadAtomicBoundedSettingAsync(
                key,
                AtomicBoundedSettingsLimits.MaximumValueUtf8Bytes,
                cancellationToken).ConfigureAwait(false);
        }
        catch (AccountGenerationMutationCanceledException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw SanitizedCancellation(cancellationToken);
        }
        catch
        {
            return CatalogLoadOutcome.DependencyFailure();
        }

        if (read.Result == AtomicBoundedSettingReadResult.Missing)
        {
            return CatalogLoadOutcome.Valid(new Catalog(), revision: null);
        }
        if (read.Result == AtomicBoundedSettingReadResult.DependencyFailure)
        {
            return CatalogLoadOutcome.DependencyFailure();
        }
        if (read.Result == AtomicBoundedSettingReadResult.Oversized
            || read.Revision is null)
        {
            return CatalogLoadOutcome.Corrupt();
        }

        try
        {
            var catalog = JsonSerializer.Deserialize<Catalog>(read.GetValueCopy());
            return catalog is not null && ValidateCatalog(catalog)
                ? CatalogLoadOutcome.Valid(catalog, read.Revision)
                : CatalogLoadOutcome.Corrupt();
        }
        catch
        {
            return CatalogLoadOutcome.Corrupt();
        }
    }

    private static bool TrySerializeCatalog(Catalog catalog, out byte[] serialized)
    {
        serialized = [];
        try
        {
            serialized = JsonSerializer.SerializeToUtf8Bytes(catalog);
            return serialized.Length <= AtomicBoundedSettingsLimits.MaximumValueUtf8Bytes;
        }
        catch
        {
            serialized = [];
            return false;
        }
    }

    private static bool ValidateCatalog(Catalog catalog)
    {
        if (catalog.Version != StagedSelfHostedProfileLimits.SchemaVersion
            || catalog.Items is null
            || catalog.Items.Count > StagedSelfHostedProfileLimits.MaxCandidatesPerAccount)
        {
            return false;
        }

        long totalBytes = 0;
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var fingerprints = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in catalog.Items)
        {
            if (item is null
                || item.Id is null
                || item.Id.Length != StagedSelfHostedProfileLimits.CandidateIdBytes
                || item.Id.AsSpan().IndexOfAnyExcept((byte)0) < 0
                || item.Fingerprint is null
                || item.Fingerprint.Length != StagedSelfHostedProfileLimits.FingerprintBytes
                || item.CandidateBytes is null
                || item.CandidateBytes.Length is 0
                    or > StagedSelfHostedProfileLimits.MaxCandidateBytes
                || item.DisplayHint?.Length
                    > StagedSelfHostedProfileLimits.MaxDisplayHintCharacters
                || !TryNormalizeDisplayHint(item.DisplayHint, out var normalizedHint)
                || !string.Equals(item.DisplayHint, normalizedHint, StringComparison.Ordinal)
                || !CryptographicOperations.FixedTimeEquals(
                    item.Fingerprint,
                    SHA256.HashData(item.CandidateBytes))
                || !ids.Add(Convert.ToHexString(item.Id))
                || !fingerprints.Add(Convert.ToHexString(item.Fingerprint)))
            {
                return false;
            }

            totalBytes += item.CandidateBytes.Length;
            if (totalBytes > StagedSelfHostedProfileLimits.MaxAccountCandidateBytes)
            {
                return false;
            }
        }

        SortItems(catalog.Items);
        return true;
    }

    private static bool TryNormalizeDisplayHint(string? value, out string? normalized)
    {
        normalized = null;
        if (value is null)
        {
            return true;
        }
        if (value.Length > StagedSelfHostedProfileLimits.MaxDisplayHintCharacters
            || string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        try
        {
            normalized = value.Normalize(NormalizationForm.FormC);
        }
        catch
        {
            return false;
        }

        var remaining = normalized.AsSpan();
        while (!remaining.IsEmpty)
        {
            var status = Rune.DecodeFromUtf16(remaining, out var rune, out var consumed);
            if (status != OperationStatus.Done)
            {
                normalized = null;
                return false;
            }
            var category = Rune.GetUnicodeCategory(rune);
            if (category is UnicodeCategory.Control
                or UnicodeCategory.Format
                or UnicodeCategory.LineSeparator
                or UnicodeCategory.ParagraphSeparator)
            {
                normalized = null;
                return false;
            }
            remaining = remaining[consumed..];
        }

        try
        {
            if (Encoding.UTF8.GetByteCount(normalized)
                > StagedSelfHostedProfileLimits.MaxDisplayHintUtf8Bytes)
            {
                normalized = null;
                return false;
            }
        }
        catch
        {
            normalized = null;
            return false;
        }
        return true;
    }

    private string SettingsKey(SelfHostedProfileStagingAccountScope accountScope)
    {
        var material = new byte[SettingsScopeDomain.Length + accountScope.Value.Length];
        SettingsScopeDomain.CopyTo(material);
        accountScope.Value.CopyTo(material.AsSpan(SettingsScopeDomain.Length));
        return SettingsPrefix
            + Convert.ToHexStringLower(providers.ComputeFingerprint(material));
    }

    private bool TrySettingsKey(
        SelfHostedProfileStagingAccountScope accountScope,
        CancellationToken cancellationToken,
        out string key)
    {
        key = string.Empty;
        try
        {
            key = SettingsKey(accountScope);
            return key.Length == SettingsPrefix.Length
                + StagedSelfHostedProfileLimits.FingerprintBytes * 2;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw SanitizedCancellation(cancellationToken);
        }
        catch
        {
            key = string.Empty;
            return false;
        }
    }

    private static CatalogItem? FindById(
        IReadOnlyList<CatalogItem> items,
        StagedSelfHostedProfileCandidateId candidateId) =>
        items.SingleOrDefault(item =>
            CryptographicOperations.FixedTimeEquals(item.Id, candidateId.Value));

    private static OperationCanceledException SanitizedCancellation(
        CancellationToken cancellationToken) =>
        new(
            "Staged self-hosted profile operation was canceled.",
            cancellationToken);

    private static StagedSelfHostedProfileCandidate ToCandidate(CatalogItem item) =>
        new(
            StagedSelfHostedProfileCandidateId.FromBytes(item.Id),
            StagedSelfHostedProfileLimits.SchemaVersion,
            item.CandidateBytes.Length);

    private static void SortItems(List<CatalogItem> items) =>
        items.Sort(static (left, right) =>
            left.Id.AsSpan().SequenceCompareTo(right.Id));

    private enum CatalogLoadResult
    {
        Valid,
        Corrupt,
        DependencyFailure
    }

    private sealed class CatalogLoadOutcome
    {
        private CatalogLoadOutcome(
            CatalogLoadResult result,
            Catalog catalog,
            AtomicBoundedSettingRevision? revision)
        {
            Result = result;
            Catalog = catalog;
            Revision = revision;
        }

        public CatalogLoadResult Result { get; }

        public Catalog Catalog { get; }

        public AtomicBoundedSettingRevision? Revision { get; }

        public static CatalogLoadOutcome Valid(
            Catalog catalog,
            AtomicBoundedSettingRevision? revision) =>
            new(CatalogLoadResult.Valid, catalog, revision);

        public static CatalogLoadOutcome Corrupt() =>
            new(CatalogLoadResult.Corrupt, new Catalog(), null);

        public static CatalogLoadOutcome DependencyFailure() =>
            new(CatalogLoadResult.DependencyFailure, new Catalog(), null);
    }

    private sealed class Catalog
    {
        public int Version { get; set; } = StagedSelfHostedProfileLimits.SchemaVersion;

        public List<CatalogItem> Items { get; set; } = [];
    }

    private sealed class CatalogItem
    {
        public byte[] Id { get; set; } = [];

        public byte[] Fingerprint { get; set; } = [];

        public byte[] CandidateBytes { get; set; } = [];

        public string? DisplayHint { get; set; }
    }
}
