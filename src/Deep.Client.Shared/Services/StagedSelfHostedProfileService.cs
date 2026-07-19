using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
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

    internal byte[] CopyValue() => value.ToArray();

    public bool Equals(StagedSelfHostedProfileOpaqueValue? other) =>
        other is not null
        && other.GetType() == GetType()
        && CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) =>
        Equals(obj as StagedSelfHostedProfileOpaqueValue);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(GetType());
        hash.AddBytes(value);
        return hash.ToHashCode();
    }

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

    public byte[] ToArray() => CopyValue();
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
        int candidateByteLength,
        string? displayHint)
    {
        Id = StagedSelfHostedProfileCandidateId.FromBytes(id.Value);
        SchemaVersion = schemaVersion;
        CandidateByteLength = candidateByteLength;
        DisplayHint = displayHint;
    }

    public StagedSelfHostedProfileCandidateId Id { get; }

    public int SchemaVersion { get; }

    public int CandidateByteLength { get; }

    public string? DisplayHint { get; }

    public bool Equals(StagedSelfHostedProfileCandidate? other) =>
        other is not null
        && Id.Equals(other.Id)
        && SchemaVersion == other.SchemaVersion
        && CandidateByteLength == other.CandidateByteLength
        && string.Equals(DisplayHint, other.DisplayHint, StringComparison.Ordinal);

    public override bool Equals(object? obj) =>
        Equals(obj as StagedSelfHostedProfileCandidate);

    public override int GetHashCode() =>
        HashCode.Combine(Id, SchemaVersion, CandidateByteLength, DisplayHint);

    public override string ToString() => "[staged-unverified-self-hosted-profile-candidate]";
}

public enum StagedSelfHostedProfileSaveResult
{
    Saved,
    Idempotent,
    InvalidCandidate,
    CapacityExceeded,
    Corrupt
}

public enum StagedSelfHostedProfileListResult
{
    Success,
    Corrupt
}

public enum StagedSelfHostedProfileReadResult
{
    Missing,
    Found,
    Corrupt
}

public enum StagedSelfHostedProfileExportResult
{
    Missing,
    Exported,
    Corrupt
}

public enum StagedSelfHostedProfileDeleteResult
{
    Missing,
    Deleted,
    Corrupt
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
        byte[]? candidateBytes = null)
    {
        Result = result;
        this.candidateBytes = candidateBytes?.ToArray() ?? [];
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

public sealed class StagedSelfHostedProfileService
{
    private const string SettingsPrefix = "account.self-hosted-staging.v1.";
    private static ReadOnlySpan<byte> SettingsScopeDomain =>
        "deep.staged-self-hosted-profile.settings-scope/v1"u8;
    private readonly ISettingsRepository settings;
    private readonly SemaphoreSlim mutationGate = new(1, 1);

    public StagedSelfHostedProfileService(ISettingsRepository settings)
    {
        this.settings = settings ?? throw new ArgumentNullException(nameof(settings));
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

        var candidateBytes = canonicalEnvelopeCandidate.ToArray();
        if (schemaVersion != StagedSelfHostedProfileLimits.SchemaVersion
            || candidateBytes.Length is 0
                or > StagedSelfHostedProfileLimits.MaxCandidateBytes
            || !TryNormalizeDisplayHint(displayHint, out var normalizedHint))
        {
            return new(StagedSelfHostedProfileSaveResult.InvalidCandidate);
        }

        var fingerprint = SHA256.HashData(candidateBytes);
        await mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var loaded = await LoadCatalogAsync(accountScope, cancellationToken).ConfigureAwait(false);
            if (loaded.Result == CatalogLoadResult.Corrupt)
            {
                return new(StagedSelfHostedProfileSaveResult.Corrupt);
            }

            var catalog = loaded.Catalog;
            var duplicate = catalog.Items.SingleOrDefault(item =>
                CryptographicOperations.FixedTimeEquals(item.Fingerprint, fingerprint)
                && item.CandidateBytes.AsSpan().SequenceEqual(candidateBytes));
            if (duplicate is not null)
            {
                return new(
                    StagedSelfHostedProfileSaveResult.Idempotent,
                    ToCandidate(duplicate));
            }

            if (catalog.Items.Count >= StagedSelfHostedProfileLimits.MaxCandidatesPerAccount
                || catalog.Items.Sum(static item => item.CandidateBytes.Length)
                    + candidateBytes.Length
                    > StagedSelfHostedProfileLimits.MaxAccountCandidateBytes)
            {
                return new(StagedSelfHostedProfileSaveResult.CapacityExceeded);
            }

            var item = new CatalogItem
            {
                Id = CreateCandidateId(catalog.Items),
                Fingerprint = fingerprint,
                CandidateBytes = candidateBytes,
                DisplayHint = normalizedHint
            };
            catalog.Items.Add(item);
            SortItems(catalog.Items);
            await PersistCatalogAsync(accountScope, catalog, cancellationToken).ConfigureAwait(false);
            return new(StagedSelfHostedProfileSaveResult.Saved, ToCandidate(item));
        }
        finally
        {
            mutationGate.Release();
        }
    }

    public async Task<StagedSelfHostedProfileListOutcome> ListAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        cancellationToken.ThrowIfCancellationRequested();
        await mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var loaded = await LoadCatalogAsync(accountScope, cancellationToken).ConfigureAwait(false);
            if (loaded.Result == CatalogLoadResult.Corrupt)
            {
                return new(StagedSelfHostedProfileListResult.Corrupt);
            }

            var candidates = loaded.Catalog.Items
                .Select(ToCandidate)
                .ToArray();
            return new(
                StagedSelfHostedProfileListResult.Success,
                Array.AsReadOnly(candidates));
        }
        finally
        {
            mutationGate.Release();
        }
    }

    public async Task<StagedSelfHostedProfileReadOutcome> ReadAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        StagedSelfHostedProfileCandidateId candidateId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(candidateId);
        cancellationToken.ThrowIfCancellationRequested();
        await mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var loaded = await LoadCatalogAsync(accountScope, cancellationToken).ConfigureAwait(false);
            if (loaded.Result == CatalogLoadResult.Corrupt)
            {
                return new(StagedSelfHostedProfileReadResult.Corrupt);
            }

            var item = FindById(loaded.Catalog.Items, candidateId);
            return item is null
                ? new(StagedSelfHostedProfileReadResult.Missing)
                : new(StagedSelfHostedProfileReadResult.Found, ToCandidate(item));
        }
        finally
        {
            mutationGate.Release();
        }
    }

    public async Task<StagedSelfHostedProfileExportOutcome> ExportAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        StagedSelfHostedProfileCandidateId candidateId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(candidateId);
        cancellationToken.ThrowIfCancellationRequested();
        await mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var loaded = await LoadCatalogAsync(accountScope, cancellationToken).ConfigureAwait(false);
            if (loaded.Result == CatalogLoadResult.Corrupt)
            {
                return new(StagedSelfHostedProfileExportResult.Corrupt);
            }

            var item = FindById(loaded.Catalog.Items, candidateId);
            return item is null
                ? new(StagedSelfHostedProfileExportResult.Missing)
                : new(
                    StagedSelfHostedProfileExportResult.Exported,
                    item.CandidateBytes);
        }
        finally
        {
            mutationGate.Release();
        }
    }

    public async Task<StagedSelfHostedProfileDeleteResult> DeleteAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        StagedSelfHostedProfileCandidateId candidateId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(candidateId);
        cancellationToken.ThrowIfCancellationRequested();
        await mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var loaded = await LoadCatalogAsync(accountScope, cancellationToken).ConfigureAwait(false);
            if (loaded.Result == CatalogLoadResult.Corrupt)
            {
                return StagedSelfHostedProfileDeleteResult.Corrupt;
            }

            var item = FindById(loaded.Catalog.Items, candidateId);
            if (item is null)
            {
                return StagedSelfHostedProfileDeleteResult.Missing;
            }

            loaded.Catalog.Items.Remove(item);
            await PersistCatalogAsync(
                accountScope,
                loaded.Catalog,
                cancellationToken).ConfigureAwait(false);
            return StagedSelfHostedProfileDeleteResult.Deleted;
        }
        finally
        {
            mutationGate.Release();
        }
    }

    private async Task<CatalogLoadOutcome> LoadCatalogAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        CancellationToken cancellationToken)
    {
        Catalog? catalog;
        try
        {
            catalog = await settings.GetAsync<Catalog>(
                SettingsKey(accountScope),
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return CatalogLoadOutcome.Corrupt();
        }

        if (catalog is null)
        {
            return CatalogLoadOutcome.Valid(new Catalog());
        }

        return ValidateCatalog(catalog)
            ? CatalogLoadOutcome.Valid(catalog)
            : CatalogLoadOutcome.Corrupt();
    }

    private async Task PersistCatalogAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        Catalog catalog,
        CancellationToken cancellationToken)
    {
        try
        {
            if (catalog.Items.Count == 0)
            {
                await settings.DeleteAsync(
                    SettingsKey(accountScope),
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await settings.SetAsync(
                    SettingsKey(accountScope),
                    catalog,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            throw new StagedSelfHostedProfilePersistenceException();
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
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        try
        {
            normalized = value.Normalize(NormalizationForm.FormC);
        }
        catch (ArgumentException)
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

        if (Encoding.UTF8.GetByteCount(normalized)
            > StagedSelfHostedProfileLimits.MaxDisplayHintUtf8Bytes)
        {
            normalized = null;
            return false;
        }

        return true;
    }

    private static byte[] CreateCandidateId(IReadOnlyList<CatalogItem> items)
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var value = RandomNumberGenerator.GetBytes(
                StagedSelfHostedProfileLimits.CandidateIdBytes);
            if (value.AsSpan().IndexOfAnyExcept((byte)0) >= 0
                && items.All(item => !item.Id.AsSpan().SequenceEqual(value)))
            {
                return value;
            }
        }

        throw new StagedSelfHostedProfilePersistenceException();
    }

    private static CatalogItem? FindById(
        IReadOnlyList<CatalogItem> items,
        StagedSelfHostedProfileCandidateId candidateId) =>
        items.SingleOrDefault(item =>
            CryptographicOperations.FixedTimeEquals(item.Id, candidateId.Value));

    private static StagedSelfHostedProfileCandidate ToCandidate(CatalogItem item) =>
        new(
            StagedSelfHostedProfileCandidateId.FromBytes(item.Id),
            StagedSelfHostedProfileLimits.SchemaVersion,
            item.CandidateBytes.Length,
            item.DisplayHint);

    private static void SortItems(List<CatalogItem> items) =>
        items.Sort(static (left, right) =>
            left.Id.AsSpan().SequenceCompareTo(right.Id));

    private static string SettingsKey(
        SelfHostedProfileStagingAccountScope accountScope)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(SettingsScopeDomain);
        hash.AppendData(accountScope.Value);
        return SettingsPrefix + Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private enum CatalogLoadResult
    {
        Valid,
        Corrupt
    }

    private sealed class CatalogLoadOutcome
    {
        private CatalogLoadOutcome(CatalogLoadResult result, Catalog catalog)
        {
            Result = result;
            Catalog = catalog;
        }

        public CatalogLoadResult Result { get; }

        public Catalog Catalog { get; }

        public static CatalogLoadOutcome Valid(Catalog catalog) =>
            new(CatalogLoadResult.Valid, catalog);

        public static CatalogLoadOutcome Corrupt() =>
            new(CatalogLoadResult.Corrupt, new Catalog());
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
