using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Deep.Client.Shared.Persistence;

/// <summary>
/// Bounds account-generation JSON settings before they are copied or materialized and
/// provides optimistic compare-and-exchange without exposing storage revisions.
/// </summary>
public static class AtomicBoundedSettingsLimits
{
    public const int RevisionBytes = 16;
    public const int MaximumKeyCharacters = 256;
    public const int MaximumKeyUtf8Bytes = 512;
    public const int MaximumValueUtf8Bytes = 768 * 1024;
    internal const int EnvelopeOverheadBytes = 128;
}

public enum AtomicBoundedSettingReadResult
{
    Missing,
    Found,
    Oversized,
    DependencyFailure
}

public enum AtomicBoundedSettingMutationResult
{
    Applied,
    Conflict,
    Missing,
    TooLarge,
    DependencyFailure,
    OutcomeUnknown
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class AtomicBoundedSettingRevision :
    IEquatable<AtomicBoundedSettingRevision>
{
    private readonly byte[] value;

    private AtomicBoundedSettingRevision(ReadOnlySpan<byte> value)
    {
        if (value.Length != AtomicBoundedSettingsLimits.RevisionBytes
            || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("Opaque bounded-setting revision is invalid.", nameof(value));
        }

        this.value = value.ToArray();
    }

    internal ReadOnlySpan<byte> Value => value;

    internal static AtomicBoundedSettingRevision FromBytes(ReadOnlySpan<byte> value) =>
        new(value);

    public bool Equals(AtomicBoundedSettingRevision? other) =>
        other is not null
        && CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) =>
        Equals(obj as AtomicBoundedSettingRevision);

    public override int GetHashCode() => typeof(AtomicBoundedSettingRevision).GetHashCode();

    public override string ToString() => "[opaque-bounded-setting-revision]";
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class AtomicBoundedSettingReadOutcome
{
    private readonly byte[] value;

    internal AtomicBoundedSettingReadOutcome(
        AtomicBoundedSettingReadResult result,
        AtomicBoundedSettingRevision? revision = null,
        ReadOnlySpan<byte> value = default)
    {
        Result = result;
        Revision = revision is null
            ? null
            : AtomicBoundedSettingRevision.FromBytes(revision.Value);
        this.value = value.ToArray();
    }

    public AtomicBoundedSettingReadResult Result { get; }

    public AtomicBoundedSettingRevision? Revision { get; }

    public byte[] GetValueCopy() => value.ToArray();

    public override string ToString() => "[atomic-bounded-setting-read-outcome]";
}

public interface IAtomicBoundedSettingsRepository
{
    Task<AtomicBoundedSettingReadOutcome> ReadAtomicBoundedSettingAsync(
        string key,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default);

    Task<AtomicBoundedSettingMutationResult> CreateAtomicBoundedSettingAsync(
        string key,
        ReadOnlyMemory<byte> utf8Json,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default);

    Task<AtomicBoundedSettingMutationResult> ReplaceAtomicBoundedSettingAsync(
        string key,
        AtomicBoundedSettingRevision expectedRevision,
        ReadOnlyMemory<byte> utf8Json,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default);

    Task<AtomicBoundedSettingMutationResult> DeleteAtomicBoundedSettingAsync(
        string key,
        AtomicBoundedSettingRevision expectedRevision,
        int maximumValueUtf8Bytes,
        CancellationToken cancellationToken = default);
}

internal enum AtomicBoundedSettingsFaultPoint
{
    BeforeCommit,
    AfterMutationBeforePersistence,
    AfterCommit
}

internal enum AtomicBoundedEnvelopeReadResult
{
    Found,
    Oversized,
    Invalid
}

internal sealed class AtomicBoundedEnvelope
{
    public required byte[] Revision { get; init; }

    public required byte[] Value { get; init; }
}

internal static class AtomicBoundedSettingsEnvelope
{
    private const int Version = 1;
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public static bool IsValidKeyAndLimit(string? key, int maximumValueUtf8Bytes)
    {
        if (key is null
            || key.Length is 0 or > AtomicBoundedSettingsLimits.MaximumKeyCharacters
            || maximumValueUtf8Bytes is <= 0
                or > AtomicBoundedSettingsLimits.MaximumValueUtf8Bytes)
        {
            return false;
        }

        try
        {
            return StrictUtf8.GetByteCount(key)
                <= AtomicBoundedSettingsLimits.MaximumKeyUtf8Bytes;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    public static bool IsValidInput(
        string? key,
        ReadOnlyMemory<byte> utf8Json,
        int maximumValueUtf8Bytes)
    {
        if (!IsValidKeyAndLimit(key, maximumValueUtf8Bytes)
            || utf8Json.Length is 0
            || utf8Json.Length > maximumValueUtf8Bytes)
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(utf8Json);
            return document.RootElement.ValueKind is not JsonValueKind.Undefined;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    public static int MaximumStoredUtf8Bytes(int maximumValueUtf8Bytes) =>
        checked(((maximumValueUtf8Bytes + 2) / 3 * 4)
            + AtomicBoundedSettingsLimits.EnvelopeOverheadBytes);

    public static string Create(ReadOnlySpan<byte> revision, ReadOnlySpan<byte> value)
    {
        var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("version", Version);
            writer.WriteString("revision", Convert.ToHexStringLower(revision));
            writer.WriteBase64String("value", value);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length));
    }

    public static AtomicBoundedEnvelopeReadResult TryRead(
        string storedEnvelope,
        int maximumValueUtf8Bytes,
        out AtomicBoundedEnvelope? envelope)
    {
        envelope = null;
        if (storedEnvelope.Length
            > MaximumStoredUtf8Bytes(maximumValueUtf8Bytes))
        {
            return AtomicBoundedEnvelopeReadResult.Oversized;
        }

        int storedBytes;
        try
        {
            storedBytes = StrictUtf8.GetByteCount(storedEnvelope);
        }
        catch (ArgumentException)
        {
            return AtomicBoundedEnvelopeReadResult.Invalid;
        }
        if (storedBytes > MaximumStoredUtf8Bytes(maximumValueUtf8Bytes))
        {
            return AtomicBoundedEnvelopeReadResult.Oversized;
        }

        try
        {
            using var document = JsonDocument.Parse(storedEnvelope);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || root.EnumerateObject().Count() != 3
                || !root.TryGetProperty("version", out var version)
                || version.ValueKind != JsonValueKind.Number
                || !version.TryGetInt32(out var parsedVersion)
                || parsedVersion != Version
                || !root.TryGetProperty("revision", out var revisionElement)
                || revisionElement.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("value", out var valueElement)
                || valueElement.ValueKind != JsonValueKind.String)
            {
                return AtomicBoundedEnvelopeReadResult.Invalid;
            }

            var revisionText = revisionElement.GetString();
            if (revisionText is null
                || revisionText.Length != AtomicBoundedSettingsLimits.RevisionBytes * 2)
            {
                return AtomicBoundedEnvelopeReadResult.Invalid;
            }
            var revision = Convert.FromHexString(revisionText);
            if (revision.Length != AtomicBoundedSettingsLimits.RevisionBytes
                || revision.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            {
                return AtomicBoundedEnvelopeReadResult.Invalid;
            }

            var valueText = valueElement.GetString();
            if (valueText is null
                || valueText.Length > ((maximumValueUtf8Bytes + 2) / 3 * 4))
            {
                return AtomicBoundedEnvelopeReadResult.Oversized;
            }
            var maximumDecodedBytes = checked(valueText.Length / 4 * 3);
            var value = new byte[Math.Min(maximumDecodedBytes, maximumValueUtf8Bytes)];
            if (!Convert.TryFromBase64String(valueText, value, out var valueBytes)
                || valueBytes is 0
                || valueBytes > maximumValueUtf8Bytes)
            {
                return AtomicBoundedEnvelopeReadResult.Invalid;
            }
            Array.Resize(ref value, valueBytes);
            using var valueDocument = JsonDocument.Parse(value);

            envelope = new AtomicBoundedEnvelope
            {
                Revision = revision,
                Value = value
            };
            return AtomicBoundedEnvelopeReadResult.Found;
        }
        catch (JsonException)
        {
            return AtomicBoundedEnvelopeReadResult.Invalid;
        }
        catch (FormatException)
        {
            return AtomicBoundedEnvelopeReadResult.Invalid;
        }
        catch (ArgumentException)
        {
            return AtomicBoundedEnvelopeReadResult.Invalid;
        }
        catch (OverflowException)
        {
            return AtomicBoundedEnvelopeReadResult.Invalid;
        }
    }

    public static byte[] CreateRevision()
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var revision = RandomNumberGenerator.GetBytes(
                AtomicBoundedSettingsLimits.RevisionBytes);
            if (revision.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
            {
                return revision;
            }
        }

        throw new CryptographicException("Bounded-setting revision generation failed.");
    }
}
