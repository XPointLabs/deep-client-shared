using System.Security.Cryptography;
using System.Globalization;
using System.Text;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Domain;

public enum DeepAccountActivationState
{
    ActiveLocal = 1,
    RestorePendingActivation = 2
}

public sealed record DeepAccount(
    DeepPermanentIdV1 PermanentId,
    DeepAccountIdentityCapability AccountIdentity,
    string DisplayName,
    DateTimeOffset RegisteredAt,
    DeepAccountActivationState ActivationState,
    DeviceId32 CurrentDeviceId);

public sealed class DeepDevice
{
    private readonly byte[] prekeyPublicKey;

    public DeepDevice(
        LocalDeviceIdentityIntent identity,
        ReadOnlySpan<byte> prekeyPublicKey,
        DateTimeOffset createdAt)
    {
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        if (prekeyPublicKey.Length != DeepAccountStoreContract.KeyMaterialSize
            || prekeyPublicKey.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The device prekey public key must contain exactly 32 nonzero bytes.",
                nameof(prekeyPublicKey));
        }

        this.prekeyPublicKey = prekeyPublicKey.ToArray();
        CreatedAt = createdAt;
    }

    public LocalDeviceIdentityIntent Identity { get; }

    public DateTimeOffset CreatedAt { get; }

    public DeviceId32 DeviceId => Identity.DeviceId;

    public ulong DeviceGeneration => Identity.DeviceGeneration;

    public DeviceRevocationHandle32 RevocationHandle => Identity.RevocationHandle;

    public ReadOnlyMemory<byte> SigningPublicKey => Identity.SigningPublicKey.Bytes;

    public ReadOnlyMemory<byte> AgreementPublicKey => Identity.AgreementPublicKey.Bytes;

    public ReadOnlyMemory<byte> PrekeyPublicKey => prekeyPublicKey.ToArray();
}

public sealed record DeepLocalProfile(string DisplayName, DateTimeOffset UpdatedAt);

internal static class DeepDisplayName
{
    internal const int MaxLength = 128;
    internal const int MaxUtf8Bytes = 256;

    internal static string Normalize(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (!IsWellFormedUtf16(value))
        {
            throw new ArgumentException("Display name contains invalid UTF-16.", parameterName);
        }

        var normalized = value.Normalize(NormalizationForm.FormC).Trim();
        if (normalized.Length is < 1 or > MaxLength
            || Encoding.UTF8.GetByteCount(normalized) > MaxUtf8Bytes)
        {
            throw new ArgumentException(
                $"Display name must contain 1..{MaxLength} normalized UTF-16 code units " +
                $"and at most {MaxUtf8Bytes} UTF-8 bytes.",
                parameterName);
        }

        foreach (var rune in normalized.EnumerateRunes())
        {
            var category = Rune.GetUnicodeCategory(rune);
            if (category is UnicodeCategory.Control
                or UnicodeCategory.Format
                or UnicodeCategory.LineSeparator
                or UnicodeCategory.ParagraphSeparator
                or UnicodeCategory.Surrogate)
            {
                throw new ArgumentException(
                    "Display name contains a control, bidi/format, or line-separator character.",
                    parameterName);
            }
        }

        return normalized;
    }

    internal static bool IsCanonical(string? value)
    {
        if (value is null)
        {
            return false;
        }
        try
        {
            return string.Equals(value, Normalize(value, nameof(value)), StringComparison.Ordinal);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool IsWellFormedUtf16(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            var current = value[index];
            if (char.IsHighSurrogate(current))
            {
                if (++index >= value.Length || !char.IsLowSurrogate(value[index]))
                {
                    return false;
                }
            }
            else if (char.IsLowSurrogate(current))
            {
                return false;
            }
        }
        return true;
    }
}

public sealed record DeepLocalIdentitySnapshot(
    int StoreGeneration,
    ReadOnlyMemory<byte> NetworkId,
    DeepAccount Account,
    DeepDevice Device,
    DeepLocalProfile Profile,
    DeepSecureStorageSlots SecureSlots);

public sealed record DeepAccountCreationResult(
    DeepLocalIdentitySnapshot Identity);

public delegate void DeepRecoveryPhraseUtf8Consumer(ReadOnlySpan<byte> canonicalPhraseUtf8);

internal delegate TResult DeepRecoveryPhraseUtf8Reader<TResult>(ReadOnlySpan<byte> canonicalPhraseUtf8);

/// <summary>
/// Owns a mutable UTF-8 recovery-phrase input. The portable STORE boundary never
/// accepts or returns a managed string containing the phrase.
/// </summary>
public sealed class DeepOwnedRecoveryPhraseUtf8 : IDisposable
{
    private const int MaxLength = 4096;
    private readonly object gate = new();
    private byte[]? value;

    private DeepOwnedRecoveryPhraseUtf8(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty || value.Length > MaxLength)
        {
            throw new ArgumentException("Recovery phrase UTF-8 input is empty or too large.", nameof(value));
        }
        this.value = value.ToArray();
    }

    public static DeepOwnedRecoveryPhraseUtf8 CopyFrom(ReadOnlySpan<byte> canonicalPhraseUtf8) =>
        new(canonicalPhraseUtf8);

    internal TResult Use<TResult>(DeepRecoveryPhraseUtf8Reader<TResult> reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        lock (gate)
        {
            return reader(value ?? throw new ObjectDisposedException(nameof(DeepOwnedRecoveryPhraseUtf8)));
        }
    }

    internal bool FixedTimeEquals(ReadOnlySpan<byte> candidate)
    {
        lock (gate)
        {
            var current = value
                ?? throw new ObjectDisposedException(nameof(DeepOwnedRecoveryPhraseUtf8));
            return current.Length == candidate.Length
                && CryptographicOperations.FixedTimeEquals(current, candidate);
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            var current = value;
            value = null;
            if (current is not null)
            {
                CryptographicOperations.ZeroMemory(current);
            }
        }
    }
}

/// <summary>
/// Owns a locally prepared recovery phrase until one exact, user-confirmed commit.
/// Preparing and revealing this draft never mutates durable or secure state.
/// </summary>
public sealed class DeepPreparedAccountCreationDraft : IDisposable
{
    private readonly object gate = new();
    private readonly object owner;
    private VerifiedDeepRecoveryPhrase? phrase;
    private DraftState state;

    internal DeepPreparedAccountCreationDraft(
        object owner,
        string displayName,
        VerifiedDeepRecoveryPhrase phrase)
    {
        this.owner = owner ?? throw new ArgumentNullException(nameof(owner));
        DisplayName = displayName;
        this.phrase = phrase ?? throw new ArgumentNullException(nameof(phrase));
    }

    internal string DisplayName { get; }

    public void RevealCanonicalPhraseOnce(DeepRecoveryPhraseUtf8Consumer consumer)
    {
        ArgumentNullException.ThrowIfNull(consumer);
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(state is DraftState.Committing or DraftState.Consumed, this);
            if (state != DraftState.Prepared)
            {
                throw new InvalidOperationException("The recovery phrase has already been revealed.");
            }
            state = DraftState.Revealed;
            UseCanonicalPhraseUtf8(phrase!, bytes =>
            {
                consumer(bytes);
                return true;
            });
        }
    }

    internal VerifiedDeepRecoveryPhrase BeginCommit(
        object expectedOwner,
        DeepOwnedRecoveryPhraseUtf8 userConfirmation)
    {
        ArgumentNullException.ThrowIfNull(userConfirmation);
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(state is DraftState.Committing or DraftState.Consumed, this);
            if (!ReferenceEquals(owner, expectedOwner))
            {
                throw new InvalidOperationException("The prepared account draft belongs to another account service.");
            }
            if (state != DraftState.Revealed)
            {
                throw new InvalidOperationException(
                    "Reveal and confirm the canonical recovery phrase before committing the account.");
            }
            var matches = UseCanonicalPhraseUtf8(
                phrase!,
                userConfirmation.FixedTimeEquals);
            if (!matches)
            {
                throw new ArgumentException(
                    "Recovery phrase confirmation does not exactly match the canonical phrase.",
                    nameof(userConfirmation));
            }
            state = DraftState.Committing;
            return phrase!;
        }
    }

    internal void CompleteCommit()
    {
        VerifiedDeepRecoveryPhrase? ownedPhrase;
        lock (gate)
        {
            if (state != DraftState.Committing)
            {
                return;
            }
            state = DraftState.Consumed;
            ownedPhrase = phrase;
            phrase = null;
        }
        ownedPhrase?.Dispose();
    }

    public void Dispose()
    {
        VerifiedDeepRecoveryPhrase? ownedPhrase = null;
        lock (gate)
        {
            if (state == DraftState.Consumed)
            {
                return;
            }
            if (state == DraftState.Committing)
            {
                return;
            }
            state = DraftState.Consumed;
            ownedPhrase = phrase;
            phrase = null;
        }
        ownedPhrase?.Dispose();
    }

    internal static TResult UseCanonicalPhraseUtf8<TResult>(
        VerifiedDeepRecoveryPhrase phrase,
        DeepRecoveryPhraseUtf8Reader<TResult> reader)
    {
        ArgumentNullException.ThrowIfNull(phrase);
        ArgumentNullException.ThrowIfNull(reader);
        TResult result = default!;
        phrase.UseCanonicalUtf8(bytes => result = reader(bytes));
        return result;
    }

    private enum DraftState
    {
        Prepared = 0,
        Revealed = 1,
        Committing = 2,
        Consumed = 3
    }
}
