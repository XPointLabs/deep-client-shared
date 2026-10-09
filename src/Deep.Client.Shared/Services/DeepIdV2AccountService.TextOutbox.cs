using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Services;
public sealed partial class DeepIdV2AccountService
{
    internal async Task CompactOwnOrdinaryOutboxAsync(Did2MessagingSessionScope scope, int maximumRows,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source);
        if (maximumRows is < 1 or > Did2CompactionPlan.MaximumRows) throw new ArgumentOutOfRangeException(nameof(maximumRows));
        source.RequireAccountOwner(this);
        var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        await owner.CompactOwnedOrdinaryOutboxAsync(TrustedUnixSeconds(), verifier, scope, maximumRows,
            own, source, ct).ConfigureAwait(false);
    }

    internal async Task<Did2CompactionPlan.Preparation> PrepareOwnOrdinaryOutboxCompactionAsync(
        Did2MessagingSessionScope scope, int maximumRows, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source);
        if (maximumRows is < 1 or > Did2CompactionPlan.MaximumRows) throw new ArgumentOutOfRangeException(nameof(maximumRows));
        source.RequireAccountOwner(this);
        var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.PrepareOwnedOrdinaryOutboxCompactionAsync(TrustedUnixSeconds(), verifier, scope, maximumRows,
            own, source, ct).ConfigureAwait(false);
    }

    internal async Task<DirectTextOutboxEntry> PrepareOwnDirectAttachmentOfferAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> assetOperation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span); ProtectedDph2PreClaimJournal.RequireIntent(assetOperation.Span);
        var op = operation.ToArray(); var asset = assetOperation.ToArray();
        try
        {
            var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await owner.PrepareDirectAttachmentOfferAsync(TrustedUnixSeconds(), verifier, scope, op, asset, pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(op); CryptographicOperations.ZeroMemory(asset); }
    }

    internal async Task<DirectTextOutboxEntry> PrepareOwnDirectTextAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, string text,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source);
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        _ = ApplicationCoreCodec.CreateMessageCreatePayload(text);
        var op = operation.ToArray();
        try
        {
            source.RequireAccountOwner(this);
            var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await owner.PrepareDirectTextAsync(TrustedUnixSeconds(), verifier, scope, op, text, pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(op); }
    }
}
