using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    internal async Task<Did2ContactAcceptanceState> ReadOwnContactAcceptanceAsync(Did2MessagingSessionScope scope,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.ReadContactAcceptanceAsync(TrustedUnixSeconds(), verifier, scope, pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
    }

    internal async Task<OwnedDid2ContactAcceptDraft> PrepareOwnContactAcceptAsync(
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(source);
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        if (scope.IsInitiator) throw new System.Security.Cryptography.CryptographicException("This account is not the pending recipient.");
        var op = operation.ToArray();
        try
        {
            source.RequireAccountOwner(this);
            var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await owner.PrepareContactAcceptAsync(TrustedUnixSeconds(), verifier, scope, op, pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(op); }
    }
}
