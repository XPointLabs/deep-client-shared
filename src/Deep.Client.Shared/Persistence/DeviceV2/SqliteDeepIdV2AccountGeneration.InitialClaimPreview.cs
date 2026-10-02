using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class SqliteDeepIdV2AccountGeneration
{
    internal static async ValueTask<Dph2InitialClaimPreview> PreviewInitialClaimUnderLeaseAsync(
        IDeepSecureStorage storage, string statePath, VerifiedDeepIdV2CurrentAccount current, Dph2Record dph2,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        VerifiedDeepIdV2DirectoryFreshness initiator, OnionMonotonicReading reading,
        OnionTrustedTimeAuthority trustedTime, int maximumMessagesWithoutPqInjection, CancellationToken ct)
    {
        // Open verifies exact account/instance marker and full staged public
        // inventory hash against its protected tip before restoring any secret.
        var opened = await OpenPreKeyStoreAsync(storage, statePath, current, allowInitialize: false, ct).ConfigureAwait(false);
        await using var store = opened.Store;
        try
        {
            var retained = await store.ReadRestoredInitialSecretsAsync(dph2, fresh.Proof, reading, ct).ConfigureAwait(false);
            using var secrets = retained.Secrets;
            return await current.Verified.DeviceSecrets.PreviewInitialClaimAsync(dph2, fresh.Proof, initiator,
                retained.Offering, secrets, trustedTime, maximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(opened.ScopeHash); }
    }

    // Internal prerequisite for the atomic responder owner, never a UI/service
    // prepare API. The caller must hold the account lease and retain it through
    // subsequent exact replay/reservation/session/inbox commit.
    internal static async ValueTask<ResponderInitialSessionCommitCapability> PrepareInitialSessionUnderLeaseAsync(
        IDeepSecureStorage storage, string statePath, VerifiedDeepIdV2CurrentAccount current,
        VerifiedDph2InitialClaim verifiedClaim, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        VerifiedDeepIdV2DirectoryFreshness initiator, OnionMonotonicReading reading,
        OnionTrustedTimeAuthority trustedTime, int maximumMessagesWithoutPqInjection, CancellationToken ct)
    {
        var opened = await OpenPreKeyStoreAsync(storage, statePath, current, allowInitialize: false, ct).ConfigureAwait(false);
        await using var store = opened.Store;
        try
        {
            var dph2 = Dph2Codec.Decode(verifiedClaim.Initiation.ExactBytes.Span);
            var retained = await store.ReadRestoredInitialSecretsAsync(dph2, fresh.Proof, reading, ct).ConfigureAwait(false);
            using var secrets = retained.Secrets;
            return await current.Verified.DeviceSecrets.PrepareInitialSessionAsync(verifiedClaim, fresh.Proof, initiator,
                secrets, trustedTime, maximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(opened.ScopeHash); }
    }
}
