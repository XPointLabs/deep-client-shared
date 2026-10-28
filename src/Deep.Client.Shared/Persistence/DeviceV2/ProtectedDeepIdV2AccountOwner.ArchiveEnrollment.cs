using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Set only inside the explicit leased enrollment entry. It permits the
    // existing old-plan owner to drain V1 before the single V2/all0 catalog CAS;
    // it never grants an ordinary opener or V2 state0 fallback.
    private bool archiveEnrollmentInProgress;

    private async Task<ProtectedDid2MessagingSessionCatalog.Snapshot> ReadMessagingCatalogForCompactionAsync(
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, CancellationToken ct)
    {
        var owner = new ProtectedDid2MessagingSessionCatalog(storage, networkId, account.Span, instance.Span);
        if (!archiveEnrollmentInProgress) return await owner.ReadAsync(ct).ConfigureAwait(false);
        var result = await owner.ReadForEnrollmentAsync(ct).ConfigureAwait(false);
        if (result.Version != 1)
        {
            result.Dispose();
            throw new CryptographicException("Only the actual old catalog may enter explicit legacy-plan draining.");
        }
        return result;
    }
}
