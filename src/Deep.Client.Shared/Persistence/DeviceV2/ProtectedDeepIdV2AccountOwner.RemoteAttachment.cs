using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // A key-free UI/history row is only a selector. Decryption permission comes
    // from the actual authenticated native receive under the protected floor.
    internal async Task<OwnedDeepSecret> ReadReceivedAttachmentManifestAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> logicalId, ReadOnlyMemory<byte> authorDeviceId, CancellationToken ct)
    {
        if (logicalId.Length != 32 || authorDeviceId.Length != 32) throw new ArgumentException("Exact received attachment selector required.");
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        var result = await opened.WithSqlAsync(sql => sql.ReadVerifiedAttachmentManifest(floor, logicalId.Span, authorDeviceId.Span), ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireActive(); return result;
    }
}
