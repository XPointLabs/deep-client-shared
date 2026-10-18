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
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        OwnedDeepSecret? result = null;
        try
        {
            foreach (var native in opened.Sql.ReadVerifiedIncomingEvents(floor, ct))
            {
                using var exact = native.OwnAuthenticatedDmc2();
                var parsed = exact.Use(bytes => ApplicationCoreCodec.DecodeDmc2(bytes));
                try
                {
                    if (!parsed.LogicalMessageId.Span.SequenceEqual(logicalId.Span) || !parsed.SenderDeviceId.Span.SequenceEqual(authorDeviceId.Span)) continue;
                    if (parsed.ParsedPayload is not AttachmentOfferDmc2Payload offer ||
                        !parsed.SenderAccountId.Span.SequenceEqual(scope.RemoteAccount) ||
                        !parsed.ConversationId.Span.SequenceEqual(scope.Conversation) || result is not null)
                        throw new CryptographicException("Received attachment selector has no unique authenticated peer offer.");
                    var manifest = OwnedByteExports.TakeArray(offer.Manifest.CanonicalBytes);
                    try { result = new(manifest); }
                    finally { CryptographicOperations.ZeroMemory(manifest); }
                }
                finally { if (parsed.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
            }
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            var released = result ?? throw new InvalidOperationException("Received attachment is absent from authenticated native history.");
            result = null; return released;
        }
        finally { result?.Dispose(); }
    }
}
