using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Deadline denial/closure is local original custody, not a reason to fetch
    // a current recipient or renew a grant. Historical Stored is checked first
    // by the business facade; closure never claims non-delivery or deletes work.
    internal async Task RequireInitialContactRetryTimeAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope requestedScope, ReadOnlyMemory<byte> initialIntent,
        ReadOnlyMemory<byte> originalDcr, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        ProtectedDph2PreClaimJournal.RequireIntent(initialIntent.Span);
        var intent = initialIntent.ToArray(); var dcr = originalDcr.ToArray(); var op = InitialMailboxOperation(intent);
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
            await RequireContactControlRetryTimeUnderLeaseAsync(current, held, scope, op, intent, dcr,
                verifier, own, source, ct).ConfigureAwait(false);
        }
        finally { foreach (var bytes in new[] { intent, dcr, op }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task RequireContactControlRetryTimeUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> initialIntent, ReadOnlyMemory<byte> originalDcr, IDeepMlDsa65Verifier verifier,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease); RequireRetainedStoreOwnScope(scope, own);
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
        await ResumeStoppedControlWorkUnderLeaseAsync(current, held, opened, scope, operation, verifier, own, source, ct).ConfigureAwait(false);
        await RequireControlWorkNotStoppedUnderLeaseAsync(scope, operation, held, ct).ConfigureAwait(false);
        var deadline = await ReadMailboxApplicationRetryDeadlineUnderLeaseAsync(current, held, opened,
            scope, operation, initialIntent, ct).ConfigureAwait(false);
        var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
        var elapsed = checked(first.SampleSeconds - own.Proof.MonotonicSample);
        if (checked(own.Proof.TrustedUpperUnixSeconds + elapsed) < deadline) return;
        var native = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, operation, initialIntent, ct).ConfigureAwait(false);
        byte[] snapshot = [], closed = [];
        try
        {
            if (!initialIntent.IsEmpty)
                await RequireRetainedInitialDraftAndRecipientUnderLeaseAsync(current, held, opened,
                    initialIntent, originalDcr, native, ct).ConfigureAwait(false);
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Contact retry expiry lost original send custody.");
            snapshot = raw.Use(bytes => bytes.ToArray());
            using var sends = ProtectedDid2MailboxSendJournal.Decode(snapshot, scope.Network, scope.LocalAccount, scope.Instance);
            var entry = sends.Current(scope.Hash, operation.Span);
            if (entry is not null)
            {
                if (entry.RetryUntil != Math.Min(entry.Expires, deadline))
                    throw new CryptographicException("Contact retry expiry differs from its actual original application deadline.");
                // Upper-bound crossing denies work, but only lower time proves
                // terminal expiry. Keep uncertain original custody unchanged.
                if (checked(own.Proof.TrustedLowerUnixSeconds + elapsed) >= entry.RetryUntil)
                    closed = await CloseExpiredMailboxAttemptUnderLeaseAsync(current, held, opened, scope, operation,
                        initialIntent, native, sends, snapshot, scope.Instance.ToArray(), source, own, ct).ConfigureAwait(false) ?? [];
            }
            if (checked(own.Proof.TrustedLowerUnixSeconds + elapsed) >= deadline)
                if (!await TryStopControlWorkUnderLeaseAsync(current, held, opened, scope, operation,
                    ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired, verifier, own, source, ct).ConfigureAwait(false))
                    throw new CryptographicException("Expired control work lost its actual explicit command.");
            await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            throw new IOException("The original contact-control application retry deadline forbids further dispatch.");
        }
        finally { foreach (var bytes in new[] { native, snapshot, closed }) CryptographicOperations.ZeroMemory(bytes); }
    }

    // Actual authenticated source only. Neither SQL transport flags nor a caller
    // timestamp can extend application expiry or mint a new logical deadline.
    private async Task<ulong> ReadMailboxApplicationRetryDeadlineUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> initialIntent, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (!initialIntent.IsEmpty)
        {
            var initial = opened.Sql.ReadVerifiedActiveInitialEvents(floor);
            try
            {
                if (!FixedRoute(InitialMailboxOperation(initialIntent.Span), operation.Span))
                    throw new CryptographicException("Initial retry selected another native intent.");
                return Math.Min(ApplicationRetryUntil(ApplicationCoreCodec.DecodeDmc2(initial.SessionInit)),
                    ApplicationRetryUntil(ApplicationCoreCodec.DecodeDmc2(initial.Hello)));
            }
            finally { CryptographicOperations.ZeroMemory(initial.SessionInit); CryptographicOperations.ZeroMemory(initial.Hello); }
        }
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
            storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        using var acceptsRaw = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Application retry lost mandatory acceptance custody.");
        using var accepts = acceptsRaw.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        var acceptance = accepts.FindScope(scope);
        if (acceptance is not null && FixedRoute(acceptance.Operation, operation.Span))
        {
            using var history = await ReadRetainedContactAcceptEventUnderLeaseAsync(held, opened, application, acceptance, operation, ct).ConfigureAwait(false);
            return history.Use(bytes => ApplicationRetryUntil(ApplicationCoreCodec.DecodeDmc2(bytes)));
        }
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Application retry lost mandatory ordinary authoring custody.");
        using var authored = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        using var retained = await application.ReconcileOwnedTextOutboxAsync(authored, current.AccountId,
            BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, operation, ct).ConfigureAwait(false) ??
            throw new CryptographicException("Working retry lost its actual ordinary event.");
        using var native = opened.Sql.ReadVerifiedOperation(floor, operation.Span) ??
            throw new CryptographicException("Working retry has no committed native event.");
        var exact = OwnedByteExports.TakeArray(retained.ExactDmc2);
        try
        {
            if (native.Direction != 1 || !FixedRoute(native.EventHash, SHA256.HashData(exact)))
                throw new CryptographicException("Application retry differs from committed native custody.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return ApplicationRetryUntil(ApplicationCoreCodec.DecodeDmc2(exact));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    // Consumes a freshly decoded, caller-owned record, never a borrowed history
    // or asset owner. Reading a deadline grants no permission to erase durable keys.
    internal static ulong ApplicationRetryUntil(ParsedDmc2 message)
    {
        try { return message.ExpiresAtUnixMilliseconds == 0 ? ulong.MaxValue : message.ExpiresAtUnixMilliseconds / 1_000; }
        finally { if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
    }

    private async Task RequireMailboxRetryTimeUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        HeldDeepIdV2AccountLease held, ulong retryUntil, CancellationToken ct)
    {
        var reading = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
        var upper = checked(own.Proof.TrustedUpperUnixSeconds + checked(reading.SampleSeconds - own.Proof.MonotonicSample));
        if (upper >= retryUntil) throw new IOException("The authenticated application retry deadline has expired.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }
}
