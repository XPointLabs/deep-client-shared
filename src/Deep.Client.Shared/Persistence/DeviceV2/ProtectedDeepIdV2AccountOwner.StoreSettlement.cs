using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Untrusted original response + selectors only. Past receipt authentication
    // is separate from current own authority and never renews dispatch admission.
    internal async Task<ClientMailboxStoreResult> AdoptOriginalMailboxStoreReplyAsync(ulong unixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope requestedScope,
        ReadOnlyMemory<byte> nativeOperation, ReadOnlyMemory<byte> selectedAttempt, ReadOnlyMemory<byte> initialIntent,
        ReadOnlyMemory<byte> untrustedReply, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(nativeOperation.Span);
        ProtectedDph2PreClaimJournal.RequireIntent(selectedAttempt.Span);
        if (!initialIntent.IsEmpty) ProtectedDph2PreClaimJournal.RequireIntent(initialIntent.Span);
        if (untrustedReply.Length != MailboxReceiptV3Limits.QuorumFixedHeaderLength +
            2 * MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength + 64)
            throw new CryptographicException("Original Store reply has an unsupported bounded profile.");
        RequireRetainedStoreOwnScope(requestedScope, own);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, requestedScope, ct).ConfigureAwait(false);
        return await AdoptOriginalMailboxStoreReplyUnderLeaseAsync(current, held, opened, verifier, requestedScope,
            nativeOperation, selectedAttempt, initialIntent, untrustedReply, own, source, ct).ConfigureAwait(false);
    }

    private async Task<ClientMailboxStoreResult> AdoptOriginalMailboxStoreReplyUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope requestedScope,
        ReadOnlyMemory<byte> nativeOperation, ReadOnlyMemory<byte> selectedAttempt, ReadOnlyMemory<byte> initialIntent,
        ReadOnlyMemory<byte> untrustedReply, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(nativeOperation.Span);
        ProtectedDph2PreClaimJournal.RequireIntent(selectedAttempt.Span);
        var expectedBytes = MailboxReceiptV3Limits.QuorumFixedHeaderLength +
            2 * MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength + 64;
        if (untrustedReply.Length != expectedBytes)
            throw new CryptographicException("Original Store reply has an unsupported bounded profile.");
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        var op = nativeOperation.ToArray(); var attempt = selectedAttempt.ToArray(); var intent = initialIntent.ToArray();
        var reply = untrustedReply.ToArray(); byte[] envelope = [], sendRoot = [], grantRoot = [], exact = [];
        try
        {
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            RequireRetainedStoreOwnScope(scope, own);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            envelope = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, op, intent, ct).ConfigureAwait(false);
            using (var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Late Store lost mandatory send custody.")) sendRoot = raw.Use(bytes => bytes.ToArray());
            using (var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Late Store lost original acquisition custody.")) grantRoot = raw.Use(bytes => bytes.ToArray());
            using var sends = ProtectedDid2MailboxSendJournal.Decode(sendRoot, scope.Network, scope.LocalAccount, scope.Instance);
            using var grants = ProtectedDid2MailboxGrantJournal.Decode(grantRoot, scope.Network, scope.LocalAccount, scope.Instance);
            _ = sends.Chain(scope.Hash, op); // Reject foreign/orphan selectors, not just a parsed matching row.
            if (!sends.Entries.TryGetValue(Convert.ToHexString(ProtectedDid2MailboxSendJournal.Key(scope.Hash, attempt)), out var entry) ||
                !entry.Prepared || !FixedRoute(entry.Operation, op) || !FixedRoute(entry.Attempt, attempt))
                throw new CryptographicException("Late Store cannot invent a prepared original attempt.");
            var acquisition = grants.Entries.Values.SingleOrDefault(value => ProtectedDid2MailboxGrantJournal.HasWinner(value) &&
                FixedRoute(SHA256.HashData(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(value).Span).Field(8).Span),
                    entry.GrantHash)) ?? throw new CryptographicException("Late Store lost its original acquisition winner.");
            var (grant, route) = await RequireOriginalAttemptGrantAsync(entry, acquisition, own, source, scope, ct).ConfigureAwait(false);
            RequireOriginalAttemptBody(entry, grant, route, scope, envelope); sends.RequireGrant(grant);
            if (sends.MinimumCounter(entry.GrantHash) <= entry.Counter)
                throw new CryptographicException("Late Store lost the independently protected reserved counter.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
            var metadata = await application.RequireStorePublicEvidenceAsync(scope, op, attempt, ct).ConfigureAwait(false);
            await RequireStoreEvidenceCommitmentUnderLeaseAsync(held, scope, op, attempt, metadata, ct).ConfigureAwait(false);
            if (metadata.IsInitial != !intent.AsSpan().IsEmpty ||
                !FixedRoute(metadata.Logical.Span, entry.MailboxOperation) ||
                !FixedRoute(metadata.ExactPma.Span, ProtectedDid2MailboxGrantJournal.OriginalPolicy(acquisition).Span))
                throw new CryptographicException("Late Store public facts differ from original prepared custody.");
            if (!metadata.IsInitial)
            {
                var nativeRoute = await ReadOriginalPeerStoreRouteAsync(current, held, opened, application, route.ExactBytes, ct).ConfigureAwait(false);
                if (!FixedRoute(nativeRoute.ExactBytes.Span, route.ExactBytes.Span))
                    throw new CryptographicException("Late Store lost its authenticated native recipient route.");
            }
            if (!FixedRoute(metadata.OriginalRoute.Span, route.ExactBytes.Span))
                throw new CryptographicException("Late Store route differs from its original recipient evidence.");
            var read = await application.ReadTransportOutboxAsync(VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span),
                OutboxLogicalId.FromBytes(entry.MailboxOperation), ct).ConfigureAwait(false);
            if (read is not { Result: TransportOutboxReadResult.Found, Item: not null })
                throw new CryptographicException("Late Store cannot reconstruct an absent original SQL request.");
            exact = read.Item.GetCiphertextBundleCopy();
            RequireOriginalAttemptRequest(entry, grant, route, MailboxAuthenticatedClientRequestCodec.Decode(exact), exact, envelope, read.Item);
            var replicas = MailboxStoreReplicaEvidenceVerifier.Verify(own.Network, own.Authority, route, metadata.Replicas);
            var upper = checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample);
            var verified = await VerifyOriginalStoreReplyAsync(scope, envelope, route, metadata, replicas,
                own, source, upper, read.Item, exact, reply, ct).ConfigureAwait(false);
            if (metadata.IsInitial)
                await RequireOriginalInitialStoreRecipientUnderLeaseAsync(current, held, opened, scope, intent, metadata,
                    envelope, exact, verified, own.Authority, verifier, ct).ConfigureAwait(false);
            async Task Recheck(CancellationToken token)
            {
                await RecheckRouteFreshnessAsync(current, source, own, held, first, token).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, sendRoot, token).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, grantRoot, token).ConfigureAwait(false);
                var final = await opened.Custody.ReconcileAsync(token).ConfigureAwait(false);
                if (!FixedRoute(final.Exact.Span, floor.Exact.Span))
                    throw new CryptographicException("Native custody changed during original Store settlement.");
                token.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            }
            await Recheck(ct).ConfigureAwait(false);
            if (read.Item.State is TransportOutboxState.Durable or TransportOutboxState.Delivered)
            {
                var existing = read.Item.Attempts.Single(value => value.State == TransportOutboxAttemptState.Durable).GetEvidenceCopy();
                try { if (!FixedRoute(existing, reply)) throw new CryptographicException("Late Store cannot replace original terminal evidence."); }
                finally { CryptographicOperations.ZeroMemory(existing); }
            }
            else await application.CommitOwnedOriginalStoreReplyAsync(scope, op, attempt, metadata, read.Item,
                grant, verified, upper, Recheck, ct).ConfigureAwait(false);
            var finalMetadata = await application.RequireStorePublicEvidenceAsync(scope, op, attempt, ct).ConfigureAwait(false);
            RequireSameInitialStoreEvidence(metadata, finalMetadata);
            var result = await VerifyOriginalStoreOutcomeAsync(scope, attempt, envelope, application, route,
                finalMetadata, replicas, own, source, upper, ct).ConfigureAwait(false);
            await Recheck(ct).ConfigureAwait(false);
            if (!intent.AsSpan().IsEmpty)
                _ = await TryReadRetainedInitialStoreUnderLeaseAsync(current, held, opened, scope, intent,
                    null, own, source, verifier, ct).ConfigureAwait(false) ?? throw new CryptographicException("Settled Initial lost its original Store.");
            // DBR2 has no authored command completion/AppAck. The original
            // SQL request and authenticated Store evidence above are its only
            // transport outcome; they do not claim native peer acceptance.
            if (intent.Length == 0 && !envelope.AsSpan().StartsWith("DBR2"u8))
                await RetainOrdinaryStoreCompletionUnderLeaseAsync(current, held, opened, scope, op, attempt,
                    finalMetadata, own, source, ct).ConfigureAwait(false);
            await Recheck(ct).ConfigureAwait(false);
            return new(result.Cursor, result.Disposition, false, result.CoordinatorReceipt.CoordinatorId.Span);
        }
        finally { foreach (var bytes in new[] { op, attempt, intent, reply, envelope, sendRoot, grantRoot, exact }) CryptographicOperations.ZeroMemory(bytes); }
    }
}
