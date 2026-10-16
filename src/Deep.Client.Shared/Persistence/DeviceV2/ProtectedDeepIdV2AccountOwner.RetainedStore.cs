using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Public text retry after outbox-only cleanup selects a historical result,
    // never reconstructs an ordinary command or ratchet-encrypts again.
    internal async Task<ClientMailboxStoreResult?> ReadRetainedDirectTextStoreAsync(ulong unixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation, string text,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var payload = ApplicationCoreCodec.CreateMessageCreatePayload(text);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Public text retry lost mandatory authored custody.");
        using var ordinary = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        if (ordinary.Entries.ContainsKey(Convert.ToHexString(operation.Span))) return null; // Existing command has its normal exact owner.
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        using var native = opened.Sql.ReadVerifiedOperation(floor, operation.Span);
        if (native is null) return null; // Unavailable retry; absence never authorizes creation.
        if (native.Direction != 1) throw new CryptographicException("Public text retry selected a receive operation.");
        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
            storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
        var exact = await application.ReadRetainedAuthoredEventAsync(scope, native.EventHash.ToArray(), ct).ConfigureAwait(false) ??
            throw new CryptographicException("Compacted public text retry lost its independent history.");
        try
        {
            RequireRequestedOrdinaryPayload(exact, payload);
            return await TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope,
                operation, own, source, ct).ConfigureAwait(false) ??
                throw new IOException("No retained dispatchable command or verified original Store exists.");
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    internal async Task<ClientMailboxStoreResult?> ReadRetainedMessagingStoreAsync(ulong unixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope requestedScope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
        return await TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope,
            operation, own, source, ct).ConfigureAwait(false);
    }

    // Historical outcome only: no holder secret, send floor, grant journal,
    // fresh peer route or current replica key is used to recreate old custody.
    private async Task<ClientMailboxStoreResult?> TryReadRetainedMessagingStoreUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Cached Store lost its mandatory authored custody.");
        var original = raw.Use(bytes => bytes.ToArray()); byte[] sendRoot = [], acceptanceRoot = [], completionGrantRoot = [];
        try
        {
            using var ordinary = ProtectedDid2DirectTextJournal.Decode(original, scope.Network, scope.LocalAccount, scope.Instance);
            ordinary.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command);
            var retainedSuccess = ordinary.TerminalAudits.TryGetValue(Convert.ToHexString(operation.Span), out var terminal) &&
                terminal.Reason == 3;
            if (command?.Pending == true) return null;
            var recoverOrdinaryCompletion = command is not null && !command.Stored;
            if (command is not null && !FixedRoute(command.Scope.Exact, scope.Exact))
                throw new CryptographicException("Retained Store selected a different authored scope.");
            using (var accept = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Cached Store lost its mandatory acceptance custody."))
                acceptanceRoot = accept.Use(bytes => bytes.ToArray());
            using var commands = ProtectedDid2ContactAcceptJournal.Decode(acceptanceRoot, scope.Network, scope.LocalAccount, scope.Instance);
            var acceptance = commands.FindScope(scope);
            if (acceptance is not null && !FixedRoute(acceptance.Operation, operation.Span)) acceptance = null;
            if (acceptance is not null && command is not null)
                throw new CryptographicException("Historical Store has ambiguous acceptance and ordinary command custody.");

            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            using var native = opened.Sql.ReadVerifiedOperation(floor, operation.Span);
            if (native is null)
            {
                if (command is null && acceptance is null && !retainedSuccess) return null;
                throw new CryptographicException("Cached Store lost its independently committed native event.");
            }
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
            // Registered send custody may be empty after verified retirement,
            // but losing the mandatory root is corruption, not retirement.
            // Neither its entries nor its floors supply the historical result.
            using (var retainedSend = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Retained Store lost its mandatory send registration."))
                sendRoot = retainedSend.Use(bytes => bytes.ToArray());
            using var retainedSends = ProtectedDid2MailboxSendJournal.Decode(sendRoot, scope.Network, scope.LocalAccount, scope.Instance);
            using var selected = await ReadRetainedStoreAttemptCandidateUnderLeaseAsync(held, scope, operation,
                native.ExactEnvelope.ToArray(), application, retainedSends, ct).ConfigureAwait(false);
            if (selected is null)
            {
                if (acceptance is not null || recoverOrdinaryCompletion) return null;
                // Removed stopped work may retain an unsettled native send.
                // Audit expiry cannot turn that unknown outcome into success
                // or corruption. All actual attempt evidence was checked above;
                // returning no result grants neither dispatch nor new authoring.
                if (command is null && !retainedSuccess) return null;
                throw new CryptographicException("Completed ordinary work lost its exact original Store evidence.");
            }

            var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            RequireRetainedStoreOwnScope(scope, own);
            if (acceptance is null)
                await RequireRetainedOrdinaryEventUnderLeaseAsync(current, held, opened, scope, operation, ordinary,
                    ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
            else await RequireRetainedContactAcceptEventUnderLeaseAsync(held, opened, application, acceptance, operation, ct).ConfigureAwait(false);
            if (command is not null && !FixedRoute(command.EventHash, native.EventHash))
                throw new CryptographicException("Retained Store differs from its original protected command.");
            var metadata = selected.Evidence;
            if (metadata.IsInitial) throw new CryptographicException("An ordinary Store cannot use initial recipient evidence.");
            var route = await ReadOriginalPeerStoreRouteAsync(current, held, opened, application, metadata.OriginalRoute, ct).ConfigureAwait(false);
            var publicKeys = MailboxStoreReplicaEvidenceVerifier.Verify(own.Network, own.Authority, route, metadata.Replicas);
            var currentUpper = checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample);
            if (native.Direction != 1) throw new CryptographicException("Historical Store cannot select a receive row.");
            var receipt = await VerifyOriginalStoreOutcomeAsync(scope, selected.Attempt, native.ExactEnvelope.ToArray(), application,
                route, metadata, publicKeys, own, source, currentUpper, ct).ConfigureAwait(false);

            await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
            if (acceptance is null)
                await RequireRetainedOrdinaryEventUnderLeaseAsync(current, held, opened, scope, operation, ordinary,
                    ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
            else await RequireRetainedContactAcceptEventUnderLeaseAsync(held, opened, application, acceptance, operation, ct).ConfigureAwait(false);
            var finalFloor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(finalFloor.Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Historical Store native custody changed during verification.");
            var finalRoute = await ReadOriginalPeerStoreRouteAsync(current, held, opened, application, metadata.OriginalRoute, ct).ConfigureAwait(false);
            if (!FixedRoute(route.ExactBytes.Span, finalRoute.ExactBytes.Span))
                throw new CryptographicException("Historical Store original peer route changed during verification.");
            var finalMetadata = await application.RequireStorePublicEvidenceAsync(scope, operation, selected.Attempt, ct).ConfigureAwait(false);
            var before = metadata.CopyRecords(); var after = finalMetadata.CopyRecords();
            try
            {
                if (before.Where((bytes, index) => !FixedRoute(bytes, after[index])).Any())
                    throw new CryptographicException("Historical Store public evidence changed during verification.");
            }
            finally { foreach (var bytes in before.Concat(after)) CryptographicOperations.ZeroMemory(bytes); }
            // Re-read actual SQL evidence/coordinator, not a cached boolean.
            var finalReceipt = await VerifyOriginalStoreOutcomeAsync(scope, selected.Attempt, native.ExactEnvelope.ToArray(), application,
                route, finalMetadata, publicKeys, own, source, currentUpper, ct).ConfigureAwait(false);
            if (receipt.Cursor != finalReceipt.Cursor || receipt.Disposition != finalReceipt.Disposition ||
                !FixedRoute(MailboxReceiptV3Codec.EncodeDurableQuorum(receipt.CoordinatorReceipt),
                    MailboxReceiptV3Codec.EncodeDurableQuorum(finalReceipt.CoordinatorReceipt)))
                throw new CryptographicException("Historical Store outcome changed during verification.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, original, ct).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, sendRoot, ct).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2ContactAcceptJournal.Slot, acceptanceRoot, ct).ConfigureAwait(false);
            await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
            if (recoverOrdinaryCompletion)
            {
                // Working (not yet Stored) custody cannot have been retired.
                // Join its exact prepared MAU, independent counter floor and
                // original acquisition before adopting the local marker.
                using (var grantRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Interrupted Store completion lost original grant custody."))
                    completionGrantRoot = grantRoot.Use(bytes => bytes.ToArray());
                using var grants = ProtectedDid2MailboxGrantJournal.Decode(completionGrantRoot, scope.Network, scope.LocalAccount, scope.Instance);
                using var sends = ProtectedDid2MailboxSendJournal.Decode(sendRoot, scope.Network, scope.LocalAccount, scope.Instance);
                await RequireOriginalMailboxSendCommitmentAsync(current, held, opened, scope, operation, selected.Attempt,
                    native.ExactEnvelope.ToArray(), application, sends, grants, own, source, currentUpper, ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, completionGrantRoot, ct).ConfigureAwait(false);
                // Verify exact SQL Durable request/quorum and its pre-ingress
                // public evidence, then adopt only the interrupted local marker.
                // This neither renews admission nor invokes a transport callback.
#if DEEP_TEST_INTERNALS
                Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeOrdinaryCompletion);
#endif
                await RetainOrdinaryStoreCompletionUnderLeaseAsync(current, held, opened, scope, operation, selected.Attempt, metadata, own, source, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterOrdinaryCompletion);
#endif
                await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
            }
            if (acceptance is not null)
                await RetainContactStoreCompletionUnderLeaseAsync(current, held, scope, operation, own, source, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return new(receipt.Cursor, receipt.Disposition, false, receipt.CoordinatorReceipt.CoordinatorId.Span);
        }
        finally { foreach (var bytes in new[] { original, sendRoot, acceptanceRoot, completionGrantRoot }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static async Task<ContactPolicy> RequireRetainedContactAcceptEventUnderLeaseAsync(
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, SqliteDeepMailboxStore application,
        ProtectedDid2ContactAcceptJournal.Entry winner, ReadOnlyMemory<byte> operation, CancellationToken ct)
    {
        using var exact = await ReadRetainedContactAcceptEventUnderLeaseAsync(held, opened, application, winner, operation, ct).ConfigureAwait(false);
        return exact.Use(bytes => ((ContactAcceptDmc2Payload)ApplicationCoreCodec.DecodeDmc2(bytes).ParsedPayload).Policy);
    }

    private static async Task<OwnedDeepSecret> ReadRetainedContactAcceptEventUnderLeaseAsync(
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, SqliteDeepMailboxStore application,
        ProtectedDid2ContactAcceptJournal.Entry winner, ReadOnlyMemory<byte> operation, CancellationToken ct)
    {
        var scope = opened.Scope;
        if (scope.IsInitiator || !FixedRoute(winner.Scope.Exact, scope.Exact) || !FixedRoute(winner.Operation, operation.Span))
            throw new CryptographicException("Retained ContactAccept has no exact local explicit-command winner.");
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        using var native = opened.Sql.ReadVerifiedOperation(floor, operation.Span) ??
            throw new CryptographicException("Retained ContactAccept lost its actual committed send.");
        if (native.Direction != 1 || !FixedRoute(native.EventHash, winner.EventHash))
            throw new CryptographicException("Retained ContactAccept differs from its actual native send.");
        var initial = opened.Sql.ReadVerifiedActiveInitialEvents(floor);
        byte[]? accepted = null;
        try
        {
            if (!FixedRoute(winner.HelloHash, SHA256.HashData(initial.Hello)))
                throw new CryptographicException("Retained ContactAccept differs from its authenticated initial Hello.");
            accepted = await application.ReadContactAcceptAsync(scope.LocalAccount.ToArray(),
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope.Conversation.ToArray(),
                scope.LocalAccount.ToArray(), scope.LocalDevice.ToArray(), ct).ConfigureAwait(false);
            if (accepted is null)
                throw new CryptographicException("Retained ContactAccept lost its exact semantic projection.");
            winner.RequireExactAccept(accepted);
            var parsed = ApplicationCoreCodec.DecodeDmc2(accepted);
            if (parsed.ParsedPayload is not ContactAcceptDmc2Payload payload)
                throw new CryptographicException("Retained ContactAccept has no canonical acceptance policy.");
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            return new OwnedDeepSecret(accepted);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(initial.SessionInit); CryptographicOperations.ZeroMemory(initial.Hello);
            if (accepted is not null) CryptographicOperations.ZeroMemory(accepted);
        }
    }

    private async Task RetainMessageStoreEvidenceBeforeDispatchUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation, Did2StorePublicEvidence evidence, CancellationToken ct)
    {
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Store preparation lost mandatory acceptance custody.");
        var original = raw.Use(bytes => bytes.ToArray());
        try
        {
            using var commands = ProtectedDid2ContactAcceptJournal.Decode(original, scope.Network, scope.LocalAccount, scope.Instance);
            var winner = commands.FindScope(scope);
            if (winner is null || !FixedRoute(winner.Operation, operation.Span))
            {
                await RetainOrdinaryStoreEvidenceBeforeDispatchUnderLeaseAsync(current, held, opened, scope, operation,
                    evidence, ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2ContactAcceptJournal.Slot, original, ct).ConfigureAwait(false);
                return;
            }
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
            await RequireRetainedContactAcceptEventUnderLeaseAsync(held, opened, application, winner, operation, ct).ConfigureAwait(false);
            var attempt = await RequireCurrentStoreEvidenceAttemptUnderLeaseAsync(current, held, opened, scope, operation,
                ReadOnlyMemory<byte>.Empty, evidence, ct).ConfigureAwait(false);
            try { await application.RecordStorePublicEvidenceAsync(scope, operation, attempt, evidence, ct).ConfigureAwait(false); }
            finally { CryptographicOperations.ZeroMemory(attempt); }
            await RequireRetainedContactAcceptEventUnderLeaseAsync(held, opened, application, winner, operation, ct).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2ContactAcceptJournal.Slot, original, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive();
        }
        finally { CryptographicOperations.ZeroMemory(original); }
    }

    private static void RequireRetainedStoreOwnScope(Did2MessagingSessionScope scope,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own)
    {
        var checkpoint = own.Proof.CurrentCheckpoint ?? throw new CryptographicException("Retained Store has no current owned directory.");
        var directory = checkpoint.Directory.Record;
        var device = checkpoint.Binding.Identity.ActiveDevices.SingleOrDefault(item => FixedRoute(item.Certificate.DeviceId.Span, scope.LocalDevice));
        if (!FixedRoute(directory.NetworkId.Span, scope.Network) || !FixedRoute(directory.DeepAccountId.Span, scope.LocalAccount) ||
            !FixedRoute(directory.RecordHash.Span, scope.LocalDirectory) ||
            directory.AccountGeneration != BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]) ||
            device is null || device.Certificate.DeviceGeneration != scope.LocalDeviceGeneration)
            throw new CryptographicException("Retained Store does not belong to the independently current owned endpoint.");
    }

    private static async Task<VerifiedMailboxDurableQuorumV3> VerifyOriginalStoreOutcomeAsync(
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> attempt, ReadOnlyMemory<byte> actualEnvelope,
        SqliteDeepMailboxStore application, ParsedContactRouteClosure route, Did2StorePublicEvidence metadata,
        VerifiedMailboxStoreReplicaEvidence replicas, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, ulong currentUpper, CancellationToken ct)
    {
        var logical = MailboxSendOperation(scope, attempt.Span, actualEnvelope.Span);
        if (!FixedRoute(logical, metadata.Logical.Span))
            throw new CryptographicException("Original Store identity differs from its committed native event.");
        var read = await application.ReadTransportOutboxAsync(OutboxAccountScope.FromBytes(metadata.AccountScope.Span), OutboxLogicalId.FromBytes(logical), ct).ConfigureAwait(false);
        if (read is not { Result: TransportOutboxReadResult.Found, Item.State: TransportOutboxState.Durable or TransportOutboxState.Delivered })
            throw new CryptographicException("Compacted work has no durable original SQL transport outcome.");
        // Neither status nor recipient acknowledgement authenticates Store.
        // Verify the unchanged original Durable attempt below in either state.
        var exact = read.Item.GetCiphertextBundleCopy();
        var quorum = read.Item.Attempts.Single(attempt => attempt.State == TransportOutboxAttemptState.Durable).GetEvidenceCopy();
        try
        {
            var result = await VerifyOriginalStoreReplyAsync(scope, actualEnvelope, route, metadata, replicas,
                own, source, currentUpper, read.Item, exact, quorum, ct).ConfigureAwait(false);
            var request = MailboxAuthenticatedClientRequestCodec.Decode(exact);
            var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Binding.CanonicalRequest.Span);
            await application.RequireRetainedCoordinatorStatementAsync(request.Presentation.Grant, result,
                body.ExpiresAtUnixSeconds, ct).ConfigureAwait(false);
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(quorum); CryptographicOperations.ZeroMemory(logical); }
    }

    // Authentication of an untrusted original reply. This does not install
    // a grant, mutate SQL, renew admission or authorize a fresh dispatch.
    private static async Task<VerifiedMailboxDurableQuorumV3> VerifyOriginalStoreReplyAsync(
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> actualEnvelope,
        ParsedContactRouteClosure route, Did2StorePublicEvidence metadata,
        VerifiedMailboxStoreReplicaEvidence replicas, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, ulong currentUpper, TransportOutboxItemSnapshot snapshot,
        ReadOnlyMemory<byte> exact, ReadOnlyMemory<byte> quorum, CancellationToken ct)
    {
        var logical = metadata.Logical.ToArray();
        try
        {
            var mau = MailboxAuthenticatedClientRequestCodec.Decode(exact.Span);
            var grant = mau.Presentation.Grant;
            if (mau.Binding.Operation != MailboxAuthenticatedOperation.Store || !FixedRoute(mau.Binding.OperationId.Span, logical) ||
                !FixedRoute(metadata.AccountScope.Span, VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span).Value) ||
                !FixedRoute(snapshot.LogicalId.Value, logical) ||
                !FixedRoute(snapshot.DedupMaterial.Value, mau.Binding.RequestDigest.Span) ||
                !PublicKeyAuth.VerifyDetached(mau.Presentation.HolderSignature.ToArray(),
                    MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(mau.Presentation), grant.HolderPublicKey.ToArray()))
                throw new CryptographicException("Original Store request has no exact holder-signed native binding.");
            // Signed original interval only; this value never escapes as new
            // admission authority. Independently current own/network guards remain.
            var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(own.Network, own.Authority,
                own.MailboxAuthority.ExactPma2, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            await own.RequireOriginalMailboxNamespacesAsync(host, metadata.ExactPma, route.Projection,
                MailboxCapabilityDomain.Deposit, ct).ConfigureAwait(false);
            var policy = ContactCodec.Decode("PMA2", metadata.ExactPma.Span);
            var issuerKey = policy.Field(5);
            if (grant.NotBeforeUnixSeconds < BinaryPrimitives.ReadUInt64BigEndian(policy.Field(11).Span) ||
                grant.ExpiresAtUnixSeconds > BinaryPrimitives.ReadUInt64BigEndian(policy.Field(12).Span) ||
                grant.Domain != MailboxCapabilityDomain.Deposit || grant.Lifecycle != MailboxCapabilityLifecycle.Active ||
                !FixedRoute(grant.NetworkId.Span, scope.Network) || !FixedRoute(grant.IssuerPublicKey.Span, issuerKey.Span) ||
                grant.Generation < BinaryPrimitives.ReadUInt64BigEndian(policy.Field(7).Span) ||
                grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds > BinaryPrimitives.ReadUInt32BigEndian(policy.Field(8).Span) ||
                grant.Epoch != BinaryPrimitives.ReadUInt64BigEndian(route.Selection.Field(4).Span) ||
                !FixedRoute(grant.MembershipCommitment.Span, route.Projection.ArtifactHash.Span) ||
                !FixedRoute(grant.SelectionInput.Span, route.Selection.Field(3).Span) ||
                !PublicKeyAuth.VerifyDetached(grant.IssuerSignature.ToArray(),
                    MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), issuerKey.ToArray()))
                throw new CryptographicException("Original Store grant differs from its signed original policy/selector.");
            var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(mau.Binding.CanonicalRequest.Span);
            if (!FixedRoute(envelope.Ciphertext.Span, actualEnvelope.Span) || envelope.Epoch != grant.Epoch ||
                snapshot.ExpiresAt != DateTimeOffset.FromUnixTimeSeconds(checked((long)envelope.ExpiresAtUnixSeconds)) ||
                !FixedRoute(envelope.OperationId.Span, logical) ||
                !FixedRoute(envelope.MailboxId.Bytes.Span, route.Reachability.Field(2).Span) ||
                !FixedRoute(envelope.PlacementId.Bytes.Span, route.Reachability.Field(10).Span) ||
                !FixedRoute(MailboxPlacementCommitment.Compute(envelope.PlacementId), grant.PlacementCommitment.Span) ||
                envelope.CreatedAtUnixSeconds < grant.NotBeforeUnixSeconds || envelope.CreatedAtUnixSeconds >= grant.ExpiresAtUnixSeconds)
                throw new CryptographicException("Original Store body differs from the actual committed event/route.");
            var pinned = new ClientMailboxPinnedRoute(envelope.PlacementId, grant.MembershipCommitment.Span,
                replicas.FirstNodeId.Span, replicas.FirstReceiptPublicKey.Span, replicas.SecondNodeId.Span, replicas.SecondReceiptPublicKey.Span);
            var result = new PinnedClientMailboxReceiptVerifier(new SodiumMailboxPeerReplicationCrypto()).VerifyDurable(quorum.Span, new()
            {
                Epoch = grant.Epoch, OperationId = envelope.OperationId, MailboxId = envelope.MailboxId, Route = pinned,
                EnvelopeDigest = SHA256.HashData(actualEnvelope.Span), ExpiresAtUnixSeconds = envelope.ExpiresAtUnixSeconds,
                AllowedDispositions = new HashSet<MailboxReplicaDisposition> { MailboxReplicaDisposition.Stored, MailboxReplicaDisposition.Duplicate }
            });
            if (!FixedRoute(result.CoordinatorReceipt.CoordinatorId.Span, replicas.FirstNodeId.Span))
                throw new CryptographicException("Original Store receipt differs from its authenticated sole writer.");
            foreach (var receipt in result.ReplicaReceipts)
            {
                if (receipt.AcceptedAtUnixSeconds < grant.NotBeforeUnixSeconds || receipt.AcceptedAtUnixSeconds >= grant.ExpiresAtUnixSeconds)
                    throw new CryptographicException("Original Store receipt is outside its signed grant acceptance interval.");
                if (receipt.AcceptedAtUnixSeconds < envelope.CreatedAtUnixSeconds)
                    throw new CryptographicException("Original Store receipt precedes its exact object creation.");
                if (receipt.AcceptedAtUnixSeconds < replicas.OriginalViewNotBefore || receipt.AcceptedAtUnixSeconds >= replicas.OriginalViewExpiresAt)
                    throw new CryptographicException("Original Store receipt is outside its signed original view interval.");
                if (receipt.DurableAtUnixSeconds > currentUpper)
                    throw new CryptographicException("Original Store receipt is later than independently protected current time.");
            }
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(logical); }
    }

    private static async Task<ParsedContactRouteClosure> ReadInitialPeerStoreRouteAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened,
        SqliteDeepMailboxStore application, CancellationToken ct)
    {
        var scope = opened.Scope; var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        var initial = opened.Sql.ReadVerifiedActiveInitialEvents(floor); byte[]? accepted = null;
        try
        {
            var hello = ApplicationCoreCodec.DecodeDmc2(initial.Hello);
            if (hello.ParsedPayload is not ContactHelloDmc2Payload greeting ||
                !FixedRoute(hello.NetworkId.Span, scope.Network) || !FixedRoute(hello.ConversationId.Span, scope.Conversation) ||
                !FixedRoute(hello.SenderAccountId.Span, scope.IsInitiator ? scope.LocalAccount : scope.RemoteAccount) ||
                !FixedRoute(hello.SenderDeviceId.Span, scope.IsInitiator ? scope.LocalDevice : scope.RemoteDevice))
                throw new CryptographicException("Original peer route lost authenticated native Hello custody.");
            if (!scope.IsInitiator) { ct.ThrowIfCancellationRequested(); held.RequireActive(); return greeting.MailboxRoute.Route; }
            accepted = await application.ReadContactAcceptAsync(current.AccountId, BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]),
                scope.Conversation.ToArray(), scope.RemoteAccount.ToArray(), scope.RemoteDevice.ToArray(), ct).ConfigureAwait(false) ??
                throw new CryptographicException("Original peer route lost its acceptance projection.");
            using var received = opened.Sql.ReadVerifiedReceiveForEvent(floor, SHA256.HashData(accepted)) ??
                throw new CryptographicException("Original peer route lost actual authenticated acceptance custody.");
            using var plain = received.OwnAuthenticatedDmc2();
            if (!plain.Use(bytes => FixedRoute(bytes, accepted)))
                throw new CryptographicException("Original peer acceptance differs from the authenticated receive.");
            var response = ApplicationCoreCodec.DecodeDmc2(accepted);
            if (response.ParsedPayload is not ContactAcceptDmc2Payload consent ||
                !FixedRoute(response.NetworkId.Span, scope.Network) || !FixedRoute(response.ConversationId.Span, scope.Conversation) ||
                !FixedRoute(response.SenderAccountId.Span, scope.RemoteAccount) || !FixedRoute(response.SenderDeviceId.Span, scope.RemoteDevice) ||
                !FixedRoute(consent.RelationshipId.Span, scope.Relationship) || !FixedRoute(consent.ContactHelloHash.Span, SHA256.HashData(initial.Hello)))
                throw new CryptographicException("Original peer route differs from its authenticated conversation.");
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return consent.MailboxRoute.Route;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(initial.SessionInit); CryptographicOperations.ZeroMemory(initial.Hello);
            if (accepted is not null) CryptographicOperations.ZeroMemory(accepted);
        }
    }
}
