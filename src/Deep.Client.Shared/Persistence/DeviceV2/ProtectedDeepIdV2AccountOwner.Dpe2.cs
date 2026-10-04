using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Client.Shared.Persistence.MessagingV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<IReadOnlyList<DirectAttachmentOfferSnapshot>> ListMessagingAttachmentOffersAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
        if ((await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false)).Status != 1)
            throw new InvalidDataException("An inactive session cannot project attachment history.");
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        var entries = await application.ListDirectAttachmentOffersAsync(current.AccountId,
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope.Conversation.ToArray(),
            cancellationToken: ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireActive();
        return entries;
    }

    internal async Task<IReadOnlyList<DirectMessageCreateSnapshot>> ListMessagingMessagesAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (floor.Status != 1) throw new InvalidDataException("A latched or unactivated session grants no application projection.");
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
            storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        var messages = await application.ListDirectMessageCreatesAsync(current.AccountId,
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]),
            scope.Conversation.ToArray(), cancellationToken: ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireActive();
        return messages;
    }

    internal Task<OwnedDid2MessagingPersistedEvent> SendMessagingAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> exactDmc2, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct) =>
        RunMessagingAsync(trustedUnixSeconds, verifier, scope, operation, exactDmc2, true, own, peer, source, ct);

    internal Task<OwnedDid2MessagingPersistedEvent> ReceiveMessagingAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> exactDpe2,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct) =>
        RunMessagingAsync(trustedUnixSeconds, verifier, scope, ReadOnlyMemory<byte>.Empty, exactDpe2, false, own, peer, source, ct);

    private async Task<OwnedDid2MessagingPersistedEvent> RunMessagingAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> input, bool send, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (input.IsEmpty || input.Length > (send ? 33082 : 65536))
            throw new InvalidDataException("DID2 ordinary message exceeds its closed bound.");
        if (send) ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var exact = input.ToArray(); var op = operation.ToArray(); byte[] eventHash = [];
        OwnedDid2MessagingPersistedEvent? result = null;
        ParsedDmc2? senderEvent = null, stagedEvent = null;
        try
        {
            if (send)
            {
                var parsed = senderEvent = ApplicationCoreCodec.DecodeDmc2(exact);
                Deep.Client.Shared.Services.DeepIdV2AccountService.RequireOwnedSendKind(parsed.ContentKind);
                if (!Did2MessagingSessionScope.Fixed(parsed.NetworkId.Span, scope.Network) ||
                    !Did2MessagingSessionScope.Fixed(parsed.SenderAccountId.Span, scope.LocalAccount) ||
                    !Did2MessagingSessionScope.Fixed(parsed.SenderDeviceId.Span, scope.LocalDevice) ||
                    AuthenticatedDirectDmc2.IsDirectKind(parsed.ContentKind) &&
                    (parsed.SenderClientSequence < 3 || !Did2MessagingSessionScope.Fixed(parsed.ConversationId.Span, scope.Conversation)))
                    throw new CryptographicException("DID2 send event has a different owned endpoint.");
                eventHash = SHA256.HashData(exact);
            }
            else
            {
                var parsed = Dpe2Codec.Decode(exact);
                if (!Did2MessagingSessionScope.Fixed(parsed.NetworkId.Span, scope.Network) ||
                    !Did2MessagingSessionScope.Fixed(parsed.SessionId.Span, scope.Session) ||
                    !Did2MessagingSessionScope.Fixed(parsed.SenderDeviceId.Span, scope.RemoteDevice) ||
                    !Did2MessagingSessionScope.Fixed(parsed.RecipientDeviceId.Span, scope.LocalDevice))
                    throw new CryptographicException("DID2 receive envelope has a different session endpoint.");
                op = parsed.OperationId.ToArray();
            }
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
            var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
            OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(
                storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (senderEvent?.ContentKind == Dmc2ContentKind.ContactAccept)
                await RequireLocalContactAcceptWinnerAsync(scope, op, exact, ct).ConfigureAwait(false);
            if (senderEvent?.ContentKind is
                Dmc2ContentKind.MessageCreate or Dmc2ContentKind.AttachmentOffer)
                await RequireOwnedTextForSendAsync(current, held, scope, op, exact, ct).ConfigureAwait(false);
            if (senderEvent?.ParsedPayload is AttachmentOfferDmc2Payload attachment)
                await RequireOwnedAttachmentForSendAsync(current, held, attachment.Manifest, own, peer, first, ct).ConfigureAwait(false);
            if (send)
            {
                result = opened.Sql.ReadVerifiedOperation(floor, op);
                if (result is not null)
                {
                    if (result.Direction != 1) throw new CryptographicException("DID2 local operation collides with a retained receive.");
                    if (!Did2MessagingSessionScope.Fixed(result.EventHash, eventHash))
                    {
                        var conflict = Did2OwnedSendConflict.Verify(opened.Sql, scope, floor, op, exact);
                        await opened.Custody.LatchOwnedSendAsync(conflict, ct).ConfigureAwait(false);
                        throw new CryptographicException("DID2 changed local send content durably latched the session.");
                    }
                }
            }
            if (result is null)
            {
                var context = opened.Sql.CreateVerifiedTransitionContext(floor, op, send ? [] : exact);
                using var state = opened.Sql.ReadVerifiedLatest(floor);
                var authority = new AccountDpe2Authority(opened, held, floor, op, eventHash, send ? [] : exact,
                    context.ReceiveReplayDisposition);
                if (send)
                {
                    using var prepared = state.Use(bytes => ExactDpe2DurableTransactionProducer.PrepareSend(
                        bytes, context, exact, scope.Network, op));
                    state.Dispose(); // Do not retain the owner copy of old TRS across durable commit.
                    using var success = await prepared.CommitAsync(authority, ct).ConfigureAwait(false);
                }
                else
                {
                    using var prepared = state.Use(bytes => ExactDpe2DurableTransactionProducer.PrepareReceive(bytes, context, exact));
                    state.Dispose();
                    using var success = await prepared.CommitAsync(authority, ct).ConfigureAwait(false);
                }
                // Read the actual committed row, also on exact replay. Never use
                // an in-memory success payload as crash/materialization evidence.
                var stable = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                result = opened.Sql.ReadVerifiedOperation(stable, op) ??
                    throw new CryptographicException("DID2 committed message has no durable event readback.");
            }
            // The committed row is the handoff source, not the Protocol success
            // payload. Group/contact controls need separate state consumers.
            using var received = send ? null : result.OwnAuthenticatedDmc2();
            stagedEvent = send ? senderEvent! :
                received!.Use(bytes => ApplicationCoreCodec.DecodeDmc2(bytes));
            if (AuthenticatedDirectDmc2.IsDirectKind(stagedEvent.ContentKind))
            {
                var stable = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                using var handoff = AuthenticatedDirectDmc2.FromOwnedDid2Commit(opened, stable, op, send ? exact : []);
                using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                    storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
                RequireApplicationDisposition(await application.MaterializeDirectDmc2Async(handoff, ct).ConfigureAwait(false));
            }
            else if (stagedEvent.ContentKind == Dmc2ContentKind.ContactAccept)
            {
                using var handoff = await AuthenticatedContactAcceptDmc2.FromOwnedCommitAsync(opened, op, send ? exact : [],
                    storage, own, peer, source, held, ct).ConfigureAwait(false);
                using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                    storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
                RequireApplicationDisposition(await application.MaterializeContactAcceptAsync(handoff, ct).ConfigureAwait(false));
            }
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            if (senderEvent?.ParsedPayload is AttachmentOfferDmc2Payload offered)
            {
                var final = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
                if (final.SampleSeconds < first.SampleSeconds || !Did2MessagingSessionScope.Fixed(final.BootId.Span, first.BootId.Span))
                    throw new CryptographicException("Attachment offer send crossed protected clock continuity.");
                RequireAttachmentOfferTime(offered.Manifest, own, peer, final);
            }
            var released = result; result = null; return released;
        }
        finally
        {
            if (senderEvent?.ParsedPayload is AttachmentOfferDmc2Payload sentAttachment) sentAttachment.Manifest.Dispose();
            if (!ReferenceEquals(senderEvent, stagedEvent) && stagedEvent?.ParsedPayload is AttachmentOfferDmc2Payload receivedAttachment)
                receivedAttachment.Manifest.Dispose();
            result?.Dispose(); CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(eventHash);
        }
    }

    // No externally constructible authority, callback or raw-store adapter.
    // Its inputs are captured by the one account operation while holding its
    // real lease; both initial-key retirement and current heads were verified.
    private sealed class AccountDpe2Authority(OwnedDid2MessagingStorage opened, HeldDeepIdV2AccountLease held,
        Did2MessagingFloor floor, byte[] operation, byte[] sendEventHash, byte[] receivedEnvelope,
        ExactDpe2ReceiveReplayDisposition replay) : IExactDpe2DurableTransactionAuthority
    {
        private int consumed;
        public async ValueTask<ExactDpe2DurableCommitReceipt> CommitAsync(ExactDpe2DurablePersistencePlan plan,
            ExactDpe2DurableCommitCompletion completion, CancellationToken cancellationToken = default)
        {
            held.RequireActive(); cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Exchange(ref consumed, 1) != 0)
                throw new InvalidOperationException("DID2 account transaction authority is single-use.");
            using var snapshot = ExactDpe2ProtocolPlanSnapshot.Capture(plan);
            var send = sendEventHash.Length != 0;
            if (snapshot.Direction != (send ? MessagingCryptoV1Direction.Send : MessagingCryptoV1Direction.Receive) ||
                !Did2MessagingSessionScope.Fixed(snapshot.OperationId, operation) ||
                snapshot.PriorStateGeneration != floor.RatchetGeneration ||
                snapshot.CheckpointPriorGeneration != floor.RatchetGeneration || snapshot.ExpectedJournalGeneration != floor.Ordinal ||
                !Did2MessagingSessionScope.Fixed(snapshot.JournalPredecessor, floor.Head) ||
                !Did2MessagingSessionScope.Fixed(snapshot.PriorStateCommitment, floor.RatchetCommitment) ||
                !Did2MessagingSessionScope.Fixed(snapshot.CheckpointPriorCommitment, floor.RatchetCommitment) ||
                !Did2MessagingSessionScope.Fixed(SHA256.HashData(snapshot.PriorTrs1), floor.RatchetHash) ||
                !send && !Did2MessagingSessionScope.Fixed(snapshot.ExactEnvelope, receivedEnvelope) ||
                snapshot.HasStateMutation != (replay == ExactDpe2ReceiveReplayDisposition.Fresh))
                throw new CryptographicException("DID2 sealed operation differs from its owned durable preparation.");
            var current = await opened.Custody.ReconcileAsync(cancellationToken).ConfigureAwait(false);
            if (!Did2MessagingSessionScope.Fixed(current.Exact.Span, floor.Exact.Span))
                throw new CryptographicException("DID2 operation predecessor changed under the held lease.");
            if (snapshot.HasStateMutation)
            {
                using var mutation = OwnedDid2MessagingMutation.Ratchet(opened.Scope, floor, plan, sendEventHash);
                current = await opened.Custody.CommitOwnedAsync(mutation, cancellationToken).ConfigureAwait(false);
            }
            using var retained = opened.Sql.ReadVerifiedOperation(current, operation) ??
                throw new CryptographicException("DID2 transaction has no verified durable event.");
            if (retained.Direction != (send ? 1 : 2) ||
                !Did2MessagingSessionScope.Fixed(retained.ExactEnvelope, snapshot.ExactEnvelope) ||
                send && !Did2MessagingSessionScope.Fixed(retained.EventHash, sendEventHash))
                throw new CryptographicException("DID2 durable event differs from its sealed transaction.");
            cancellationToken.ThrowIfCancellationRequested(); held.RequireActive();
            return completion.Complete(snapshot.HasStateMutation ? ExactDpe2DurableCommitDisposition.Committed :
                ExactDpe2DurableCommitDisposition.ExactReplay);
        }
    }
}
