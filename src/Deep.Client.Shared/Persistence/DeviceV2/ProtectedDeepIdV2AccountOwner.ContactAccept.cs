using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal enum Did2ContactAcceptanceState
{
    IncomingRequest = 1, OutgoingRequest = 2, LocalAcceptanceRetained = 3, PeerAcceptanceRetained = 4,
}

internal sealed class OwnedDid2ContactAcceptDraft : IDisposable
{
    private byte[]? operation, exact;
    internal OwnedDid2ContactAcceptDraft(ProtectedDid2ContactAcceptJournal.Entry winner)
    { operation = winner.Operation.ToArray(); exact = winner.Accept.ToArray(); }
    internal ReadOnlySpan<byte> Operation => operation ?? throw new ObjectDisposedException(nameof(OwnedDid2ContactAcceptDraft));
    internal ReadOnlySpan<byte> ExactDmc2 => exact ?? throw new ObjectDisposedException(nameof(OwnedDid2ContactAcceptDraft));
    public void Dispose()
    {
        var op = Interlocked.Exchange(ref operation, null); var bytes = Interlocked.Exchange(ref exact, null);
        if (op is not null) CryptographicOperations.ZeroMemory(op);
        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        GC.SuppressFinalize(this);
    }
    ~OwnedDid2ContactAcceptDraft() => Dispose();
}

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<Did2ContactAcceptanceState> ReadContactAcceptanceAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
        using var pending = await AuthenticatedInitialDmc2Batch.FromOwnedDid2Async(opened, own, peer, source, held, ct).ConfigureAwait(false);
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        var responder = scope.IsInitiator ? scope.RemoteAccount.ToArray() : scope.LocalAccount.ToArray();
        var device = scope.IsInitiator ? scope.RemoteDevice.ToArray() : scope.LocalDevice.ToArray();
        byte[]? accepted = null; var hello = pending.FirstApplicationDmc2;
        try
        {
            accepted = await application.ReadContactAcceptAsync(current.AccountId, pending.LocalAccountGeneration,
                scope.Conversation.ToArray(), responder, device, ct).ConfigureAwait(false);
            if (accepted is not null)
            {
                var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                if (scope.IsInitiator)
                {
                    using var received = opened.Sql.ReadVerifiedReceiveForEvent(floor, SHA256.HashData(accepted)) ??
                        throw new CryptographicException("Peer acceptance has no actual authenticated receive custody.");
                    using var plain = received.OwnAuthenticatedDmc2();
                    if (!plain.Use(bytes => Did2MessagingSessionScope.Fixed(bytes, accepted)))
                        throw new CryptographicException("Peer acceptance differs from actual receive custody.");
                }
                else
                {
                    using var marker = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                        throw new InvalidDataException("Local acceptance has no protected explicit command.");
                    using var commands = marker.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                    var winner = commands.FindScope(scope) ?? throw new CryptographicException("Local acceptance has no protected winner.");
                    using var sent = opened.Sql.ReadVerifiedOperation(floor, winner.Operation) ?? throw new CryptographicException("Local acceptance was not durably sent.");
                    if (sent.Direction != 1 || !Did2MessagingSessionScope.Fixed(winner.Accept, accepted) ||
                        !Did2MessagingSessionScope.Fixed(sent.EventHash, SHA256.HashData(accepted)))
                        throw new CryptographicException("Local acceptance differs from its actual command/send custody.");
                }
                await ApplicationCoreVerifier.RequireContactAcceptEndpointBindingsAsync(ApplicationCoreCodec.DecodeDmc2(accepted),
                    ApplicationCoreCodec.DecodeDmc2(hello), scope.IsInitiator ? own.Proof : peer,
                    scope.IsInitiator ? peer : own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            }
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            return accepted is null ? scope.IsInitiator ? Did2ContactAcceptanceState.OutgoingRequest : Did2ContactAcceptanceState.IncomingRequest :
                scope.IsInitiator ? Did2ContactAcceptanceState.PeerAcceptanceRetained : Did2ContactAcceptanceState.LocalAcceptanceRetained;
        }
        finally
        {
            foreach (var bytes in new[] { responder, device, hello }) CryptographicOperations.ZeroMemory(bytes);
            if (accepted is not null) CryptographicOperations.ZeroMemory(accepted);
        }
    }

    private async Task RequireLocalContactAcceptWinnerAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> exact, CancellationToken ct)
    {
        if (scope.IsInitiator) throw new CryptographicException("The initiator cannot author the responder acceptance.");
        using var snapshot = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Explicit local contact acceptance custody is absent.");
        using var journal = snapshot.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes,
            scope.Network, scope.LocalAccount, scope.Instance));
        var winner = journal.FindScope(scope);
        if (winner is null || !Did2MessagingSessionScope.Fixed(winner.Operation, operation.Span) ||
            !Did2MessagingSessionScope.Fixed(winner.Accept, exact.Span))
            throw new CryptographicException("Only the exact protected explicit acceptance winner may be sent.");
    }

    // Explicit local command. Its recoverable draft is not a DPE2, active
    // contact, semantic receipt, transport route or mailbox ACK.
    internal async Task<OwnedDid2ContactAcceptDraft> PrepareContactAcceptAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope); ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        if (scope.IsInitiator) throw new CryptographicException("Only the pending recipient can explicitly accept this Hello.");
        var op = operation.ToArray(); byte[] before = [], after = [], helloBytes = [];
        OwnedDid2ContactAcceptDraft? draft = null;
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
            var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
            OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(
                storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
            using var pending = await AuthenticatedInitialDmc2Batch.FromOwnedDid2Async(opened, own, peer, source, held, ct).ConfigureAwait(false);
            helloBytes = pending.FirstApplicationDmc2;
            using var protectedJournal = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected acceptance custody is absent; no regeneration is permitted.");
            before = protectedJournal.Use(bytes => bytes.ToArray());
            using var journal = ProtectedDid2ContactAcceptJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
            if (journal.Entries.TryGetValue(Convert.ToHexString(op), out var priorOperation) &&
                !Did2MessagingSessionScope.Fixed(priorOperation.Scope.Exact, scope.Exact))
                throw new CryptographicException("Local acceptance operation belongs to another pending contact.");
            var winner = journal.FindScope(scope);
            if (winner is null)
            {
                var hello = ApplicationCoreCodec.DecodeDmc2(helloBytes);
                var upper = Math.Max(checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample),
                    checked(peer.TrustedUpperUnixSeconds + first.SampleSeconds - peer.MonotonicSample));
                var created = Math.Max(checked(hello.CreatedAtUnixMilliseconds + 1), checked((upper + 1) * 1000));
                RequireAcceptDraftExpiry(hello.ExpiresAtUnixMilliseconds, created);
                if (journal.Entries.Count == ProtectedDid2ContactAcceptJournal.MaximumEntries)
                    throw new IOException("Protected acceptance custody is full.");
                if (journal.Entries.ContainsKey(Convert.ToHexString(op)))
                    throw new CryptographicException("Local acceptance operation belongs to another pending contact.");
                using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                    storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
                await application.RequireUnusedContactAcceptPositionAsync(scope.LocalAccount.ToArray(),
                    BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope.Conversation.ToArray(),
                    scope.LocalDevice.ToArray(), ct).ConfigureAwait(false);
                var rendezvous = await SqliteDeepIdV2AccountGeneration.EnsureContactRendezvousUnderLeaseAsync(
                    storage, current, op, own, first, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                var expiry = Math.Min(hello.ExpiresAtUnixMilliseconds,
                    checked((BinaryPrimitives.ReadUInt64BigEndian(rendezvous.Record.Field(12).Span) - 1) * 1000));
                RequireAcceptDraftExpiry(expiry, created);
                var logical = ProtectedDid2ContactAcceptJournal.LogicalId(scope, op);
                try
                {
                    using var publication = await OpenOwnPermanentMailboxPublicationUnderLeaseAsync(current, held, source, own, ct).ConfigureAwait(false);
                    var mailbox = Deep.Protocol.ContactV2.DeepIdV2ContactMailboxRouteCodec.Decode(
                        Deep.Protocol.ContactV2.DeepIdV2ContactMailboxRouteCodec.Encode(publication.Route));
                    var authored = await ApplicationCoreCodec.AuthorVerifiedContactAcceptAsync(hello, peer, rendezvous, mailbox,
                        logical, 3, created, expiry, source.RendezvousTrustedTime, cancellationToken: ct).ConfigureAwait(false);
                    await publication.RecheckAsync(ct).ConfigureAwait(false);
                    winner = ProtectedDid2ContactAcceptJournal.Entry.FromAuthor(scope, op, helloBytes, authored);
                }
                finally { CryptographicOperations.ZeroMemory(logical); }
                journal.Entries.Add(Convert.ToHexString(op), winner);
                after = ProtectedDid2ContactAcceptJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
                ct.ThrowIfCancellationRequested(); held.RequireActive();
                if (!await storage.CompareExchangeAsync(ProtectedDid2ContactAcceptJournal.Slot, before, after, ct).ConfigureAwait(false))
                    throw new CryptographicException("Acceptance custody changed under its account lease.");
            }
            if (!Did2MessagingSessionScope.Fixed(winner.HelloHash, SHA256.HashData(helloBytes)))
                throw new CryptographicException("Retained acceptance belongs to another exact pending Hello.");
            await ApplicationCoreVerifier.RequireContactAcceptEndpointBindingsAsync(ApplicationCoreCodec.DecodeDmc2(winner.Accept),
                ApplicationCoreCodec.DecodeDmc2(helloBytes), peer, own.Proof, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            draft = new(winner);
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            var result = draft; draft = null; return result;
        }
        finally
        {
            draft?.Dispose(); CryptographicOperations.ZeroMemory(op); CryptographicOperations.ZeroMemory(before);
            CryptographicOperations.ZeroMemory(after); CryptographicOperations.ZeroMemory(helloBytes);
        }
    }

    // Reject an expired request before allocating rendezvous/accept custody;
    // never mint a malformed Accept or extend its authenticated Hello interval.
    internal static void RequireAcceptDraftExpiry(ulong expiresAtMilliseconds, ulong createdAtMilliseconds)
    {
        if (expiresAtMilliseconds <= createdAtMilliseconds)
            throw new InvalidOperationException("The contact request has expired; a new Hello is required.");
    }
}
