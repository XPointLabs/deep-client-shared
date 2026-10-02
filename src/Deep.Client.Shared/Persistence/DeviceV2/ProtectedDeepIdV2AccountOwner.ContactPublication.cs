using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<VerifiedDeepIdV2PublicationAuthorization> EnsureContactPublicationAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        Did2ContactRouteConfiguration configuration, IDid2ContactPublicationSource publicationSource, CancellationToken ct)
    {
        var result = await EnsureContactPublicationCoreAsync(trustedUnixSeconds, verifier, intent,
            source, fresh, configuration, publicationSource, null, ct).ConfigureAwait(false);
        return result.Authorization ?? throw new InvalidOperationException("Publication authorization is absent.");
    }

    internal async Task<VerifiedDeepIdV2PublicationCommit> EnsureContactPublicationCommitAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        Did2ContactRouteConfiguration configuration, IDid2ContactPublicationSource publicationSource,
        IDid2ContactReplicaPublicationTransport transport, CancellationToken ct,
        Did2OwnedPermanentContactPlan? bootstrap = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        var result = await EnsureContactPublicationCoreAsync(trustedUnixSeconds, verifier, intent,
            source, fresh, configuration, publicationSource, transport, ct, bootstrap).ConfigureAwait(false);
        return result.Commit ?? throw new InvalidOperationException("Publication commit is absent.");
    }

    private async Task<(VerifiedDeepIdV2PublicationAuthorization? Authorization, VerifiedDeepIdV2PublicationCommit? Commit)>
        EnsureContactPublicationCoreAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        Did2ContactRouteConfiguration configuration, IDid2ContactPublicationSource publicationSource,
        IDid2ContactReplicaPublicationTransport? transport, CancellationToken ct,
        Did2OwnedPermanentContactPlan? bootstrap = null)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        var first = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[]? snapshot = null; byte[]? capability = null;
        try
        {
            RequirePermanentContactPlan(bootstrap, current, instance, intent.Span);
            using var owned = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected publication custody is absent; explicit local reset is required.");
            snapshot = owned.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2ContactRouteJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var name = Convert.ToHexString(intent.Span);
            if (!state.Entries.TryGetValue(name, out var entry) || entry.Phase < 4 || !entry.Matches(configuration))
                throw new CryptographicException("Publication requires exact retained contact object custody.");
            var checkpoint = fresh.Proof.CurrentCheckpoint!;
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(entry.Record(0).Span), checkpoint.Binding, checkpoint.Directory);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, first.BootId.Span, first.SampleSeconds);
            var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(authorization, fresh.Network, fresh.Authority,
                entry.Record(5), entry.Record(6), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var permanent = await new ProtectedDeepIdV2ResolverCapabilityStore(storage, networkId, current.AccountId.Span)
                .ReadVerifiedAsync(checkpoint.Binding.DeepId, ct).ConfigureAwait(false);
            capability = permanent.ResolverReadCapability.ToArray();
            var contact = await DeepIdV2ContactObjectAuthor.RestoreAsync(route, entry.Record(7), entry.Record(8), capability, ct).ConfigureAwait(false);
            if (entry.Phase == 4)
            {
                var nonce = RandomNumberGenerator.GetBytes(32); var operation = RandomNumberGenerator.GetBytes(32);
                var retrieve = RandomNumberGenerator.GetBytes(32);
                try
                {
                    var candidate = await DeepIdV2PublicationAuthorityAuthor.AuthorGenesisRequestAsync(route, contact,
                        current.Verified.DeviceSecrets, nonce, operation, retrieve, ct).ConfigureAwait(false);
                    await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                    var next = entry.WithPublicationRequest(candidate.WireRequest, networkId, current.AccountId.Span);
                    state.Entries[name] = next; entry.Dispose(); entry = next;
                    var adopted = await SaveRouteJournalAsync(state, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
                }
                finally
                { CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(operation); CryptographicOperations.ZeroMemory(retrieve); }
            }
            // The exact request, including nonce and owner Retrieve, is durable
            // and independently read back before the first external callback.
            var request = ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span);
            // A retained commit is historical evidence, never a renewal of its
            // short-lived request/XPA dispatch permission.
            if (entry.Phase < 7 || transport is null)
                await DeepIdV2PublicationAuthorityAuthor.VerifyRequestAsync(route, request, ct).ConfigureAwait(false);
            if (entry.Phase == 5)
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(TimeSpan.FromSeconds(30));
                var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease,
                    sqlStatePath, current, source.AccountOwner, held, deadline.Token).ConfigureAwait(false);
                var dispatch = new Did2OwnedContactTransportContext(custody, fresh.Network, held);
                var returned = await publicationSource.FetchAsync(request, dispatch, deadline.Token).AsTask()
                    .WaitAsync(deadline.Token).ConfigureAwait(false);
                if (returned.Length is < ContactPublicationAuthorityWireCodec.MinimumResponseBytes or > ContactPublicationAuthorityWireCodec.MaximumResponseBytes)
                    throw new InvalidDataException("Publication response exceeds its exact bound.");
                var response = returned.ToArray();
                try
                {
                    var wire = ContactPublicationAuthorityWireCodec.DecodeResponse(request, response);
                    _ = await DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(route, request, wire.ExactXpu1, deadline.Token).ConfigureAwait(false);
                    await RecheckRouteFreshnessAsync(current, source, fresh, held, first, deadline.Token).ConfigureAwait(false);
                    var next = entry.WithPublicationResponse(response, networkId, current.AccountId.Span);
                    state.Entries[name] = next; entry.Dispose(); entry = next;
                    var adopted = await SaveRouteJournalAsync(state, snapshot, current.AccountId, instance, deadline.Token).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
                }
                finally { CryptographicOperations.ZeroMemory(response); }
            }
            var winner = ContactPublicationAuthorityWireCodec.DecodeResponse(request, entry.Record(10).Span);
            VerifiedDeepIdV2PublicationAuthorization? authorized = null;
            if (entry.Phase < 7 || transport is null)
                authorized = await DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(route, request, winner.ExactXpu1, ct).ConfigureAwait(false);
            await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
            if (transport is null)
            {
                ct.ThrowIfCancellationRequested(); held.RequireActive(); return (authorized, null);
            }
            if (entry.Phase == 6)
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(TimeSpan.FromSeconds(30));
                var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease,
                    sqlStatePath, current, source.AccountOwner, held, deadline.Token).ConfigureAwait(false);
                var dispatch = new Did2OwnedContactTransportContext(custody, fresh.Network, held);
                var returned = await transport.PublishAsync(winner.ExactXpu1, dispatch, deadline.Token)
                    .WaitAsync(deadline.Token).ConfigureAwait(false);
                if (returned.Length is < 256 or > DeepIdV2PublicationCommitVerifier.MaximumResultBytes)
                    throw new InvalidDataException("Publication commit result exceeds its exact bound.");
                var response = returned.ToArray();
                try
                {
                    var committed = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(route, contact,
                        request, winner.ExactXpu1, response, deadline.Token).ConfigureAwait(false);
                    // A late callback cannot persist/return success after its dispatch
                    // permission expires, the floor changes, or the account resets.
                    _ = await DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(route, request,
                        winner.ExactXpu1, deadline.Token).ConfigureAwait(false);
                    await RecheckRouteFreshnessAsync(current, source, fresh, held, first, deadline.Token).ConfigureAwait(false);
                    var next = entry.WithPublicationCommit(committed, networkId, current.AccountId.Span);
                    state.Entries[name] = next; entry.Dispose(); entry = next;
                    var adopted = await SaveRouteJournalAsync(state, snapshot, current.AccountId, instance, deadline.Token).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
                }
                finally { CryptographicOperations.ZeroMemory(response); }
            }
            // Always independently verify the exact persisted/read-back winner;
            // phase 7 invokes neither threshold nor replica publication again.
            var result = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(route, contact,
                request, winner.ExactXpu1, entry.Record(11), ct).ConfigureAwait(false);
            await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return (null, result);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance);
            if (snapshot is not null) CryptographicOperations.ZeroMemory(snapshot);
            if (capability is not null) CryptographicOperations.ZeroMemory(capability);
        }
    }
}
