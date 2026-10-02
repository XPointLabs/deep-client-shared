using System.Security.Cryptography;
using Deep.Client.Shared.Services.AttachmentV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private async Task<ParsedDam1> ReadStableAttachmentManifestUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        SqliteDeepMailboxStore application, ReadOnlyMemory<byte> operation, CancellationToken ct)
    {
        held.RequireOwner(lease); ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage,
            networkId, current.AccountId, ct).ConfigureAwait(false);
        using var marker = await storage.ReadOwnedAsync(ProtectedDid2AttachmentJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Protected attachment custody is absent.");
        using var state = marker.Use(bytes => ProtectedDid2AttachmentJournal.Decode(bytes, networkId, current.AccountId.Span, instance));
        if (!state.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var entry) || entry.Pending)
            throw new CryptographicException("Only an exact stable owned asset may be offered.");
        using var asset = await application.ReconcileOwnedAttachmentsAsync(state, current.AccountId,
            current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.AccountGeneration,
            networkId, operation, ct).ConfigureAwait(false) ??
            throw new CryptographicException("An offered asset lost its exact SQL custody.");
        using var manifest = asset.OwnManifest();
        var result = manifest.Use(bytes => entry.RequireManifest(bytes, networkId));
        try { ct.ThrowIfCancellationRequested(); held.RequireActive(); return result; }
        catch { result.Dispose(); throw; }
    }

    private async Task RequireOwnedAttachmentForSendAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, ParsedDam1 offered,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, OnionMonotonicReading reading, CancellationToken ct)
    {
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage,
            networkId, current.AccountId, ct).ConfigureAwait(false);
        using var marker = await storage.ReadOwnedAsync(ProtectedDid2AttachmentJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Protected attachment custody is absent.");
        using var state = marker.Use(bytes => ProtectedDid2AttachmentJournal.Decode(bytes, networkId, current.AccountId.Span, instance));
        var entry = state.Entries.Values.SingleOrDefault(candidate => Did2MessagingSessionScope.Fixed(candidate.Object, offered.ObjectId.Span)) ??
            throw new CryptographicException("A raw attachment offer has no owned asset custody.");
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage,
            sqlStatePath, current, held, ct).ConfigureAwait(false);
        using var retained = await ReadStableAttachmentManifestUnderLeaseAsync(current, held, application, entry.Operation.ToArray(), ct).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(retained.CanonicalBytes.Span, offered.CanonicalBytes.Span))
            throw new CryptographicException("Attachment offer differs from its exact stable owned manifest.");
        RequireAttachmentOfferTime(retained, own, peer, reading);
    }

    private static void RequireAttachmentOfferTime(ParsedDam1 manifest,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, OnionMonotonicReading reading)
    {
        var upper = Math.Max(checked(own.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample),
            checked(peer.TrustedUpperUnixSeconds + reading.SampleSeconds - peer.MonotonicSample));
        if (manifest.ExpiresAtUnixSeconds <= checked(upper + 1))
            throw new CryptographicException("The offered asset cannot cover the current endpoint interval and authored time.");
    }

    internal async Task<OwnedAttachmentPreparation> ReadLocalAttachmentAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> operation, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span); var op = operation.ToArray(); byte[] root = [], stable = [];
        OwnedAttachmentPreparation? result = null;
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
            var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            using var marker = await storage.ReadOwnedAsync(ProtectedDid2AttachmentJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected attachment custody is absent.");
            root = marker.Use(bytes => bytes.ToArray()); using var state = ProtectedDid2AttachmentJournal.Decode(root, networkId, current.AccountId.Span, instance);
            var name = Convert.ToHexString(op);
            if (!state.Entries.TryGetValue(name, out var entry) || state.Pending is { } pending && !ReferenceEquals(entry, pending))
                throw new InvalidOperationException("The exact adopted attachment operation must be resumed.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            result = await application.ReconcileOwnedAttachmentsAsync(state, current.AccountId,
                current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.AccountGeneration, networkId, op, ct).ConfigureAwait(false) ??
                throw new CryptographicException("An adopted attachment has no exact SQL readback.");
            if (entry.Pending)
            {
                state.Entries[name] = entry.Stabilize(); entry.Dispose();
                stable = ProtectedDid2AttachmentJournal.Encode(state, networkId, current.AccountId.Span, instance);
                ct.ThrowIfCancellationRequested(); held.RequireActive();
                if (!await storage.CompareExchangeAsync(ProtectedDid2AttachmentJournal.Slot, root, stable, ct).ConfigureAwait(false))
                    throw new CryptographicException("Attachment custody changed during exact recovery.");
            }
            ct.ThrowIfCancellationRequested(); held.RequireActive(); var released = result; result = null; return released;
        }
        finally { result?.Dispose(); foreach (var bytes in new[] { op, root, stable }) CryptographicOperations.ZeroMemory(bytes); }
    }

    internal async Task<OwnedAttachmentPreparation> PrepareLocalAttachmentAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> operation, Stream input, long length,
        string filename, string mediaType, ulong expiresAt, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span); ArgumentNullException.ThrowIfNull(input);
        if (length is < 1 or > 26214400) throw new ArgumentOutOfRangeException(nameof(length));
        var op = operation.ToArray(); byte[] root = [], pendingBytes = [], stableBytes = [], exact = [];
        OwnedAttachmentPreparation? result = null;
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
            var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            using var marker = await storage.ReadOwnedAsync(ProtectedDid2AttachmentJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected attachment custody is absent.");
            root = marker.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2AttachmentJournal.Decode(root, networkId, current.AccountId.Span, instance);
            var name = Convert.ToHexString(op); state.Entries.TryGetValue(name, out var entry);
            if (state.Pending is { } pending && !ReferenceEquals(pending, entry))
                throw new InvalidOperationException("Resume the existing pending attachment before adopting another.");
            if (entry is null && state.Entries.Count == ProtectedDid2AttachmentJournal.MaximumEntries)
                throw new InvalidOperationException("Attachment custody requires verified lifecycle rollover.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            var generation = current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.AccountGeneration;
            result = await application.ReconcileOwnedAttachmentsAsync(state, current.AccountId, generation, networkId,
                entry is null ? ReadOnlyMemory<byte>.Empty : op, ct).ConfigureAwait(false);
            if (entry is not null)
            {
                if (result is null) throw new CryptographicException("An adopted attachment has no SQL readback.");
                using var retained = result.OwnManifest(); using var manifest = retained.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
                if (manifest.TotalPlaintextBytes != (ulong)length || manifest.Filename != filename || manifest.MediaType != mediaType || manifest.ExpiresAtUnixSeconds != expiresAt)
                    throw new CryptographicException("A repeated attachment command changed its metadata.");
                await RequireExactAttachmentInputAsync(input, length, entry.PlaintextHash.ToArray(), ct).ConfigureAwait(false);
            }
            else
            {
                using var prepared = await AttachmentObjectPreparation.PrepareAsync(input, length, networkId, filename, mediaType, expiresAt, ct).ConfigureAwait(false);
                using var manifest = prepared.OwnManifest(); exact = manifest.Use(bytes => bytes.ToArray());
                entry = ProtectedDid2AttachmentJournal.Entry.Prepare(op, exact, prepared.PlaintextHash);
                state.Entries.Add(name, entry);
                await application.InsertAttachmentCandidateAsync(op, prepared, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2AttachmentTestHooks.Hit(Did2AttachmentFailpoint.AfterSqlBeforePending);
#endif
                pendingBytes = ProtectedDid2AttachmentJournal.Encode(state, networkId, current.AccountId.Span, instance);
                ct.ThrowIfCancellationRequested(); held.RequireActive();
                if (!await storage.CompareExchangeAsync(ProtectedDid2AttachmentJournal.Slot, root, pendingBytes, ct).ConfigureAwait(false))
                    throw new CryptographicException("Attachment custody changed under its account lease.");
#if DEEP_TEST_INTERNALS
                Did2AttachmentTestHooks.Hit(Did2AttachmentFailpoint.AfterPending);
#endif
                result = await application.ReconcileOwnedAttachmentsAsync(state, current.AccountId, generation, networkId, op, ct).ConfigureAwait(false);
                if (result is null) throw new CryptographicException("The adopted asset has no exact SQL readback.");
            }
            if (entry.Pending)
            {
                state.Entries[name] = entry.Stabilize(); entry.Dispose();
                stableBytes = ProtectedDid2AttachmentJournal.Encode(state, networkId, current.AccountId.Span, instance);
                ct.ThrowIfCancellationRequested(); held.RequireActive();
                if (!await storage.CompareExchangeAsync(ProtectedDid2AttachmentJournal.Slot,
                    pendingBytes.Length == 0 ? root : pendingBytes, stableBytes, ct).ConfigureAwait(false))
                    throw new CryptographicException("Pending attachment custody changed before stable adoption.");
#if DEEP_TEST_INTERNALS
                Did2AttachmentTestHooks.Hit(Did2AttachmentFailpoint.AfterStable);
#endif
            }
            ct.ThrowIfCancellationRequested(); held.RequireActive(); var released = result; result = null; return released!;
        }
        finally { result?.Dispose(); foreach (var bytes in new[] { op, root, pendingBytes, stableBytes, exact }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static async Task RequireExactAttachmentInputAsync(Stream input, long length, byte[] expected, CancellationToken ct)
    {
        var buffer = new byte[262144]; using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] digest = [];
        try
        {
            for (long offset = 0; offset < length;)
            {
                var count = (int)Math.Min(buffer.Length, length - offset);
                await input.ReadExactlyAsync(buffer.AsMemory(0, count), ct).ConfigureAwait(false); hash.AppendData(buffer.AsSpan(0, count));
                CryptographicOperations.ZeroMemory(buffer.AsSpan(0, count)); offset += count;
            }
            if (await input.ReadAsync(buffer.AsMemory(0, 1), ct).ConfigureAwait(false) != 0) throw new InvalidDataException("Attachment retry exceeds its exact input length.");
            digest = hash.GetHashAndReset();
            if (!Did2MessagingSessionScope.Fixed(digest, expected)) throw new CryptographicException("An attachment operation changed its plaintext.");
        }
        finally { foreach (var bytes in new[] { buffer, expected, digest }) CryptographicOperations.ZeroMemory(bytes); }
    }
}
