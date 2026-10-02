using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Local custody only. No prekey is consumed and no dispatch is authorized
    // by authoring this exact recoverable winner.
    internal async Task<OwnedDid2InitialContactDraft> PrepareInitialContactDraftAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent,
        DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(intent.Span);
        var op = intent.ToArray(); byte[] instance = [], before = [], after = [], metadata = new byte[288];
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
            var contact = await RecheckPermanentContactUnderLeaseAsync(current, source, resolved, held, ct).ConfigureAwait(false);
            var peer = contact.Contact.Authorization.Freshness;
            var first = await RequireMessagingFreshnessAsync(current, resolved.Own, peer, source, held, ct).ConfigureAwait(false);
            using var publication = await OpenOwnPermanentMailboxPublicationUnderLeaseAsync(current, held, source, resolved.Own, ct).ConfigureAwait(false);
            var mailbox = DeepIdV2ContactMailboxRouteCodec.Decode(DeepIdV2ContactMailboxRouteCodec.Encode(publication.Route));
            var ownCheckpoint = resolved.Own.Proof.CurrentCheckpoint!;
            var ownDmd = current.Verified.PublicEvidence.Directory.Record;
            // Exact prediction precedes rendezvous or claim mutation. The
            // actual records are independently bounded again by Entry.Create.
            ProtectedDid2ContactStartJournal.RequireInitialBucket(282 + 72 + ownDmd.CanonicalBytes.Length,
                282 + 682 + mailbox.ExactBytes.Length);
            FillInitialContactMetadata(metadata, op, contact.Contact, ownCheckpoint);
            instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected initial contact draft custody is absent; explicit reset is required.");
            before = root.Use(bytes => bytes.ToArray());
            using var journal = ProtectedDid2ContactStartJournal.Decode(before, networkId, current.AccountId.Span, instance);
            var name = Convert.ToHexString(op);
            if (!journal.Entries.TryGetValue(name, out var winner))
            {
                if (journal.Entries.Count >= ProtectedDid2ContactStartJournal.MaximumEntries)
                    throw new IOException("Protected initial contact draft custody is full.");
                var predictedSize = ProtectedDid2ContactStartJournal.HeaderBytes +
                    journal.Entries.Values.Sum(entry => 4 + entry.Exact.Length) + 4 +
                    ProtectedDid2ContactStartJournal.PrefixBytes + 282 + 72 + ownDmd.CanonicalBytes.Length + 282 + 682 + mailbox.ExactBytes.Length;
                if (predictedSize > ProtectedDid2ContactStartJournal.MaximumBytes)
                    throw new IOException("Protected initial contact draft byte capacity is exhausted.");
                var authoringReading = await RequireMessagingFreshnessAsync(current, resolved.Own, peer, source, held, ct).ConfigureAwait(false);
                if (authoringReading.SampleSeconds < first.SampleSeconds || !FixedRoute(authoringReading.BootId.Span, first.BootId.Span))
                    throw new CryptographicException("Initial draft authoring crossed protected clock continuity.");
                var rendezvous = await SqliteDeepIdV2AccountGeneration.EnsureContactRendezvousUnderLeaseAsync(
                    storage, current, op, resolved.Own, authoringReading, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                var upper = Math.Max(checked(resolved.Own.Proof.TrustedUpperUnixSeconds + authoringReading.SampleSeconds - resolved.Own.Proof.MonotonicSample),
                    checked(peer.TrustedUpperUnixSeconds + authoringReading.SampleSeconds - peer.MonotonicSample));
                var created = checked((upper + 1) * 1000);
                var expiry = Math.Min(checked(created + 3_600_000),
                    checked((BinaryPrimitives.ReadUInt64BigEndian(rendezvous.Record.Field(12).Span) - 1) * 1000));
                RequireAcceptDraftExpiry(expiry, checked(created + 1));
                var relationship = NewRouteRandom32(); var initLogical = NewRouteRandom32(); var helloLogical = NewRouteRandom32(); var nonce = NewRouteRandom32();
                byte[] conversation = [];
                try
                {
                    while (FixedRoute(initLogical, helloLogical) || helloLogical.AsSpan().IndexOfAnyExcept((byte)0) < 0) RandomNumberGenerator.Fill(helloLogical);
                    conversation = ApplicationCoreVerifier.ComputeContactConversationId(networkId, relationship, current.AccountId.Span, metadata.AsSpan(64, 32));
                    var init = ApplicationCoreCodec.AuthorDmc2(networkId, initLogical, conversation, current.AccountId.Span,
                        mailbox.Authorization.PublisherDeviceId.Span, 1, created, expiry, Dmc2Flags.None, [],
                        ApplicationCoreCodec.CreateSessionInitPayload(nonce, ownDmd, SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl));
                    var hello = (await ApplicationCoreCodec.AuthorVerifiedContactHelloAsync(rendezvous, mailbox, peer,
                        relationship, helloLogical, conversation, checked(created + 1), expiry, source.RendezvousTrustedTime, cancellationToken: ct).ConfigureAwait(false)).Record;
                    winner = ProtectedDid2ContactStartJournal.Entry.Create(metadata, init, hello, networkId, current.AccountId.Span);
                    journal.Entries.Add(name, winner);
                    after = ProtectedDid2ContactStartJournal.Encode(journal, networkId, current.AccountId.Span, instance);
                }
                finally
                {
                    foreach (var bytes in new[] { relationship, initLogical, helloLogical, nonce, conversation }) CryptographicOperations.ZeroMemory(bytes);
                }
            }
            if (!FixedRoute(winner.Exact[..288], metadata))
                throw new CryptographicException("The retained contact intent belongs to another endpoint or exact peer contact.");
            var retainedHello = ApplicationCoreCodec.DecodeDmc2(winner.Hello);
            if (retainedHello.ParsedPayload is not ContactHelloDmc2Payload payload || !FixedRoute(payload.MailboxRoute.ExactBytes.Span, mailbox.ExactBytes.Span))
                throw new CryptographicException("The retained draft differs from the actual own publication.");
            async Task Recheck(CancellationToken token)
            {
                await publication.RecheckAsync(token).ConfigureAwait(false);
                await ApplicationCoreVerifier.RequireContactHelloEndpointBindingsAsync(retainedHello, resolved.Own.Proof, peer, source.RendezvousTrustedTime, token).ConfigureAwait(false);
                var time = await RequireClaimContactTimeAsync(current, source, resolved, held, contact.Contact, contact.Time, token).ConfigureAwait(false);
                if (time.MonotonicSample < first.SampleSeconds || !FixedRoute(time.BootId.Span, first.BootId.Span) ||
                    retainedHello.ExpiresAtUnixMilliseconds <= checked(time.UpperUnixSeconds * 1000))
                    throw new CryptographicException("The retained initial contact draft is expired or crossed clock continuity.");
                token.ThrowIfCancellationRequested(); held.RequireActive();
            }
            await Recheck(ct).ConfigureAwait(false);
            if (after.Length != 0 && !await storage.CompareExchangeAsync(ProtectedDid2ContactStartJournal.Slot, before, after, ct).ConfigureAwait(false))
                throw new CryptographicException("Initial contact draft custody changed under its account lease.");
            using var readback = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Initial contact draft custody disappeared before release.");
            if (!readback.Use(bytes => FixedRoute(bytes, after.Length == 0 ? before : after)))
                throw new CryptographicException("Initial contact draft custody differs from exact protected readback.");
            await Recheck(ct).ConfigureAwait(false);
            return new(winner, networkId, current.AccountId.Span);
        }
        finally
        {
            foreach (var bytes in new[] { op, instance, before, after, metadata }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task RequireInitialContactDraftForClaimUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved,
        VerifiedDeepIdV2PermanentContactResolveClosure contact,
        HeldDeepIdV2AccountLease held, ReadOnlyMemory<byte> intent, CancellationToken ct)
    {
        var first = await RequireMessagingFreshnessAsync(current, resolved.Own, contact.Authorization.Freshness, source, held, ct).ConfigureAwait(false);
        using var publication = await OpenOwnPermanentMailboxPublicationUnderLeaseAsync(current, held, source, resolved.Own, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[] snapshot = [], metadata = new byte[288];
        try
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("A protected initial contact draft is required before prekey claim.");
            snapshot = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2ContactStartJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            if (!state.Entries.TryGetValue(Convert.ToHexString(intent.Span), out var winner))
                throw new InvalidOperationException("An exact initial contact draft must be retained before prekey claim.");
            FillInitialContactMetadata(metadata, intent.Span, contact, resolved.Own.Proof.CurrentCheckpoint!);
            if (!FixedRoute(winner.Exact[..288], metadata))
                throw new CryptographicException("The retained initial draft belongs to another peer or endpoint generation.");
            var hello = ApplicationCoreCodec.DecodeDmc2(winner.Hello);
            var payload = (ContactHelloDmc2Payload)hello.ParsedPayload;
            if (!FixedRoute(payload.MailboxRoute.ExactBytes.Span, DeepIdV2ContactMailboxRouteCodec.Encode(publication.Route)))
                throw new CryptographicException("The retained initial draft has a different own publication.");
            await ApplicationCoreVerifier.RequireContactHelloEndpointBindingsAsync(hello, resolved.Own.Proof,
                contact.Authorization.Freshness, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var time = await contact.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
            if (time.MonotonicSample < first.SampleSeconds || !FixedRoute(time.BootId.Span, first.BootId.Span) ||
                hello.ExpiresAtUnixMilliseconds <= checked(time.UpperUnixSeconds * 1000))
                throw new CryptographicException("The retained initial contact draft is expired; it cannot authorize a claim.");
            await publication.RecheckAsync(ct).ConfigureAwait(false);
            using var readback = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("The protected initial draft disappeared before claim.");
            if (!readback.Use(bytes => FixedRoute(bytes, snapshot)))
                throw new CryptographicException("The protected initial draft changed before claim.");
            var final = await RequireMessagingFreshnessAsync(current, resolved.Own, contact.Authorization.Freshness, source, held, ct).ConfigureAwait(false);
            if (final.SampleSeconds < time.MonotonicSample || !FixedRoute(final.BootId.Span, time.BootId.Span) ||
                hello.ExpiresAtUnixMilliseconds <= checked((time.UpperUnixSeconds + final.SampleSeconds - time.MonotonicSample) * 1000))
                throw new CryptographicException("Initial draft claim release crossed its deadline or protected clock.");
            ct.ThrowIfCancellationRequested(); held.RequireActive();
        }
        finally { foreach (var bytes in new[] { instance, snapshot, metadata }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void FillInitialContactMetadata(Span<byte> metadata, ReadOnlySpan<byte> intent,
        VerifiedDeepIdV2PermanentContactResolveClosure contact, Deep.Protocol.AccountDirectoryV1.VerifiedAdc1V2 own)
    {
        var peer = contact.Authorization.Freshness.CurrentCheckpoint!;
        intent.CopyTo(metadata);
        peer.Binding.DeepId.RecordHash.Span.CopyTo(metadata[32..]);
        peer.Binding.Record.DeepAccountId.Span.CopyTo(metadata[64..]);
        contact.PublisherDevice.Certificate.DeviceId.Span.CopyTo(metadata[96..]);
        peer.Binding.Record.RecordHash.Span.CopyTo(metadata[128..]);
        peer.Directory.Record.RecordHash.Span.CopyTo(metadata[160..]);
        SHA256.HashData(contact.Contact.CanonicalBytes.Span, metadata.Slice(192, 32));
        own.Binding.Record.RecordHash.Span.CopyTo(metadata[224..]);
        own.Directory.Record.RecordHash.Span.CopyTo(metadata[256..]);
    }

    internal async Task<DeepIdV2InitialSessionCommit?> FindCompletedContactDraftAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent,
        ReadOnlyMemory<byte> initial, ReadOnlyMemory<byte> hello,
        DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var contact = await RecheckPermanentContactUnderLeaseAsync(current, source, resolved, held, ct).ConfigureAwait(false);
        await RequireInitialContactDraftForClaimUnderLeaseAsync(current, source, resolved, contact.Contact, held, intent, ct).ConfigureAwait(false);
        using var store = await SqliteDeepIdV2AccountGeneration.OpenCurrentDeviceStateStoreAsync(storage, sqlStatePath, current, ct).ConfigureAwait(false);
        if (!await store.HasCompletedInitialSessionAsync(intent, ct).ConfigureAwait(false)) return null;
        var retained = await store.ReadMessagingSourceByIntentUnderLeaseAsync(intent, ct).ConfigureAwait(false);
        try
        {
            var conversation = retained.RequireInitialConversation(initial.Span, hello.Span);
            CryptographicOperations.ZeroMemory(conversation);
            if (!FixedRoute(retained.Record.ResponderAccountId.Span, contact.Contact.Authorization.Authorization.Binding.Record.DeepAccountId.Span) ||
                !FixedRoute(retained.Record.ResponderDeviceId.Span, contact.Contact.PublisherDevice.Certificate.DeviceId.Span))
                throw new CryptographicException("The completed initial contact belongs to another current recipient.");
            await RequireInitialContactDraftForClaimUnderLeaseAsync(current, source, resolved, contact.Contact, held, intent, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return retained;
        }
        catch { retained.Dispose(); throw; }
    }
}
