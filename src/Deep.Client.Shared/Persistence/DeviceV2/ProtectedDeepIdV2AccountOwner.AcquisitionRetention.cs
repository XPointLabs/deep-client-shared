using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // A working-set move, NOT retirement, settlement or a new authority cache.
    // Complete original custody stays authenticated; every replay floor and all
    // native/application SQL remain unchanged. Unknown/selected work stays live.
    private async Task SealInactiveMailboxAcquisitionsUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, ReadOnlyMemory<byte> instance, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        var before = raw.Use(bytes => bytes.ToArray());
        byte[] replacement = [];
        var copies = new List<(string Slot, byte[] Bytes)>();
        try
        {
            using var grants = ProtectedDid2MailboxGrantJournal.Decode(before, networkId, current.AccountId.Span, instance.Span);
            var workingTarget = Math.Min(ProtectedDid2MailboxGrantJournal.MaximumEntries - 16,
                Math.Max(16, checked(grants.Selections.Count * 2)));
            if (grants.Entries.Count <= workingTarget ||
                grants.Retained.Count >= ProtectedDid2MailboxGrantJournal.MaximumRetained) return;
            using var readRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
            using var reads = readRaw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, networkId, current.AccountId.Span, instance.Span));
            if (reads.Active is not null || reads.Phase != 0) return;
            using var sendRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
            using var sends = sendRaw.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, networkId, current.AccountId.Span, instance.Span));
            var reading = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
            var lower = checked(fresh.Proof.TrustedLowerUnixSeconds + reading.SampleSeconds - fresh.Proof.MonotonicSample);
            // One bounded atomic transaction, not eight complete protected
            // inventory parses/encryptions. Every candidate keeps the same
            // independent expiry, floor and outstanding-work prerequisites.
            for (var batch = 0; batch < 8 && grants.Entries.Count > workingTarget &&
                grants.Retained.Count < ProtectedDid2MailboxGrantJournal.MaximumRetained; batch++)
            {
                string? selected = null;
                foreach (var pair in grants.Entries)
                {
                    byte[] entry;
                    try { entry = ProtectedDid2MailboxGrantJournal.RequireSealableOldest(grants, Convert.FromHexString(pair.Key)); }
                    catch (IOException) { continue; } // Pure bounded scheduling selector only.
                    var exactGrant = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8);
                    var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(exactGrant.Span);
                    var hash = SHA256.HashData(exactGrant.Span);
                    if (lower < grant.ExpiresAtUnixSeconds || !HasRetainedAcquisitionFloor(sends, reads, hash, grant.Domain) ||
                        sends.Entries.Values.Any(send => FixedRoute(send.GrantHash, hash)) ||
                        reads.Closed.Values.Any(read => FixedRoute(read.Grant, hash))) continue;
                    selected = pair.Key; break;
                }
                if (selected is null) break;
                var acquisition = Convert.FromHexString(selected);
                var retained = ProtectedDid2MailboxGrantJournal.StageSealedOldest(grants, acquisition,
                    networkId, current.AccountId.Span, instance.Span);
                copies.Add((ProtectedDid2MailboxGrantJournal.RetainedSlot(acquisition), retained));
            }
            if (copies.Count == 0) return;
            replacement = ProtectedDid2MailboxGrantJournal.Encode(grants, networkId, current.AccountId.Span, instance.Span);
            await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
            var sendBefore = sendRaw.Use(bytes => bytes.ToArray()); var readBefore = readRaw.Use(bytes => bytes.ToArray());
            try
            {
#if DEEP_TEST_INTERNALS
                    Did2AcquisitionRetentionTestHooks.Hit(Did2AcquisitionRetentionFailpoint.BeforeSeal);
#endif
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, sendBefore, ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxReadJournal.Slot, readBefore, ct).ConfigureAwait(false);
                if (!await storage.CompareExchangeAndInsertAsync(ProtectedDid2MailboxGrantJournal.Slot, before,
                    replacement, copies.Select(copy => new DeepSecureStorageWrite(copy.Slot, copy.Bytes)).ToArray(), ct).ConfigureAwait(false))
                    throw new CryptographicException("Sealed acquisition conflicts with its exact working predecessor or existing custody.");
#if DEEP_TEST_INTERNALS
                    Did2AcquisitionRetentionTestHooks.Hit(Did2AcquisitionRetentionFailpoint.AfterSeal);
#endif
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, replacement, ct).ConfigureAwait(false);
                foreach (var copy in copies)
                    await RequireExactProtectedMailboxRootAsync(copy.Slot, copy.Bytes, ct).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(sendBefore); CryptographicOperations.ZeroMemory(readBefore); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(replacement);
            foreach (var copy in copies) CryptographicOperations.ZeroMemory(copy.Bytes);
        }
    }

    private static bool HasRetainedAcquisitionFloor(ProtectedDid2MailboxSendJournal.State sends,
        ProtectedDid2MailboxReadJournal.State reads, ReadOnlySpan<byte> hash, MailboxCapabilityDomain domain)
    {
        var ownedHash = hash.ToArray();
        try
        {
            return domain == MailboxCapabilityDomain.Deposit
                ? sends.Floors.Values.Any(floor => floor.HighestCounter != 0 && FixedRoute(floor.GrantHash, ownedHash))
                : domain == MailboxCapabilityDomain.Retrieve && reads.Counters.ContainsKey(Convert.ToHexString(hash));
        }
        finally { CryptographicOperations.ZeroMemory(ownedHash); }
    }

    private async Task MaintainRetainedMailboxAcquisitionsUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, ReadOnlyMemory<byte> instance, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        var before = raw.Use(bytes => bytes.ToArray()); byte[] replacement = [];
        try
        {
            using var grants = ProtectedDid2MailboxGrantJournal.Decode(before, networkId, current.AccountId.Span, instance.Span);
            if (grants.Retained.Count == 0) return;
            var host = await MailboxHostAuthorityV2Verifier.VerifyPolicyAsync(fresh.Network, fresh.Authority,
                fresh.MailboxAuthority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            // Every admitted selection epoch is positive. No sealed old epoch
            // can be excluded by epoch1; avoid reading private archives in steady state.
            if (host.SelectionEpoch == 1) return;
            using var readRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
            using var reads = readRaw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, networkId, current.AccountId.Span, instance.Span));
            using var sendRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
            using var sends = sendRaw.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, networkId, current.AccountId.Span, instance.Span));
            if (reads.Active is not null || reads.Phase != 0) return;
            foreach (var pair in grants.Retained.OrderByDescending(item => item.Value.Phase).ThenBy(item => item.Key, StringComparer.Ordinal))
            {
                var reference = pair.Value;
                if (reference.Phase == 2 && grants.Entries.ContainsKey(pair.Key)) return; // Existing strict owner still owns retirement.
                var slot = ProtectedDid2MailboxGrantJournal.RetainedSlot(Convert.FromHexString(pair.Key));
                using var retainedRaw = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false);
                if (retainedRaw is null)
                {
                    if (reference.Phase != 3) throw new CryptographicException("Mandatory sealed acquisition custody is absent; no repair is permitted.");
                    if (sends.Floors.Values.Any(floor => FixedRoute(floor.GrantHash, reference.GrantHash)) ||
                        reads.Counters.ContainsKey(Convert.ToHexString(reference.GrantHash)))
                        throw new CryptographicException("Deleted acquisition still has a replay-floor dependency.");
                    grants.Retained.Remove(pair.Key); reference.Dispose(); grants.Revision = checked(grants.Revision + 1);
                    replacement = ProtectedDid2MailboxGrantJournal.Encode(grants, networkId, current.AccountId.Span, instance.Span);
                    await SaveRetainedAcquisitionRootAsync(before, replacement, current, source, fresh, held, ct).ConfigureAwait(false);
                    return;
                }
                using var retainedState = retainedRaw.Use(bytes => ProtectedDid2MailboxGrantJournal.DecodeRetained(grants, pair.Key,
                    bytes, networkId, current.AccountId.Span, instance.Span));
                var entry = retainedState.Entries[pair.Key];
                var route = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span);
                var epoch = BinaryPrimitives.ReadUInt64BigEndian(route.Projection.Field(6).Span);
                var reading = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
                var lower = checked(fresh.Proof.TrustedLowerUnixSeconds + reading.SampleSeconds - fresh.Proof.MonotonicSample);
                if (host.SelectionEpoch <= epoch || lower < ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(entry)) continue;
                await MailboxEpochExclusion.RequireExclusionAsync(entry, route, host, fresh, reading, epoch, ct).ConfigureAwait(false);
                if (reference.Phase == 1)
                {
                    var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span);
                    if (!HasRetainedAcquisitionFloor(sends, reads, reference.GrantHash, grant.Domain))
                        throw new CryptographicException("Sealed acquisition lost its independent replay floor.");
                    try { replacement = ProtectedDid2MailboxGrantJournal.RestoreRetainedOldest(grants, pair.Key, entry, networkId, current.AccountId.Span, instance.Span); }
                    catch (IOException) { continue; } // Pure structural pins, before any effect.
#if DEEP_TEST_INTERNALS
                    Did2AcquisitionRetentionTestHooks.Hit(Did2AcquisitionRetentionFailpoint.BeforeRestore);
#endif
                    await SaveRetainedAcquisitionRootAsync(before, replacement, current, source, fresh, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2AcquisitionRetentionTestHooks.Hit(Did2AcquisitionRetentionFailpoint.AfterRestore);
#endif
                    return;
                }
                if (sends.Floors.Values.Any(floor => FixedRoute(floor.GrantHash, reference.GrantHash)) ||
                    reads.Counters.ContainsKey(Convert.ToHexString(reference.GrantHash)))
                    throw new CryptographicException("Acquisition cannot discard retained custody before original replay retirement.");
                reference.Phase = 3; grants.Revision = checked(grants.Revision + 1);
                replacement = ProtectedDid2MailboxGrantJournal.Encode(grants, networkId, current.AccountId.Span, instance.Span);
                await SaveRetainedAcquisitionRootAsync(before, replacement, current, source, fresh, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2AcquisitionRetentionTestHooks.Hit(Did2AcquisitionRetentionFailpoint.BeforeDelete);
#endif
                if (!await storage.CompareAndDeleteAsync(ProtectedDid2MailboxGrantJournal.Slot, replacement, [slot], ct).ConfigureAwait(false))
                    throw new CryptographicException("Retained acquisition deletion changed its protected guard.");
#if DEEP_TEST_INTERNALS
                Did2AcquisitionRetentionTestHooks.Hit(Did2AcquisitionRetentionFailpoint.AfterDelete);
#endif
                return; // Reference remains until an independent read confirms deletion.
            }
        }
        finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(replacement); }
    }

    private async Task SaveRetainedAcquisitionRootAsync(byte[] before, byte[] after,
        VerifiedDeepIdV2CurrentAccount current, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
        if (!await storage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, before, after, ct).ConfigureAwait(false))
            throw new CryptographicException("Retained acquisition root changed during its exact transition.");
        await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, after, ct).ConfigureAwait(false);
    }
}
