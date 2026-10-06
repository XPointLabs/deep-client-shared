using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // A held, non-serializable prerequisite for a future dependency-closed
    // compaction plan. It is not a deletion permission or non-issuance result.
    internal sealed class MailboxEpochExclusion : IDisposable
    {
        private readonly ProtectedDeepIdV2AccountOwner owner;
        private readonly HeldDeepIdV2AccountLease held;
        private readonly VerifiedDeepIdV2CurrentAccount current;
        private readonly DeepIdV2ContactPathAuthoritySource source;
        private readonly DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh;
        private readonly VerifiedMailboxHostAuthorityV2 authority;
        private readonly OnionMonotonicReading first;
        private readonly byte[] root, instance, acquisition;
        private readonly SemaphoreSlim gate = new(1, 1);
        private bool disposed;

        private MailboxEpochExclusion(ProtectedDeepIdV2AccountOwner owner, HeldDeepIdV2AccountLease held,
            VerifiedDeepIdV2CurrentAccount current, DeepIdV2ContactPathAuthoritySource source,
            DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
            VerifiedMailboxHostAuthorityV2 authority, OnionMonotonicReading first,
            byte[] root, byte[] instance, byte[] acquisition, ulong originalEpoch, bool unresolved)
        {
            this.owner = owner; this.held = held; this.current = current; this.source = source;
            this.fresh = fresh; this.authority = authority; this.first = first;
            this.root = root; this.instance = instance; this.acquisition = acquisition;
            OriginalSelectionEpoch = originalEpoch; ExcludingSelectionEpoch = authority.SelectionEpoch;
            IsUnresolvedAcquisition = unresolved;
        }

        internal ulong OriginalSelectionEpoch { get; }
        internal ulong ExcludingSelectionEpoch { get; }
        internal bool IsUnresolvedAcquisition { get; }
        internal ReadOnlyMemory<byte> AcquisitionHash => acquisition.ToArray();
        internal ReadOnlyMemory<byte> OriginalGrantRootHash => SHA256.HashData(root);

        internal static async Task<MailboxEpochExclusion> OpenAsync(ProtectedDeepIdV2AccountOwner owner,
            ulong unixSeconds, IDeepMlDsa65Verifier verifier, DeepIdV2ContactPathAuthoritySource source,
            DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, byte[] acquisition, CancellationToken ct)
        {
            if (acquisition.Length != 32 || acquisition.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                throw new ArgumentException("An exact original acquisition hash is required.", nameof(acquisition));
            var held = await owner.lease.AcquireAsync(ct).ConfigureAwait(false);
            VerifiedDeepIdV2CurrentAccount? current = null;
            byte[]? snapshot = null, instance = null;
            MailboxEpochExclusion? result = null;
            try
            {
                current = await owner.RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
                var first = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
                var authority = await MailboxHostAuthorityV2Verifier.VerifyAsync(fresh.Network, fresh.Authority,
                    fresh.MailboxAuthority.ExactPma2, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
                    owner.storage, owner.networkId, current.AccountId, ct).ConfigureAwait(false);
                using var protectedRoot = await owner.storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Original acquisition custody is absent; epoch exclusion cannot repair it.");
                snapshot = protectedRoot.Use(bytes => bytes.ToArray());
                using var state = ProtectedDid2MailboxGrantJournal.Decode(snapshot, owner.networkId, current.AccountId.Span, instance);
                if (!state.Entries.TryGetValue(Convert.ToHexString(acquisition), out var entry))
                    throw new InvalidDataException("Epoch exclusion requires an exact protected original acquisition.");
                var originalRoute = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span);
                var originalEpoch = BinaryPrimitives.ReadUInt64BigEndian(originalRoute.Projection.Field(6).Span);
                RequireExclusion(entry, originalRoute, authority, fresh, first, originalEpoch);
                result = new(owner, held, current, source, fresh, authority, first,
                    snapshot, instance, acquisition.ToArray(), originalEpoch, ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(entry));
                await result.RecheckAsync(ct).ConfigureAwait(false);
                return result;
            }
            catch
            {
                if (result is not null) result.Dispose();
                else
                {
                    current?.Dispose(); held.Dispose();
                    if (snapshot is not null) CryptographicOperations.ZeroMemory(snapshot);
                    if (instance is not null) CryptographicOperations.ZeroMemory(instance);
                }
                throw;
            }
        }

        // Every consumer must recheck under this same live account lease. A
        // copied hash/scalar, old capability or caller clock cannot replace it.
        internal async Task RecheckAsync(CancellationToken ct = default)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(disposed, this); held.RequireOwner(owner.lease);
                var reading = await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                await authority.EnsureCurrentAsync(ct).ConfigureAwait(false);
                using var actualRoot = await owner.storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new CryptographicException("Epoch exclusion lost original grant custody.");
                if (!actualRoot.Use(bytes => FixedRoute(bytes, root)))
                    throw new CryptographicException("Epoch exclusion no longer binds the exact grant root.");
                var actualInstance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
                    owner.storage, owner.networkId, current.AccountId, ct).ConfigureAwait(false);
                try
                {
                    if (!FixedRoute(actualInstance, instance)) throw new CryptographicException("Epoch exclusion changed account instance.");
                }
                finally { CryptographicOperations.ZeroMemory(actualInstance); }
                using var state = ProtectedDid2MailboxGrantJournal.Decode(root, owner.networkId, current.AccountId.Span, instance);
                var entry = state.Entries[Convert.ToHexString(acquisition)];
                var originalRoute = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span);
                RequireExclusion(entry, originalRoute, authority, fresh, reading, OriginalSelectionEpoch);
                // Also re-read the native DNH2/anchor after the other reads.
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                using var finalRoot = await owner.storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new CryptographicException("Epoch exclusion lost original grant custody after floor recheck.");
                if (!finalRoot.Use(bytes => FixedRoute(bytes, root)))
                    throw new CryptographicException("Epoch exclusion grant root changed during floor recheck.");
                ct.ThrowIfCancellationRequested(); held.RequireActive();
            }
            finally { gate.Release(); }
        }

        private static void RequireExclusion(byte[] entry, ParsedContactRouteClosure originalRoute,
            VerifiedMailboxHostAuthorityV2 authority, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
            OnionMonotonicReading reading, ulong originalEpoch)
        {
            if (!ProtectedDid2MailboxGrantJournal.HasWinner(entry) && !ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(entry))
                throw new CryptographicException("A pending acquisition has no closed epoch-exclusion disposition.");
            var originalPolicy = ContactCodec.Decode("PMA2", ProtectedDid2MailboxGrantJournal.OriginalPolicy(entry).Span);
            if (!FixedRoute(originalPolicy.Field(13).Span, fresh.Authority.AuthorityCoreReference.Span))
                throw new NotSupportedException("Epoch exclusion requires the existing exact authority lineage; rollover is unavailable.");
            if (ProtectedDid2MailboxGrantJournal.HasWinner(entry))
                ContactCodec.ValidateMailboxGrantResultRouteBinding(
                    ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span), originalRoute);
            var lower = checked(fresh.Proof.TrustedLowerUnixSeconds + checked(reading.SampleSeconds - fresh.Proof.MonotonicSample));
            if (authority.SelectionEpoch <= originalEpoch || lower < ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(entry))
                throw new CryptographicException("Epoch exclusion requires an irreversible advance and the original possible-issuance ceiling.");
        }

        public void Dispose()
        {
            gate.Wait();
            try
            {
                if (disposed) return;
                disposed = true; current.Dispose(); held.Dispose();
                CryptographicOperations.ZeroMemory(root); CryptographicOperations.ZeroMemory(instance);
                CryptographicOperations.ZeroMemory(acquisition);
            }
            finally { gate.Release(); }
        }
    }
}
