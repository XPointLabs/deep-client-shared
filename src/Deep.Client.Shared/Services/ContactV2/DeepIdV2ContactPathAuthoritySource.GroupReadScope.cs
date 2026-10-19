using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.ContactV2;

public sealed partial class DeepIdV2ContactPathAuthoritySource
{
    private readonly GroupReadState? groupReads;

    // An explicit group-command child, not ambient state or a process cache.
    // Share the real acquisition gate and all actual protected owners.
    private DeepIdV2ContactPathAuthoritySource(DeepIdV2ContactPathAuthoritySource parent)
    {
        genesisPin = parent.genesisPin; accounts = parent.accounts; proofs = parent.proofs;
        artifacts = parent.artifacts; networkStore = parent.networkStore; networkHistory = parent.networkHistory;
        trustedTime = parent.trustedTime; clock = parent.clock; gate = parent.gate;
        groupReads = new();
    }

    internal GroupReadScope OpenGroupReadScope() => new(this);

    internal sealed class GroupReadScope : IDisposable
    {
        private readonly bool owns;
        internal DeepIdV2ContactPathAuthoritySource Source { get; }
        internal GroupReadScope(DeepIdV2ContactPathAuthoritySource parent)
        {
            parent.groupReads?.RequireActive(); owns = parent.groupReads is null;
            Source = owns ? new(parent) : parent;
        }
        public void Dispose() { if (owns) Source.groupReads!.Close(); }
    }

    private sealed class GroupReadState
    {
        private readonly object sync = new();
        private bool active = true;
        private OwnPreKeyAuthoringAuthority? own;
        private readonly Dictionary<string, MessagingEndpointAuthority> peers = new(StringComparer.Ordinal);
        internal void RequireActive() { lock (sync) ObjectDisposedException.ThrowIf(!active, this); }
        internal OwnPreKeyAuthoringAuthority? ReadOwn() { lock (sync) { RequireActive(); return own; } }
        internal void SetOwn(OwnPreKeyAuthoringAuthority value)
        { lock (sync) { RequireActive(); own = value; peers.Clear(); } }
        internal void ResetUncapturedPair() { lock (sync) { RequireActive(); own = null; peers.Clear(); } }
        internal VerifiedDeepIdV2DirectoryFreshness? ReadPeer(ReadOnlySpan<byte> did, OwnPreKeyAuthoringAuthority expected)
        {
            lock (sync)
            {
                RequireActive(); return peers.TryGetValue(Convert.ToHexString(SHA256.HashData(did)), out var pair) &&
                    ReferenceEquals(pair.Own, expected) ? pair.Peer : null;
            }
        }
        internal void SetPeer(ReadOnlySpan<byte> did, OwnPreKeyAuthoringAuthority expected, VerifiedDeepIdV2DirectoryFreshness peer)
        {
            lock (sync)
            {
                RequireActive(); var key = Convert.ToHexString(SHA256.HashData(did));
                if (!peers.ContainsKey(key) && peers.Count >= 100) throw new IOException("Group read scope exceeds its member bound.");
                peers[key] = new(expected, peer);
            }
        }
        internal void Close() { lock (sync) { active = false; own = null; peers.Clear(); } }
    }

    // Called only under the shared acquisition gate, before a new owner loan.
    // A naturally elapsed proof starts a new acquisition, never renews an old
    // loan or changes any captured original request. Other failures propagate.
    private async ValueTask<OwnPreKeyAuthoringAuthority?> ReadGroupOwnAsync(CancellationToken ct)
    {
        var own = groupReads?.ReadOwn(); if (own is null) return null;
        var reading = await clock.ReadAsync(ct).ConfigureAwait(false) ??
            throw new CryptographicException("Group read scope has no actual monotonic clock.");
        if (!own.Proof.IsCurrentAtMonotonic(reading.BootId.Span, own.Proof.MonotonicSample) || reading.SampleSeconds < own.Proof.MonotonicSample)
            throw new CryptographicException("Group read scope crossed a clock discontinuity.");
        if (reading.SampleSeconds >= own.Proof.FreshnessDeadlineMonotonicSeconds) return null;
        await proofs.RequireStillFreshAsync(own.Proof, own.Authority, ct).ConfigureAwait(false);
        var floor = await networkHistory.ReadHistoryAsync(ct).ConfigureAwait(false);
        if (floor is null || floor.Snapshot.ForkLatched || !Same(floor.Snapshot.ProtectedLkg, own.Network.ProtectedLkg) ||
            !Fixed(floor.ExactHistory.Span, OnionNetworkProtectedHistoryCodec.Encode(own.Network)))
            throw new CryptographicException("Group read scope no longer binds actual network custody.");
        own.Network.EnsureCurrent();
        _ = await VerifyMailboxAuthorityAsync(own.NamespaceRecords, own.Network, own.Authority, own.Proof, ct).ConfigureAwait(false);
        groupReads!.RequireActive(); ct.ThrowIfCancellationRequested(); return own;
    }
}
