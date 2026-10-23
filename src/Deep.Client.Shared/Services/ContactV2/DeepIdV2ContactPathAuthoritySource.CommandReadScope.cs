using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.ContactV2;

public sealed partial class DeepIdV2ContactPathAuthoritySource
{
    private readonly CommandReadState? commandReads;

    // An explicit command child, not ambient state or a process cache.
    // Share the real acquisition gate and all actual protected owners.
    private DeepIdV2ContactPathAuthoritySource(DeepIdV2ContactPathAuthoritySource parent, bool workingSession = false)
    {
        genesisPin = parent.genesisPin; accounts = parent.accounts; proofs = parent.proofs;
        artifacts = parent.artifacts; networkStore = parent.networkStore; networkHistory = parent.networkHistory;
        trustedTime = parent.trustedTime; clock = parent.clock; gate = parent.gate;
        commandReads = new(workingSession);
    }

    internal CommandReadScope OpenCommandReadScope() => new(this);
    internal CommandReadScope OpenWorkingGroupScope() => new(this, workingSession: true);
    // A new phase must acquire its own authority even when its caller already
    // has a command/working memo. In particular ACK never borrows receive's proof.
    internal CommandReadScope OpenIndependentCommandReadScope() => new(this, independent: true);

    internal async Task DiscardUncapturedAuthorityAsync(CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (commandReads?.WorkingSession == true)
                commandReads.ObserveClock(await clock.ReadAsync(ct).ConfigureAwait(false));
            commandReads?.ResetUncapturedPair();
        }
        finally { gate.Release(); }
    }

    // Separate pre-effect authority refresh. Existing captured loans/requests
    // retain their own immutable authority and are never renewed by this call.
    internal async Task RefreshWorkingAuthorityAsync(CancellationToken ct, bool onlyWhenDue = false)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (onlyWhenDue)
            {
                var current = await clock.ReadAsync(ct).ConfigureAwait(false);
                commandReads!.ObserveClock(current);
                // Scheduling only: do not borrow/validate authority merely to
                // decide whether idle work is due. Missing context is acquired
                // on demand, never speculatively after an independent ACK.
                // Every business borrow still calls ReadCommandOwnAsync and
                // rejoins actual protected floors, account, issuer and time.
                var existing = commandReads.ReadOwn();
                ct.ThrowIfCancellationRequested();
                if (existing is null) return;
                if (current.SampleSeconds < existing.Proof.MonotonicSample ||
                    !existing.Proof.IsCurrentAtMonotonic(current.BootId.Span, existing.Proof.MonotonicSample))
                    throw new CryptographicException("Working authority crossed a clock discontinuity.");
                if (current.SampleSeconds < existing.Proof.FreshnessDeadlineMonotonicSeconds &&
                    existing.Proof.FreshnessDeadlineMonotonicSeconds - current.SampleSeconds > 30) return;
            }
            if (commandReads?.WorkingSession == true)
                commandReads.ObserveClock(await clock.ReadAsync(ct).ConfigureAwait(false));
            commandReads?.ResetUncapturedPair();
            _ = await VerifyCurrentNetworkCoreAsync(ct).ConfigureAwait(false);
        }
        catch { commandReads?.ResetUncapturedPair(); throw; }
        finally { gate.Release(); }
    }

    internal sealed class CommandReadScope : IDisposable
    {
        private readonly bool owns;
        internal DeepIdV2ContactPathAuthoritySource Source { get; }
        internal CommandReadScope(DeepIdV2ContactPathAuthoritySource parent, bool workingSession = false, bool independent = false)
        {
            parent.commandReads?.RequireActive(); owns = independent || parent.commandReads is null;
            Source = owns ? new(parent, workingSession) : parent;
        }
        public void Dispose() { if (owns) Source.commandReads!.Close(); }
    }

    private sealed class CommandReadState(bool workingSession)
    {
        internal bool WorkingSession { get; } = workingSession;
        private readonly object sync = new();
        private bool active = true;
        private OwnPreKeyAuthoringAuthority? own;
        private byte[]? boot;
        private ulong lastSample;
        private readonly Dictionary<string, MessagingEndpointAuthority> peers = new(StringComparer.Ordinal);
        internal void RequireActive() { lock (sync) ObjectDisposedException.ThrowIf(!active, this); }
        internal OwnPreKeyAuthoringAuthority? ReadOwn() { lock (sync) { RequireActive(); return own; } }
        internal void SetOwn(OwnPreKeyAuthoringAuthority value)
        {
            lock (sync)
            {
                RequireActive();
                own = value; peers.Clear();
            }
        }
        internal void ObserveClock(OnionMonotonicReading reading)
        {
            lock (sync)
            {
                RequireActive();
                if (boot is not null && (!boot.AsSpan().SequenceEqual(reading.BootId.Span) || reading.SampleSeconds < lastSample))
                    throw new CryptographicException("Working authority crossed a clock discontinuity.");
                boot ??= reading.BootId.ToArray(); lastSample = reading.SampleSeconds;
            }
        }
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
    private async ValueTask<OwnPreKeyAuthoringAuthority?> ReadCommandOwnAsync(CancellationToken ct)
    {
        var own = commandReads?.ReadOwn(); if (own is null) return null;
        var reading = await clock.ReadAsync(ct).ConfigureAwait(false) ??
            throw new CryptographicException("Group read scope has no actual monotonic clock.");
        if (commandReads!.WorkingSession) commandReads.ObserveClock(reading);
        if (!own.Proof.IsCurrentAtMonotonic(reading.BootId.Span, own.Proof.MonotonicSample) || reading.SampleSeconds < own.Proof.MonotonicSample)
            throw new CryptographicException("Group read scope crossed a clock discontinuity.");
        if (reading.SampleSeconds >= own.Proof.FreshnessDeadlineMonotonicSeconds) return null;
        await proofs.RequireStillFreshAsync(own.Proof, own.Authority, ct).ConfigureAwait(false);
        if (commandReads!.WorkingSession)
            await accounts.RequireCurrentWorkingDirectoryAsync(own.Proof, reading, ct).ConfigureAwait(false);
        var floor = await networkHistory.ReadHistoryAsync(ct).ConfigureAwait(false);
        if (floor is null || floor.Snapshot.ForkLatched || !Same(floor.Snapshot.ProtectedLkg, own.Network.ProtectedLkg) ||
            !Fixed(floor.ExactHistory.Span, OnionNetworkProtectedHistoryCodec.Encode(own.Network)))
            throw new CryptographicException("Group read scope no longer binds actual network custody.");
        own.Network.EnsureCurrent();
        _ = await VerifyMailboxAuthorityAsync(own.NamespaceRecords, own.Network, own.Authority, own.Proof, ct).ConfigureAwait(false);
        if (commandReads!.WorkingSession)
        {
            await proofs.RequireStillFreshAsync(own.Proof, own.Authority, ct).ConfigureAwait(false);
            commandReads.ObserveClock(await clock.ReadAsync(ct).ConfigureAwait(false));
        }
        commandReads!.RequireActive(); ct.ThrowIfCancellationRequested(); return own;
    }
}
