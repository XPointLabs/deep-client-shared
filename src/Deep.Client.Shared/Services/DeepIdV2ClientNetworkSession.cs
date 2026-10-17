using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services;

/// <summary>Owns public bootstrap/proof clients for one command. It exposes no
/// authority shortcut: each account operation independently verifies current
/// proofs, protected floors, route, grants and custody through Source.</summary>
public sealed class DeepIdV2ClientNetworkSession : IDisposable
{
    private readonly DeepIdV2AccountService accounts;
    private readonly HttpServiceTransportFactory factory;
    private readonly string origin;
    private readonly VerifiedXPointNetworkAuthority authority;
    private readonly IDeepMlDsa65VerifierLease verifier;
    private readonly DeepIdV2DirectoryProofClient proofs;
    private readonly HttpDeepIdV2NetworkClosureArtifactSource artifacts;
    private bool disposed;
    public DeepIdV2ContactPathAuthoritySource Source { get; }
    // Same public-HTTP connection isolation as the physical composition. Not
    // passed to the independently selected ONION connector or a retry policy.
    private static readonly HttpServiceClientOptions PublicHttp = new(
        PooledConnectionLifetime: TimeSpan.FromTicks(1), UseSystemProxy: true);

    private DeepIdV2ClientNetworkSession(DeepIdV2AccountService accounts,
        HttpServiceTransportFactory factory, string origin, VerifiedXPointNetworkAuthority authority,
        IDeepMlDsa65VerifierLease verifier, DeepIdV2DirectoryProofClient proofs,
        HttpDeepIdV2NetworkClosureArtifactSource artifacts, DeepIdV2ContactPathAuthoritySource source)
    {
        this.accounts = accounts; this.factory = factory; this.origin = origin; this.authority = authority;
        this.verifier = verifier; this.proofs = proofs; this.artifacts = artifacts; Source = source;
    }

    public static async Task<DeepIdV2ClientNetworkSession> OpenAsync(
        DeepIdV2AccountService accounts, HttpServiceTransportFactory factory, string origin,
        XPointNetworkGenesisPin genesis, ReadOnlyMemory<byte> exactGenesisXna1,
        ReadOnlyMemory<byte> exactGenesisDts1, ReadOnlyMemory<byte> exactGenesisHead,
        ReadOnlyMemory<byte> genesisHeadCoreHash, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(accounts); ArgumentNullException.ThrowIfNull(factory);
        ArgumentNullException.ThrowIfNull(genesis);
        // Copy caller buffers before the first callback. Local genesis pins are
        // operator configuration, not a distributed current-authority assertion.
        var xna = exactGenesisXna1.ToArray(); var dts = exactGenesisDts1.ToArray();
        var head = exactGenesisHead.ToArray(); var headPin = genesisHeadCoreHash.ToArray();
        if (xna.Length is < 1 or > 65535 || dts.Length is < 1 or > 65535 ||
            head.Length is < 1 or > 4096 || headPin.Length != 32)
            throw new ArgumentException("Public bootstrap input exceeds its bounds.");
        var original = XPointNetworkAuthorityVerifier.Verify(genesis, [xna], [dts]);
        _ = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(original, head, headPin);
        var artifacts = factory.CreateDeepIdV2NetworkClosureArtifactSource(origin, clientOptions: PublicHttp);
        IDeepMlDsa65VerifierLease? verifier = null; DeepIdV2DirectoryProofClient? proofs = null;
        try
        {
            var history = await artifacts.FetchCurrentAsync(genesis.NetworkId, null, ct).ConfigureAwait(false);
            if (history.ExactXna1AuthorityChain.Count == 0 || history.ExactDts1PolicyChain.Count == 0 ||
                !history.ExactXna1AuthorityChain[0].Span.SequenceEqual(xna) ||
                !history.ExactDts1PolicyChain[0].Span.SequenceEqual(dts))
                throw new CryptographicException("Distributed history differs from configured genesis.");
            var authority = XPointNetworkAuthorityVerifier.Verify(genesis,
                history.ExactXna1AuthorityChain, history.ExactDts1PolicyChain);
            _ = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(authority, head, headPin);
            var floor = await accounts.OpenDirectoryLkgStoreAsync(authority, head, headPin, ct).ConfigureAwait(false);
            verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
            var clock = new ProcessClock();
            proofs = factory.CreateDeepIdV2DirectoryProofClient(origin, clock, verifier, floor, clientOptions: PublicHttp);
            var networkFloor = await accounts.OpenNetworkLkgStoreAsync(genesis, ct).ConfigureAwait(false);
            var source = new DeepIdV2ContactPathAuthoritySource(genesis, accounts, proofs, artifacts, networkFloor, clock);
            return new(accounts, factory, origin, authority, verifier, proofs, artifacts, source);
        }
        catch { proofs?.Dispose(); verifier?.Dispose(); artifacts.Dispose(); throw; }
    }

    public async Task VerifyAndPublishAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        using var admission = factory.CreateDeepIdV2GenesisAdmissionClient(origin, clientOptions: PublicHttp);
        var result = await accounts.AdmitAndVerifyGenesisAsync(admission, proofs, authority,
            cancellationToken: ct).ConfigureAwait(false);
        if (result.CurrentCheckpoint is null || result.NextProtectedLkg.TreeSize == 0)
            throw new CryptographicException("Account genesis has no current directory checkpoint.");
        _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source, ct).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true; proofs.Dispose(); artifacts.Dispose(); verifier.Dispose();
    }

    private sealed class ProcessClock : IOnionMonotonicClock
    {
        private readonly byte[] boot = RandomNumberGenerator.GetBytes(16);
        private readonly long started = Stopwatch.GetTimestamp();
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(boot,
                checked(1000UL + (ulong)Math.Floor(Stopwatch.GetElapsedTime(started).TotalSeconds))));
        }
    }
}
