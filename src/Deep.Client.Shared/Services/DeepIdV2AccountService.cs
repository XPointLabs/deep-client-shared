using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Network-free DID2 account entry point for a single private device store.
/// It never reads or migrates the incompatible STORE-V1 namespace.
/// </summary>
public sealed class DeepIdV2AccountService
{
    private readonly ProtectedDeepIdV2AccountOwner owner;
    private readonly IClock clock;
    private readonly ushort deploymentProfileId;
    private readonly Func<IDeepMlDsa65VerifierLease> verifierFactory;

    public DeepIdV2AccountService(IDeepSecureStorage storage,
        string privateDirectory, ReadOnlySpan<byte> networkId,
        ushort deploymentProfileId, IClock clock,
        Func<IDeepMlDsa65VerifierLease> verifierFactory)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateDirectory);
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.deploymentProfileId = deploymentProfileId;
        this.verifierFactory = verifierFactory ??
            throw new ArgumentNullException(nameof(verifierFactory));
        var directory = Path.GetFullPath(privateDirectory);
        if (!Directory.Exists(directory))
            throw new DirectoryNotFoundException(
                "The DID2 account requires an existing private directory.");
        owner = new ProtectedDeepIdV2AccountOwner(storage,
            new DeepIdV2AccountFileLease(Path.Combine(directory,
                "deep-store-v2-account.lock")),
            Path.Combine(directory, "deep-store-v2-account.dsv2"),
            networkId, deploymentProfileId);
    }

    public async Task<DeepIdV2AccountSnapshot?> GetCurrentAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        var trustedUnixSeconds = TrustedUnixSeconds();
        using var current = await owner.ReadCurrentAsync(trustedUnixSeconds,
            verifier, cancellationToken).ConfigureAwait(false);
        return current is null ? null : Snapshot(current);
    }

    public async Task<DeepIdV2AccountSnapshot> CreateAsync(
        string displayName, CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        using var current = await owner.CreateFreshAsync(displayName,
            TrustedUnixSeconds(), verifier, cancellationToken)
            .ConfigureAwait(false);
        return Snapshot(current);
    }

    /// <summary>
    /// Re-authors the same public DGA1 V2 admission from the protected exact
    /// genesis closure on every retry. This is not a Registry acceptance or
    /// a directory freshness capability.
    /// </summary>
    public async Task<byte[]> PrepareGenesisAdmissionAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        var trustedUnixSeconds = TrustedUnixSeconds();
        using var current = await owner.ReadCurrentAsync(trustedUnixSeconds,
            verifier, cancellationToken).ConfigureAwait(false) ??
            throw new InvalidOperationException(
                "A verified DID2 account is required for genesis admission.");
        return EncodeGenesisAdmission(current, trustedUnixSeconds, verifier);
    }

    private byte[] EncodeGenesisAdmission(
        VerifiedDeepIdV2CurrentAccount current, ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier)
    {
        var evidence = current.Verified.PublicEvidence;
        var binding = evidence.Binding;
        var identity = binding.Identity;
        var request = new DeepIdV2GenesisAdmissionRequest(
            identity.Account.Certificate.CanonicalBytes.Span,
            identity.Revocations.Snapshot.CanonicalBytes.Span,
            identity.ActiveDevices.Select(device => device.Certificate.CanonicalBytes)
                .ToArray(),
            binding.DeepId.CanonicalBytes.Span,
            binding.Record.CanonicalBytes.Span,
            evidence.Directory.Record.CanonicalBytes.Span,
            evidence.Checkpoint.Checkpoint.CanonicalBytes.Span, []);
        _ = DeepIdV2GenesisAdmissionVerifier.Verify(request,
            trustedUnixSeconds, deploymentProfileId, 2, verifier);
        var operationId = GenesisOperationId(binding.DeepId.RecordHash.Span,
            binding.Record.RecordHash.Span);
        return DeepIdV2GenesisAdmissionWireCodec.EncodeRequest(
            new DeepIdV2GenesisAdmissionWireRequest(operationId, request));
    }

    /// <summary>
    /// A DGR1 receipt is only an untrusted transport acknowledgement. This
    /// operation succeeds only after an independent DID2-bound, nonce-fresh
    /// ADH1/DTT1/ADP1 proof is verified and its rollback floor is committed.
    /// </summary>
    public async Task<VerifiedDeepIdV2DirectoryFreshness>
        AdmitAndVerifyGenesisAsync(
            DeepIdV2GenesisAdmissionClient admissionClient,
            DeepIdV2DirectoryProofClient proofClient,
            VerifiedXPointNetworkAuthority authority,
            ushort supportedReader = 2,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(admissionClient);
        ArgumentNullException.ThrowIfNull(proofClient);
        ArgumentNullException.ThrowIfNull(authority);
        byte[] exactDga1;
        VerifiedDab2 binding;
        using (var verifier = OpenVerifier())
        {
            var trustedUnixSeconds = TrustedUnixSeconds();
            using var current = await owner.ReadCurrentAsync(trustedUnixSeconds,
                    verifier, cancellationToken).ConfigureAwait(false) ??
                throw new InvalidOperationException(
                    "A verified DID2 account is required for genesis admission.");
            exactDga1 = EncodeGenesisAdmission(current, trustedUnixSeconds,
                verifier);
            binding = current.Verified.PublicEvidence.Binding;
        }
        try
        {
            var request = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(
                exactDga1).Admission;
            _ = await admissionClient.AdmitAsync(exactDga1, cancellationToken)
                .ConfigureAwait(false);
            var verified = await proofClient.FetchOwnGenesisAsync(
                    binding, authority,
                    deploymentProfileId, supportedReader, cancellationToken)
                .ConfigureAwait(false);
            var checkpoint = verified.CurrentCheckpoint;
            if (checkpoint is null ||
                !CryptographicOperations.FixedTimeEquals(
                    checkpoint.Binding.DeepId.CanonicalBytes.Span,
                    request.ExactDid2.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    checkpoint.Binding.Record.CanonicalBytes.Span,
                    request.ExactDab2.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    checkpoint.Checkpoint.CanonicalBytes.Span,
                    request.ExactAdc1V2.Span))
                throw new CryptographicException(
                    "The authenticated DID2 proof does not confirm the exact local genesis admission.");
            using var finalVerifier = OpenVerifier();
            using var finalCurrent = await owner.ReadCurrentAsync(
                    TrustedUnixSeconds(), finalVerifier, cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException(
                    "The DID2 account disappeared during directory verification.");
            var finalBinding = finalCurrent.Verified.PublicEvidence.Binding;
            if (!CryptographicOperations.FixedTimeEquals(
                    finalBinding.DeepId.CanonicalBytes.Span,
                    request.ExactDid2.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    finalBinding.Record.CanonicalBytes.Span,
                    request.ExactDab2.Span))
                throw new CryptographicException(
                    "The local DID2 account changed during directory verification.");
            return verified;
        }
        finally { CryptographicOperations.ZeroMemory(exactDga1); }
    }

    /// <summary>
    /// Opens the account-owned, SQLCipher-backed DID2 directory floor. The
    /// caller supplies the separately pinned signed empty V2 head; no V1
    /// directory state is read or migrated.
    /// </summary>
    public async Task<IDeepIdV2DirectoryProtectedLkgStore>
        OpenDirectoryLkgStoreAsync(
            VerifiedXPointNetworkAuthority authority,
            ReadOnlyMemory<byte> exactGenesisAdh1,
            ReadOnlyMemory<byte> protectedGenesisCoreHash,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        using var verifier = OpenVerifier();
        return await owner.OpenDirectoryLkgStoreAsync(TrustedUnixSeconds(),
            verifier, authority, exactGenesisAdh1,
            protectedGenesisCoreHash, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Caller owns and must dispose the returned phrase. Null means the user
    /// permanently deleted this device's retained phrase.
    /// </summary>
    public async Task<VerifiedDeepRecoveryPhrase?> ReadRetainedRecoveryPhraseAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadRetainedRecoveryPhraseAsync(
            TrustedUnixSeconds(), verifier, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task DeleteRetainedRecoveryPhraseAsync(
        CancellationToken cancellationToken = default)
    {
        using var verifier = OpenVerifier();
        await owner.DeleteRetainedRecoveryPhraseAsync(TrustedUnixSeconds(),
            verifier, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Explicit destructive reset, never an automatic repair path.</summary>
    public Task ResetExplicitlyAsync(CancellationToken cancellationToken = default) =>
        owner.ResetExplicitlyAsync(cancellationToken).AsTask();

    private IDeepMlDsa65VerifierLease OpenVerifier() =>
        verifierFactory() ?? throw new InvalidOperationException(
            "The DID2 verifier factory returned no verifier lease.");

    private static byte[] GenesisOperationId(ReadOnlySpan<byte> did2Hash,
        ReadOnlySpan<byte> dab2Hash)
    {
        ReadOnlySpan<byte> domain =
            "Deep/Application/V2/genesis-admission-operation"u8;
        var transcript = new byte[domain.Length + 64];
        domain.CopyTo(transcript);
        did2Hash.CopyTo(transcript.AsSpan(domain.Length));
        dab2Hash.CopyTo(transcript.AsSpan(domain.Length + 32));
        return SHA256.HashData(transcript);
    }

    private ulong TrustedUnixSeconds()
    {
        var seconds = clock.UtcNow.ToUnixTimeSeconds();
        if (seconds < 0)
            throw new InvalidOperationException(
                "The DID2 account clock precedes the Unix epoch.");
        return checked((ulong)seconds);
    }

    private static DeepIdV2AccountSnapshot Snapshot(
        VerifiedDeepIdV2CurrentAccount current) =>
        new(current.DisplayName, current.AccountId.Span,
            current.PermanentId);
}

public sealed class DeepIdV2AccountSnapshot
{
    private readonly byte[] accountId;

    internal DeepIdV2AccountSnapshot(string displayName,
        ReadOnlySpan<byte> accountId, DeepPermanentIdV2 permanentId)
    {
        DisplayName = displayName;
        this.accountId = accountId.ToArray();
        PermanentId = permanentId;
    }

    public string DisplayName { get; }
    public ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    public DeepPermanentIdV2 PermanentId { get; }
}
