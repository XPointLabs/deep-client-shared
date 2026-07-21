using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace Deep.Client.Shared.Services;

public enum DormantSelfHostedProfileVerificationStatus
{
    Verified = 1,
    Missing = 2,
    InvalidRequest = 3,
    BoundsExceeded = 4,
    Malformed = 5,
    TrustRejected = 6,
    CorruptStaging = 7,
    DependencyFailure = 8
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class DormantSelfHostedProfileVerificationParameters
{
    public DormantSelfHostedProfileVerificationParameters(
        ulong verificationTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocol)
    {
        VerificationTimeUnixSeconds = verificationTimeUnixSeconds;
        AllowedClockSkewSeconds = allowedClockSkewSeconds;
        Protocol = protocol;
    }

    public ulong VerificationTimeUnixSeconds { get; }

    public uint AllowedClockSkewSeconds { get; }

    public ushort Protocol { get; }

    public override string ToString() =>
        nameof(DormantSelfHostedProfileVerificationParameters);
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class DormantSelfHostedProfileVerificationMetadata
{
    internal DormantSelfHostedProfileVerificationMetadata(
        string fingerprint,
        ushort minimumProtocol,
        ushort maximumProtocol,
        int componentCount,
        int bridgeCount)
    {
        Fingerprint = fingerprint;
        MinimumProtocol = minimumProtocol;
        MaximumProtocol = maximumProtocol;
        ComponentCount = componentCount;
        BridgeCount = bridgeCount;
    }

    public string Fingerprint { get; }

    public ushort MinimumProtocol { get; }

    public ushort MaximumProtocol { get; }

    public int ComponentCount { get; }

    public int BridgeCount { get; }

    public override string ToString() => "[dormant-self-hosted-profile-metadata]";
}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class DormantSelfHostedProfileVerificationOutcome
{
    internal DormantSelfHostedProfileVerificationOutcome(
        DormantSelfHostedProfileVerificationStatus status,
        DormantSelfHostedProfileVerificationMetadata? metadata = null)
    {
        Status = status;
        Metadata = metadata;
    }

    public DormantSelfHostedProfileVerificationStatus Status { get; }

    public DormantSelfHostedProfileVerificationMetadata? Metadata { get; }

    public override string ToString() => "[dormant-self-hosted-profile-verification-outcome]";
}

/// <summary>
/// Verifies one defensive snapshot of a staged candidate without persisting,
/// selecting, activating, relabeling, deleting, or connecting it.
/// </summary>
public sealed class DormantSelfHostedProfileVerificationService
{
    private readonly StagedSelfHostedProfileService staging;
    private readonly IMembershipSignatureVerifier verifier;
    private readonly SemaphoreSlim verificationGate = new(1, 1);

    public DormantSelfHostedProfileVerificationService(
        StagedSelfHostedProfileService staging,
        IMembershipSignatureVerifier verifier)
    {
        this.staging = staging ?? throw new ArgumentNullException(nameof(staging));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
    }

    public async Task<DormantSelfHostedProfileVerificationOutcome> VerifyAsync(
        SelfHostedProfileStagingAccountScope accountScope,
        StagedSelfHostedProfileCandidateId candidateId,
        DormantSelfHostedProfileVerificationParameters parameters,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(candidateId);
        ArgumentNullException.ThrowIfNull(parameters);
        ThrowIfCanceled(cancellationToken);

        StagedSelfHostedProfileExportOutcome exported;
        try
        {
            exported = await staging.ExportAsync(
                accountScope,
                candidateId,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw SanitizedCancellation(cancellationToken);
        }
        catch (Exception)
        {
            return Outcome(DormantSelfHostedProfileVerificationStatus.DependencyFailure);
        }

        ThrowIfCanceled(cancellationToken);
        switch (exported.Result)
        {
            case StagedSelfHostedProfileExportResult.Missing:
                return Outcome(DormantSelfHostedProfileVerificationStatus.Missing);
            case StagedSelfHostedProfileExportResult.Corrupt:
                return Outcome(DormantSelfHostedProfileVerificationStatus.CorruptStaging);
            case StagedSelfHostedProfileExportResult.DependencyFailure:
                return Outcome(DormantSelfHostedProfileVerificationStatus.DependencyFailure);
            case StagedSelfHostedProfileExportResult.Exported:
                break;
            default:
                return Outcome(DormantSelfHostedProfileVerificationStatus.DependencyFailure);
        }

        byte[] candidateBytes;
        try
        {
            candidateBytes = exported.GetCandidateBytesCopy();
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch (Exception)
        {
            return Outcome(DormantSelfHostedProfileVerificationStatus.DependencyFailure);
        }

        try
        {
            if (candidateBytes.Length > ProfileCarrierLimits.MaximumFilePayloadBytes)
                return Outcome(DormantSelfHostedProfileVerificationStatus.BoundsExceeded);

            ProfileCarrierVerificationOptions options;
            try
            {
                options = new ProfileCarrierVerificationOptions(
                    parameters.VerificationTimeUnixSeconds,
                    parameters.AllowedClockSkewSeconds,
                    parameters.Protocol);
            }
            catch (OutOfMemoryException)
            {
                throw;
            }
            catch (ProfileCarrierException)
            {
                return Outcome(DormantSelfHostedProfileVerificationStatus.InvalidRequest);
            }
            catch (Exception)
            {
                return Outcome(DormantSelfHostedProfileVerificationStatus.DependencyFailure);
            }

            try
            {
                await verificationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw SanitizedCancellation(cancellationToken);
            }

            try
            {
                ThrowIfCanceled(cancellationToken);
                var guardedVerifier = new GuardedMembershipVerifier(verifier, cancellationToken);
                try
                {
                    var result = ProfileCarrierVerifier.VerifyExact(
                        candidateBytes,
                        options,
                        guardedVerifier);
                    ThrowIfCanceled(cancellationToken);
                    if (guardedVerifier.DependencyFailed)
                        return Outcome(DormantSelfHostedProfileVerificationStatus.DependencyFailure);
                    if (!TryCreateMetadata(result, out var metadata))
                        return Outcome(DormantSelfHostedProfileVerificationStatus.DependencyFailure);
                    return new(DormantSelfHostedProfileVerificationStatus.Verified, metadata);
                }
                catch (OutOfMemoryException)
                {
                    throw;
                }
                catch (ProfileCarrierException exception)
                {
                    ThrowIfCanceled(cancellationToken);
                    if (guardedVerifier.DependencyFailed)
                        return Outcome(DormantSelfHostedProfileVerificationStatus.DependencyFailure);
                    return Outcome(exception.Error switch
                    {
                        ProfileCarrierError.BoundsExceeded =>
                            DormantSelfHostedProfileVerificationStatus.BoundsExceeded,
                        ProfileCarrierError.VerificationRejected =>
                            DormantSelfHostedProfileVerificationStatus.TrustRejected,
                        ProfileCarrierError.InvalidFraming or ProfileCarrierError.InvalidInput =>
                            DormantSelfHostedProfileVerificationStatus.Malformed,
                        _ => DormantSelfHostedProfileVerificationStatus.DependencyFailure
                    });
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw SanitizedCancellation(cancellationToken);
                }
                catch (Exception)
                {
                    ThrowIfCanceled(cancellationToken);
                    return Outcome(DormantSelfHostedProfileVerificationStatus.DependencyFailure);
                }
            }
            finally
            {
                verificationGate.Release();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(candidateBytes);
        }
    }

    private static bool TryCreateMetadata(
        ProfileCarrierVerificationResult result,
        out DormantSelfHostedProfileVerificationMetadata? metadata)
    {
        metadata = null;
        var fingerprint = result.Fingerprint;
        if (fingerprint is null
            || fingerprint.Length != 71
            || !fingerprint.StartsWith("sha256:", StringComparison.Ordinal)
            || result.MinimumProtocol == 0
            || result.MinimumProtocol > result.MaximumProtocol
            || result.ComponentCount is < 4 or > ProfileCarrierLimits.MaximumComponents
            || result.BridgeCount is < 1
            || result.BridgeCount != result.ComponentCount -
                ProfileCarrierLimits.RequiredNonBridgeComponents)
        {
            return false;
        }

        for (var index = 7; index < fingerprint.Length; index++)
        {
            var value = fingerprint[index];
            if (value is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
                return false;
        }

        metadata = new(
            fingerprint,
            result.MinimumProtocol,
            result.MaximumProtocol,
            result.ComponentCount,
            result.BridgeCount);
        return true;
    }

    private static DormantSelfHostedProfileVerificationOutcome Outcome(
        DormantSelfHostedProfileVerificationStatus status) => new(status);

    private static void ThrowIfCanceled(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
            throw SanitizedCancellation(cancellationToken);
    }

    private static OperationCanceledException SanitizedCancellation(
        CancellationToken cancellationToken) => new(cancellationToken);

    private sealed class GuardedMembershipVerifier(
        IMembershipSignatureVerifier inner,
        CancellationToken cancellationToken) : IMembershipSignatureVerifier
    {
        private int dependencyFailed;

        public bool DependencyFailed => Volatile.Read(ref dependencyFailed) != 0;

        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            if (cancellationToken.IsCancellationRequested)
                return false;
            try
            {
                var accepted = inner.Verify(
                    signerId,
                    publicKey,
                    domain,
                    signingBytes,
                    signature);
                return !cancellationToken.IsCancellationRequested && accepted;
            }
            catch (OutOfMemoryException)
            {
                throw;
            }
            catch (Exception)
            {
                if (!cancellationToken.IsCancellationRequested)
                    Interlocked.Exchange(ref dependencyFailed, 1);
                return false;
            }
        }
    }
}
