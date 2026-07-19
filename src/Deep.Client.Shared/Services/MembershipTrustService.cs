using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Client.Shared.Services;

public sealed class MembershipTrustService(
    IMembershipTrustRepository repository,
    IMembershipSignatureVerifier? verifier,
    IClock clock,
    MembershipTrustOptions options)
{
    public Task<MembershipTrustStatus> InitializeAsync(
        MembershipTrustProfile profile,
        CancellationToken cancellationToken = default) =>
        ExecutePublicAsync(
            () => InitializeCoreAsync(
                SnapshotProfile(profile),
                CanonicalOperationTime(clock.UtcNow),
                cancellationToken));

    private async Task<MembershipTrustStatus> InitializeCoreAsync(
        MembershipTrustProfile profile,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!options.Enabled)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Disabled);
        }
        if (verifier is null)
        {
            return MembershipTrustStatus.For(MembershipTrustState.VerifierUnavailable);
        }
        try
        {
            ValidateOptions();
            var clockStatus = await ObserveClockAsync(
                profile.OpaqueProfileKey,
                now,
                cancellationToken).ConfigureAwait(false);
            if (clockStatus is not null)
            {
                return clockStatus;
            }
            var pins = ValidateBootstrapPins(profile);
            var profileBinding = ComputeProfileBinding(profile);
            var authority = await repository.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                MembershipTrustDomain.Authority,
                cancellationToken).ConfigureAwait(false);
            if (authority.Result == MembershipTrustReadResult.Corrupt)
            {
                return MembershipTrustStatus.For(
                    MembershipTrustState.Corrupt,
                    MembershipTrustEvent.LocalStateRejected);
            }
            if (authority.Result == MembershipTrustReadResult.Found &&
                (authority.Head is null ||
                 !authority.Head.ProfileBindingHash.AsSpan().SequenceEqual(profileBinding)))
            {
                return MembershipTrustStatus.For(MembershipTrustState.ProtocolUnsupported);
            }

            if (authority.Result == MembershipTrustReadResult.Missing)
            {
                var bootstrap = VerifyBootstrap(profile, now);
                var authorityRecord = MembershipTrustRecord.Create(
                    profile.OpaqueProfileKey,
                    MembershipTrustDomain.Authority,
                    revision: 1,
                    sequence: bootstrap.Delegation.Sequence,
                    previousSequence: bootstrap.Genesis.GenesisSequence,
                    previousCanonicalHash: bootstrap.GenesisHash,
                    canonicalEnvelope: profile.SignedDelegation,
                    state: MembershipTrustState.Healthy,
                    observedAt: now,
                    validUntil: Unix(bootstrap.Delegation.ValidUntilUnixSeconds),
                    validFrom: Unix(bootstrap.Delegation.ValidFromUnixSeconds),
                    canonicalHash: bootstrap.DelegationHash,
                    profileBindingHash: profileBinding,
                    artifactKind: MembershipTrustArtifactKind.Delegation);
                if (await repository.CommitMembershipTrustAsync(
                        authorityRecord,
                        expectedHeadRevision: null,
                        cancellationToken).ConfigureAwait(false)
                    is not (MembershipTrustCommitResult.Applied or MembershipTrustCommitResult.Idempotent))
                {
                    return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
                }
            }
            else
            {
                var persisted = RevalidateAuthority(
                    authority,
                    pins.Genesis,
                    pins.GenesisHash,
                    pins.CanonicalDelegation);
                if (persisted is not null)
                {
                    return persisted;
                }
            }

            if (profile.BridgeAnchor is null || profile.MembershipAnchor is null)
            {
                return MembershipTrustStatus.For(
                    MembershipTrustState.MissingBootstrap,
                    MembershipTrustEvent.BootstrapRequired);
            }

            var bridge = await EnsureAnchorAsync(
                profile,
                MembershipTrustDomain.Bridge,
                profile.BridgeAnchor,
                profileBinding,
                now,
                cancellationToken).ConfigureAwait(false);
            if (bridge.State != MembershipTrustState.Healthy)
            {
                return bridge;
            }
            var membership = await EnsureAnchorAsync(
                profile,
                MembershipTrustDomain.Membership,
                profile.MembershipAnchor,
                profileBinding,
                now,
                cancellationToken).ConfigureAwait(false);
            if (membership.State != MembershipTrustState.Healthy)
            {
                return membership;
            }

            var revalidated = await RevalidateContentHeadsAsync(
                profile,
                pins.Genesis,
                cancellationToken).ConfigureAwait(false);
            if (revalidated is not null)
            {
                return revalidated;
            }

            return await EvaluateCoreAsync(
                profile,
                now,
                observeClock: false,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (MembershipContractException exception)
        {
            return FromContractError(exception.Error);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidDataException or OverflowException)
        {
            return MembershipTrustStatus.For(
                MembershipTrustState.Corrupt,
                MembershipTrustEvent.VerificationRejected);
        }
    }

    public Task<MembershipTrustStatus> ApplyMembershipAsync(
        MembershipTrustProfile profile,
        ReadOnlyMemory<byte> canonicalSignedEnvelope,
        CancellationToken cancellationToken = default) =>
        ExecutePublicAsync(
            () => ApplyContentAsync(
                SnapshotProfile(profile),
                MembershipTrustDomain.Membership,
                Bounded(canonicalSignedEnvelope),
                CanonicalOperationTime(clock.UtcNow),
                cancellationToken));

    public Task<MembershipTrustStatus> ApplyBridgeAsync(
        MembershipTrustProfile profile,
        ReadOnlyMemory<byte> canonicalSignedEnvelope,
        CancellationToken cancellationToken = default) =>
        ExecutePublicAsync(
            () => ApplyContentAsync(
                SnapshotProfile(profile),
                MembershipTrustDomain.Bridge,
                Bounded(canonicalSignedEnvelope),
                CanonicalOperationTime(clock.UtcNow),
                cancellationToken));

    public Task<MembershipTrustStatus> ApplyDelegationAsync(
        MembershipTrustProfile profile,
        ReadOnlyMemory<byte> canonicalSignedEnvelope,
        CancellationToken cancellationToken = default) =>
        ExecutePublicAsync(
            () => ApplyAuthorityAsync(
                SnapshotProfile(profile),
                Bounded(canonicalSignedEnvelope),
                MembershipTrustArtifactKind.Delegation,
                CanonicalOperationTime(clock.UtcNow),
                cancellationToken));

    public Task<MembershipTrustStatus> ApplyRevocationAsync(
        MembershipTrustProfile profile,
        ReadOnlyMemory<byte> canonicalSignedEnvelope,
        CancellationToken cancellationToken = default) =>
        ExecutePublicAsync(
            () => ApplyAuthorityAsync(
                SnapshotProfile(profile),
                Bounded(canonicalSignedEnvelope),
                MembershipTrustArtifactKind.Revocation,
                CanonicalOperationTime(clock.UtcNow),
                cancellationToken));

    private async Task<MembershipTrustStatus> ApplyAuthorityAsync(
        MembershipTrustProfile profile,
        ReadOnlyMemory<byte> canonicalSignedEnvelope,
        MembershipTrustArtifactKind artifactKind,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!options.Enabled)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Disabled);
        }
        if (verifier is null)
        {
            return MembershipTrustStatus.For(MembershipTrustState.VerifierUnavailable);
        }

        try
        {
            ValidateOptions();
            var pins = ValidateBootstrapPins(profile);
            var genesis = pins.Genesis;
            var profileBinding = ComputeProfileBinding(profile);
            var clockStatus = await ObserveClockAsync(
                profile.OpaqueProfileKey,
                now,
                cancellationToken).ConfigureAwait(false);
            if (clockStatus is not null)
            {
                return clockStatus;
            }

            var bytes = Bounded(canonicalSignedEnvelope);
            var current = await repository.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                MembershipTrustDomain.Authority,
                cancellationToken).ConfigureAwait(false);
            if (current.Result != MembershipTrustReadResult.Found ||
                current.Head is null ||
                current.Head.State is not (MembershipTrustState.Healthy or MembershipTrustState.Revoked) ||
                !current.Head.ProfileBindingHash.AsSpan().SequenceEqual(profileBinding))
            {
                return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
            }
            var persistedStatus = RevalidateAuthority(
                current,
                pins.Genesis,
                pins.GenesisHash,
                pins.CanonicalDelegation);
            if (persistedStatus is not null)
            {
                return persistedStatus;
            }

            var decoded = DecodeAuthorityCandidate(bytes, artifactKind);
            if (decoded.Sequence < current.Head.Sequence)
            {
                return MembershipTrustStatus.For(MembershipTrustState.ProtocolUnsupported);
            }
            if (decoded.Sequence == current.Head.Sequence &&
                current.Head.ArtifactKind == artifactKind &&
                current.Head.CanonicalEnvelope.AsSpan().SequenceEqual(bytes))
            {
                return EvaluateAuthorityReplay(current.Head, now);
            }
            var lkg = decoded.Sequence == current.Head.Sequence
                ? new MembershipLastKnownGood
                {
                    NetworkId = genesis.NetworkId.ToArray(),
                    PolicyVersion = genesis.PolicyVersion,
                    Sequence = current.Head.PreviousSequence,
                    CanonicalHash = current.Head.PreviousCanonicalHash.ToArray()
                }
                : new MembershipLastKnownGood
                {
                    NetworkId = genesis.NetworkId.ToArray(),
                    PolicyVersion = genesis.PolicyVersion,
                    Sequence = current.Head.Sequence,
                    CanonicalHash = current.Head.CanonicalHash.ToArray()
                };
            var revokedDelegationHashes = DecodeRevokedDelegationHashes(
                current.Head.RevokedDelegationHashes);
            var revocationOverflow = false;
            if (artifactKind == MembershipTrustArtifactKind.Revocation)
            {
                var revocation = (SignerRevocation)decoded.Value;
                var target = decoded.Sequence == current.Head.Sequence
                    ? current.Predecessor
                    : current.Head;
                if (target is null ||
                    target.ArtifactKind != MembershipTrustArtifactKind.Delegation ||
                    !revocation.DelegationHash.Span.SequenceEqual(target.CanonicalHash))
                {
                    return MembershipTrustStatus.For(MembershipTrustState.ProtocolUnsupported);
                }
                revocationOverflow =
                    revokedDelegationHashes.Count ==
                        MembershipLimits.MaximumRevokedDelegationHashes &&
                    !revokedDelegationHashes.Any(
                        value => value.Span.SequenceEqual(revocation.DelegationHash.Span));
            }
            var verifiedHash = VerifyAuthorityCandidate(decoded, genesis, lkg, now);
            if (artifactKind == MembershipTrustArtifactKind.Revocation &&
                !revocationOverflow)
            {
                revokedDelegationHashes = AddRevokedDelegationHash(
                    revokedDelegationHashes,
                    ((SignerRevocation)decoded.Value).DelegationHash);
            }
            if (decoded.Sequence == current.Head.Sequence)
            {
                return await PersistForkAsync(
                    profile,
                    MembershipTrustDomain.Authority,
                    current.Head,
                    bytes,
                    verifiedHash,
                    (decoded.ValidFrom, decoded.ValidUntil),
                    now,
                    artifactKind,
                    signingAuthorityEnvelope: [],
                    revokedDelegationHashes: FlattenRevokedDelegationHashes(
                        revokedDelegationHashes),
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }

            return await CommitAuthorityAsync(
                profile,
                current.Head,
                bytes,
                verifiedHash,
                decoded.Sequence,
                decoded.ValidFrom,
                decoded.ValidUntil,
                revocationOverflow
                    ? MembershipTrustState.Corrupt
                    : decoded.State,
                artifactKind,
                FlattenRevokedDelegationHashes(revokedDelegationHashes),
                now,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (MembershipContractException exception)
        {
            return FromContractError(exception.Error);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidDataException or OverflowException)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
        }
    }

    public Task<MembershipTrustStatus> EvaluateAsync(
        MembershipTrustProfile profile,
        CancellationToken cancellationToken = default) =>
        ExecutePublicAsync(
            () => EvaluateCoreAsync(
                SnapshotProfile(profile),
                CanonicalOperationTime(clock.UtcNow),
                observeClock: true,
                cancellationToken));

    private async Task<MembershipTrustStatus> EvaluateCoreAsync(
        MembershipTrustProfile profile,
        DateTimeOffset now,
        bool observeClock,
        CancellationToken cancellationToken)
    {
        if (!options.Enabled)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Disabled);
        }
        if (verifier is null)
        {
            return MembershipTrustStatus.For(MembershipTrustState.VerifierUnavailable);
        }

        byte[] profileBinding;
        NetworkGenesis genesis;
        try
        {
            ValidateOptions();
            genesis = DecodePinnedGenesis(profile);
            var canonicalDelegation = Bounded(profile.SignedDelegation);
            RequireExact(
                canonicalDelegation,
                MembershipContractCodec.EncodeSignedDelegation(
                    MembershipContractCodec.DecodeSignedDelegation(canonicalDelegation)));
            profileBinding = ComputeProfileBinding(profile);
            if (observeClock)
            {
                var clockStatus = await ObserveClockAsync(
                    profile.OpaqueProfileKey,
                    now,
                    cancellationToken).ConfigureAwait(false);
                if (clockStatus is not null)
                {
                    return clockStatus;
                }
            }
        }
        catch (MembershipContractException exception)
        {
            return FromContractError(exception.Error);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidDataException or OverflowException)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
        }

        var snapshots = new List<MembershipTrustReadSnapshot>(3);
        foreach (var domain in new[]
                 {
                     MembershipTrustDomain.Authority,
                     MembershipTrustDomain.Bridge,
                     MembershipTrustDomain.Membership
                 })
        {
            var snapshot = await repository.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                domain,
                cancellationToken).ConfigureAwait(false);
            if (snapshot.Result == MembershipTrustReadResult.Corrupt)
            {
                return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
            }
            if (snapshot.Result == MembershipTrustReadResult.Missing || snapshot.Head is null)
            {
                return MembershipTrustStatus.For(MembershipTrustState.MissingBootstrap);
            }
            if (!snapshot.Head.ProfileBindingHash.AsSpan().SequenceEqual(profileBinding))
            {
                return MembershipTrustStatus.For(MembershipTrustState.ProtocolUnsupported);
            }
            snapshots.Add(snapshot);
        }

        MembershipTrustStatus? revalidated;
        try
        {
            revalidated = await RevalidateContentHeadsAsync(
                profile,
                genesis,
                cancellationToken).ConfigureAwait(false);
        }
        catch (MembershipContractException exception)
        {
            return FromContractError(exception.Error);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidDataException or OverflowException)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
        }
        if (revalidated is not null)
        {
            return revalidated;
        }

        var blocking = snapshots.Select(static snapshot => snapshot.Head!.State)
            .FirstOrDefault(static state => state is
                MembershipTrustState.ForkDetected or
                MembershipTrustState.Revoked or
                MembershipTrustState.Corrupt);
        if (blocking != default)
        {
            return MembershipTrustStatus.For(blocking);
        }

        var notYetValid = snapshots.Max(static snapshot => snapshot.Head!.ValidFrom);
        if (now + options.AllowedClockSkew < notYetValid)
        {
            return MembershipTrustStatus.For(MembershipTrustState.NotYetValid);
        }

        var expires = snapshots.Min(static snapshot => snapshot.Head!.ValidUntil);
        if (now > expires + options.AllowedClockSkew)
        {
            if (options.StaleGrace > TimeSpan.Zero &&
                now <= expires + options.AllowedClockSkew + options.StaleGrace)
            {
                return MembershipTrustStatus.For(MembershipTrustState.DegradedStale);
            }
            return MembershipTrustStatus.For(MembershipTrustState.Expired);
        }

        if (!await HeadsMatchAsync(
                profile.OpaqueProfileKey,
                snapshots,
                cancellationToken).ConfigureAwait(false))
        {
            return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
        }
        return MembershipTrustStatus.For(MembershipTrustState.Healthy);
    }

    private async Task<bool> HeadsMatchAsync(
        string opaqueProfileKey,
        IReadOnlyList<MembershipTrustReadSnapshot> expected,
        CancellationToken cancellationToken)
    {
        var domains = new[]
        {
            MembershipTrustDomain.Authority,
            MembershipTrustDomain.Bridge,
            MembershipTrustDomain.Membership
        };
        if (expected.Count != domains.Length)
        {
            return false;
        }
        for (var index = 0; index < domains.Length; index++)
        {
            var current = await repository.ReadMembershipTrustAsync(
                opaqueProfileKey,
                domains[index],
                cancellationToken).ConfigureAwait(false);
            var expectedHead = expected[index].Head;
            if (current.Result != MembershipTrustReadResult.Found ||
                current.Head is null ||
                expectedHead is null ||
                current.Head.Revision != expectedHead.Revision ||
                !current.Head.PayloadDigest.AsSpan().SequenceEqual(
                    expectedHead.PayloadDigest))
            {
                return false;
            }
        }
        return true;
    }

    private MembershipTrustStatus EvaluateAuthorityReplay(
        MembershipTrustRecord current,
        DateTimeOffset now)
    {
        if (current.State != MembershipTrustState.Healthy)
        {
            return MembershipTrustStatus.For(
                current.State,
                MembershipTrustEvent.StateUnchanged);
        }
        if (now + options.AllowedClockSkew < current.ValidFrom)
        {
            return MembershipTrustStatus.For(MembershipTrustState.NotYetValid);
        }
        if (now > current.ValidUntil + options.AllowedClockSkew)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Expired);
        }
        return MembershipTrustStatus.For(
            MembershipTrustState.Healthy,
            MembershipTrustEvent.StateUnchanged);
    }

    public Task<MembershipTrustStatus> ImportSelfHostedGenesisAsync(
        SelfHostedGenesisImport import,
        CancellationToken cancellationToken = default) =>
        ExecutePublicAsync(
            () => ImportSelfHostedGenesisCoreAsync(
                SnapshotImport(import),
                CanonicalOperationTime(clock.UtcNow),
                cancellationToken));

    private async Task<MembershipTrustStatus> ImportSelfHostedGenesisCoreAsync(
        SelfHostedGenesisImport import,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!options.Enabled)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Disabled);
        }
        if (verifier is null)
        {
            return MembershipTrustStatus.For(MembershipTrustState.VerifierUnavailable);
        }
        try
        {
            ValidateProfileKey(import.OpaqueProfileKey, allowSelfHosted: true);
            if (!import.OpaqueProfileKey.StartsWith("install:self-hosted:", StringComparison.Ordinal))
            {
                throw new InvalidDataException("Self-hosted profiles require an independent namespace.");
            }
            var clockStatus = await ObserveClockAsync(
                import.OpaqueProfileKey,
                now,
                cancellationToken,
                allowSelfHosted: true).ConfigureAwait(false);
            if (clockStatus is not null)
            {
                return clockStatus;
            }
            var bytes = Bounded(import.CanonicalGenesis);
            var signatures = DecodeSelfHostedSignatures(import.CanonicalSignatures);
            var genesis = MembershipContractVerifier.ImportSelfHostedGenesis(
                bytes,
                import.ExpectedNetworkId,
                import.ExpectedCanonicalGenesisSha256,
                signatures,
                verifier);
            RequireExact(bytes, MembershipContractCodec.EncodeGenesis(genesis));
            var record = MembershipTrustRecord.Create(
                import.OpaqueProfileKey,
                MembershipTrustDomain.Authority,
                revision: 1,
                sequence: genesis.GenesisSequence,
                previousSequence: genesis.GenesisSequence - 1,
                previousCanonicalHash: new byte[MembershipLimits.HashLength],
                canonicalEnvelope: bytes,
                state: MembershipTrustState.MissingBootstrap,
                observedAt: now,
                validUntil: DateTimeOffset.MaxValue,
                canonicalHash: MembershipContractHash.Sha256(bytes),
                profileBindingHash: ComputeSelfHostedBinding(import),
                artifactKind: MembershipTrustArtifactKind.SelfHostedGenesis);
            var result = await repository.CommitMembershipTrustAsync(
                record,
                expectedHeadRevision: null,
                cancellationToken).ConfigureAwait(false);
            return result is MembershipTrustCommitResult.Applied or MembershipTrustCommitResult.Idempotent
                ? MembershipTrustStatus.For(MembershipTrustState.MissingBootstrap)
                : MembershipTrustStatus.For(MembershipTrustState.Corrupt);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (MembershipContractException exception)
        {
            return FromContractError(exception.Error);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidDataException or OverflowException)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
        }
    }

    private async Task<MembershipTrustStatus> ApplyContentAsync(
        MembershipTrustProfile profile,
        MembershipTrustDomain domain,
        ReadOnlyMemory<byte> canonicalSignedEnvelope,
        DateTimeOffset operationNow,
        CancellationToken cancellationToken)
    {
        var ready = await RequireReadyAsync(profile, operationNow, cancellationToken).ConfigureAwait(false);
        if (ready.Blocked is not null)
        {
            return ready.Blocked;
        }

        try
        {
            var bytes = Bounded(canonicalSignedEnvelope);
            var authority = await repository.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                MembershipTrustDomain.Authority,
                cancellationToken).ConfigureAwait(false);
            var current = await repository.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                domain,
                cancellationToken).ConfigureAwait(false);
            if (authority.Result != MembershipTrustReadResult.Found ||
                authority.Head is null ||
                authority.Head.State != MembershipTrustState.Healthy ||
                current.Result != MembershipTrustReadResult.Found ||
                current.Head is null ||
                current.Head.State != MembershipTrustState.Healthy)
            {
                return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
            }

            var genesis = DecodePinnedGenesis(profile);
            var delegation = MembershipContractCodec.DecodeSignedDelegation(
                authority.Head.CanonicalEnvelope);
            RequireExact(
                authority.Head.CanonicalEnvelope,
                MembershipContractCodec.EncodeSignedDelegation(delegation));
            var candidate = DecodeContent(domain, bytes);
            var sequence = ContentSequence(candidate);

            if (ready.StrictSuccessorRequired && sequence <= current.Head.Sequence)
            {
                return MembershipTrustStatus.For(ready.PreservedState);
            }
            if (sequence < current.Head.Sequence)
            {
                return MembershipTrustStatus.For(MembershipTrustState.ProtocolUnsupported);
            }
            if (sequence == current.Head.Sequence &&
                current.Head.CanonicalEnvelope.AsSpan().SequenceEqual(bytes))
            {
                if (current.Head.Revision > 1 &&
                    !current.Head.SigningAuthorityEnvelope.AsSpan().SequenceEqual(
                        authority.Head.CanonicalEnvelope))
                {
                    return MembershipTrustStatus.For(
                        MembershipTrustState.ProtocolUnsupported);
                }
                return MembershipTrustStatus.For(
                    MembershipTrustState.Healthy,
                    MembershipTrustEvent.StateUnchanged);
            }

            var lkg = sequence == current.Head.Sequence
                ? new MembershipLastKnownGood
                {
                    NetworkId = genesis.NetworkId.ToArray(),
                    PolicyVersion = genesis.PolicyVersion,
                    Sequence = current.Head.PreviousSequence,
                    CanonicalHash = current.Head.PreviousCanonicalHash.ToArray()
                }
                : ToLastKnownGood(
                    current.Head,
                    genesis.NetworkId,
                    genesis.PolicyVersion);
            var context = new MembershipVerificationContext
            {
                Genesis = genesis,
                ActiveDelegation = delegation,
                AuthorityLastKnownGood = ToLastKnownGood(authority.Head),
                RevokedDelegationHashes = DecodeRevokedDelegationHashes(
                    authority.Head.RevokedDelegationHashes),
                LastKnownGood = lkg,
                VerificationTimeUnixSeconds = Seconds(operationNow),
                AllowedClockSkewSeconds = AllowedSkewSeconds(),
                ClientProtocol = options.ClientProtocol
            };
            var verified = VerifyContent(domain, candidate, context);
            var verifiedHash = VerifiedHash(verified);

            if (sequence == current.Head.Sequence)
            {
                if (verifiedHash.Span.SequenceEqual(current.Head.CanonicalHash))
                {
                    return MembershipTrustStatus.For(
                        MembershipTrustState.Healthy,
                        MembershipTrustEvent.StateUnchanged);
                }
                return await PersistForkAsync(
                    profile,
                    domain,
                    current.Head,
                    bytes,
                    verifiedHash.ToArray(),
                    ContentValidity(candidate),
                    operationNow,
                    domain == MembershipTrustDomain.Bridge
                        ? MembershipTrustArtifactKind.Bridge
                        : MembershipTrustArtifactKind.Membership,
                    authority.Head.CanonicalEnvelope,
                    revokedDelegationHashes: [],
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }

            var validity = ContentValidity(candidate);
            var record = MembershipTrustRecord.Create(
                profile.OpaqueProfileKey,
                domain,
                current.Head.Revision + 1,
                sequence,
                current.Head.Sequence,
                current.Head.CanonicalHash,
                bytes,
                MembershipTrustState.Healthy,
                operationNow,
                Unix(validity.ValidUntil),
                Unix(validity.ValidFrom),
                verifiedHash.ToArray(),
                current.Head.ProfileBindingHash,
                signingAuthorityEnvelope: authority.Head.CanonicalEnvelope);
            var result = await repository.CommitMembershipTrustAsync(
                record,
                current.Head.Revision,
                cancellationToken).ConfigureAwait(false);
            if (result is MembershipTrustCommitResult.Applied or MembershipTrustCommitResult.Idempotent)
            {
                var authorityFence = await repository.ReadMembershipTrustAsync(
                    profile.OpaqueProfileKey,
                    MembershipTrustDomain.Authority,
                    cancellationToken).ConfigureAwait(false);
                if (!SameHead(authority, authorityFence))
                {
                    return await EvaluateCoreAsync(
                        profile,
                        operationNow,
                        observeClock: false,
                        cancellationToken).ConfigureAwait(false);
                }
                var contentFence = await repository.ReadMembershipTrustAsync(
                    profile.OpaqueProfileKey,
                    domain,
                    cancellationToken).ConfigureAwait(false);
                if (contentFence.Result != MembershipTrustReadResult.Found ||
                    contentFence.Head is null ||
                    contentFence.Head.Revision != record.Revision ||
                    !contentFence.Head.PayloadDigest.AsSpan().SequenceEqual(
                        record.PayloadDigest))
                {
                    return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
                }
                return MembershipTrustStatus.For(
                    MembershipTrustState.Healthy,
                    MembershipTrustEvent.StateAccepted);
            }
            if (result == MembershipTrustCommitResult.Conflict)
            {
                var winner = await repository.ReadMembershipTrustAsync(
                    profile.OpaqueProfileKey,
                    domain,
                    cancellationToken).ConfigureAwait(false);
                if (winner.Result == MembershipTrustReadResult.Found &&
                    winner.Head is not null &&
                    winner.Head.Sequence == sequence &&
                    !winner.Head.CanonicalHash.AsSpan().SequenceEqual(verifiedHash.Span))
                {
                    return await PersistForkAsync(
                        profile,
                        domain,
                        winner.Head,
                        bytes,
                        verifiedHash.ToArray(),
                        validity,
                        operationNow,
                        domain == MembershipTrustDomain.Bridge
                            ? MembershipTrustArtifactKind.Bridge
                            : MembershipTrustArtifactKind.Membership,
                        authority.Head.CanonicalEnvelope,
                        revokedDelegationHashes: [],
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                }
            }
            return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (MembershipContractException exception)
        {
            return FromContractError(exception.Error);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidDataException or OverflowException)
        {
            return MembershipTrustStatus.For(
                MembershipTrustState.Corrupt,
                MembershipTrustEvent.VerificationRejected);
        }
    }

    private async Task<MembershipTrustStatus> PersistForkAsync(
        MembershipTrustProfile profile,
        MembershipTrustDomain domain,
        MembershipTrustRecord current,
        byte[] candidateEnvelope,
        byte[] candidateHash,
        (ulong ValidFrom, ulong ValidUntil) validity,
        DateTimeOffset operationNow,
        MembershipTrustArtifactKind artifactKind,
        byte[] signingAuthorityEnvelope,
        byte[] revokedDelegationHashes,
        CancellationToken cancellationToken)
    {
        var fork = MembershipTrustRecord.Create(
            profile.OpaqueProfileKey,
            domain,
            current.Revision + 1,
            current.Sequence,
            current.PreviousSequence,
            current.PreviousCanonicalHash,
            candidateEnvelope,
            MembershipTrustState.ForkDetected,
            operationNow,
            Unix(validity.ValidUntil),
            Unix(validity.ValidFrom),
            candidateHash,
            current.ProfileBindingHash,
            artifactKind,
            signingAuthorityEnvelope,
            revokedDelegationHashes);
        var result = await repository.CommitMembershipTrustAsync(
            fork,
            current.Revision,
            cancellationToken).ConfigureAwait(false);
        return result is MembershipTrustCommitResult.Applied or MembershipTrustCommitResult.Idempotent
            ? MembershipTrustStatus.For(
                MembershipTrustState.ForkDetected,
                MembershipTrustEvent.EquivocationObserved)
            : MembershipTrustStatus.For(MembershipTrustState.Corrupt);
    }

    private async Task<ContentReadiness> RequireReadyAsync(
        MembershipTrustProfile profile,
        DateTimeOffset operationNow,
        CancellationToken cancellationToken)
    {
        var initialized = await InitializeCoreAsync(
            profile,
            operationNow,
            cancellationToken).ConfigureAwait(false);
        if (initialized.State == MembershipTrustState.Healthy)
        {
            return new ContentReadiness(
                Blocked: null,
                StrictSuccessorRequired: false,
                PreservedState: MembershipTrustState.Healthy);
        }
        if ((initialized.State is MembershipTrustState.ProtocolUnsupported or
                MembershipTrustState.Revoked) &&
            await CanRefreshSupersededContentAsync(
                profile,
                initialized.State,
                cancellationToken).ConfigureAwait(false))
        {
            return new ContentReadiness(
                Blocked: null,
                StrictSuccessorRequired: true,
                PreservedState: initialized.State);
        }
        return new ContentReadiness(
            initialized,
            StrictSuccessorRequired: false,
            PreservedState: initialized.State);
    }

    private async Task<bool> CanRefreshSupersededContentAsync(
        MembershipTrustProfile profile,
        MembershipTrustState initializedState,
        CancellationToken cancellationToken)
    {
        try
        {
            var profileBinding = ComputeProfileBinding(profile);
            var authority = await repository.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                MembershipTrustDomain.Authority,
                cancellationToken).ConfigureAwait(false);
            if (authority.Result != MembershipTrustReadResult.Found ||
                authority.Head is null ||
                authority.Head.State != MembershipTrustState.Healthy ||
                authority.Head.ArtifactKind != MembershipTrustArtifactKind.Delegation ||
                !authority.Head.ProfileBindingHash.AsSpan().SequenceEqual(profileBinding))
            {
                return false;
            }

            var revoked = DecodeRevokedDelegationHashes(
                authority.Head.RevokedDelegationHashes);
            var foundExpectedReason = false;
            foreach (var domain in new[]
                     {
                         MembershipTrustDomain.Bridge,
                         MembershipTrustDomain.Membership
                     })
            {
                var snapshot = await repository.ReadMembershipTrustAsync(
                    profile.OpaqueProfileKey,
                    domain,
                    cancellationToken).ConfigureAwait(false);
                if (snapshot.Result != MembershipTrustReadResult.Found ||
                    snapshot.Head is null ||
                    snapshot.Head.State != MembershipTrustState.Healthy ||
                    !snapshot.Head.ProfileBindingHash.AsSpan().SequenceEqual(profileBinding))
                {
                    return false;
                }
                if (snapshot.Head.ArtifactKind == MembershipTrustArtifactKind.Anchor)
                {
                    continue;
                }
                var signingDelegation = MembershipContractCodec.DecodeSignedDelegation(
                    snapshot.Head.SigningAuthorityEnvelope);
                RequireExact(
                    snapshot.Head.SigningAuthorityEnvelope,
                    MembershipContractCodec.EncodeSignedDelegation(signingDelegation));
                var signingHash = MembershipContractHash.Sha256(
                    MembershipContractCodec.GetDelegationSigningBytes(signingDelegation));
                var isRevoked = revoked.Any(value => value.Span.SequenceEqual(signingHash));
                var isSuperseded = !authority.Head.CanonicalHash.AsSpan().SequenceEqual(signingHash);
                foundExpectedReason |= initializedState == MembershipTrustState.Revoked
                    ? isRevoked
                    : isSuperseded && !isRevoked;
            }
            return foundExpectedReason;
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidDataException or
                MembershipContractException or OverflowException)
        {
            return false;
        }
    }

    private async Task<MembershipTrustStatus> EnsureAnchorAsync(
        MembershipTrustProfile profile,
        MembershipTrustDomain domain,
        MembershipTrustAnchor anchor,
        byte[] profileBinding,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (anchor.Sequence == 0 ||
            anchor.Sequence > long.MaxValue ||
            anchor.CanonicalHash is null ||
            anchor.CanonicalHash.Length != MembershipLimits.HashLength)
        {
            return MembershipTrustStatus.For(MembershipTrustState.MissingBootstrap);
        }

        var existing = await repository.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            domain,
            cancellationToken).ConfigureAwait(false);
        if (existing.Result == MembershipTrustReadResult.Corrupt)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
        }
        if (existing.Result == MembershipTrustReadResult.Found)
        {
            if (existing.Head is null ||
                !existing.Head.ProfileBindingHash.AsSpan().SequenceEqual(profileBinding) ||
                existing.Head.Sequence < anchor.Sequence ||
                (existing.Head.Sequence == anchor.Sequence &&
                 !existing.Head.CanonicalHash.AsSpan().SequenceEqual(anchor.CanonicalHash)))
            {
                return MembershipTrustStatus.For(MembershipTrustState.ProtocolUnsupported);
            }
            return existing.Head.State == MembershipTrustState.Healthy
                ? MembershipTrustStatus.For(MembershipTrustState.Healthy)
                : MembershipTrustStatus.For(existing.Head.State);
        }

        var record = MembershipTrustRecord.Create(
            profile.OpaqueProfileKey,
            domain,
            revision: 1,
            sequence: anchor.Sequence,
            previousSequence: anchor.Sequence - 1,
            previousCanonicalHash: new byte[MembershipLimits.HashLength],
            canonicalEnvelope: anchor.CanonicalHash,
            state: MembershipTrustState.Healthy,
            observedAt: now,
            validUntil: DateTimeOffset.MaxValue,
            validFrom: DateTimeOffset.UnixEpoch,
            canonicalHash: anchor.CanonicalHash,
            profileBindingHash: profileBinding,
            artifactKind: MembershipTrustArtifactKind.Anchor);
        var result = await repository.CommitMembershipTrustAsync(
            record,
            expectedHeadRevision: null,
            cancellationToken).ConfigureAwait(false);
        return result is MembershipTrustCommitResult.Applied or MembershipTrustCommitResult.Idempotent
            ? MembershipTrustStatus.For(MembershipTrustState.Healthy)
            : MembershipTrustStatus.For(MembershipTrustState.Corrupt);
    }

    private async Task<MembershipTrustStatus> CommitAuthorityAsync(
        MembershipTrustProfile profile,
        MembershipTrustRecord current,
        byte[] envelope,
        byte[] canonicalHash,
        ulong sequence,
        ulong validFrom,
        ulong validUntil,
        MembershipTrustState state,
        MembershipTrustArtifactKind artifactKind,
        byte[] revokedDelegationHashes,
        DateTimeOffset operationNow,
        CancellationToken cancellationToken)
    {
        var record = MembershipTrustRecord.Create(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Authority,
            current.Revision + 1,
            sequence,
            current.Sequence,
            current.CanonicalHash,
            envelope,
            state,
            operationNow,
            Unix(validUntil),
            Unix(validFrom),
            canonicalHash,
            current.ProfileBindingHash,
            artifactKind,
            signingAuthorityEnvelope: [],
            revokedDelegationHashes: revokedDelegationHashes);
        var result = await repository.CommitMembershipTrustAsync(
            record,
            current.Revision,
            cancellationToken).ConfigureAwait(false);
        if (result is MembershipTrustCommitResult.Applied or MembershipTrustCommitResult.Idempotent)
        {
            return MembershipTrustStatus.For(state, MembershipTrustEvent.StateAccepted);
        }
        if (result == MembershipTrustCommitResult.Conflict)
        {
            var winner = await repository.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                MembershipTrustDomain.Authority,
                cancellationToken).ConfigureAwait(false);
            if (winner.Result == MembershipTrustReadResult.Found &&
                winner.Head is not null &&
                winner.Head.Sequence == sequence)
            {
                if (winner.Head.CanonicalHash.AsSpan().SequenceEqual(canonicalHash))
                {
                    return MembershipTrustStatus.For(
                        winner.Head.State,
                        MembershipTrustEvent.StateUnchanged);
                }
                return await PersistForkAsync(
                    profile,
                    MembershipTrustDomain.Authority,
                    winner.Head,
                    envelope,
                    canonicalHash,
                    (validFrom, validUntil),
                    operationNow,
                    artifactKind,
                    signingAuthorityEnvelope: [],
                    revokedDelegationHashes: revokedDelegationHashes,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }
        }
        return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
    }

    private BootstrapVerification VerifyBootstrap(
        MembershipTrustProfile profile,
        DateTimeOffset now)
    {
        ValidateProfileKey(profile.OpaqueProfileKey);
        var genesis = DecodePinnedGenesis(profile);
        var signedDelegation = Bounded(profile.SignedDelegation);
        var delegation = MembershipContractCodec.DecodeSignedDelegation(signedDelegation);
        RequireExact(signedDelegation, MembershipContractCodec.EncodeSignedDelegation(delegation));
        var genesisHash = MembershipContractHash.Sha256(profile.CanonicalGenesis);
        var verified = MembershipContractVerifier.VerifyDelegation(
            delegation,
            genesis,
            new MembershipLastKnownGood
            {
                NetworkId = genesis.NetworkId.ToArray(),
                PolicyVersion = genesis.PolicyVersion,
                Sequence = genesis.GenesisSequence,
                CanonicalHash = genesisHash
            },
            checked((ulong)now.ToUnixTimeSeconds()),
            AllowedSkewSeconds(),
            options.ClientProtocol,
            verifier!);
        return new BootstrapVerification(
            genesis,
            genesisHash,
            delegation,
            verified.CanonicalHash.ToArray());
    }

    private BootstrapPins ValidateBootstrapPins(MembershipTrustProfile profile)
    {
        ValidateProfileKey(profile.OpaqueProfileKey);
        var genesis = DecodePinnedGenesis(profile);
        var signedDelegation = Bounded(profile.SignedDelegation);
        var delegation = MembershipContractCodec.DecodeSignedDelegation(signedDelegation);
        RequireExact(signedDelegation, MembershipContractCodec.EncodeSignedDelegation(delegation));
        return new BootstrapPins(
            genesis,
            MembershipContractHash.Sha256(profile.CanonicalGenesis),
            delegation,
            signedDelegation);
    }

    private MembershipTrustStatus? RevalidateAuthority(
        MembershipTrustReadSnapshot snapshot,
        NetworkGenesis genesis,
        byte[] genesisHash,
        byte[] canonicalBootstrapDelegation)
    {
        if (snapshot.Head is null)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
        }
        if (snapshot.Head.Revision == 1)
        {
            if (snapshot.Head.ArtifactKind != MembershipTrustArtifactKind.Delegation)
            {
                return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
            }
            if (!snapshot.Head.CanonicalEnvelope.AsSpan().SequenceEqual(canonicalBootstrapDelegation))
            {
                return MembershipTrustStatus.For(MembershipTrustState.ProtocolUnsupported);
            }
            if (snapshot.Head.RevokedDelegationHashes.Length != 0 ||
                snapshot.Head.SigningAuthorityEnvelope.Length != 0)
            {
                return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
            }
            VerifyPersistedAuthorityRecord(snapshot.Head, genesis, genesis.GenesisSequence, genesisHash);
            return null;
        }
        if (snapshot.Predecessor is null)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
        }

        VerifyPersistedAuthorityRecord(
            snapshot.Predecessor,
            genesis,
            snapshot.Predecessor.PreviousSequence,
            snapshot.Predecessor.PreviousCanonicalHash);
        VerifyPersistedAuthorityRecord(
            snapshot.Head,
            genesis,
            snapshot.Head.PreviousSequence,
            snapshot.Head.PreviousCanonicalHash);
        if (snapshot.Head.SigningAuthorityEnvelope.Length != 0)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
        }
        if (snapshot.Head.State != MembershipTrustState.ForkDetected)
        {
            var predecessorRevoked = DecodeRevokedDelegationHashes(
                snapshot.Predecessor.RevokedDelegationHashes);
            if (snapshot.Head.ArtifactKind == MembershipTrustArtifactKind.Delegation)
            {
                if (!snapshot.Head.RevokedDelegationHashes.AsSpan().SequenceEqual(
                        snapshot.Predecessor.RevokedDelegationHashes))
                {
                    return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
                }
            }
            else
            {
                var revocation = MembershipContractCodec.DecodeSignedRevocation(
                    snapshot.Head.CanonicalEnvelope);
                var targetMatches =
                    snapshot.Predecessor.ArtifactKind ==
                        MembershipTrustArtifactKind.Delegation &&
                    revocation.DelegationHash.Span.SequenceEqual(
                        snapshot.Predecessor.CanonicalHash);
                var isTerminalOverflow =
                    snapshot.Head.State == MembershipTrustState.Corrupt &&
                    predecessorRevoked.Count ==
                        MembershipLimits.MaximumRevokedDelegationHashes &&
                    !predecessorRevoked.Any(
                        value => value.Span.SequenceEqual(
                            revocation.DelegationHash.Span)) &&
                    snapshot.Head.RevokedDelegationHashes.AsSpan().SequenceEqual(
                        snapshot.Predecessor.RevokedDelegationHashes);
                var isNormalRevocation =
                    snapshot.Head.State == MembershipTrustState.Revoked &&
                    snapshot.Head.RevokedDelegationHashes.AsSpan().SequenceEqual(
                        FlattenRevokedDelegationHashes(
                            AddRevokedDelegationHash(
                                predecessorRevoked,
                                revocation.DelegationHash)));
                if (!targetMatches || (!isTerminalOverflow && !isNormalRevocation))
                {
                    return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
                }
            }
        }
        return null;
    }

    private void VerifyPersistedAuthorityRecord(
        MembershipTrustRecord record,
        NetworkGenesis genesis,
        ulong predecessorSequence,
        byte[] predecessorHash)
    {
        if (record.ArtifactKind is not (
                MembershipTrustArtifactKind.Delegation or
                MembershipTrustArtifactKind.Revocation))
        {
            throw new InvalidDataException("Persisted authority artifact is invalid.");
        }
        var candidate = DecodeAuthorityCandidate(record.CanonicalEnvelope, record.ArtifactKind);
        var hash = VerifyAuthorityCandidate(
            candidate,
            genesis,
            new MembershipLastKnownGood
            {
                NetworkId = genesis.NetworkId.ToArray(),
                PolicyVersion = genesis.PolicyVersion,
                Sequence = predecessorSequence,
                CanonicalHash = predecessorHash.ToArray()
            },
            VerificationInstant(record));
        if (candidate.Sequence != record.Sequence ||
            candidate.ValidFrom != checked((ulong)record.ValidFrom.ToUnixTimeSeconds()) ||
            candidate.ValidUntil != checked((ulong)record.ValidUntil.ToUnixTimeSeconds()) ||
            !hash.AsSpan().SequenceEqual(record.CanonicalHash) ||
            record.State != MembershipTrustState.ForkDetected &&
            record.State != candidate.State &&
            !(record.State == MembershipTrustState.Corrupt &&
              record.ArtifactKind == MembershipTrustArtifactKind.Revocation))
        {
            throw new InvalidDataException("Persisted authority record failed revalidation.");
        }
    }

    private async Task<MembershipTrustStatus?> RevalidateContentHeadsAsync(
        MembershipTrustProfile profile,
        NetworkGenesis genesis,
        CancellationToken cancellationToken)
    {
        var authority = await repository.ReadMembershipTrustAsync(
            profile.OpaqueProfileKey,
            MembershipTrustDomain.Authority,
            cancellationToken).ConfigureAwait(false);
        if (authority.Head is null ||
            authority.Head.State != MembershipTrustState.Healthy ||
            authority.Head.ArtifactKind != MembershipTrustArtifactKind.Delegation)
        {
            return null;
        }
        var delegation = MembershipContractCodec.DecodeSignedDelegation(authority.Head.CanonicalEnvelope);
        RequireExact(
            authority.Head.CanonicalEnvelope,
            MembershipContractCodec.EncodeSignedDelegation(delegation));
        var activeDelegationHash = authority.Head.CanonicalHash;
        var revokedDelegationHashes = DecodeRevokedDelegationHashes(
            authority.Head.RevokedDelegationHashes);
        MembershipTrustStatus? superseded = null;

        foreach (var (domain, anchor, kind) in new[]
                 {
                     (MembershipTrustDomain.Bridge, profile.BridgeAnchor!, MembershipTrustArtifactKind.Bridge),
                     (MembershipTrustDomain.Membership, profile.MembershipAnchor!, MembershipTrustArtifactKind.Membership)
                 })
        {
            var snapshot = await repository.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                domain,
                cancellationToken).ConfigureAwait(false);
            if (snapshot.Head is null)
            {
                return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
            }
            if (snapshot.Head.Revision == 1)
            {
                if (snapshot.Head.ArtifactKind != MembershipTrustArtifactKind.Anchor ||
                    snapshot.Head.Sequence != anchor.Sequence ||
                    !snapshot.Head.CanonicalHash.AsSpan().SequenceEqual(anchor.CanonicalHash) ||
                    !snapshot.Head.CanonicalEnvelope.AsSpan().SequenceEqual(anchor.CanonicalHash))
                {
                    return MembershipTrustStatus.For(MembershipTrustState.ProtocolUnsupported);
                }
                continue;
            }
            if (snapshot.Predecessor is null || snapshot.Head.ArtifactKind != kind)
            {
                return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
            }
            if (snapshot.Predecessor.Revision > 1)
            {
                VerifyPersistedContentRecord(
                    snapshot.Predecessor,
                    domain,
                    genesis,
                    revokedDelegationHashes: []);
            }
            var signingAuthorityHash = VerifyPersistedContentRecord(
                snapshot.Head,
                domain,
                genesis,
                revokedDelegationHashes);
            if (!signingAuthorityHash.AsSpan().SequenceEqual(activeDelegationHash))
            {
                superseded = MembershipTrustStatus.For(
                    MembershipTrustState.ProtocolUnsupported);
            }
        }
        return superseded;
    }

    private byte[] VerifyPersistedContentRecord(
        MembershipTrustRecord record,
        MembershipTrustDomain domain,
        NetworkGenesis genesis,
        IReadOnlyList<ReadOnlyMemory<byte>> revokedDelegationHashes)
    {
        if (record.SigningAuthorityEnvelope.Length == 0)
        {
            throw new InvalidDataException("Persisted content authority is missing.");
        }
        var delegation = MembershipContractCodec.DecodeSignedDelegation(
            record.SigningAuthorityEnvelope);
        RequireExact(
            record.SigningAuthorityEnvelope,
            MembershipContractCodec.EncodeSignedDelegation(delegation));
        var authorityHash = MembershipContractVerifier.VerifyDelegation(
            delegation,
            genesis,
            new MembershipLastKnownGood
            {
                NetworkId = genesis.NetworkId.ToArray(),
                PolicyVersion = genesis.PolicyVersion,
                Sequence = checked(delegation.Sequence - 1),
                CanonicalHash = delegation.PreviousHash.ToArray()
            },
            Seconds(VerificationInstant(record)),
            AllowedSkewSeconds(),
            options.ClientProtocol,
            verifier!).CanonicalHash.ToArray();
        var candidate = DecodeContent(domain, record.CanonicalEnvelope);
        var context = new MembershipVerificationContext
        {
            Genesis = genesis,
            ActiveDelegation = delegation,
            AuthorityLastKnownGood = new MembershipLastKnownGood
            {
                NetworkId = genesis.NetworkId.ToArray(),
                PolicyVersion = genesis.PolicyVersion,
                Sequence = delegation.Sequence,
                CanonicalHash = authorityHash
            },
            RevokedDelegationHashes = revokedDelegationHashes,
            LastKnownGood = new MembershipLastKnownGood
            {
                NetworkId = genesis.NetworkId.ToArray(),
                PolicyVersion = genesis.PolicyVersion,
                Sequence = record.PreviousSequence,
                CanonicalHash = record.PreviousCanonicalHash.ToArray()
            },
            VerificationTimeUnixSeconds = Seconds(VerificationInstant(record)),
            AllowedClockSkewSeconds = AllowedSkewSeconds(),
            ClientProtocol = options.ClientProtocol
        };
        var verified = VerifyContent(domain, candidate, context);
        var validity = ContentValidity(candidate);
        if (ContentSequence(candidate) != record.Sequence ||
            validity.ValidFrom != checked((ulong)record.ValidFrom.ToUnixTimeSeconds()) ||
            validity.ValidUntil != checked((ulong)record.ValidUntil.ToUnixTimeSeconds()) ||
            !VerifiedHash(verified).Span.SequenceEqual(record.CanonicalHash))
        {
            throw new InvalidDataException("Persisted content record failed revalidation.");
        }
        return authorityHash;
    }

    private static DateTimeOffset VerificationInstant(MembershipTrustRecord record)
    {
        if (record.ObservedAt < record.ValidFrom)
        {
            return record.ValidFrom;
        }
        if (record.ObservedAt > record.ValidUntil)
        {
            return record.ValidUntil;
        }
        return record.ObservedAt;
    }

    private NetworkGenesis DecodePinnedGenesis(MembershipTrustProfile profile)
    {
        var canonical = Bounded(profile.CanonicalGenesis);
        if (profile.ExpectedNetworkId is null ||
            profile.ExpectedNetworkId.Length != MembershipLimits.NetworkIdLength ||
            profile.ExpectedCanonicalGenesisSha256 is null ||
            profile.ExpectedCanonicalGenesisSha256.Length != MembershipLimits.HashLength)
        {
            throw new InvalidDataException("Membership bootstrap pins are invalid.");
        }
        var genesis = MembershipContractCodec.DecodeGenesis(canonical);
        RequireExact(canonical, MembershipContractCodec.EncodeGenesis(genesis));
        if (!genesis.NetworkId.Span.SequenceEqual(profile.ExpectedNetworkId) ||
            !MembershipContractHash.Sha256(canonical).AsSpan()
                .SequenceEqual(profile.ExpectedCanonicalGenesisSha256))
        {
            throw new MembershipContractException(
                MembershipContractError.AuthorityMismatch,
                "Pinned membership bootstrap does not match.");
        }
        return genesis;
    }

    private object DecodeContent(MembershipTrustDomain domain, byte[] bytes) =>
        domain switch
        {
            MembershipTrustDomain.Membership => DecodeMembership(bytes),
            MembershipTrustDomain.Bridge => DecodeBridge(bytes),
            _ => throw new ArgumentOutOfRangeException(nameof(domain))
        };

    private static AuthorityCandidate DecodeAuthorityCandidate(
        byte[] bytes,
        MembershipTrustArtifactKind artifactKind)
    {
        if (artifactKind == MembershipTrustArtifactKind.Delegation)
        {
            var value = MembershipContractCodec.DecodeSignedDelegation(bytes);
            RequireExact(bytes, MembershipContractCodec.EncodeSignedDelegation(value));
            return new AuthorityCandidate(
                artifactKind,
                value,
                value.Sequence,
                value.ValidFromUnixSeconds,
                value.ValidUntilUnixSeconds,
                MembershipTrustState.Healthy);
        }
        if (artifactKind == MembershipTrustArtifactKind.Revocation)
        {
            var value = MembershipContractCodec.DecodeSignedRevocation(bytes);
            RequireExact(bytes, MembershipContractCodec.EncodeSignedRevocation(value));
            return new AuthorityCandidate(
                artifactKind,
                value,
                value.Sequence,
                value.ValidFromUnixSeconds,
                value.ValidUntilUnixSeconds,
                MembershipTrustState.Revoked);
        }
        throw new ArgumentOutOfRangeException(nameof(artifactKind));
    }

    private byte[] VerifyAuthorityCandidate(
        AuthorityCandidate candidate,
        NetworkGenesis genesis,
        MembershipLastKnownGood lastKnownGood,
        DateTimeOffset now) =>
        candidate.ArtifactKind switch
        {
            MembershipTrustArtifactKind.Delegation =>
                MembershipContractVerifier.VerifyDelegation(
                    (SignerDelegation)candidate.Value,
                    genesis,
                    lastKnownGood,
                    Seconds(now),
                    AllowedSkewSeconds(),
                    options.ClientProtocol,
                    verifier!).CanonicalHash.ToArray(),
            MembershipTrustArtifactKind.Revocation =>
                MembershipContractVerifier.VerifyRevocation(
                    (SignerRevocation)candidate.Value,
                    genesis,
                    lastKnownGood,
                    Seconds(now),
                    AllowedSkewSeconds(),
                    options.ClientProtocol,
                    verifier!).CanonicalHash.ToArray(),
            _ => throw new ArgumentOutOfRangeException(nameof(candidate))
        };

    private static IReadOnlyList<ReadOnlyMemory<byte>> DecodeRevokedDelegationHashes(
        byte[] flattened)
    {
        ArgumentNullException.ThrowIfNull(flattened);
        if (flattened.Length % MembershipLimits.HashLength != 0 ||
            flattened.Length >
                MembershipLimits.MaximumRevokedDelegationHashes * MembershipLimits.HashLength)
        {
            throw new InvalidDataException("Revoked delegation set is invalid.");
        }
        var values = new List<ReadOnlyMemory<byte>>(
            flattened.Length / MembershipLimits.HashLength);
        for (var offset = 0; offset < flattened.Length; offset += MembershipLimits.HashLength)
        {
            var value = flattened.AsSpan(offset, MembershipLimits.HashLength).ToArray();
            if (values.Any(existing => existing.Span.SequenceEqual(value)))
            {
                throw new InvalidDataException("Revoked delegation set is invalid.");
            }
            values.Add(value);
        }
        return values;
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> AddRevokedDelegationHash(
        IReadOnlyList<ReadOnlyMemory<byte>> current,
        ReadOnlyMemory<byte> candidate)
    {
        if (candidate.Length != MembershipLimits.HashLength)
        {
            throw new InvalidDataException("Revoked delegation hash is invalid.");
        }
        if (current.Any(value => value.Span.SequenceEqual(candidate.Span)))
        {
            return current;
        }
        if (current.Count >= MembershipLimits.MaximumRevokedDelegationHashes)
        {
            throw new InvalidDataException("Revoked delegation set is full.");
        }
        return current
            .Select(value => (ReadOnlyMemory<byte>)value.ToArray())
            .Append(candidate.ToArray())
            .ToArray();
    }

    private static byte[] FlattenRevokedDelegationHashes(
        IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        if (values.Count > MembershipLimits.MaximumRevokedDelegationHashes)
        {
            throw new InvalidDataException("Revoked delegation set is invalid.");
        }
        var flattened = new byte[checked(values.Count * MembershipLimits.HashLength)];
        for (var index = 0; index < values.Count; index++)
        {
            if (values[index].Length != MembershipLimits.HashLength)
            {
                throw new InvalidDataException("Revoked delegation hash is invalid.");
            }
            values[index].Span.CopyTo(
                flattened.AsSpan(index * MembershipLimits.HashLength));
        }
        return flattened;
    }

    private static SignedMembershipCommitment DecodeMembership(byte[] bytes)
    {
        var value = MembershipContractCodec.DecodeSignedMembership(bytes);
        RequireExact(bytes, MembershipContractCodec.EncodeSignedMembership(value));
        return value;
    }

    private static SignedBridgeSnapshot DecodeBridge(byte[] bytes)
    {
        var value = MembershipContractCodec.DecodeSignedBridge(bytes);
        RequireExact(bytes, MembershipContractCodec.EncodeSignedBridge(value));
        return value;
    }

    private object VerifyContent(
        MembershipTrustDomain domain,
        object candidate,
        MembershipVerificationContext context) =>
        domain switch
        {
            MembershipTrustDomain.Membership =>
                MembershipContractVerifier.VerifyMembership(
                    (SignedMembershipCommitment)candidate,
                    context,
                    verifier!),
            MembershipTrustDomain.Bridge =>
                MembershipContractVerifier.VerifyBridge(
                    (SignedBridgeSnapshot)candidate,
                    context,
                    verifier!),
            _ => throw new ArgumentOutOfRangeException(nameof(domain))
        };

    private static ReadOnlyMemory<byte> VerifiedHash(object verified) =>
        verified switch
        {
            VerifiedMembershipCommitment membership => membership.CanonicalHash,
            VerifiedBridgeSnapshot bridge => bridge.CanonicalHash,
            _ => throw new ArgumentOutOfRangeException(nameof(verified))
        };

    private static ulong ContentSequence(object candidate) =>
        candidate switch
        {
            SignedMembershipCommitment membership => membership.Statement.Sequence,
            SignedBridgeSnapshot bridge => bridge.Statement.Sequence,
            _ => throw new ArgumentOutOfRangeException(nameof(candidate))
        };

    private static (ulong ValidFrom, ulong ValidUntil) ContentValidity(object candidate) =>
        candidate switch
        {
            SignedMembershipCommitment membership =>
                (membership.Statement.ValidFromUnixSeconds, membership.Statement.ValidUntilUnixSeconds),
            SignedBridgeSnapshot bridge =>
                (bridge.Statement.ValidFromUnixSeconds, bridge.Statement.ValidUntilUnixSeconds),
            _ => throw new ArgumentOutOfRangeException(nameof(candidate))
        };

    private byte[] Bounded(ReadOnlyMemory<byte> value)
    {
        if (value.Length is <= 0 || value.Length > options.MaximumEnvelopeBytes)
        {
            throw new InvalidDataException("Membership envelope is invalid.");
        }
        return value.ToArray();
    }

    private void ValidateOptions()
    {
        if (options.MaximumEnvelopeBytes is <= 0 or > MembershipTrustRecord.MaximumEnvelopeLength ||
            options.ClientProtocol == 0 ||
            options.AllowedClockSkew < TimeSpan.Zero ||
            options.ClockRollbackTolerance < TimeSpan.Zero ||
            options.StaleGrace < TimeSpan.Zero)
        {
            throw new InvalidDataException("Membership trust options are invalid.");
        }
        _ = AllowedSkewSeconds();
    }

    private static void ValidateProfileKey(
        string opaqueProfileKey,
        bool allowSelfHosted = false)
    {
        if (string.IsNullOrWhiteSpace(opaqueProfileKey) ||
            opaqueProfileKey.Length > MembershipTrustRecord.MaximumProfileKeyLength ||
            !opaqueProfileKey.StartsWith("install:", StringComparison.Ordinal) ||
            !allowSelfHosted &&
            opaqueProfileKey.StartsWith("install:self-hosted:", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Membership profile is invalid.");
        }
    }

    private static bool SameHead(
        MembershipTrustReadSnapshot expected,
        MembershipTrustReadSnapshot actual) =>
        expected.Result == MembershipTrustReadResult.Found &&
        expected.Head is not null &&
        actual.Result == MembershipTrustReadResult.Found &&
        actual.Head is not null &&
        expected.Head.Revision == actual.Head.Revision &&
        expected.Head.PayloadDigest.AsSpan().SequenceEqual(
            actual.Head.PayloadDigest);

    private static MembershipTrustProfile SnapshotProfile(
        MembershipTrustProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return new MembershipTrustProfile(
            profile.OpaqueProfileKey,
            RequiredCopy(profile.CanonicalGenesis),
            RequiredCopy(profile.ExpectedNetworkId),
            RequiredCopy(profile.ExpectedCanonicalGenesisSha256),
            RequiredCopy(profile.SignedDelegation),
            SnapshotAnchor(profile.BridgeAnchor),
            SnapshotAnchor(profile.MembershipAnchor));
    }

    private static MembershipTrustAnchor? SnapshotAnchor(
        MembershipTrustAnchor? anchor) =>
        anchor is null
            ? null
            : new MembershipTrustAnchor(
                anchor.Sequence,
                RequiredCopy(anchor.CanonicalHash));

    private static SelfHostedGenesisImport SnapshotImport(
        SelfHostedGenesisImport import)
    {
        ArgumentNullException.ThrowIfNull(import);
        return new SelfHostedGenesisImport(
            import.OpaqueProfileKey,
            RequiredCopy(import.CanonicalGenesis),
            RequiredCopy(import.ExpectedNetworkId),
            RequiredCopy(import.ExpectedCanonicalGenesisSha256),
            RequiredCopy(import.CanonicalSignatures));
    }

    private static byte[] RequiredCopy(byte[]? value) =>
        value?.ToArray() ??
        throw new InvalidDataException("Membership trust input is invalid.");

    private static DateTimeOffset CanonicalOperationTime(DateTimeOffset value) =>
        DateTimeOffset.FromUnixTimeSeconds(value.ToUnixTimeSeconds());

    private static async Task<MembershipTrustStatus> ExecutePublicAsync(
        Func<Task<MembershipTrustStatus>> operation)
    {
        try
        {
            return await operation().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return MembershipTrustStatus.For(
                MembershipTrustState.Corrupt,
                MembershipTrustEvent.VerificationRejected);
        }
    }

    private static byte[] ComputeProfileBinding(MembershipTrustProfile profile)
    {
        if (profile.BridgeAnchor is null || profile.MembershipAnchor is null)
        {
            throw new InvalidDataException("Membership anchors are missing.");
        }
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("deep.membership-trust-profile/v1"u8);
        hash.AppendData(MembershipContractHash.Sha256(profile.CanonicalGenesis));
        hash.AppendData(SHA256.HashData(profile.SignedDelegation));
        AppendAnchor(hash, MembershipTrustDomain.Bridge, profile.BridgeAnchor);
        AppendAnchor(hash, MembershipTrustDomain.Membership, profile.MembershipAnchor);
        return hash.GetHashAndReset();
    }

    private static byte[] ComputeSelfHostedBinding(SelfHostedGenesisImport import)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("deep.membership-trust-self-host/v1"u8);
        hash.AppendData(SHA256.HashData(import.CanonicalGenesis));
        hash.AppendData(import.ExpectedNetworkId);
        hash.AppendData(import.ExpectedCanonicalGenesisSha256);
        hash.AppendData(SHA256.HashData(import.CanonicalSignatures));
        return hash.GetHashAndReset();
    }

    private static IReadOnlyList<MembershipSignature> DecodeSelfHostedSignatures(byte[] canonical)
    {
        ArgumentNullException.ThrowIfNull(canonical);
        if (canonical.Length < 8 ||
            !canonical.AsSpan(0, 4).SequenceEqual("DSIG"u8) ||
            BinaryPrimitives.ReadUInt16BigEndian(canonical.AsSpan(4, 2)) != 1)
        {
            throw new InvalidDataException("Self-hosted signature envelope is invalid.");
        }
        var count = BinaryPrimitives.ReadUInt16BigEndian(canonical.AsSpan(6, 2));
        if (count is 0 or > 64)
        {
            throw new InvalidDataException("Self-hosted signature count is invalid.");
        }

        var offset = 8;
        var signatures = new List<MembershipSignature>(count);
        byte[]? previousSigner = null;
        for (var index = 0; index < count; index++)
        {
            if (canonical.Length - offset < MembershipLimits.SignerIdLength + 2)
            {
                throw new InvalidDataException("Self-hosted signature envelope is truncated.");
            }
            var signerId = canonical.AsSpan(offset, MembershipLimits.SignerIdLength).ToArray();
            offset += MembershipLimits.SignerIdLength;
            var length = BinaryPrimitives.ReadUInt16BigEndian(canonical.AsSpan(offset, 2));
            offset += 2;
            if (length is 0 or > MembershipLimits.MaximumSignatureLength ||
                canonical.Length - offset < length ||
                previousSigner is not null &&
                previousSigner.AsSpan().SequenceCompareTo(signerId) >= 0)
            {
                throw new InvalidDataException("Self-hosted signature envelope is non-canonical.");
            }
            signatures.Add(new MembershipSignature
            {
                SignerId = signerId,
                Domain = MembershipSignatureDomain.Genesis,
                Signature = canonical.AsSpan(offset, length).ToArray()
            });
            offset += length;
            previousSigner = signerId;
        }
        if (offset != canonical.Length)
        {
            throw new InvalidDataException("Self-hosted signature envelope has trailing bytes.");
        }
        return signatures;
    }

    private static void AppendAnchor(
        IncrementalHash hash,
        MembershipTrustDomain domain,
        MembershipTrustAnchor anchor)
    {
        Span<byte> bytes = stackalloc byte[12];
        BinaryPrimitives.WriteInt32BigEndian(bytes, (int)domain);
        BinaryPrimitives.WriteUInt64BigEndian(bytes[4..], anchor.Sequence);
        hash.AppendData(bytes);
        hash.AppendData(anchor.CanonicalHash);
    }

    private uint AllowedSkewSeconds()
    {
        var seconds = options.AllowedClockSkew.TotalSeconds;
        if (seconds < 0 ||
            seconds > MembershipLimits.MaximumClockSkewSeconds ||
            seconds != Math.Truncate(seconds))
        {
            throw new InvalidDataException("Membership clock policy is invalid.");
        }
        return checked((uint)seconds);
    }

    private async Task<MembershipTrustStatus?> ObserveClockAsync(
        string opaqueProfileKey,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        bool allowSelfHosted = false)
    {
        ValidateProfileKey(opaqueProfileKey, allowSelfHosted);
        if (now < DateTimeOffset.UnixEpoch)
        {
            throw new InvalidDataException("Membership clock is invalid.");
        }
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var snapshot = await repository.ReadMembershipTrustClockAsync(
                opaqueProfileKey,
                cancellationToken).ConfigureAwait(false);
            if (snapshot.Result == MembershipTrustClockReadResult.Corrupt)
            {
                return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
            }
            if (snapshot.Record is not null &&
                now + options.ClockRollbackTolerance < snapshot.Record.ObservedAt)
            {
                return MembershipTrustStatus.For(MembershipTrustState.ClockRollback);
            }
            if (snapshot.Record is not null && now <= snapshot.Record.ObservedAt)
            {
                return null;
            }

            var record = MembershipTrustClockRecord.Create(
                opaqueProfileKey,
                (snapshot.Record?.Revision ?? 0) + 1,
                now);
            var result = await repository.CommitMembershipTrustClockAsync(
                record,
                snapshot.Record?.Revision,
                cancellationToken).ConfigureAwait(false);
            if (result is MembershipTrustClockCommitResult.Applied or
                MembershipTrustClockCommitResult.Idempotent)
            {
                return null;
            }
            if (result is MembershipTrustClockCommitResult.Rollback)
            {
                return MembershipTrustStatus.For(MembershipTrustState.ClockRollback);
            }
            if (result is MembershipTrustClockCommitResult.Corrupt)
            {
                return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
            }
        }
        return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
    }

    private static ulong Seconds(DateTimeOffset value)
    {
        var seconds = value.ToUnixTimeSeconds();
        if (seconds < 0)
        {
            throw new InvalidDataException("Membership clock is invalid.");
        }
        return checked((ulong)seconds);
    }

    private static DateTimeOffset Unix(ulong seconds)
    {
        if (seconds > 253402300799UL)
        {
            throw new OverflowException("Membership timestamp is outside the supported range.");
        }
        return DateTimeOffset.FromUnixTimeSeconds(checked((long)seconds));
    }

    private static MembershipLastKnownGood ToLastKnownGood(MembershipTrustRecord record) =>
        new()
        {
            NetworkId = MembershipContractCodec.DecodeSignedDelegation(record.CanonicalEnvelope)
                .NetworkId.ToArray(),
            PolicyVersion = MembershipContractCodec.DecodeSignedDelegation(record.CanonicalEnvelope)
                .PolicyVersion,
            Sequence = record.Sequence,
            CanonicalHash = record.CanonicalHash.ToArray()
        };

    private static MembershipLastKnownGood ToLastKnownGood(
        MembershipTrustRecord record,
        ReadOnlyMemory<byte> networkId,
        uint policyVersion) =>
        new()
        {
            NetworkId = networkId.ToArray(),
            PolicyVersion = policyVersion,
            Sequence = record.Sequence,
            CanonicalHash = record.CanonicalHash.ToArray()
        };

    private static void RequireExact(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> canonical)
    {
        if (!actual.SequenceEqual(canonical))
        {
            throw new InvalidDataException("Membership envelope is not canonical.");
        }
    }

    private static MembershipTrustStatus FromContractError(MembershipContractError error) =>
        error switch
        {
            MembershipContractError.NotYetValid =>
                MembershipTrustStatus.For(MembershipTrustState.NotYetValid, MembershipTrustEvent.VerificationRejected),
            MembershipContractError.Expired =>
                MembershipTrustStatus.For(MembershipTrustState.Expired, MembershipTrustEvent.VerificationRejected),
            MembershipContractError.RevokedDelegation =>
                MembershipTrustStatus.For(MembershipTrustState.Revoked, MembershipTrustEvent.VerificationRejected),
            MembershipContractError.ForkDetected =>
                MembershipTrustStatus.For(MembershipTrustState.ForkDetected, MembershipTrustEvent.EquivocationObserved),
            MembershipContractError.InvalidField or
            MembershipContractError.InvalidLength or
            MembershipContractError.InvalidMagic or
            MembershipContractError.InvalidEnum or
            MembershipContractError.ReservedFieldNotZero or
            MembershipContractError.NonCanonicalOrder =>
                MembershipTrustStatus.For(MembershipTrustState.Corrupt, MembershipTrustEvent.VerificationRejected),
            _ => MembershipTrustStatus.For(
                MembershipTrustState.ProtocolUnsupported,
                MembershipTrustEvent.VerificationRejected)
        };

    private sealed record BootstrapVerification(
        NetworkGenesis Genesis,
        byte[] GenesisHash,
        SignerDelegation Delegation,
        byte[] DelegationHash);

    private sealed record BootstrapPins(
        NetworkGenesis Genesis,
        byte[] GenesisHash,
        SignerDelegation Delegation,
        byte[] CanonicalDelegation);

    private sealed record AuthorityCandidate(
        MembershipTrustArtifactKind ArtifactKind,
        object Value,
        ulong Sequence,
        ulong ValidFrom,
        ulong ValidUntil,
        MembershipTrustState State);

    private sealed record ContentReadiness(
        MembershipTrustStatus? Blocked,
        bool StrictSuccessorRequired,
        MembershipTrustState PreservedState);
}
