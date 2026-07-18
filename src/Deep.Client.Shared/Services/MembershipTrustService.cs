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
    public async Task<MembershipTrustStatus> InitializeAsync(
        MembershipTrustProfile profile,
        CancellationToken cancellationToken = default)
    {
        if (!options.Enabled)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Disabled);
        }
        if (verifier is null)
        {
            return MembershipTrustStatus.For(MembershipTrustState.VerifierUnavailable);
        }

        var now = clock.UtcNow;
        try
        {
            ValidateOptions();
            var bootstrap = VerifyBootstrap(profile, now);
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

            if (authority.Result == MembershipTrustReadResult.Missing)
            {
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
                    canonicalHash: bootstrap.DelegationHash);
                if (await repository.CommitMembershipTrustAsync(
                        authorityRecord,
                        expectedHeadRevision: null,
                        cancellationToken).ConfigureAwait(false)
                    is not (MembershipTrustCommitResult.Applied or MembershipTrustCommitResult.Idempotent))
                {
                    return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
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
                bootstrap.Delegation,
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
                bootstrap.Delegation,
                now,
                cancellationToken).ConfigureAwait(false);
            if (membership.State != MembershipTrustState.Healthy)
            {
                return membership;
            }

            return await EvaluateAsync(profile, cancellationToken).ConfigureAwait(false);
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
        ApplyContentAsync(
            profile,
            MembershipTrustDomain.Membership,
            canonicalSignedEnvelope,
            cancellationToken);

    public Task<MembershipTrustStatus> ApplyBridgeAsync(
        MembershipTrustProfile profile,
        ReadOnlyMemory<byte> canonicalSignedEnvelope,
        CancellationToken cancellationToken = default) =>
        ApplyContentAsync(
            profile,
            MembershipTrustDomain.Bridge,
            canonicalSignedEnvelope,
            cancellationToken);

    public async Task<MembershipTrustStatus> ApplyDelegationAsync(
        MembershipTrustProfile profile,
        ReadOnlyMemory<byte> canonicalSignedEnvelope,
        CancellationToken cancellationToken = default)
    {
        var ready = await RequireReadyAsync(profile, cancellationToken).ConfigureAwait(false);
        if (ready is not null)
        {
            return ready;
        }

        try
        {
            var bytes = Bounded(canonicalSignedEnvelope);
            var candidate = MembershipContractCodec.DecodeSignedDelegation(bytes);
            RequireExact(bytes, MembershipContractCodec.EncodeSignedDelegation(candidate));
            var genesis = DecodePinnedGenesis(profile);
            var current = await repository.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                MembershipTrustDomain.Authority,
                cancellationToken).ConfigureAwait(false);
            if (current.Result != MembershipTrustReadResult.Found ||
                current.Head is null ||
                current.Head.State != MembershipTrustState.Healthy)
            {
                return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
            }

            if (candidate.Sequence <= current.Head.Sequence)
            {
                return candidate.Sequence == current.Head.Sequence &&
                       current.Head.CanonicalEnvelope.AsSpan().SequenceEqual(bytes)
                    ? MembershipTrustStatus.For(MembershipTrustState.Healthy, MembershipTrustEvent.StateUnchanged)
                    : MembershipTrustStatus.For(MembershipTrustState.ProtocolUnsupported, MembershipTrustEvent.VerificationRejected);
            }

            var verified = MembershipContractVerifier.VerifyDelegation(
                candidate,
                genesis,
                ToLastKnownGood(current.Head),
                NowSeconds(),
                AllowedSkewSeconds(),
                options.ClientProtocol,
                verifier!);
            return await CommitAuthorityAsync(
                profile,
                current.Head,
                bytes,
                verified.CanonicalHash.ToArray(),
                candidate.Sequence,
                candidate.ValidFromUnixSeconds,
                candidate.ValidUntilUnixSeconds,
                MembershipTrustState.Healthy,
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

    public async Task<MembershipTrustStatus> ApplyRevocationAsync(
        MembershipTrustProfile profile,
        ReadOnlyMemory<byte> canonicalSignedEnvelope,
        CancellationToken cancellationToken = default)
    {
        var ready = await RequireReadyAsync(profile, cancellationToken).ConfigureAwait(false);
        if (ready is not null)
        {
            return ready;
        }

        try
        {
            var bytes = Bounded(canonicalSignedEnvelope);
            var candidate = MembershipContractCodec.DecodeSignedRevocation(bytes);
            RequireExact(bytes, MembershipContractCodec.EncodeSignedRevocation(candidate));
            var current = await repository.ReadMembershipTrustAsync(
                profile.OpaqueProfileKey,
                MembershipTrustDomain.Authority,
                cancellationToken).ConfigureAwait(false);
            if (current.Result != MembershipTrustReadResult.Found ||
                current.Head is null ||
                current.Head.State != MembershipTrustState.Healthy)
            {
                return MembershipTrustStatus.For(MembershipTrustState.Corrupt);
            }

            var verified = MembershipContractVerifier.VerifyRevocation(
                candidate,
                DecodePinnedGenesis(profile),
                ToLastKnownGood(current.Head),
                NowSeconds(),
                AllowedSkewSeconds(),
                options.ClientProtocol,
                verifier!);
            return await CommitAuthorityAsync(
                profile,
                current.Head,
                bytes,
                verified.CanonicalHash.ToArray(),
                candidate.Sequence,
                candidate.ValidFromUnixSeconds,
                candidate.ValidUntilUnixSeconds,
                MembershipTrustState.Revoked,
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

    public async Task<MembershipTrustStatus> EvaluateAsync(
        MembershipTrustProfile profile,
        CancellationToken cancellationToken = default)
    {
        if (!options.Enabled)
        {
            return MembershipTrustStatus.For(MembershipTrustState.Disabled);
        }
        if (verifier is null)
        {
            return MembershipTrustStatus.For(MembershipTrustState.VerifierUnavailable);
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
            snapshots.Add(snapshot);
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

        var now = clock.UtcNow;
        var highWater = snapshots.Max(static snapshot => snapshot.Head!.ObservedAt);
        if (now + options.ClockRollbackTolerance < highWater)
        {
            return MembershipTrustStatus.For(MembershipTrustState.ClockRollback);
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

        return MembershipTrustStatus.For(MembershipTrustState.Healthy);
    }

    public async Task<MembershipTrustStatus> ImportSelfHostedGenesisAsync(
        SelfHostedGenesisImport import,
        CancellationToken cancellationToken = default)
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
            ValidateProfileKey(import.OpaqueProfileKey);
            var bytes = Bounded(import.CanonicalGenesis);
            var genesis = MembershipContractVerifier.ImportSelfHostedGenesis(
                bytes,
                import.ExpectedNetworkId,
                import.ExpectedCanonicalGenesisSha256,
                import.Signatures,
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
                observedAt: clock.UtcNow,
                validUntil: DateTimeOffset.MaxValue,
                canonicalHash: MembershipContractHash.Sha256(bytes));
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
        CancellationToken cancellationToken)
    {
        var ready = await RequireReadyAsync(profile, cancellationToken).ConfigureAwait(false);
        if (ready is not null)
        {
            return ready;
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

            if (sequence < current.Head.Sequence)
            {
                return MembershipTrustStatus.For(MembershipTrustState.ProtocolUnsupported);
            }
            if (sequence == current.Head.Sequence &&
                current.Head.CanonicalEnvelope.AsSpan().SequenceEqual(bytes))
            {
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
                RevokedDelegationHashes = [],
                LastKnownGood = lkg,
                VerificationTimeUnixSeconds = NowSeconds(),
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
                    cancellationToken).ConfigureAwait(false);
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
                clock.UtcNow,
                Unix(validity.ValidUntil),
                Unix(validity.ValidFrom),
                verifiedHash.ToArray());
            var result = await repository.CommitMembershipTrustAsync(
                record,
                current.Head.Revision,
                cancellationToken).ConfigureAwait(false);
            if (result is MembershipTrustCommitResult.Applied or MembershipTrustCommitResult.Idempotent)
            {
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
                        cancellationToken).ConfigureAwait(false);
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
            clock.UtcNow,
            Unix(validity.ValidUntil),
            Unix(validity.ValidFrom),
            candidateHash);
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

    private async Task<MembershipTrustStatus?> RequireReadyAsync(
        MembershipTrustProfile profile,
        CancellationToken cancellationToken)
    {
        var initialized = await InitializeAsync(profile, cancellationToken).ConfigureAwait(false);
        return initialized.State == MembershipTrustState.Healthy ? null : initialized;
    }

    private async Task<MembershipTrustStatus> EnsureAnchorAsync(
        MembershipTrustProfile profile,
        MembershipTrustDomain domain,
        MembershipTrustAnchor anchor,
        SignerDelegation delegation,
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
            return existing.Head!.State == MembershipTrustState.Healthy
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
            validUntil: Unix(delegation.ValidUntilUnixSeconds),
            validFrom: Unix(delegation.ValidFromUnixSeconds),
            canonicalHash: anchor.CanonicalHash);
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
            clock.UtcNow,
            Unix(validUntil),
            Unix(validFrom),
            canonicalHash);
        var result = await repository.CommitMembershipTrustAsync(
            record,
            current.Revision,
            cancellationToken).ConfigureAwait(false);
        return result is MembershipTrustCommitResult.Applied or MembershipTrustCommitResult.Idempotent
            ? MembershipTrustStatus.For(state, MembershipTrustEvent.StateAccepted)
            : MembershipTrustStatus.For(MembershipTrustState.Corrupt);
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

    private static void ValidateProfileKey(string opaqueProfileKey)
    {
        if (string.IsNullOrWhiteSpace(opaqueProfileKey) ||
            opaqueProfileKey.Length > MembershipTrustRecord.MaximumProfileKeyLength ||
            !opaqueProfileKey.StartsWith("install:", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Membership profile is invalid.");
        }
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

    private ulong NowSeconds()
    {
        var value = clock.UtcNow.ToUnixTimeSeconds();
        if (value < 0)
        {
            throw new InvalidDataException("Membership clock is invalid.");
        }
        return checked((ulong)value);
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
}
