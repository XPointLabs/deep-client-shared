using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    /// <summary>Publishes this account's permanent contact through the selected
    /// three-hop carrier. Restart resumes protected exact custody. The result
    /// proves a durable commit, not contact acceptance or message permission.</summary>
    public Task<VerifiedDeepIdV2PublicationCommit> EnsureOwnPermanentContactPublishedAsync(
        DeepIdV2ContactPathAuthoritySource source, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        var coordination = new Did2ContactCoordinationOnionSource(source);
        return EnsureOwnPermanentContactPublishedAsync(source, coordination, coordination,
            new Did2ContactReplicaPublicationOnionTransport(source), cancellationToken);
    }

    internal async Task<VerifiedDeepIdV2PublicationCommit> EnsureOwnPermanentContactPublishedAsync(
        DeepIdV2ContactPathAuthoritySource source, IDid2ContactRouteThresholdSource threshold,
        IDid2ContactPublicationSource publication, IDid2ContactReplicaPublicationTransport transport,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        var plan = await ReadOwnPermanentContactPlanAsync(ct).ConfigureAwait(false);
        var committed = await EnsureOwnContactPublicationCommitAsync(plan.Intent, source,
            Did2OwnedPermanentContactPlan.Configuration(), threshold, plan.Profile, publication, transport, ct, plan).ConfigureAwait(false);
        var after = await ReadOwnPermanentContactPlanAsync(ct).ConfigureAwait(false);
        if (!plan.Matches(after))
            throw new System.Security.Cryptography.CryptographicException("The permanent-contact account instance changed during publication.");
        ct.ThrowIfCancellationRequested(); return committed;
    }

    internal async Task<Did2OwnedPermanentContactPlan> ReadOwnPermanentContactPlanAsync(CancellationToken ct = default)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadPermanentContactPlanAsync(TrustedUnixSeconds(), verifier, ct).ConfigureAwait(false);
    }

    internal async Task<VerifiedDeepIdV2PublicationCommit> EnsureOwnContactPublicationCommitAsync(
        ReadOnlyMemory<byte> logicalIntent32, DeepIdV2ContactPathAuthoritySource source,
        Did2ContactRouteConfiguration configuration, IDid2ContactRouteThresholdSource thresholdSource,
        string profileName, IDid2ContactPublicationSource publicationSource,
        IDid2ContactReplicaPublicationTransport transport, CancellationToken ct = default,
        Did2OwnedPermanentContactPlan? bootstrap = null)
    {
        ArgumentNullException.ThrowIfNull(publicationSource); ArgumentNullException.ThrowIfNull(transport);
        ProtectedDph2PreClaimJournal.RequireIntent(logicalIntent32.Span);
        var intent = logicalIntent32.ToArray();
        _ = await EnsureOwnContactObjectAsync(intent, source, configuration, thresholdSource, profileName, ct, bootstrap).ConfigureAwait(false);
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.EnsureContactPublicationCommitAsync(TrustedUnixSeconds(), verifier, intent,
            source, fresh, configuration, publicationSource, transport, ct, bootstrap).ConfigureAwait(false);
    }

    internal async Task<VerifiedDeepIdV2PublicationAuthorization> EnsureOwnContactPublicationAsync(
        ReadOnlyMemory<byte> logicalIntent32, DeepIdV2ContactPathAuthoritySource source,
        Did2ContactRouteConfiguration configuration, IDid2ContactRouteThresholdSource thresholdSource,
        string profileName, IDid2ContactPublicationSource publicationSource, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(publicationSource);
        ProtectedDph2PreClaimJournal.RequireIntent(logicalIntent32.Span);
        var intent = logicalIntent32.ToArray();
        _ = await EnsureOwnContactObjectAsync(intent, source, configuration, thresholdSource, profileName, ct).ConfigureAwait(false);
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.EnsureContactPublicationAsync(TrustedUnixSeconds(), verifier, intent,
            source, fresh, configuration, publicationSource, ct).ConfigureAwait(false);
    }

    internal async Task<AuthoredDeepIdV2ContactObject> EnsureOwnContactObjectAsync(
        ReadOnlyMemory<byte> logicalIntent32, DeepIdV2ContactPathAuthoritySource source,
        Did2ContactRouteConfiguration configuration, IDid2ContactRouteThresholdSource thresholdSource,
        string profileName, CancellationToken cancellationToken = default,
        Did2OwnedPermanentContactPlan? bootstrap = null)
    {
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(thresholdSource);
        cancellationToken.ThrowIfCancellationRequested();
        ProtectedDph2PreClaimJournal.RequireIntent(logicalIntent32.Span);
        var intent = logicalIntent32.ToArray();
        var profile = Domain.DeepDisplayName.Normalize(profileName, nameof(profileName));
        if (System.Text.Encoding.UTF8.GetByteCount(profile) > 128)
            throw new ArgumentException("Contact profile exceeds its UTF-8 bound.", nameof(profileName));
        source.RequireAccountOwner(this);
        _ = await EnsureOwnContactRouteAsync(intent, source, configuration, thresholdSource, cancellationToken, bootstrap).ConfigureAwait(false);
        var staged = await ReadOwnStagedPreKeyPublicationAsync(cancellationToken).ConfigureAwait(false) ??
            throw new InvalidOperationException("Owned prekey custody is absent.");
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, cancellationToken).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.EnsureContactObjectAsync(TrustedUnixSeconds(), verifier, intent,
            source, fresh, staged, configuration, profile, cancellationToken, bootstrap).ConfigureAwait(false);
    }

    // Shipping activation requires the live DID2 threshold/publication client.
    // No public caller-selected signing or protected-slot API is exposed.
    internal async Task<VerifiedDeepIdV2ContactRouteClosure> EnsureOwnContactRouteAsync(
        ReadOnlyMemory<byte> logicalIntent32, DeepIdV2ContactPathAuthoritySource source,
        Did2ContactRouteConfiguration configuration, IDid2ContactRouteThresholdSource thresholdSource,
        CancellationToken cancellationToken = default, Did2OwnedPermanentContactPlan? bootstrap = null)
    {
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(thresholdSource);
        cancellationToken.ThrowIfCancellationRequested();
        ProtectedDph2PreClaimJournal.RequireIntent(logicalIntent32.Span);
        var intent = logicalIntent32.ToArray(); source.RequireAccountOwner(this);
        var staged = await EnsureOwnInitialPreKeyInventoryAsync(source, cancellationToken).ConfigureAwait(false);
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, cancellationToken).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.EnsureContactRouteAsync(TrustedUnixSeconds(), verifier, intent,
            source, fresh, staged.ExactDca1, configuration, thresholdSource, cancellationToken, bootstrap).ConfigureAwait(false);
    }
}
