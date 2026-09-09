using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepNative;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV1;

/// <summary>
/// Exact resolver transcript presented to the trusted identity/directory/route
/// verifier. The structurally decoded XIS1 is not trusted by itself.
/// </summary>
public sealed class ContactResolverVerificationInput
{
    internal ContactResolverVerificationInput(
        ImportedContactAddress address,
        Xiq1Request request,
        Xis1Result result)
    {
        Address = address ?? throw new ArgumentNullException(nameof(address));
        Request = request ?? throw new ArgumentNullException(nameof(request));
        Result = result ?? throw new ArgumentNullException(nameof(result));
    }

    public ImportedContactAddress Address { get; }
    public Xiq1Request Request { get; }
    public Xis1Result Result { get; }
}

/// <summary>
/// Implementations authenticate the XIS1 service transcript (including one-time
/// claim receipts), obtain current non-forgeable protocol capabilities, and only
/// then call ContactResolverTrustedVerification.Accept. A structural transport
/// result alone cannot mint VerifiedContactBundleEvidence.
/// </summary>
public interface IContactResolverTrustedVerifier
{
    ValueTask<ContactResolverTrustedVerificationResult> VerifyAsync(
        ContactResolverVerificationInput input,
        ContactStoreScope localScope,
        ContactRelationshipId32 relationshipId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Store-ready result minted by the trusted verifier. The package remains
/// byte-only recovery evidence and cannot substitute for Protocol authority.
/// </summary>
public sealed class ContactResolverTrustedVerificationResult
{
    internal ContactResolverTrustedVerificationResult(
        VerifiedContactBundleEvidence evidence,
        ContactVerifiedPeerPackageEvidence recoveryPackage)
    {
        Evidence = evidence ?? throw new ArgumentNullException(nameof(evidence));
        RecoveryPackage = recoveryPackage ?? throw new ArgumentNullException(nameof(recoveryPackage));
    }

    public VerifiedContactBundleEvidence Evidence { get; }
    internal ContactVerifiedPeerPackageEvidence RecoveryPackage { get; }
}

/// <summary>
/// Fresh protocol authority recovered from a persisted byte-only peer package.
/// This is the object DPK2/DPH2 orchestration must consume after restart.
/// </summary>
public sealed class ContactResolverReverifiedPeerAuthority
{
    private readonly byte[] packageHash;

    internal ContactResolverReverifiedPeerAuthority(
        VerifiedContactBundleEvidence evidence,
        ContactResolverVerifiedCapabilitySet capabilities,
        ReadOnlySpan<byte> packageHash32)
    {
        Evidence = evidence ?? throw new ArgumentNullException(nameof(evidence));
        ArgumentNullException.ThrowIfNull(capabilities);
        if (packageHash32.Length != 32)
            throw new ArgumentException("The verified-peer package hash must contain exactly 32 bytes.", nameof(packageHash32));
        Bundle = capabilities.Bundle;
        Route = capabilities.Route;
        Placement = capabilities.Placement;
        ClaimReceipt = capabilities.ClaimReceipt;
        packageHash = packageHash32.ToArray();
    }

    public VerifiedContactBundleEvidence Evidence { get; }
    public VerifiedContactBundleClosure Bundle { get; }
    public VerifiedContactRouteClosure Route { get; }
    public VerifiedContactServicePlacement Placement { get; }
    public VerifiedXis1InviteClaimReceipt? ClaimReceipt { get; }
    public ReadOnlyMemory<byte> PackageHash => packageHash.ToArray();
}

/// <summary>
/// Production ownership boundary for the protocol verifiers which mint the
/// non-forgeable closure capabilities. Implementations receive only the exact
/// decoded resolver transcript; they never receive caller-selected keys or a
/// boolean trust decision.
/// </summary>
public interface IContactResolverVerifiedCapabilitySource
{
    ValueTask<ContactResolverVerifiedCapabilitySet> VerifyAsync(
        ContactResolverVerificationInput input,
        CancellationToken cancellationToken = default);
}

public sealed class ContactResolverVerifiedCapabilitySet
{
    internal ContactResolverVerifiedCapabilitySet(
        VerifiedContactBundleClosure bundle,
        VerifiedContactRouteClosure route,
        VerifiedContactServicePlacement placement,
        VerifiedXis1InviteClaimReceipt? claimReceipt)
    {
        Bundle = bundle ?? throw new ArgumentNullException(nameof(bundle));
        Route = route ?? throw new ArgumentNullException(nameof(route));
        Placement = placement ?? throw new ArgumentNullException(nameof(placement));
        ClaimReceipt = claimReceipt;
    }

    public VerifiedContactBundleClosure Bundle { get; }
    public VerifiedContactRouteClosure Route { get; }
    public VerifiedContactServicePlacement Placement { get; }
    public VerifiedXis1InviteClaimReceipt? ClaimReceipt { get; }
}

/// <summary>
/// Stable fail-closed signal used when the public Protocol surface cannot mint
/// a required remote Contact closure from the exact resolver transcript.
/// </summary>
public sealed class ContactResolverCapabilityUnavailableException : CryptographicException
{
    public const string PermanentPathAuthorityUnavailable =
        "CONTACT01_PERMANENT_PATH_AUTHORITY_UNAVAILABLE";
    public const string ClaimPathAuthorityUnavailable =
        "CONTACT01_CLAIM_PATH_AUTHORITY_UNAVAILABLE";

    internal ContactResolverCapabilityUnavailableException(string code, string message)
        : base(message) => Code = code;

    public string Code { get; }
}

internal interface IPermanentContactResolverCapabilityVerifier
{
    ValueTask<PermanentContactResolverCapabilities> VerifyAsync(
        ContactResolverVerificationInput input,
        ParsedDid1 permanentDeepId,
        ContactResolveCurrentValuePathAuthority path,
        CancellationToken cancellationToken);
}

internal sealed class PermanentContactResolverCapabilities
{
    internal PermanentContactResolverCapabilities(
        VerifiedContactBundleClosure bundle,
        VerifiedContactRouteClosure route)
    {
        Bundle = bundle ?? throw new ArgumentNullException(nameof(bundle));
        Route = route ?? throw new ArgumentNullException(nameof(route));
    }

    internal VerifiedContactBundleClosure Bundle { get; }
    internal VerifiedContactRouteClosure Route { get; }
}

internal sealed class ProtocolPermanentContactResolverCapabilityVerifier :
    IPermanentContactResolverCapabilityVerifier
{
    internal static ProtocolPermanentContactResolverCapabilityVerifier Instance { get; } = new();

    private ProtocolPermanentContactResolverCapabilityVerifier()
    {
    }

    public async ValueTask<PermanentContactResolverCapabilities> VerifyAsync(
        ContactResolverVerificationInput input,
        ParsedDid1 permanentDeepId,
        ContactResolveCurrentValuePathAuthority path,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var permanent = PermanentContactResolveVerifier.Verify(
            permanentDeepId,
            input.Request,
            input.Result,
            input.Result.Field(19),
            path.DirectoryFreshness,
            path.Placement,
            path.CurrentBootId.Span,
            path.CurrentMonotonicSample);
        var route = await ProductionContactResolverVerifiedCapabilitySource.VerifyRouteAsync(
            input,
            permanent.Contact,
            permanent.PublisherDevice,
            permanent.Authorization,
            path.Authority,
            path.Network,
            path.DirectoryFreshness,
            path.ExactXnv1,
            path.ExactXnh1,
            path.ExactPmt2,
            path.TrustedTimeAuthority,
            cancellationToken).ConfigureAwait(false);
        return new PermanentContactResolverCapabilities(permanent.Contact, route);
    }
}

/// <summary>
/// Production capability source for exact permanent and one-time XIS1 results.
/// It obtains a targeted current-value directory proof and current XPoint
/// placement through the protected path-authority composition, then mints the
/// identity and route capabilities with distinct Protocol verifier semantics.
/// </summary>
public sealed class ProductionContactResolverVerifiedCapabilitySource :
    IContactResolverVerifiedCapabilitySource
{
    private readonly IContactResolvePathAuthoritySource pathAuthority;
    private readonly IPermanentContactResolverCapabilityVerifier permanentVerifier;

    public ProductionContactResolverVerifiedCapabilitySource(
        IContactResolvePathAuthoritySource pathAuthority)
        : this(pathAuthority, ProtocolPermanentContactResolverCapabilityVerifier.Instance)
    {
    }

    internal ProductionContactResolverVerifiedCapabilitySource(
        IContactResolvePathAuthoritySource pathAuthority,
        IPermanentContactResolverCapabilityVerifier permanentVerifier)
    {
        this.pathAuthority = pathAuthority ?? throw new ArgumentNullException(nameof(pathAuthority));
        this.permanentVerifier = permanentVerifier ?? throw new ArgumentNullException(nameof(permanentVerifier));
    }

    public async ValueTask<ContactResolverVerifiedCapabilitySet> VerifyAsync(
        ContactResolverVerificationInput input,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ContactResolverTrustedVerification.ValidateExactTranscript(input);
        if (input.Address.Kind == ContactAddressKind.PermanentDeepId)
            return await VerifyPermanentAsync(input, cancellationToken).ConfigureAwait(false);
        if (input.Address.Kind != ContactAddressKind.OneTimeInvitation)
            throw new CryptographicException("The imported contact address kind is unsupported.");
        if (pathAuthority is not IContactResolveClaimPathAuthoritySource claimPathSource)
            throw new ContactResolverCapabilityUnavailableException(
                ContactResolverCapabilityUnavailableException.ClaimPathAuthorityUnavailable,
                "The configured path authority cannot mint a targeted current-value directory closure.");

        var exactDia1 = ContactCodec.Decode("DIA1", input.Address.CanonicalBytes.Span);
        ContactRecord exactDcr1;
        var protectedObject = input.Result.Field(19).ToArray();
        try
        {
            exactDcr1 = ContactResolverTrustedVerification.OpenExactDcr(
                input.Address, protectedObject);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedObject);
        }

        var dcb1 = ContactCodec.Decode("DCB1", exactDcr1.Field(2).Span);
        var lookup = AccountDirectoryAdl1Codec.Decode(dcb1.Field(20).Span);
        var claimPath = await claimPathSource.GetCurrentForOneTimeClaimAsync(
            input.Request, lookup.DirectoryLookupKey, cancellationToken).ConfigureAwait(false);
        ContactResolverTrustedVerification.ValidatePlacement(input, claimPath.Placement);

        var claimReceipt = Xis1InviteClaimReceiptVerifier.Verify(
            input.Request, input.Result, claimPath.Placement);
        var claim = ContactClaimClosureVerifier.VerifyOneTimeClaim(
            claimReceipt,
            exactDia1,
            claimPath.DirectoryFreshness,
            claimPath.CurrentBootId.Span,
            claimPath.CurrentMonotonicSample);

        var route = await VerifyRouteAsync(
            input,
            claim.Contact,
            claim.PublisherDevice,
            claim.Authorization,
            claimPath.Authority,
            claimPath.Network,
            claimPath.DirectoryFreshness,
            claimPath.ExactXnv1,
            claimPath.ExactXnh1,
            claimPath.ExactPmt2,
            claimPath.TrustedTimeAuthority,
            cancellationToken).ConfigureAwait(false);
        return new ContactResolverVerifiedCapabilitySet(
            claim.Contact, route, claimPath.Placement, claimReceipt);
    }

    private async ValueTask<ContactResolverVerifiedCapabilitySet> VerifyPermanentAsync(
        ContactResolverVerificationInput input,
        CancellationToken cancellationToken)
    {
        if (pathAuthority is not IContactResolvePermanentPathAuthoritySource permanentPathSource)
            throw new ContactResolverCapabilityUnavailableException(
                ContactResolverCapabilityUnavailableException.PermanentPathAuthorityUnavailable,
                "The configured path authority cannot mint a targeted current-value permanent DID1 closure.");

        var exactDid1 = ApplicationCoreCodec.DecodeDid1(input.Address.CanonicalBytes.Span);
        var permanentPath = await permanentPathSource.GetCurrentForPermanentResolveAsync(
            input.Request, exactDid1, cancellationToken).ConfigureAwait(false);
        ContactResolverTrustedVerification.ValidatePlacement(input, permanentPath.Placement);

        var permanent = await permanentVerifier.VerifyAsync(
            input, exactDid1, permanentPath, cancellationToken).ConfigureAwait(false);
        return new ContactResolverVerifiedCapabilitySet(
            permanent.Bundle, permanent.Route, permanentPath.Placement, claimReceipt: null);
    }

    internal static async ValueTask<VerifiedContactRouteClosure> VerifyRouteAsync(
        ContactResolverVerificationInput input,
        VerifiedContactBundleClosure contact,
        VerifiedDevice publisherDevice,
        CurrentlyAuthoritativeDca1 authorization,
        VerifiedXPointNetworkAuthority authority,
        VerifiedOnionNetworkContext network,
        VerifiedAccountDirectoryFreshness directoryFreshness,
        ReadOnlyMemory<byte> exactXnv1,
        ReadOnlyMemory<byte> exactXnh1,
        ReadOnlyMemory<byte> exactPmt2,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var routeRecords = ContactResolverTrustedVerification.ParseExactRouteClosure(
            input.Result.Field(21).Span);
        var descriptor = contact.Bundle.Field(14).Span;
        if (descriptor.Length != 651 || BinaryPrimitives.ReadUInt32BigEndian(descriptor[36..40]) != 611)
            throw new CryptographicException("The exact DCB1 descriptor is not exact XIR1 framing.");
        var xir1 = ContactCodec.Decode("XIR1", descriptor[40..]);
        var routeAuthority = await ContactNetworkAuthorityVerifier.VerifyAsync(
            authority,
            network,
            directoryFreshness,
            publisherDevice,
            authorization,
            exactXnv1,
            exactXnh1,
            directoryFreshness.ExactAdh1,
            exactPmt2,
            routeRecords[5].CanonicalBytes,
            trustedTimeAuthority,
            cancellationToken).ConfigureAwait(false);
        return ContactCodec.VerifyRouteUpdateClosure(
            xir1,
            routeRecords[0],
            routeRecords[1],
            routeRecords[2],
            routeRecords[3],
            routeRecords[4],
            routeRecords[5],
            routeAuthority);
    }
}

/// <summary>
/// Narrow host composition. It accepts only the existing protected path-authority
/// abstraction and exposes no raw trust material or caller trust decisions.
/// </summary>
public static class ContactResolverTrustedVerifierFactory
{
    public static ContactResolverTrustedVerifier CreateProduction(
        IContactResolvePathAuthoritySource pathAuthority) =>
        new(new ProductionContactResolverVerifiedCapabilitySource(pathAuthority));
}

/// <summary>
/// Production composition of ContactV1's identity, route, placement, and
/// one-time-claim protocol verifiers. A source failure, stale capability, or
/// cancellation never produces relationship evidence.
/// </summary>
public sealed class ContactResolverTrustedVerifier : IContactResolverTrustedVerifier
{
    private readonly IContactResolverVerifiedCapabilitySource capabilities;

    public ContactResolverTrustedVerifier(IContactResolverVerifiedCapabilitySource capabilities) =>
        this.capabilities = capabilities ?? throw new ArgumentNullException(nameof(capabilities));

    public async ValueTask<ContactResolverTrustedVerificationResult> VerifyAsync(
        ContactResolverVerificationInput input,
        ContactStoreScope localScope,
        ContactRelationshipId32 relationshipId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(localScope);
        ArgumentNullException.ThrowIfNull(relationshipId);
        if (input.Result.Status != Xis1Status.Success)
            throw new CryptographicException("Only a successful XIS1 can enter trusted verification.");
        ContactResolverTrustedVerification.ValidateResultShape(input);

        try
        {
            var complete = await capabilities.VerifyAsync(input, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var evidence = ContactResolverTrustedVerification.Accept(
                input, localScope, relationshipId, complete.Bundle, complete.Route,
                complete.Placement, complete.ClaimReceipt);
            return new ContactResolverTrustedVerificationResult(
                evidence,
                ContactResolverTrustedVerification.CreateRecoveryPackage(
                    input, localScope, evidence, complete.Bundle));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (CryptographicException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new CryptographicException(
                "The production ContactV1 capability source failed closed.", exception);
        }
    }

    /// <summary>
    /// Reconstructs the exact resolver transcript from encrypted-store evidence,
    /// obtains current path authority, and reruns every trusted verifier before
    /// returning capabilities usable by DPK2/DPH2 orchestration.
    /// </summary>
    public async ValueTask<ContactResolverReverifiedPeerAuthority> ReverifyAsync(
        ContactVerifiedPeerPackageEvidence recoveryPackage,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(recoveryPackage);
        try
        {
            var input = DecodeRecoveryInput(recoveryPackage);
            var complete = await capabilities.VerifyAsync(input, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var evidence = ContactResolverTrustedVerification.Accept(
                input,
                recoveryPackage.Scope,
                recoveryPackage.RelationshipId,
                complete.Bundle,
                complete.Route,
                complete.Placement,
                complete.ClaimReceipt);
            if (!evidence.ConversationId.Equals(recoveryPackage.ConversationId) ||
                !evidence.RemoteAccountId.Equals(recoveryPackage.RemoteAccountId))
                throw new CryptographicException("Reverified peer authority differs from persisted correlation.");
            var rebuilt = ContactResolverTrustedVerification.CreateRecoveryPackage(
                input, recoveryPackage.Scope, evidence, complete.Bundle);
            if (!CryptographicOperations.FixedTimeEquals(
                    rebuilt.PackageHash.Span, recoveryPackage.PackageHash.Span))
                throw new CryptographicException("Reverified peer authority differs from the exact persisted package.");
            return new ContactResolverReverifiedPeerAuthority(
                evidence, complete, recoveryPackage.PackageHash.Span);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (CryptographicException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new CryptographicException(
                "The persisted ContactV1 peer package failed closed during re-verification.", exception);
        }
    }

    private static ContactResolverVerificationInput DecodeRecoveryInput(
        ContactVerifiedPeerPackageEvidence package)
    {
        ImportedContactAddress address;
        if (package.AddressKind == ContactAddressKind.PermanentDeepId)
        {
            var did = ApplicationCoreCodec.DecodeDid1(package.ExactCanonicalAddress.Span);
            address = new ImportedContactAddress(
                package.AddressKind,
                package.NetworkId.Span,
                package.ExactCanonicalAddress.Span,
                did.Text,
                expiresAtUnixSeconds: null);
        }
        else if (package.AddressKind == ContactAddressKind.OneTimeInvitation)
        {
            var dia = ContactCodec.Decode("DIA1", package.ExactCanonicalAddress.Span);
            address = new ImportedContactAddress(
                package.AddressKind,
                package.NetworkId.Span,
                package.ExactCanonicalAddress.Span,
                DeepInvitationTextCodec.EncodeCanonical(dia),
                BinaryPrimitives.ReadUInt64BigEndian(dia.Field(8).Span));
        }
        else
        {
            throw new CryptographicException("The persisted contact address kind is unsupported.");
        }

        var request = Xiq1Codec.Decode(package.ExactXiq1.Span);
        var result = Xis1Codec.Decode(package.ExactXis1.Span, package.ExactXiq1.Span);
        return new ContactResolverVerificationInput(address, request, result);
    }
}

public static class ContactResolverTrustedVerification
{
    private const string EvidenceDomain = "Deep/Client/ContactV1/verified-XIS1";

    /// <summary>
    /// Converts protocol-owned verification capabilities into store evidence
    /// only after byte-for-byte binding them to the exact successful XIS1.
    /// </summary>
    public static VerifiedContactBundleEvidence Accept(
        ContactResolverVerificationInput input,
        ContactStoreScope localScope,
        ContactRelationshipId32 relationshipId,
        VerifiedContactBundleClosure bundle,
        VerifiedContactRouteClosure route,
        VerifiedContactServicePlacement placement,
        VerifiedXis1InviteClaimReceipt? claimReceipt)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(localScope);
        ArgumentNullException.ThrowIfNull(relationshipId);
        ArgumentNullException.ThrowIfNull(bundle);
        ArgumentNullException.ThrowIfNull(route);
        ArgumentNullException.ThrowIfNull(placement);
        if (input.Result.Status != Xis1Status.Success)
            throw Rejected("Only a verified successful XIS1 can create relationship evidence.");
        ValidateResultShape(input);

        ValidatePlacement(input, placement);

        RequireSame(input.Address.NetworkId.Span, input.Request.NetworkId.Span,
            "XIQ1 belongs to another network.");
        var expectedLocator = ContactCodecHash.OneTimeOrPermanentLocator(input.Address);
        try
        {
            RequireSame(expectedLocator, input.Request.LocatorHash.Span,
                "XIQ1 locator does not belong to the imported address.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedLocator);
        }

        ContactRecord dcr;
        var protectedDcr = input.Result.Field(19).ToArray();
        try
        {
            dcr = OpenExactDcr(input.Address, protectedDcr);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedDcr);
        }

        RequireSame(dcr.CanonicalBytes.Span, bundle.ResolverResponse.CanonicalBytes.Span,
            "The verified DCR1 differs from the exact encrypted XIS1 object.");
        RequireSame(input.Address.NetworkId.Span, dcr.Field(1).Span,
            "The verified DCR1 belongs to another network.");

        var exactRoutes = ParseExactRouteClosure(input.Result.Field(21).Span);
        var verifiedRoutes = new[]
        {
            route.Reachability, route.Authorization, route.Route,
            route.Successor, route.Projection, route.Selection,
        };
        for (var index = 0; index < exactRoutes.Length; index++)
            RequireSame(exactRoutes[index].CanonicalBytes.Span, verifiedRoutes[index].CanonicalBytes.Span,
                "The verified route capability differs from exact XIS1 route closure.");

        var descriptor = bundle.Bundle.Field(14).Span;
        if (descriptor.Length != 651 || BinaryPrimitives.ReadUInt32BigEndian(descriptor[36..40]) != 611)
            throw Rejected("The verified DCB1 descriptor is not exact XIR1 framing.");
        var exactXir1 = ContactCodec.Decode("XIR1", descriptor[40..]);
        RequireSame(exactXir1.CanonicalBytes.Span, route.Invite.CanonicalBytes.Span,
            "The verified route does not belong to the verified DCB1.");
        var xnvReference = route.Projection.Field(5).Span;
        if (xnvReference.Length != 38)
            throw Rejected("The verified route projection has an invalid XNV1 reference.");
        RequireSame(input.Request.ViewHash.Span, xnvReference[6..],
            "The verified route does not belong to the exact XIQ1 view.");

        ValidatePublication(input, bundle, exactXir1);
        ValidateAddressBinding(input.Address, bundle, exactXir1);
        ValidateClaimReceipt(input, placement, claimReceipt);
        var artifacts = ArtifactHashes(bundle, route);
        var evidenceHash = VerifiedEvidenceHash(input);
        return ContactTrustedVerifierBoundary.BundleVerified(localScope, input.Address,
            bundle.Directory.Record.DeepAccountId.Span, relationshipId, artifacts, evidenceHash);
    }

    internal static ContactVerifiedPeerPackageEvidence CreateRecoveryPackage(
        ContactResolverVerificationInput input,
        ContactStoreScope localScope,
        VerifiedContactBundleEvidence evidence,
        VerifiedContactBundleClosure bundle)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(localScope);
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(bundle);
        var directoryEntries = bundle.Directory.Record.ActiveDevices;
        var verifiedDevices = bundle.Directory.Identity.ActiveDevices;
        var devices = new ContactVerifiedPeerDeviceEvidence[directoryEntries.Count];
        for (var index = 0; index < directoryEntries.Count; index++)
        {
            var entry = directoryEntries[index];
            var verified = verifiedDevices.SingleOrDefault(device =>
                CryptographicOperations.FixedTimeEquals(
                    device.Certificate.DeviceId.Span, entry.DeviceId.Span))
                ?? throw Rejected("The verified DMD1 device set is incomplete.");
            devices[index] = new ContactVerifiedPeerDeviceEvidence(
                entry.DeviceId.Span, verified.Certificate.CanonicalBytes.Span);
        }

        return new ContactVerifiedPeerPackageEvidence(
            localScope,
            evidence.RelationshipId,
            evidence.ConversationId,
            evidence.RemoteAccountId,
            evidence.Address.Kind,
            evidence.Address.NetworkId.Span,
            evidence.Address.CanonicalBytes.Span,
            input.Request.WireBytes.Span,
            input.Result.WireBytes.Span,
            bundle.ResolverResponse.CanonicalBytes.Span,
            bundle.Bundle.CanonicalBytes.Span,
            bundle.Directory.Record.CanonicalBytes.Span,
            devices,
            input.Result.Field(21).Span,
            requireCanonicalVerification: true);
    }

    internal static void ValidatePlacement(
        ContactResolverVerificationInput input,
        VerifiedContactServicePlacement placement)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(placement);
        placement.Network.EnsureCurrent();
        RequireSame(input.Address.NetworkId.Span, placement.Network.NetworkId.Span,
            "The verified placement belongs to another network.");
        if (placement.RequestKind != ContactServiceRequestKind.ResolveInvite ||
            placement.ServiceClass != ContactServiceClass.InviteResolver)
            throw Rejected("The verified placement is not a ResolveInvite authority.");
        var expectedLocator = ContactCodecHash.OneTimeOrPermanentLocator(input.Address);
        try
        {
            if (!placement.Binds(ContactServiceRequestKind.ResolveInvite, expectedLocator))
                throw Rejected("The verified placement belongs to another resolver locator.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedLocator);
        }
        RequireSame(input.Request.ViewHash.Span, placement.ViewHash.Span,
            "The verified placement belongs to another XIQ1 view.");
        RequireSame(input.Request.PlacementHash.Span, placement.PlacementHash.Span,
            "The verified placement belongs to another XIQ1 placement.");
        var requestWindowValid =
            input.Request.IssuedAtUnixSeconds <= input.Result.ServerTimeUnixSeconds &&
            input.Result.ServerTimeUnixSeconds < input.Request.ExpiresAtUnixSeconds;
        if (!requestWindowValid ||
            input.Request.IssuedAtUnixSeconds >= placement.ValidUntilUnixSeconds ||
            input.Request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds ||
            input.Result.ServerTimeUnixSeconds >= placement.ValidUntilUnixSeconds)
            throw Rejected("The XIQ1/XIS1 time interval exceeds the verified placement lease.");
    }

    internal static void ValidateExactTranscript(ContactResolverVerificationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.Result.Status != Xis1Status.Success)
            throw Rejected("Only a successful exact XIS1 can enter production capability verification.");
        ValidateResultShape(input);
        RequireSame(input.Address.NetworkId.Span, input.Request.NetworkId.Span,
            "The imported address and exact XIQ1 belong to different networks.");
        RequireSame(input.Request.NetworkId.Span, input.Result.NetworkId.Span,
            "The exact XIS1 belongs to another network.");
        RequireSame(input.Request.OperationId.Span, input.Result.OperationId.Span,
            "The exact XIS1 belongs to another operation.");
        RequireSame(input.Request.RequestHash.Span, input.Result.RequestHash.Span,
            "The exact XIS1 belongs to another XIQ1 request.");
        if (input.Result.PaddingClass != input.Request.ResponsePaddingClass)
            throw Rejected("The exact XIS1 padding class differs from the XIQ1 request.");

        var expectedLocator = ContactCodecHash.OneTimeOrPermanentLocator(input.Address);
        try
        {
            RequireSame(expectedLocator, input.Request.LocatorHash.Span,
                "The exact XIQ1 locator does not belong to the imported address.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedLocator);
        }

        var protectedObjectHash = input.Result.Field(18).Span;
        var routeClosureHash = input.Result.Field(20).Span;
        Span<byte> actualObjectHash = stackalloc byte[32];
        Span<byte> actualRouteHash = stackalloc byte[32];
        try
        {
            SHA256.HashData(input.Result.Field(19).Span, actualObjectHash);
            SHA256.HashData(input.Result.Field(21).Span, actualRouteHash);
            if (protectedObjectHash.Length != 32 || routeClosureHash.Length != 32 ||
                !CryptographicOperations.FixedTimeEquals(protectedObjectHash, actualObjectHash) ||
                !CryptographicOperations.FixedTimeEquals(routeClosureHash, actualRouteHash))
                throw Rejected("The exact XIS1 object or route-closure hash is inconsistent.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualObjectHash);
            CryptographicOperations.ZeroMemory(actualRouteHash);
        }
    }

    internal static void ValidateResultShape(ContactResolverVerificationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var oneTime = input.Address.Kind == ContactAddressKind.OneTimeInvitation;
        if (oneTime)
        {
            if (input.Result.MutationOutcome != ContactServiceMutationOutcome.DurablyCommitted ||
                input.Result.Field(22).Length != sizeof(ulong) || input.Result.Field(23).Length != 193)
                throw Rejected("A one-time DIA1 resolution requires the exact consuming XIS1 shape.");
            return;
        }

        if (input.Address.Kind != ContactAddressKind.PermanentDeepId ||
            input.Result.MutationOutcome != ContactServiceMutationOutcome.None ||
            input.Result.Field(22).Length != 193 || !input.Result.Field(23).IsEmpty)
            throw Rejected("A permanent DID1 resolution requires the exact non-consuming XIS1 shape.");
    }

    private static void ValidateClaimReceipt(
        ContactResolverVerificationInput input,
        VerifiedContactServicePlacement placement,
        VerifiedXis1InviteClaimReceipt? claimReceipt)
    {
        var oneTime = input.Address.Kind == ContactAddressKind.OneTimeInvitation;
        if (!oneTime)
        {
            if (input.Result.MutationOutcome != ContactServiceMutationOutcome.None ||
                claimReceipt is not null || input.Result.Field(22).Length != 193 ||
                !input.Result.Field(23).IsEmpty)
                throw Rejected("A permanent DID1 resolution must not carry a consuming claim receipt.");
            return;
        }

        if (input.Result.MutationOutcome != ContactServiceMutationOutcome.DurablyCommitted ||
            claimReceipt is null)
            throw Rejected("A one-time DIA1 resolution requires the verified two-replica claim receipt.");

        RequireSame(input.Request.CanonicalBytes.Span, claimReceipt.ExactXiq1.Span,
            "The verified claim receipt belongs to another exact XIQ1.");
        RequireSame(input.Result.CanonicalBytes.Span, claimReceipt.ExactXis1.Span,
            "The verified claim receipt belongs to another exact XIS1.");
        RequireSame(input.Request.NetworkId.Span, claimReceipt.NetworkId.Span,
            "The verified claim receipt belongs to another network.");
        RequireSame(input.Request.OperationId.Span, claimReceipt.OperationId.Span,
            "The verified claim receipt belongs to another operation.");
        RequireSame(input.Request.RequestHash.Span, claimReceipt.RequestHash.Span,
            "The verified claim receipt belongs to another request hash.");
        RequireSame(input.Request.LocatorHash.Span, claimReceipt.LocatorHash.Span,
            "The verified claim receipt belongs to another locator.");
        RequireSame(input.Request.ViewHash.Span, claimReceipt.ViewHash.Span,
            "The verified claim receipt belongs to another view.");
        RequireSame(input.Request.PlacementHash.Span, claimReceipt.PlacementHash.Span,
            "The verified claim receipt belongs to another placement.");
        if (BinaryPrimitives.ReadUInt64BigEndian(input.Result.Field(16).Span) !=
                claimReceipt.PublicationGeneration ||
            BinaryPrimitives.ReadUInt64BigEndian(input.Result.Field(17).Span) !=
                claimReceipt.CurrentPublicationExpiresAtUnixSeconds ||
            BinaryPrimitives.ReadUInt64BigEndian(input.Result.Field(22).Span) !=
                claimReceipt.ClaimCommitGeneration)
            throw Rejected("The verified claim receipt has different publication or claim generations.");
        RequireSame(input.Result.Field(18).Span, claimReceipt.ObjectCiphertextHash.Span,
            "The verified claim receipt belongs to another protected object hash.");
        RequireSame(input.Result.Field(19).Span, claimReceipt.ObjectCiphertext.Span,
            "The verified claim receipt belongs to another protected object.");
        RequireSame(input.Result.Field(20).Span, claimReceipt.RouteClosureHash.Span,
            "The verified claim receipt belongs to another route closure hash.");
        RequireSame(input.Result.Field(21).Span, claimReceipt.ExactRouteClosure.Span,
            "The verified claim receipt belongs to another route closure.");
        var replicaComparer = Comparer<byte[]>.Create(
            static (left, right) => left.AsSpan().SequenceCompareTo(right));
        var expectedReplicaIds = placement.RankedReplicaNodeIds
            .Select(static value => value.ToArray())
            .OrderBy(static value => value, replicaComparer)
            .ToArray();
        var receiptReplicaIds = claimReceipt.ReplicaNodeIds
            .Select(static value => value.ToArray())
            .OrderBy(static value => value, replicaComparer)
            .ToArray();
        if (expectedReplicaIds.Length != 2 || receiptReplicaIds.Length != 2)
            throw Rejected("The verified claim receipt does not bind exactly two resolver replicas.");
        for (var index = 0; index < expectedReplicaIds.Length; index++)
            RequireSame(expectedReplicaIds[index], receiptReplicaIds[index],
                "The verified claim receipt belongs to another resolver replica set.");
    }

    internal static ContactRecord OpenExactDcr(ImportedContactAddress address, ReadOnlySpan<byte> protectedDcr)
    {
        if (address.Kind == ContactAddressKind.PermanentDeepId)
        {
            var did = ApplicationCoreCodec.DecodeDid1(address.CanonicalBytes.Span);
            using var resolution = PermanentContactResolutionDerivation.Derive(address.NetworkId.Span, did);
            return Dcr1ObjectProtectionCodec.OpenPermanent(
                protectedDcr, address.NetworkId.Span, did, resolution);
        }

        var dia = ContactCodec.Decode("DIA1", address.CanonicalBytes.Span);
        var dcr = Dcr1ObjectProtectionCodec.OpenOneTime(protectedDcr, dia);
        var dcb = ContactCodec.Decode("DCB1", dcr.Field(2).Span);
        RequireSame(dia.Field(7).Span, dcb.ArtifactHash.Span,
            "DIA1 expected DCB1 hash differs from the resolver object.");
        return dcr;
    }

    private static void ValidateAddressBinding(
        ImportedContactAddress address,
        VerifiedContactBundleClosure bundle,
        ContactRecord xir1)
    {
        RequireSame(address.NetworkId.Span, bundle.Directory.Record.NetworkId.Span,
            "Verified identity belongs to another network.");
        var expectedPolicy = address.Kind == ContactAddressKind.PermanentDeepId ? (byte)1 : (byte)2;
        if (xir1.Field(9).Span[0] != expectedPolicy)
            throw Rejected("Verified XIR1 invite policy differs from the imported address kind.");

        if (address.Kind == ContactAddressKind.PermanentDeepId)
        {
            RequireSame(address.CanonicalBytes.Span, bundle.Binding.DeepId.CanonicalBytes.Span,
                "Verified bundle belongs to another permanent Deep ID.");
        }
    }

    private static void ValidatePublication(
        ContactResolverVerificationInput input,
        VerifiedContactBundleClosure bundle,
        ContactRecord xir1)
    {
        var publicationGeneration = BinaryPrimitives.ReadUInt64BigEndian(input.Result.Field(16).Span);
        var bundleGeneration = BinaryPrimitives.ReadUInt64BigEndian(bundle.Bundle.Field(8).Span);
        if (publicationGeneration != bundleGeneration ||
            (input.Request.RequestedGeneration != 0 &&
             publicationGeneration != input.Request.RequestedGeneration))
            throw Rejected("XIS1 publication generation differs from the verified DCB1/request.");

        var publicationExpiry = BinaryPrimitives.ReadUInt64BigEndian(input.Result.Field(17).Span);
        var bundleExpiry = BinaryPrimitives.ReadUInt64BigEndian(bundle.Bundle.Field(18).Span);
        var inviteExpiry = BinaryPrimitives.ReadUInt64BigEndian(xir1.Field(14).Span);
        var maximumExpiry = Math.Min(bundleExpiry,
            Math.Min(inviteExpiry, bundle.Authorization.Verified.Record.ExpiresAtUnixSeconds));
        if (publicationExpiry <= bundle.Freshness.TrustedUpperUnixSeconds ||
            publicationExpiry > maximumExpiry)
            throw Rejected("XIS1 publication expiry is not current inside its verified signed closure.");

        var hasClaimCommit = input.Result.Field(22).Length == sizeof(ulong) &&
            input.Result.Field(23).Length == 193;
        if ((input.Address.Kind == ContactAddressKind.OneTimeInvitation) != hasClaimCommit)
            throw Rejected("XIS1 claim shape differs from the imported address kind.");
    }

    private static IReadOnlyDictionary<ContactVerifiedArtifactKind, ReadOnlyMemory<byte>> ArtifactHashes(
        VerifiedContactBundleClosure bundle,
        VerifiedContactRouteClosure route) =>
        new Dictionary<ContactVerifiedArtifactKind, ReadOnlyMemory<byte>>
        {
            [ContactVerifiedArtifactKind.Did1] = bundle.Binding.DeepId.RecordHash,
            [ContactVerifiedArtifactKind.Dab1] = bundle.Binding.Record.RecordHash,
            [ContactVerifiedArtifactKind.Dpa1] = bundle.Binding.Identity.Account.Certificate.CanonicalHash,
            [ContactVerifiedArtifactKind.Drs1] = bundle.Binding.Identity.Revocations.Snapshot.CanonicalHash,
            [ContactVerifiedArtifactKind.Dmd1] = bundle.Directory.Record.RecordHash,
            [ContactVerifiedArtifactKind.Dca1] = bundle.Authorization.Verified.Record.RecordHash,
            [ContactVerifiedArtifactKind.Dcb1] = bundle.Bundle.ArtifactHash,
            [ContactVerifiedArtifactKind.Dcr1] = bundle.ResolverResponse.ArtifactHash,
            [ContactVerifiedArtifactKind.Adh1] = bundle.Freshness.ExactAdh1CoreHash,
            [ContactVerifiedArtifactKind.Adp1] = bundle.Freshness.ExactAdp1Hash,
            [ContactVerifiedArtifactKind.ReachabilityDescriptor] = route.Reachability.ArtifactHash,
        };

    internal static ContactRecord[] ParseExactRouteClosure(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < 25 || encoded[0] != 6)
            throw Rejected("XIS1 route closure count is invalid.");
        var magics = new[] { "XRR1", "XRA1", "XRC1", "XSS1", "PMT2", "PMS2" };
        var result = new ContactRecord[magics.Length];
        var offset = 1;
        for (var index = 0; index < result.Length; index++)
        {
            if (encoded.Length - offset < 4) throw Rejected("XIS1 route closure is truncated.");
            var size = BinaryPrimitives.ReadUInt32BigEndian(encoded[offset..]);
            offset += 4;
            if (size > int.MaxValue || size > encoded.Length - offset)
                throw Rejected("XIS1 route closure has an invalid record length.");
            result[index] = ContactCodec.Decode(magics[index], encoded.Slice(offset, (int)size));
            offset += (int)size;
        }
        if (offset != encoded.Length) throw Rejected("XIS1 route closure has trailing bytes.");
        return result;
    }

    private static void RequireSame(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual, string message)
    {
        if (expected.Length != actual.Length || !CryptographicOperations.FixedTimeEquals(expected, actual))
            throw Rejected(message);
    }

    private static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> payload)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[checked(label.Length + 5 + payload.Length)];
        try
        {
            label.CopyTo(preimage, 0);
            BinaryPrimitives.WriteUInt32BigEndian(preimage.AsSpan(label.Length + 1), checked((uint)payload.Length));
            payload.CopyTo(preimage.AsSpan(label.Length + 5));
            return SHA256.HashData(preimage);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preimage);
        }
    }

    private static byte[] VerifiedEvidenceHash(ContactResolverVerificationInput input)
    {
        var transcript = new byte[153];
        transcript[0] = (byte)input.Address.Kind;
        input.Request.RequestHash.Span.CopyTo(transcript.AsSpan(1, 32));
        input.Result.Field(16).Span.CopyTo(transcript.AsSpan(33, 8));
        input.Result.Field(17).Span.CopyTo(transcript.AsSpan(41, 8));
        input.Result.Field(18).Span.CopyTo(transcript.AsSpan(49, 32));
        input.Result.Field(20).Span.CopyTo(transcript.AsSpan(81, 32));
        if (input.Address.Kind == ContactAddressKind.OneTimeInvitation)
        {
            input.Result.Field(22).Span.CopyTo(transcript.AsSpan(113, 8));
            SHA256.HashData(input.Result.Field(23).Span).CopyTo(transcript, 121);
        }
        else
        {
            SHA256.HashData(input.Result.Field(22).Span).CopyTo(transcript, 121);
        }
        try
        {
            return Sha256Domain(EvidenceDomain, transcript);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transcript);
        }
    }

    private static CryptographicException Rejected(string message) => new(message);
}

internal static class ContactCodecHash
{
    private const string OneTimeLocatorDomain = "Deep/ContactResolver/V1/one-time-locator";

    internal static byte[] OneTimeOrPermanentLocator(ImportedContactAddress address)
    {
        if (address.Kind == ContactAddressKind.PermanentDeepId)
        {
            var did = ApplicationCoreCodec.DecodeDid1(address.CanonicalBytes.Span);
            using var resolution = PermanentContactResolutionDerivation.Derive(address.NetworkId.Span, did);
            return resolution.LocatorHash.ToArray();
        }

        var dia = ContactCodec.Decode("DIA1", address.CanonicalBytes.Span);
        return Sha256Domain(OneTimeLocatorDomain, dia.Field(5).Span);
    }

    private static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> payload)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[checked(label.Length + 5 + payload.Length)];
        try
        {
            label.CopyTo(preimage, 0);
            BinaryPrimitives.WriteUInt32BigEndian(preimage.AsSpan(label.Length + 1), checked((uint)payload.Length));
            payload.CopyTo(preimage.AsSpan(label.Length + 5));
            return SHA256.HashData(preimage);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preimage);
        }
    }
}
