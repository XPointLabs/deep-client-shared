using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.XPointNetworkV1;

public sealed class ContactResolvePathAuthority
{
    public ContactResolvePathAuthority(
        VerifiedOnionNetworkContext network,
        VerifiedContactServicePlacement placement)
        : this(network, placement, canonical: null)
    {
    }

    internal ContactResolvePathAuthority(
        VerifiedOnionNetworkContext network,
        VerifiedContactServicePlacement placement,
        CanonicalContactResolveAuthority? canonical)
    {
        Network = network ?? throw new ArgumentNullException(nameof(network));
        Placement = placement ?? throw new ArgumentNullException(nameof(placement));
        Canonical = canonical;
    }

    public VerifiedOnionNetworkContext Network { get; }
    public VerifiedContactServicePlacement Placement { get; }
    internal CanonicalContactResolveAuthority? Canonical { get; }
}

/// <summary>
/// Supplies only protocol-minted current capabilities. Implementations fetch and
/// verify the signed network closure and derive exact Contact placement.
/// </summary>
public interface IContactResolvePathAuthoritySource
{
    ValueTask<ContactResolvePathAuthority> GetCurrentAsync(
        Xiq1Request request,
        CancellationToken cancellationToken);

    ValueTask<ContactResolvePathAuthority> GetCurrentAsync(
        ContactResolveCanonicalPathRequest request,
        CancellationToken cancellationToken) =>
        request.RequestKind == ContactServiceRequestKind.ResolveInvite
            ? GetCurrentAsync(Xiq1Codec.Decode(request.ExactRequest.Span), cancellationToken)
            : ValueTask.FromException<ContactResolvePathAuthority>(new ContactResolvePathException(
                "request-kind-unavailable",
                "The configured ContactResolve authority source does not support this canonical request kind."));
}

internal interface IContactResolvePublicationPathAuthoritySource
{
    ValueTask<ContactResolvePathAuthority> GetCurrentForPublicationAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> serviceCapability,
        CancellationToken cancellationToken);
}

/// <summary>
/// Canonical request facts used for NETCODEC placement. The shard key and
/// request kind are derived from Protocol records, never supplied independently.
/// </summary>
public sealed class ContactResolveCanonicalPathRequest
{
    private readonly byte[] exactRequest;
    private readonly byte[] networkId;
    private readonly byte[] viewHash;
    private readonly byte[] placementHash;
    private readonly byte[] shardKey;

    private ContactResolveCanonicalPathRequest(
        ReadOnlySpan<byte> exactRequest,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> placementHash,
        ContactServiceRequestKind requestKind,
        ReadOnlySpan<byte> shardKey,
        ulong expiresAtUnixSeconds)
    {
        this.exactRequest = exactRequest.ToArray();
        this.networkId = networkId.ToArray();
        this.viewHash = viewHash.ToArray();
        this.placementHash = placementHash.ToArray();
        this.shardKey = shardKey.ToArray();
        RequestKind = requestKind;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> ExactRequest => exactRequest.ToArray();
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> ViewHash => viewHash.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => placementHash.ToArray();
    public ContactServiceRequestKind RequestKind { get; }
    public ReadOnlyMemory<byte> ShardKey => shardKey.ToArray();
    public ulong ExpiresAtUnixSeconds { get; }

    public static ContactResolveCanonicalPathRequest Decode(ReadOnlySpan<byte> exactRequest)
    {
        if (exactRequest.Length < 4)
            throw new ContactResolvePathException(
                "contact-request-invalid", "The canonical ContactResolve request is truncated.");
        if (exactRequest[..4].SequenceEqual("XIQ1"u8))
        {
            var request = Xiq1Codec.Decode(exactRequest);
            return Create(request.CanonicalBytes.Span, request.NetworkId.Span,
                request.ViewHash.Span, request.PlacementHash.Span,
                ContactServiceRequestKind.ResolveInvite, request.LocatorHash.Span,
                request.ExpiresAtUnixSeconds);
        }
        if (exactRequest[..4].SequenceEqual("XPK1"u8))
        {
            var request = Xpk1Codec.Decode(exactRequest);
            return Create(request.CanonicalBytes.Span, request.NetworkId.Span,
                request.ViewHash.Span, request.PlacementHash.Span,
                ContactServiceRequestKind.ClaimPreKey, request.ServiceCapability.Span,
                request.ExpiresAtUnixSeconds);
        }
        if (exactRequest[..4].SequenceEqual("XPP1"u8))
        {
            var request = Xpp1BoundedCodec.Decode(exactRequest);
            if (request is not Xpp1ManifestRequest manifest)
                throw new ContactResolvePathException(
                    "xpp1-publication-context-required",
                    "A bounded XPP1 chunk or commit requires its sealed manifest publication context.");
            return FromBoundedPublication(request, manifest.Manifest.ServiceCapability.Span);
        }
        throw new ContactResolvePathException(
            "contact-request-invalid",
            "Only exact XIQ1, XPK1, or bounded XPP1 records have ContactResolve placement semantics.");
    }

    public static ContactResolveCanonicalPathRequest FromBoundedPublication(
        Xpp1BoundedRequest request,
        ReadOnlySpan<byte> verifiedServiceCapability)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (verifiedServiceCapability.Length != 32 ||
            verifiedServiceCapability.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                "The bounded publication service capability must be nonzero 32 bytes.",
                nameof(verifiedServiceCapability));
        if (request is Xpp1ManifestRequest manifest &&
            !Fixed(manifest.Manifest.ServiceCapability.Span, verifiedServiceCapability))
            throw new CryptographicException(
                "The bounded XPP1 manifest differs from the sealed publication shard key.");
        return Create(request.CanonicalBytes.Span, request.NetworkId.Span,
            request.ViewHash.Span, request.PlacementHash.Span,
            ContactServiceRequestKind.PublishPreKeyInventory,
            verifiedServiceCapability, request.ExpiresAtUnixSeconds);
    }

    private static ContactResolveCanonicalPathRequest Create(
        ReadOnlySpan<byte> exact,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> placementHash,
        ContactServiceRequestKind kind,
        ReadOnlySpan<byte> shardKey,
        ulong expiresAt)
    {
        if (exact.Length == 0 || networkId.Length != 16 || viewHash.Length != 32 ||
            placementHash.Length != 32 || shardKey.Length != 32 ||
            networkId.IndexOfAnyExcept((byte)0) < 0 ||
            viewHash.IndexOfAnyExcept((byte)0) < 0 ||
            placementHash.IndexOfAnyExcept((byte)0) < 0 ||
            shardKey.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException(
                "The canonical ContactResolve request has invalid placement facts.");
        return new ContactResolveCanonicalPathRequest(
            exact, networkId, viewHash, placementHash, kind, shardKey, expiresAt);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal interface IContactResolveClaimPathAuthoritySource
{
    ValueTask<ContactResolveCurrentValuePathAuthority> GetCurrentForOneTimeClaimAsync(
        Xiq1Request request,
        ReadOnlyMemory<byte> directoryLookupKey,
        CancellationToken cancellationToken);
}

internal interface IContactResolvePermanentPathAuthoritySource
{
    ValueTask<ContactResolveCurrentValuePathAuthority> GetCurrentForPermanentResolveAsync(
        Xiq1Request request,
        ParsedDid1 permanentDeepId,
        CancellationToken cancellationToken);
}

internal sealed class ContactResolveCurrentValuePathAuthority
{
    internal ContactResolveCurrentValuePathAuthority(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness directoryFreshness,
        VerifiedOnionNetworkContext network,
        VerifiedContactServicePlacement placement,
        ReadOnlyMemory<byte> exactXnv1,
        ReadOnlyMemory<byte> exactXnh1,
        ReadOnlyMemory<byte> exactPmt2,
        ReadOnlyMemory<byte> currentBootId,
        ulong currentMonotonicSample,
        OnionTrustedTimeAuthority trustedTimeAuthority)
    {
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
        DirectoryFreshness = directoryFreshness ?? throw new ArgumentNullException(nameof(directoryFreshness));
        Network = network ?? throw new ArgumentNullException(nameof(network));
        Placement = placement ?? throw new ArgumentNullException(nameof(placement));
        ExactXnv1 = exactXnv1.ToArray();
        ExactXnh1 = exactXnh1.ToArray();
        ExactPmt2 = exactPmt2.ToArray();
        CurrentBootId = currentBootId.ToArray();
        CurrentMonotonicSample = currentMonotonicSample;
        TrustedTimeAuthority = trustedTimeAuthority ?? throw new ArgumentNullException(nameof(trustedTimeAuthority));
    }

    internal VerifiedXPointNetworkAuthority Authority { get; }
    internal VerifiedAccountDirectoryFreshness DirectoryFreshness { get; }
    internal VerifiedOnionNetworkContext Network { get; }
    internal VerifiedContactServicePlacement Placement { get; }
    internal ReadOnlyMemory<byte> ExactXnv1 { get; }
    internal ReadOnlyMemory<byte> ExactXnh1 { get; }
    internal ReadOnlyMemory<byte> ExactPmt2 { get; }
    internal ReadOnlyMemory<byte> CurrentBootId { get; }
    internal ulong CurrentMonotonicSample { get; }
    internal OnionTrustedTimeAuthority TrustedTimeAuthority { get; }
}

public sealed class ContactResolvePathException : CryptographicException
{
    internal ContactResolvePathException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;
    public string Code { get; }
}

internal sealed record ContactResolvePreparedPath(
    PrivacyMailboxOnionAttempt Attempt,
    ContactResolvePathAuthority Authority);

/// <summary>
/// ROUTE-01 initial Contact path selector. It keeps a small protected entry-guard
/// set stable across requests and delegates all key-bearing hop construction to
/// Protocol's non-forgeable path factory.
/// </summary>
public sealed class ContactResolvePrivacyPathProvider : IPrivacyMailboxPathProvider
{
    private const int MaximumCasAttempts = 8;
    private readonly IContactResolvePathAuthoritySource authoritySource;
    private readonly IProtectedEntryGuardStore guardStore;
    private readonly Func<byte[]> newSalt;

    public ContactResolvePrivacyPathProvider(
        IContactResolvePathAuthoritySource authoritySource,
        IProtectedEntryGuardStore guardStore)
        : this(authoritySource, guardStore, CreateSalt) { }

    internal ContactResolvePrivacyPathProvider(
        IContactResolvePathAuthoritySource authoritySource,
        IProtectedEntryGuardStore guardStore,
        Func<byte[]> newSalt)
    {
        this.authoritySource = authoritySource ?? throw new ArgumentNullException(nameof(authoritySource));
        this.guardStore = guardStore ?? throw new ArgumentNullException(nameof(guardStore));
        this.newSalt = newSalt ?? throw new ArgumentNullException(nameof(newSalt));
    }

    public async ValueTask<PrivacyMailboxOnionAttempt> PrepareAsync(
        OnionOperation operation,
        ReadOnlyMemory<byte> exactCanonicalRequest,
        CancellationToken cancellationToken) =>
        (await PrepareExactAsync(
            operation,
            ContactResolveCanonicalPathRequest.Decode(exactCanonicalRequest.Span),
            ReadOnlyMemory<byte>.Empty,
            cancellationToken).ConfigureAwait(false)).Attempt;

    internal async ValueTask<ContactResolvePreparedPath> PrepareExactAsync(
        OnionOperation operation,
        ContactResolveCanonicalPathRequest request,
        ReadOnlyMemory<byte> requiredExitReplicaId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (operation != OnionOperation.ContactResolve)
            throw Fail("operation-invalid", "This path provider accepts only ContactResolve.");
        ArgumentNullException.ThrowIfNull(request);

        var authority = await authoritySource.GetCurrentAsync(request, cancellationToken).ConfigureAwait(false)
            ?? throw Fail("authority-unavailable", "The Contact path authority returned no current capabilities.");
        var network = authority.Network;
        var placement = authority.Placement;
        network.EnsureCurrent();
        if (!ReferenceEquals(network, placement.Network))
            throw Fail("placement-context-mismatch", "Contact placement belongs to another verified network context.");
        if (!Fixed(request.NetworkId.Span, network.NetworkId.Span) ||
            !Fixed(request.ViewHash.Span, placement.ViewHash.Span) ||
            !Fixed(request.PlacementHash.Span, placement.PlacementHash.Span) ||
            !placement.Binds(request.RequestKind, request.ShardKey) ||
            request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds)
            throw Fail("placement-request-mismatch",
                "The canonical ContactResolve request does not bind its exact current NETCODEC placement.");

        VerifiedCanonicalOnionRequest verifiedRequest;
        try
        {
            verifiedRequest = OnionTerminalPayloadVerifierV1.VerifyRequest(
                network, OnionOperation.ContactResolve, request.ExactRequest);
        }
        catch (Exception exception) when (exception is OnionBoundaryException or CryptographicException or ArgumentException)
        {
            throw Fail("onion-request-invalid",
                "The ContactResolve request could not be promoted to a verified canonical ONION request.", exception);
        }

        var candidates = OnionPathCandidateSnapshotFactory.Create(network);
        if (!Fixed(candidates.NetworkId.Span, request.NetworkId.Span) ||
            candidates.ViewGeneration != placement.Network.ProtectedLkg?.ViewGeneration ||
            !Fixed(candidates.ViewHash.Span, placement.ViewHash.Span))
            throw Fail("candidate-view-mismatch", "Candidate facts do not bind the exact placement view.");

        for (var attempt = 0; attempt < MaximumCasAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await guardStore.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (current is not null && !Fixed(current.NetworkId.Span, candidates.NetworkId.Span))
                throw Fail("guard-network-mismatch", "Protected entry guards belong to another network.");

            var next = Reconcile(current, candidates);
            var selected = TrySelectPath(
                network, placement, candidates, next, requiredExitReplicaId.Span);
            if (selected is null)
                throw Fail("path-diversity-insufficient", "The verified view cannot form one exact-three diverse Contact path.");

            var changed = current is null || !SameState(current, next);
            if (changed)
            {
                var write = await guardStore.CompareExchangeAsync(
                    current?.Revision, next, cancellationToken).ConfigureAwait(false);
                if (write.Disposition == EntryGuardStoreWriteDisposition.Conflict) continue;
            }
            return new ContactResolvePreparedPath(
                new PrivacyMailboxOnionAttempt(selected, verifiedRequest),
                authority);
        }
        throw new IOException("Protected entry-guard state remained contended.");
    }

    private EntryGuardState Reconcile(
        EntryGuardState? current,
        VerifiedOnionPathCandidateSnapshot snapshot)
    {
        var sameView = current is not null &&
            current.ViewGeneration == snapshot.ViewGeneration &&
            Fixed(current.ViewHash.Span, snapshot.ViewHash.Span);
        var eligible = snapshot.Candidates
            .Where(static candidate => HasRole(candidate, 0) &&
                candidate.EntryCapacityClass != OnionCandidateCapacityClass.None)
            .ToArray();
        if (sameView)
        {
            if (!current!.ConfirmedGuardNodeIds.All(id => eligible.Any(candidate => Fixed(candidate.NodeId.Span, id.Span))))
                throw Fail("guard-view-corrupt", "A same-view protected guard is absent from verified candidates.");
            return current;
        }

        byte[] salt;
        if (current is null)
        {
            salt = newSalt();
            if (salt.Length != 32 || salt.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                throw Fail("guard-salt-invalid", "The client-local CSPRNG did not return a nonzero 32-byte salt.");
        }
        else salt = current.LocalSalt.ToArray();

        var ordered = eligible
            .Select(candidate => (Candidate: candidate, Score: Score(salt, candidate.NodeId.Span)))
            .OrderBy(static item => item.Score, ByteMemoryComparer.Instance)
            .ThenBy(static item => item.Candidate.NodeId, ByteMemoryComparer.Instance)
            .Select(static item => item.Candidate)
            .ToList();
        var retainedPrimary = current is null ? null : ordered.FirstOrDefault(candidate => Fixed(candidate.NodeId.Span, current.PrimaryNodeId.Span));
        var guards = new List<VerifiedOnionPathCandidate>(3);
        if (retainedPrimary is not null) guards.Add(retainedPrimary);
        foreach (var candidate in ordered)
        {
            if (guards.Count == 3) break;
            if (guards.Any(existing => Fixed(existing.NodeId.Span, candidate.NodeId.Span))) continue;
            if (guards.All(existing => Diverse(existing, candidate))) guards.Add(candidate);
        }
        if (guards.Count == 0)
            throw Fail("entry-guard-unavailable", "The verified view has no eligible entry guard.");
        var primary = retainedPrimary ?? guards[0];
        return new EntryGuardState(
            current is null ? 1UL : checked(current.Revision + 1),
            snapshot.NetworkId.Span, snapshot.ViewGeneration, snapshot.ViewHash.Span,
            salt, primary.NodeId.Span, guards.Select(static guard => guard.NodeId));
    }

    private static VerifiedOnionPathContext? TrySelectPath(
        VerifiedOnionNetworkContext network,
        VerifiedContactServicePlacement placement,
        VerifiedOnionPathCandidateSnapshot snapshot,
        EntryGuardState guards,
        ReadOnlySpan<byte> requiredExitReplicaId)
    {
        var all = snapshot.Candidates;
        var guardOrder = guards.ConfirmedGuardNodeIds
            .OrderBy(id => Fixed(id.Span, guards.PrimaryNodeId.Span) ? 0 : 1)
            .ToArray();
        foreach (var exitId in placement.RankedReplicaNodeIds)
        {
            if (!requiredExitReplicaId.IsEmpty && !Fixed(exitId.Span, requiredExitReplicaId))
                continue;
            var exit = all.FirstOrDefault(candidate => Fixed(candidate.NodeId.Span, exitId.Span));
            if (exit is null || !HasRole(exit, 2) ||
                exit.MailboxCapacityClass == OnionCandidateCapacityClass.None) continue;
            foreach (var guardId in guardOrder)
            {
                var guard = all.FirstOrDefault(candidate => Fixed(candidate.NodeId.Span, guardId.Span));
                if (guard is null || !HasRole(guard, 0) || !Diverse(guard, exit)) continue;
                foreach (var middle in all.Where(static candidate => HasRole(candidate, 1) &&
                             candidate.RelayCapacityClass != OnionCandidateCapacityClass.None))
                {
                    if (!Diverse(guard, middle) || !Diverse(middle, exit) || !Diverse(guard, exit)) continue;
                    try
                    {
                        return OnionPathContextFactory.CreateContactResolver(
                            network, placement, guard.NodeId, middle.NodeId, exit.NodeId);
                    }
                    catch (OnionBoundaryException exception) when (
                        exception.Code.StartsWith("path-", StringComparison.Ordinal))
                    {
                        // Try another verified permutation; Protocol remains the key-diversity authority.
                    }
                }
            }
        }
        return null;
    }

    private static bool HasRole(VerifiedOnionPathCandidate candidate, int bit) =>
        (candidate.VerifiedRoleMask & (1 << bit)) != 0;

    private static bool Diverse(VerifiedOnionPathCandidate left, VerifiedOnionPathCandidate right) =>
        !Fixed(left.NodeId.Span, right.NodeId.Span) &&
        !Fixed(left.RouterOwnerId.Span, right.RouterOwnerId.Span) &&
        !Fixed(left.PhysicalHostId.Span, right.PhysicalHostId.Span) &&
        !Fixed(left.FailureDomainId.Span, right.FailureDomainId.Span) &&
        !Fixed(left.OriginId.Span, right.OriginId.Span);

    private static byte[] Score(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> nodeId)
    {
        var input = new byte[28 + salt.Length + nodeId.Length];
        "Deep/Route01/entry-guard/v1"u8.CopyTo(input);
        salt.CopyTo(input.AsSpan(28));
        nodeId.CopyTo(input.AsSpan(28 + salt.Length));
        try { return SHA256.HashData(input); }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private static byte[] CreateSalt()
    {
        var salt = new byte[32];
        do RandomNumberGenerator.Fill(salt);
        while (salt.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return salt;
    }

    private static bool SameState(EntryGuardState left, EntryGuardState right)
    {
        var a = EntryGuardStateCodec.Encode(left);
        var b = EntryGuardStateCodec.Encode(right);
        try { return Fixed(a, b); }
        finally { CryptographicOperations.ZeroMemory(a); CryptographicOperations.ZeroMemory(b); }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static ContactResolvePathException Fail(string code, string message, Exception? inner = null) => new(code, message, inner);

    private sealed class ByteMemoryComparer : IComparer<byte[]>, IComparer<ReadOnlyMemory<byte>>
    {
        internal static readonly ByteMemoryComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
        public int Compare(ReadOnlyMemory<byte> left, ReadOnlyMemory<byte> right) => left.Span.SequenceCompareTo(right.Span);
    }
}
