using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.XPointNetworkV1;

internal interface IMailboxPrivacyNetworkAuthoritySource
{
    ValueTask<VerifiedOnionNetworkContext> GetCurrentForMailboxAsync(
        ReadOnlyMemory<byte> placementCommitment,
        CancellationToken cancellationToken);
}

/// <summary>
/// Selects one exact three-hop mailbox path from the current NETCODEC authority.
/// The terminal node is pinned to one of the two replicas carried by the exact
/// scoped credential route resolved immediately before dispatch.
/// </summary>
public sealed class MailboxPrivacyPathProvider :
    IPrivacyMailboxPathProvider,
    IRouteBoundPrivacyMailboxPathProvider
{
    private const int MaximumCasAttempts = 8;
    private readonly IMailboxPrivacyNetworkAuthoritySource authoritySource;
    private readonly IProtectedEntryGuardStore guardStore;
    private readonly PrivacyMailboxRouteSelection routeSelection;
    private readonly Func<byte[]> newSalt;

    public MailboxPrivacyPathProvider(
        ProductionContactResolvePathAuthoritySource authoritySource,
        IProtectedEntryGuardStore guardStore,
        PrivacyMailboxRouteSelection routeSelection)
        : this(authoritySource, guardStore, routeSelection, CreateSalt)
    {
    }

    internal MailboxPrivacyPathProvider(
        IMailboxPrivacyNetworkAuthoritySource authoritySource,
        IProtectedEntryGuardStore guardStore,
        PrivacyMailboxRouteSelection routeSelection,
        Func<byte[]> newSalt)
    {
        this.authoritySource = authoritySource ?? throw new ArgumentNullException(nameof(authoritySource));
        this.guardStore = guardStore ?? throw new ArgumentNullException(nameof(guardStore));
        if (!Enum.IsDefined(routeSelection))
            throw new ArgumentOutOfRangeException(nameof(routeSelection));
        this.routeSelection = routeSelection;
        this.newSalt = newSalt ?? throw new ArgumentNullException(nameof(newSalt));
    }

    public ValueTask<PrivacyMailboxOnionAttempt> PrepareAsync(
        OnionOperation operation,
        ReadOnlyMemory<byte> exactCanonicalRequest,
        CancellationToken cancellationToken) =>
        ValueTask.FromException<PrivacyMailboxOnionAttempt>(Fail(
            ClientMailboxTransportFailure.ProtocolViolation,
            retryable: false,
            "Mailbox path selection requires an exact verified scoped credential route."));

    public async ValueTask<PrivacyMailboxOnionAttempt> PrepareOnRouteAsync(
        OnionOperation operation,
        ReadOnlyMemory<byte> exactCanonicalRequest,
        ScopedMailboxResolvedRoute route,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(route);
        if (operation is not (
                OnionOperation.Store or
                OnionOperation.Retrieve or
                OnionOperation.Acknowledge))
        {
            throw Fail(
                ClientMailboxTransportFailure.ProtocolViolation,
                retryable: false,
                "Mailbox path selection accepts only Store, Retrieve, or Acknowledge.");
        }

        var expectedPlacementCommitment = MailboxPlacementCommitment.Compute(route.PlacementId);
        try
        {
            if (!Fixed(expectedPlacementCommitment, route.PlacementCommitment.Span))
            {
                throw Fail(
                    ClientMailboxTransportFailure.ProtocolViolation,
                    retryable: false,
                    "The resolved mailbox route has a mismatched placement commitment.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedPlacementCommitment);
        }

        var network = await authoritySource.GetCurrentForMailboxAsync(
                route.PlacementCommitment,
                cancellationToken)
            .ConfigureAwait(false);
        network.EnsureCurrent();

        VerifiedCanonicalOnionRequest verifiedRequest;
        try
        {
            verifiedRequest = OnionTerminalPayloadVerifierV1.VerifyRequest(
                network,
                operation,
                exactCanonicalRequest);
        }
        catch (Exception exception) when (exception is
            OnionBoundaryException or CryptographicException or ArgumentException)
        {
            throw Fail(
                ClientMailboxTransportFailure.MalformedRequest,
                retryable: false,
                "The exact MAU2 request could not be promoted to a verified mailbox onion request.",
                exception);
        }

        var candidates = OnionPathCandidateSnapshotFactory.Create(network);
        var requiredExit = routeSelection == PrivacyMailboxRouteSelection.Primary
            ? route.Replicas.FirstId
            : route.Replicas.SecondId;
        for (var attempt = 0; attempt < MaximumCasAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await guardStore.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (current is not null && !Fixed(current.NetworkId.Span, candidates.NetworkId.Span))
            {
                throw Fail(
                    ClientMailboxTransportFailure.ProtocolViolation,
                    retryable: false,
                    "Protected entry guards belong to another network.");
            }

            var next = Reconcile(current, candidates);
            var selected = TrySelectPath(
                network,
                operation,
                route.Replicas,
                candidates,
                next,
                requiredExit.Span);
            if (selected is null)
            {
                throw Fail(
                    ClientMailboxTransportFailure.DependencyUnavailable,
                    retryable: true,
                    "The verified view cannot form one exact-three diverse path to the selected mailbox replica.");
            }

            if (current is null || !SameState(current, next))
            {
                var write = await guardStore.CompareExchangeAsync(
                    current?.Revision,
                    next,
                    cancellationToken).ConfigureAwait(false);
                if (write.Disposition == EntryGuardStoreWriteDisposition.Conflict)
                    continue;
            }

            return new PrivacyMailboxOnionAttempt(selected, verifiedRequest);
        }

        throw new IOException("Protected mailbox entry-guard state remained contended.");
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
            if (!current!.ConfirmedGuardNodeIds.All(id =>
                    eligible.Any(candidate => Fixed(candidate.NodeId.Span, id.Span))))
            {
                throw Fail(
                    ClientMailboxTransportFailure.ProtocolViolation,
                    retryable: false,
                    "A same-view protected entry guard is absent from verified candidates.");
            }
            return current;
        }

        byte[] salt;
        if (current is null)
        {
            salt = newSalt();
            if (salt.Length != 32 || salt.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            {
                throw Fail(
                    ClientMailboxTransportFailure.ProtocolViolation,
                    retryable: false,
                    "The client-local CSPRNG did not return a non-zero 32-byte guard salt.");
            }
        }
        else
        {
            salt = current.LocalSalt.ToArray();
        }

        var ordered = eligible
            .Select(candidate => (Candidate: candidate, Score: Score(salt, candidate.NodeId.Span)))
            .OrderBy(static item => item.Score, ByteMemoryComparer.Instance)
            .ThenBy(static item => item.Candidate.NodeId, ByteMemoryComparer.Instance)
            .Select(static item => item.Candidate)
            .ToList();
        var retainedPrimary = current is null
            ? null
            : ordered.FirstOrDefault(candidate => Fixed(
                candidate.NodeId.Span,
                current.PrimaryNodeId.Span));
        var guards = new List<VerifiedOnionPathCandidate>(3);
        if (retainedPrimary is not null)
            guards.Add(retainedPrimary);
        foreach (var candidate in ordered)
        {
            if (guards.Count == 3)
                break;
            if (guards.Any(existing => Fixed(existing.NodeId.Span, candidate.NodeId.Span)))
                continue;
            if (guards.All(existing => Diverse(existing, candidate)))
                guards.Add(candidate);
        }
        if (guards.Count == 0)
        {
            throw Fail(
                ClientMailboxTransportFailure.DependencyUnavailable,
                retryable: true,
                "The verified view has no eligible mailbox entry guard.");
        }

        var primary = retainedPrimary ?? guards[0];
        return new EntryGuardState(
            current is null ? 1UL : checked(current.Revision + 1),
            snapshot.NetworkId.Span,
            snapshot.ViewGeneration,
            snapshot.ViewHash.Span,
            salt,
            primary.NodeId.Span,
            guards.Select(static guard => guard.NodeId));
    }

    private static VerifiedOnionPathContext? TrySelectPath(
        VerifiedOnionNetworkContext network,
        OnionOperation operation,
        MailboxCredentialReplicaPair replicas,
        VerifiedOnionPathCandidateSnapshot snapshot,
        EntryGuardState guards,
        ReadOnlySpan<byte> requiredExitReplicaId)
    {
        var all = snapshot.Candidates;
        var requiredExit = requiredExitReplicaId.ToArray();
        var exit = all.FirstOrDefault(candidate =>
            Fixed(candidate.NodeId.Span, requiredExit));
        if (exit is null || !HasRole(exit, 2) ||
            exit.MailboxCapacityClass == OnionCandidateCapacityClass.None)
            return null;

        var guardOrder = guards.ConfirmedGuardNodeIds
            .OrderBy(id => Fixed(id.Span, guards.PrimaryNodeId.Span) ? 0 : 1)
            .ToArray();
        foreach (var guardId in guardOrder)
        {
            var guard = all.FirstOrDefault(candidate => Fixed(candidate.NodeId.Span, guardId.Span));
            if (guard is null || !HasRole(guard, 0) || !Diverse(guard, exit))
                continue;
            foreach (var middle in all.Where(static candidate =>
                         HasRole(candidate, 1) &&
                         candidate.RelayCapacityClass != OnionCandidateCapacityClass.None))
            {
                if (!Diverse(guard, middle) || !Diverse(middle, exit) || !Diverse(guard, exit))
                    continue;
                try
                {
                    return OnionPathContextFactory.CreateMailbox(
                        network,
                        operation,
                        replicas.FirstId,
                        replicas.SecondId,
                        guard.NodeId,
                        middle.NodeId,
                        exit.NodeId);
                }
                catch (OnionBoundaryException exception) when (
                    exception.Code.StartsWith("path-", StringComparison.Ordinal) ||
                    exception.Code.StartsWith("mailbox-replica-", StringComparison.Ordinal))
                {
                    // Try another verified permutation; Protocol remains the key-diversity authority.
                }
            }
        }
        return null;
    }

    private static bool HasRole(VerifiedOnionPathCandidate candidate, int bit) =>
        (candidate.VerifiedRoleMask & (1 << bit)) != 0;

    private static bool Diverse(
        VerifiedOnionPathCandidate left,
        VerifiedOnionPathCandidate right) =>
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
        try
        {
            return SHA256.HashData(input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static byte[] CreateSalt()
    {
        var salt = new byte[32];
        do
        {
            RandomNumberGenerator.Fill(salt);
        }
        while (salt.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return salt;
    }

    private static bool SameState(EntryGuardState left, EntryGuardState right)
    {
        var first = EntryGuardStateCodec.Encode(left);
        var second = EntryGuardStateCodec.Encode(right);
        try
        {
            return Fixed(first, second);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static ClientMailboxTransportException Fail(
        ClientMailboxTransportFailure failure,
        bool retryable,
        string message,
        Exception? inner = null) =>
        new(failure, retryable, message, inner);

    private sealed class ByteMemoryComparer : IComparer<byte[]>, IComparer<ReadOnlyMemory<byte>>
    {
        internal static readonly ByteMemoryComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) =>
            left.AsSpan().SequenceCompareTo(right);
        public int Compare(ReadOnlyMemory<byte> left, ReadOnlyMemory<byte> right) =>
            left.Span.SequenceCompareTo(right.Span);
    }
}
