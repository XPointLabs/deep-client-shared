using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Services.GroupV1;

public sealed class GroupControlPathException : CryptographicException
{
    internal GroupControlPathException(
        string code,
        string message,
        Exception? innerException = null)
        : base(message, innerException) => Code = code;

    public string Code { get; }
}

internal interface IGroupControlPrivacyPathProvider
{
    ValueTask<PrivacyMailboxOnionAttempt> PrepareAsync(
        VerifiedGroupControlRequest request,
        GroupControlIngressRoute route,
        PrivacyMailboxRouteSelection selection,
        CancellationToken cancellationToken);
}

/// <summary>
/// Selects an exact-three GroupControl path from one current Protocol-minted
/// network capability, an exact GroupControl placement, and protected entry
/// guards. Transport origins carry no authority and must match the selected
/// verified entry-router identity before any network dispatch.
/// </summary>
public sealed class GroupControlPrivacyPathProvider : IGroupControlPrivacyPathProvider
{
    private const int MaximumCasAttempts = 8;
    private readonly VerifiedOnionNetworkContext network;
    private readonly IProtectedEntryGuardStore guardStore;
    private readonly Func<byte[]> newSalt;

    public GroupControlPrivacyPathProvider(
        VerifiedOnionNetworkContext network,
        IProtectedEntryGuardStore guardStore)
        : this(network, guardStore, CreateSalt)
    {
    }

    internal GroupControlPrivacyPathProvider(
        VerifiedOnionNetworkContext network,
        IProtectedEntryGuardStore guardStore,
        Func<byte[]> newSalt)
    {
        this.network = network ?? throw new ArgumentNullException(nameof(network));
        this.guardStore = guardStore ?? throw new ArgumentNullException(nameof(guardStore));
        this.newSalt = newSalt ?? throw new ArgumentNullException(nameof(newSalt));
    }

    async ValueTask<PrivacyMailboxOnionAttempt> IGroupControlPrivacyPathProvider.PrepareAsync(
        VerifiedGroupControlRequest request,
        GroupControlIngressRoute route,
        PrivacyMailboxRouteSelection selection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(route);
        cancellationToken.ThrowIfCancellationRequested();
        if (selection is not PrivacyMailboxRouteSelection.Primary and
            not PrivacyMailboxRouteSelection.Fallback)
        {
            throw Fail("route-selection-invalid", "The GroupControl route selection is invalid.");
        }

        network.EnsureCurrent();
        ValidateRequestBinding(request);

        VerifiedCanonicalOnionRequest verifiedRequest;
        try
        {
            verifiedRequest = OnionTerminalPayloadVerifierV1.VerifyRequest(
                network,
                OnionOperation.GroupControl,
                request.CanonicalBytes);
        }
        catch (Exception exception) when (exception is
            OnionBoundaryException or CryptographicException or
            ArgumentException or InvalidDataException or OverflowException)
        {
            throw Fail(
                "group-control-request-invalid",
                "The exact GroupControl request is not canonical GSW1 or GSQ1.",
                exception);
        }

        var candidates = OnionPathCandidateSnapshotFactory.Create(network);
        if (!Fixed(candidates.NetworkId.Span, request.Record.Field(1).Span) ||
            !Fixed(candidates.ViewHash.Span, request.Placement.ViewHash.Span))
        {
            throw Fail(
                "candidate-view-mismatch",
                "Verified GroupControl candidate facts do not bind the exact placement view.");
        }

        for (var attempt = 0; attempt < MaximumCasAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await guardStore.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (current is not null &&
                !Fixed(current.NetworkId.Span, candidates.NetworkId.Span))
            {
                throw Fail(
                    "guard-network-mismatch",
                    "Protected entry guards belong to another network.");
            }

            var next = Reconcile(current, candidates);
            var selected = TrySelectPath(
                request.Placement,
                candidates,
                next,
                route.EntryRouterId,
                selection);
            if (selected is null)
            {
                throw Fail(
                    "route-binding-unavailable",
                    "The configured ingress is not the required protected GroupControl entry guard or no exact-three path is available.");
            }

            if (current is null || !SameState(current, next))
            {
                var write = await guardStore.CompareExchangeAsync(
                    current?.Revision,
                    next,
                    cancellationToken).ConfigureAwait(false);
                if (write.Disposition == EntryGuardStoreWriteDisposition.Conflict)
                {
                    continue;
                }
            }

            return new PrivacyMailboxOnionAttempt(selected, verifiedRequest);
        }

        throw new IOException("Protected GroupControl entry-guard state remained contended.");
    }

    private void ValidateRequestBinding(VerifiedGroupControlRequest request)
    {
        if (!Fixed(network.NetworkId.Span, request.Record.Field(1).Span) ||
            !Fixed(request.Record.Field(3).Span, request.Placement.ViewHash.Span) ||
            !Fixed(request.Record.Field(4).Span, request.Placement.PlacementHash.Span))
        {
            throw Fail(
                "request-placement-mismatch",
                "The GroupControl request is not bound to this network and exact placement.");
        }

        var expectedMagic = request.Kind switch
        {
            GroupControlRequestKind.Write => "GSW1",
            GroupControlRequestKind.Fetch => "GSQ1",
            _ => throw Fail(
                "request-kind-invalid",
                "The GroupControl request kind is unsupported.")
        };
        if (!string.Equals(request.Record.Magic, expectedMagic, StringComparison.Ordinal) ||
            request.CanonicalBytes.Length is < 1 or > OnionLimits.MaximumGroupControlRequestBytes)
        {
            throw Fail(
                "request-kind-mismatch",
                "The GroupControl capability contains the wrong request record kind or size.");
        }

        try
        {
            var decoded = GroupCodec.Decode(expectedMagic, request.CanonicalBytes.Span);
            if (!Fixed(decoded.CanonicalBytes.Span, request.CanonicalBytes.Span))
            {
                throw new InvalidDataException("GroupControl request round-trip changed bytes.");
            }
        }
        catch (Exception exception) when (exception is
            ArgumentException or InvalidDataException or OverflowException)
        {
            throw Fail(
                "group-control-request-invalid",
                "The GroupControl capability does not contain exact canonical bytes.",
                exception);
        }
    }

    private EntryGuardState Reconcile(
        EntryGuardState? current,
        VerifiedOnionPathCandidateSnapshot snapshot)
    {
        var sameView = current is not null &&
            current.ViewGeneration == snapshot.ViewGeneration &&
            Fixed(current.ViewHash.Span, snapshot.ViewHash.Span);
        var eligible = snapshot.Candidates
            .Where(static candidate =>
                HasRole(candidate, 0) &&
                candidate.EntryCapacityClass != OnionCandidateCapacityClass.None)
            .ToArray();
        if (sameView)
        {
            if (!current!.ConfirmedGuardNodeIds.All(id =>
                    eligible.Any(candidate => Fixed(candidate.NodeId.Span, id.Span))))
            {
                throw Fail(
                    "guard-view-corrupt",
                    "A same-view protected GroupControl guard is absent from verified candidates.");
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
                    "guard-salt-invalid",
                    "The client-local CSPRNG did not return a nonzero 32-byte guard salt.");
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
            : ordered.FirstOrDefault(candidate =>
                Fixed(candidate.NodeId.Span, current.PrimaryNodeId.Span));
        var guards = new List<VerifiedOnionPathCandidate>(3);
        if (retainedPrimary is not null)
        {
            guards.Add(retainedPrimary);
        }

        foreach (var candidate in ordered)
        {
            if (guards.Count == 3)
            {
                break;
            }

            if (guards.Any(existing => Fixed(existing.NodeId.Span, candidate.NodeId.Span)) ||
                guards.Any(existing => !Diverse(existing, candidate)))
            {
                continue;
            }

            guards.Add(candidate);
        }

        if (guards.Count == 0)
        {
            throw Fail(
                "entry-guard-unavailable",
                "The verified view has no eligible GroupControl entry guard.");
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

    private VerifiedOnionPathContext? TrySelectPath(
        VerifiedGroupControlPlacement placement,
        VerifiedOnionPathCandidateSnapshot snapshot,
        EntryGuardState guards,
        ReadOnlyMemory<byte> requiredEntryRouterId,
        PrivacyMailboxRouteSelection selection)
    {
        var all = snapshot.Candidates;
        var allowedGuardIds = selection == PrivacyMailboxRouteSelection.Primary
            ? guards.ConfirmedGuardNodeIds.Where(id => Fixed(id.Span, guards.PrimaryNodeId.Span))
            : guards.ConfirmedGuardNodeIds.Where(id => !Fixed(id.Span, guards.PrimaryNodeId.Span));
        foreach (var guardId in allowedGuardIds)
        {
            var guard = all.FirstOrDefault(candidate => Fixed(candidate.NodeId.Span, guardId.Span));
            if (guard is null ||
                !Fixed(guard.NodeId.Span, requiredEntryRouterId.Span) ||
                !HasRole(guard, 0) ||
                guard.EntryCapacityClass == OnionCandidateCapacityClass.None)
            {
                continue;
            }

            foreach (var exitId in placement.ReplicaNodeIds)
            {
                var exit = all.FirstOrDefault(candidate => Fixed(candidate.NodeId.Span, exitId.Span));
                if (exit is null ||
                    !HasRole(exit, 2) ||
                    exit.MailboxCapacityClass == OnionCandidateCapacityClass.None ||
                    !Diverse(guard, exit))
                {
                    continue;
                }

                foreach (var middle in all.Where(static candidate =>
                             HasRole(candidate, 1) &&
                             candidate.RelayCapacityClass != OnionCandidateCapacityClass.None))
                {
                    if (!Diverse(guard, middle) ||
                        !Diverse(middle, exit) ||
                        !Diverse(guard, exit))
                    {
                        continue;
                    }

                    try
                    {
                        return OnionPathContextFactory.CreateGroupControl(
                            network,
                            placement,
                            guard.NodeId,
                            middle.NodeId,
                            exit.NodeId);
                    }
                    catch (OnionBoundaryException exception) when (
                        exception.Code.StartsWith("path-", StringComparison.Ordinal))
                    {
                        // Protocol remains the final authority for hidden key,
                        // host, failure-domain, and origin diversity.
                    }
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
        var leftBytes = EntryGuardStateCodec.Encode(left);
        var rightBytes = EntryGuardStateCodec.Encode(right);
        try
        {
            return Fixed(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static GroupControlPathException Fail(
        string code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);

    private sealed class ByteMemoryComparer :
        IComparer<byte[]>,
        IComparer<ReadOnlyMemory<byte>>
    {
        internal static readonly ByteMemoryComparer Instance = new();

        public int Compare(byte[]? left, byte[]? right) =>
            left.AsSpan().SequenceCompareTo(right);

        public int Compare(ReadOnlyMemory<byte> left, ReadOnlyMemory<byte> right) =>
            left.Span.SequenceCompareTo(right.Span);
    }
}
