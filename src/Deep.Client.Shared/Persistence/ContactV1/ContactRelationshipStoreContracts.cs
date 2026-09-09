using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;

namespace Deep.Client.Shared.Persistence.ContactV1;

public enum ContactRelationshipCommitDisposition
{
    Applied = 1,
    Idempotent = 2,
    NotFound = 3,
    StaleRevision = 4,
    Conflict = 5,
    InvalidTransition = 6,
    CapacityExceeded = 7,
}

public sealed record ContactRelationshipCommitResult(
    ContactRelationshipCommitDisposition Disposition,
    ContactRelationshipSnapshot? Relationship,
    ulong? CommittedRevision);

internal enum ContactRelationshipMutationKind
{
    BundleVerified = 1,
    VerifiedTransition = 2,
    LocalBlock = 3,
    LocalDelete = 4,
}

public sealed class ContactRelationshipMutationPlan
{
    private readonly byte[] fingerprint;

    internal ContactRelationshipMutationPlan(
        ContactStoreScope scope,
        ContactMutationId32 operationId,
        DateTimeOffset occurredAt,
        VerifiedContactBundleEvidence evidence,
        ContactVerifiedPeerPackageEvidence recoveryPackage)
    {
        ArgumentNullException.ThrowIfNull(recoveryPackage);
        if (!scope.Equals(recoveryPackage.Scope) ||
            !evidence.RelationshipId.Equals(recoveryPackage.RelationshipId) ||
            !evidence.ConversationId.Equals(recoveryPackage.ConversationId) ||
            !evidence.RemoteAccountId.Equals(recoveryPackage.RemoteAccountId) ||
            evidence.Address.Kind != recoveryPackage.AddressKind ||
            !evidence.Address.NetworkId.Span.SequenceEqual(recoveryPackage.NetworkId.Span) ||
            !evidence.Address.CanonicalBytes.Span.SequenceEqual(recoveryPackage.ExactCanonicalAddress.Span))
            throw new ArgumentException("Verified-peer package differs from verifier evidence.", nameof(recoveryPackage));
        Scope = scope;
        OperationId = ContactMutationId32.FromBytes(operationId.Span);
        OccurredAt = CanonicalTime(occurredAt);
        Kind = ContactRelationshipMutationKind.BundleVerified;
        RelationshipId = ContactRelationshipId32.FromBytes(evidence.RelationshipId.Span);
        BundleEvidence = evidence;
        RecoveryPackage = recoveryPackage.Copy();
        EvidenceHash = ContactEvidenceHash32.FromVerifiedBytes(evidence.EvidenceHash.Span);
        fingerprint = ComputeFingerprint();
    }

    internal ContactRelationshipMutationPlan(
        ContactStoreScope scope,
        ContactMutationId32 operationId,
        DateTimeOffset occurredAt,
        ulong expectedRevision,
        VerifiedContactTransitionEvidence evidence)
    {
        if (expectedRevision == 0) throw new ArgumentOutOfRangeException(nameof(expectedRevision));
        Scope = scope;
        OperationId = ContactMutationId32.FromBytes(operationId.Span);
        OccurredAt = CanonicalTime(occurredAt);
        Kind = ContactRelationshipMutationKind.VerifiedTransition;
        RelationshipId = ContactRelationshipId32.FromBytes(evidence.RelationshipId.Span);
        ExpectedRevision = expectedRevision;
        VerifiedEvidenceKind = evidence.Kind;
        EvidenceHash = ContactEvidenceHash32.FromVerifiedBytes(evidence.EvidenceHash.Span);
        fingerprint = ComputeFingerprint();
    }

    internal ContactRelationshipMutationPlan(
        ContactStoreScope scope,
        ContactMutationId32 operationId,
        DateTimeOffset occurredAt,
        ContactRelationshipId32 relationshipId,
        ulong expectedRevision,
        bool delete)
    {
        if (expectedRevision == 0) throw new ArgumentOutOfRangeException(nameof(expectedRevision));
        Scope = scope;
        OperationId = ContactMutationId32.FromBytes(operationId.Span);
        OccurredAt = CanonicalTime(occurredAt);
        Kind = delete ? ContactRelationshipMutationKind.LocalDelete : ContactRelationshipMutationKind.LocalBlock;
        RelationshipId = ContactRelationshipId32.FromBytes(relationshipId.Span);
        ExpectedRevision = expectedRevision;
        fingerprint = ComputeFingerprint();
    }

    internal ContactStoreScope Scope { get; }
    internal ContactRelationshipMutationKind Kind { get; }
    internal ContactMutationId32 OperationId { get; }
    internal ContactRelationshipId32 RelationshipId { get; }
    internal ulong? ExpectedRevision { get; }
    internal DateTimeOffset OccurredAt { get; }
    internal VerifiedContactBundleEvidence? BundleEvidence { get; }
    internal ContactVerifiedPeerPackageEvidence? RecoveryPackage { get; }
    internal VerifiedContactTransitionKind? VerifiedEvidenceKind { get; }
    internal ContactEvidenceHash32? EvidenceHash { get; }
    internal ReadOnlySpan<byte> Fingerprint => fingerprint;

    private byte[] ComputeFingerprint()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, Scope.AccountId.Bytes.Span);
        Span<byte> scalar = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(scalar, checked((ulong)Scope.StoreGeneration));
        Append(hash, scalar);
        Append(hash, OperationId.Span);
        Append(hash, RelationshipId.Span);
        scalar.Clear();
        BinaryPrimitives.WriteUInt64BigEndian(scalar, ExpectedRevision ?? 0);
        Append(hash, scalar);
        BinaryPrimitives.WriteInt64BigEndian(scalar, OccurredAt.UtcTicks);
        Append(hash, scalar);
        hash.AppendData([(byte)Kind, (byte)(VerifiedEvidenceKind ?? 0)]);
        if (EvidenceHash is not null) Append(hash, EvidenceHash.Span);
        if (BundleEvidence is not null)
        {
            Append(hash, BundleEvidence.RemoteAccountId.Span);
            Append(hash, BundleEvidence.ConversationId.Span);
            hash.AppendData([(byte)BundleEvidence.Address.Kind]);
            Append(hash, BundleEvidence.Address.CanonicalBytes.Span);
            foreach (var value in BundleEvidence.ArtifactHashes.Ordered) Append(hash, value.Span);
            Append(hash, RecoveryPackage!.PackageHash.Span);
        }
        return hash.GetHashAndReset();
    }

    private static DateTimeOffset CanonicalTime(DateTimeOffset value)
    {
        var result = value.ToUniversalTime();
        if (result.Ticks < 0) throw new ArgumentOutOfRangeException(nameof(value));
        return result;
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
    }
}

internal static class ContactRelationshipStateMachine
{
    internal static ContactRelationshipCommitResult Apply(
        ContactRelationshipSnapshot current,
        ContactRelationshipMutationPlan mutation)
    {
        if (mutation.ExpectedRevision != current.Revision)
            return new(ContactRelationshipCommitDisposition.StaleRevision, current.Copy(), null);
        if (current.Revision == ulong.MaxValue || mutation.OccurredAt < current.CreatedAt)
            return new(ContactRelationshipCommitDisposition.InvalidTransition, current.Copy(), null);

        var target = Target(current.State, mutation);
        if (target is null)
            return new(ContactRelationshipCommitDisposition.InvalidTransition, current.Copy(), null);
        var next = current.WithState(target.Value,
            mutation.OccurredAt < current.UpdatedAt ? current.UpdatedAt : mutation.OccurredAt);
        return new(ContactRelationshipCommitDisposition.Applied, next, next.Revision);
    }

    private static ContactRelationshipState? Target(
        ContactRelationshipState current,
        ContactRelationshipMutationPlan mutation)
    {
        if (mutation.Kind == ContactRelationshipMutationKind.LocalBlock)
            return IsNonterminal(current) ? ContactRelationshipState.Blocked : null;
        if (mutation.Kind == ContactRelationshipMutationKind.LocalDelete)
            return IsNonterminal(current) ? ContactRelationshipState.Deleted : null;
        if (mutation.Kind != ContactRelationshipMutationKind.VerifiedTransition)
            return null;

        return (current, mutation.VerifiedEvidenceKind) switch
        {
            (ContactRelationshipState.BundleVerified, VerifiedContactTransitionKind.RequestQueued) => ContactRelationshipState.RequestQueued,
            (ContactRelationshipState.RequestQueued, VerifiedContactTransitionKind.RemoteStoreAccepted) => ContactRelationshipState.RemoteStoreAccepted,
            (ContactRelationshipState.RemoteStoreAccepted, VerifiedContactTransitionKind.RequestMaterialized) => ContactRelationshipState.RequestMaterialized,
            (ContactRelationshipState.RequestMaterialized, VerifiedContactTransitionKind.PeerAccepted) => ContactRelationshipState.PeerAccepted,
            (ContactRelationshipState.PeerAccepted, VerifiedContactTransitionKind.Activated) => ContactRelationshipState.Active,
            (ContactRelationshipState.RequestQueued or ContactRelationshipState.RemoteStoreAccepted or ContactRelationshipState.RequestMaterialized,
                VerifiedContactTransitionKind.Rejected) => ContactRelationshipState.Rejected,
            (ContactRelationshipState.RequestQueued or ContactRelationshipState.RemoteStoreAccepted or ContactRelationshipState.RequestMaterialized,
                VerifiedContactTransitionKind.Expired) => ContactRelationshipState.Expired,
            (ContactRelationshipState.Active, VerifiedContactTransitionKind.IdentityConflict) => ContactRelationshipState.IdentityConflict,
            (ContactRelationshipState.Active, VerifiedContactTransitionKind.DirectoryConflict) => ContactRelationshipState.DirectoryConflict,
            (ContactRelationshipState.Active, VerifiedContactTransitionKind.RouteStale) => ContactRelationshipState.RouteStale,
            (ContactRelationshipState.IdentityConflict or ContactRelationshipState.DirectoryConflict,
                VerifiedContactTransitionKind.ConflictRepaired) => ContactRelationshipState.Active,
            _ => null,
        };
    }

    private static bool IsNonterminal(ContactRelationshipState state) => state is
        ContactRelationshipState.BundleVerified or
        ContactRelationshipState.RequestQueued or
        ContactRelationshipState.RemoteStoreAccepted or
        ContactRelationshipState.RequestMaterialized or
        ContactRelationshipState.PeerAccepted or
        ContactRelationshipState.Active or
        ContactRelationshipState.IdentityConflict or
        ContactRelationshipState.DirectoryConflict or
        ContactRelationshipState.RouteStale;
}
