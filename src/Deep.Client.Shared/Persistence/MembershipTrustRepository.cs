using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Persistence;

internal static class MembershipTrustRepositoryValidation
{
    public static void ValidateKey(string opaqueProfileKey, MembershipTrustDomain domain)
    {
        ValidateProfileKey(opaqueProfileKey);
        if (!Enum.IsDefined(domain))
        {
            throw new ArgumentOutOfRangeException(nameof(domain));
        }
    }

    public static void ValidateProfileKey(string opaqueProfileKey)
    {
        if (string.IsNullOrWhiteSpace(opaqueProfileKey) ||
            opaqueProfileKey.Length > MembershipTrustRecord.MaximumProfileKeyLength)
        {
            throw new ArgumentException("Membership trust profile is invalid.", nameof(opaqueProfileKey));
        }
    }

    public static bool IsValid(MembershipTrustRecord? record)
    {
        try
        {
            MembershipTrustRecord.Validate(record!);
            return true;
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidDataException or OverflowException)
        {
            return false;
        }
    }

    public static MembershipTrustReadSnapshot Corrupt() =>
        new(MembershipTrustReadResult.Corrupt, null, null);

    public static MembershipTrustReadSnapshot Missing() =>
        new(MembershipTrustReadResult.Missing, null, null);

    public static bool HasValidLinkage(
        MembershipTrustRecord head,
        MembershipTrustRecord? predecessor)
    {
        if (head.Revision == 1)
        {
            return predecessor is null;
        }
        if (predecessor is null ||
            predecessor.OpaqueProfileKey != head.OpaqueProfileKey ||
            predecessor.Domain != head.Domain ||
            predecessor.Revision + 1 != head.Revision)
        {
            return false;
        }

        return head.State == MembershipTrustState.ForkDetected
            ? head.Sequence == predecessor.Sequence &&
              head.PreviousSequence == predecessor.PreviousSequence &&
              head.PreviousCanonicalHash.AsSpan().SequenceEqual(predecessor.PreviousCanonicalHash)
            : head.PreviousSequence == predecessor.Sequence &&
              head.PreviousCanonicalHash.AsSpan().SequenceEqual(predecessor.CanonicalHash);
    }

    public static bool Same(MembershipTrustRecord left, MembershipTrustRecord right) =>
        left.Version == right.Version &&
        string.Equals(left.OpaqueProfileKey, right.OpaqueProfileKey, StringComparison.Ordinal) &&
        left.Domain == right.Domain &&
        left.ArtifactKind == right.ArtifactKind &&
        left.Revision == right.Revision &&
        left.Sequence == right.Sequence &&
        left.PreviousSequence == right.PreviousSequence &&
        left.PreviousCanonicalHash.AsSpan().SequenceEqual(right.PreviousCanonicalHash) &&
        left.CanonicalEnvelope.AsSpan().SequenceEqual(right.CanonicalEnvelope) &&
        left.PayloadDigest.AsSpan().SequenceEqual(right.PayloadDigest) &&
        left.CanonicalHash.AsSpan().SequenceEqual(right.CanonicalHash) &&
        left.ProfileBindingHash.AsSpan().SequenceEqual(right.ProfileBindingHash) &&
        left.State == right.State &&
        left.ObservedAt == right.ObservedAt &&
        left.ValidFrom == right.ValidFrom &&
        left.ValidUntil == right.ValidUntil;
}
