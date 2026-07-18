using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Persistence;

internal static class MembershipTrustRepositoryValidation
{
    public static void ValidateKey(string opaqueProfileKey, MembershipTrustDomain domain)
    {
        if (string.IsNullOrWhiteSpace(opaqueProfileKey) ||
            opaqueProfileKey.Length > MembershipTrustRecord.MaximumProfileKeyLength)
        {
            throw new ArgumentException("Membership trust profile is invalid.", nameof(opaqueProfileKey));
        }
        if (!Enum.IsDefined(domain))
        {
            throw new ArgumentOutOfRangeException(nameof(domain));
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

    public static bool Same(MembershipTrustRecord left, MembershipTrustRecord right) =>
        left.Version == right.Version &&
        string.Equals(left.OpaqueProfileKey, right.OpaqueProfileKey, StringComparison.Ordinal) &&
        left.Domain == right.Domain &&
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
