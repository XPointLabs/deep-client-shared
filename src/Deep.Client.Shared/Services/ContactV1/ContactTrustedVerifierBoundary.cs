using Deep.Client.Shared.Domain.ContactV1;

namespace Deep.Client.Shared.Services.ContactV1;

/// <summary>
/// The only constructor boundary for authenticated contact evidence. Callers
/// outside the shared runtime can consume capabilities but cannot mint them.
/// No wire decoding or transport acceptance is performed here.
/// </summary>
internal static class ContactTrustedVerifierBoundary
{
    internal static VerifiedContactBundleEvidence BundleVerified(
        ContactStoreScope scope,
        ImportedContactAddress address,
        ReadOnlySpan<byte> remoteAccountId32,
        ContactRelationshipId32 relationshipId,
        IReadOnlyDictionary<ContactVerifiedArtifactKind, ReadOnlyMemory<byte>> exactArtifactHashes,
        ReadOnlySpan<byte> evidenceHash32)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(relationshipId);
        if (!scope.AccountId.Matches(remoteAccountId32))
        {
            var remote = ContactAccountId32.FromVerifiedBytes(remoteAccountId32);
            var conversation = ContactConversationId32.Derive(address.NetworkId.Span, relationshipId,
                scope.AccountId.Bytes.Span, remoteAccountId32);
            return new(scope, address, remote, relationshipId, conversation,
                new ContactVerifiedArtifactHashes(exactArtifactHashes),
                ContactEvidenceHash32.FromVerifiedBytes(evidenceHash32));
        }
        throw new ArgumentException("A contact relationship cannot target the local account.", nameof(remoteAccountId32));
    }

    internal static VerifiedContactTransitionEvidence TransitionVerified(
        ContactStoreScope scope,
        ContactRelationshipId32 relationshipId,
        VerifiedContactTransitionKind kind,
        ReadOnlySpan<byte> evidenceHash32) =>
        new(scope, relationshipId, kind, ContactEvidenceHash32.FromVerifiedBytes(evidenceHash32));
}
