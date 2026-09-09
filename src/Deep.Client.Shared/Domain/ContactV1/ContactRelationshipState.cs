using System.Security.Cryptography;

namespace Deep.Client.Shared.Domain.ContactV1;

public sealed class ContactAccountId32 : ContactIdentifier32
{
    private ContactAccountId32(ReadOnlySpan<byte> value) : base(value, "contact-account-id") { }
    internal static ContactAccountId32 FromVerifiedBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class ContactArtifactHash32 : ContactIdentifier32
{
    private ContactArtifactHash32(ReadOnlySpan<byte> value) : base(value, "contact-artifact-hash") { }
    internal static ContactArtifactHash32 FromVerifiedBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class ContactEvidenceHash32 : ContactIdentifier32
{
    private ContactEvidenceHash32(ReadOnlySpan<byte> value) : base(value, "contact-evidence-hash") { }
    internal static ContactEvidenceHash32 FromVerifiedBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class ContactMutationId32 : ContactIdentifier32
{
    private ContactMutationId32(ReadOnlySpan<byte> value) : base(value, "contact-mutation-id") { }
    public static ContactMutationId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public enum ContactVerifiedArtifactKind
{
    Did1 = 1,
    Dab1 = 2,
    Dpa1 = 3,
    Drs1 = 4,
    Dmd1 = 5,
    Dca1 = 6,
    Dcb1 = 7,
    Dcr1 = 8,
    Adh1 = 9,
    Adp1 = 10,
    ReachabilityDescriptor = 11,
}

public sealed class ContactVerifiedArtifactHashes
{
    private static readonly ContactVerifiedArtifactKind[] RequiredKinds =
        Enum.GetValues<ContactVerifiedArtifactKind>();
    private readonly ContactArtifactHash32[] hashes;

    internal ContactVerifiedArtifactHashes(IReadOnlyDictionary<ContactVerifiedArtifactKind, ReadOnlyMemory<byte>> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count != RequiredKinds.Length || RequiredKinds.Any(kind => !values.ContainsKey(kind)))
            throw new ArgumentException("The verified contact bundle closure must contain every exact V1 artifact hash once.", nameof(values));
        hashes = RequiredKinds.Select(kind => ContactArtifactHash32.FromVerifiedBytes(values[kind].Span)).ToArray();
    }

    internal ContactVerifiedArtifactHashes(IEnumerable<ContactArtifactHash32> orderedHashes)
    {
        hashes = orderedHashes.Select(static value => ContactArtifactHash32.FromVerifiedBytes(value.Span)).ToArray();
        if (hashes.Length != RequiredKinds.Length)
            throw new ArgumentException("The persisted contact bundle closure is incomplete.", nameof(orderedHashes));
    }

    public ContactArtifactHash32 this[ContactVerifiedArtifactKind kind]
    {
        get
        {
            if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
            return ContactArtifactHash32.FromVerifiedBytes(hashes[(int)kind - 1].Span);
        }
    }

    internal IEnumerable<ContactArtifactHash32> Ordered => hashes.Select(static value =>
        ContactArtifactHash32.FromVerifiedBytes(value.Span));
}

public enum VerifiedContactTransitionKind
{
    RequestQueued = 1,
    RemoteStoreAccepted = 2,
    RequestMaterialized = 3,
    PeerAccepted = 4,
    Activated = 5,
    Rejected = 6,
    Expired = 7,
    IdentityConflict = 8,
    DirectoryConflict = 9,
    RouteStale = 10,
    ConflictRepaired = 11,
}

public sealed class VerifiedContactBundleEvidence
{
    internal VerifiedContactBundleEvidence(
        ContactStoreScope scope,
        ImportedContactAddress address,
        ContactAccountId32 remoteAccountId,
        ContactRelationshipId32 relationshipId,
        ContactConversationId32 conversationId,
        ContactVerifiedArtifactHashes artifactHashes,
        ContactEvidenceHash32 evidenceHash)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        Address = address ?? throw new ArgumentNullException(nameof(address));
        RemoteAccountId = ContactAccountId32.FromVerifiedBytes(remoteAccountId.Span);
        RelationshipId = ContactRelationshipId32.FromBytes(relationshipId.Span);
        ConversationId = ContactConversationId32.FromBytes(conversationId.Span);
        ArtifactHashes = new ContactVerifiedArtifactHashes(artifactHashes.Ordered);
        EvidenceHash = ContactEvidenceHash32.FromVerifiedBytes(evidenceHash.Span);
    }

    public ContactStoreScope Scope { get; }
    public ImportedContactAddress Address { get; }
    public ContactAccountId32 RemoteAccountId { get; }
    public ContactRelationshipId32 RelationshipId { get; }
    public ContactConversationId32 ConversationId { get; }
    public ContactVerifiedArtifactHashes ArtifactHashes { get; }
    public ContactEvidenceHash32 EvidenceHash { get; }
}

public sealed class VerifiedContactTransitionEvidence
{
    internal VerifiedContactTransitionEvidence(
        ContactStoreScope scope,
        ContactRelationshipId32 relationshipId,
        VerifiedContactTransitionKind kind,
        ContactEvidenceHash32 evidenceHash)
    {
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        RelationshipId = ContactRelationshipId32.FromBytes(relationshipId.Span);
        Kind = kind;
        EvidenceHash = ContactEvidenceHash32.FromVerifiedBytes(evidenceHash.Span);
    }

    public ContactStoreScope Scope { get; }
    public ContactRelationshipId32 RelationshipId { get; }
    public VerifiedContactTransitionKind Kind { get; }
    public ContactEvidenceHash32 EvidenceHash { get; }
}

public sealed class ContactRelationshipSnapshot
{
    private readonly byte[] exactCanonicalAddress;

    internal ContactRelationshipSnapshot(
        ContactRelationshipId32 relationshipId,
        ContactConversationId32 conversationId,
        ContactAccountId32 remoteAccountId,
        ContactAddressKind addressKind,
        ReadOnlySpan<byte> exactCanonicalAddress,
        ContactRelationshipState state,
        ulong revision,
        DateTimeOffset createdAt,
        DateTimeOffset updatedAt,
        ContactVerifiedArtifactHashes artifactHashes)
    {
        if (state is ContactRelationshipState.Absent || !Enum.IsDefined(state))
            throw new ArgumentOutOfRangeException(nameof(state));
        if (revision == 0) throw new ArgumentOutOfRangeException(nameof(revision));
        if (!Enum.IsDefined(addressKind)) throw new ArgumentOutOfRangeException(nameof(addressKind));
        var expectedLength = addressKind == ContactAddressKind.PermanentDeepId ? 76 : 225;
        if (exactCanonicalAddress.Length != expectedLength)
            throw new ArgumentException("The relationship address is not exact canonical DID1/DIA1.", nameof(exactCanonicalAddress));
        createdAt = createdAt.ToUniversalTime();
        updatedAt = updatedAt.ToUniversalTime();
        if (createdAt.Ticks < 0 || updatedAt < createdAt)
            throw new ArgumentOutOfRangeException(nameof(updatedAt));

        RelationshipId = ContactRelationshipId32.FromBytes(relationshipId.Span);
        ConversationId = ContactConversationId32.FromBytes(conversationId.Span);
        RemoteAccountId = ContactAccountId32.FromVerifiedBytes(remoteAccountId.Span);
        AddressKind = addressKind;
        this.exactCanonicalAddress = exactCanonicalAddress.ToArray();
        State = state;
        Revision = revision;
        CreatedAt = createdAt;
        UpdatedAt = updatedAt;
        ArtifactHashes = new ContactVerifiedArtifactHashes(artifactHashes.Ordered);
    }

    public ContactRelationshipId32 RelationshipId { get; }
    public ContactConversationId32 ConversationId { get; }
    public ContactAccountId32 RemoteAccountId { get; }
    public ContactAddressKind AddressKind { get; }
    public ReadOnlyMemory<byte> ExactCanonicalAddress => exactCanonicalAddress.ToArray();
    public ContactRelationshipState State { get; }
    public ulong Revision { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset UpdatedAt { get; }
    public ContactVerifiedArtifactHashes ArtifactHashes { get; }

    internal ContactRelationshipSnapshot WithState(ContactRelationshipState state, DateTimeOffset updatedAt) =>
        new(RelationshipId, ConversationId, RemoteAccountId, AddressKind, ExactCanonicalAddress.Span,
            state, checked(Revision + 1), CreatedAt, updatedAt, ArtifactHashes);

    internal ContactRelationshipSnapshot Copy() => new(RelationshipId, ConversationId, RemoteAccountId,
        AddressKind, ExactCanonicalAddress.Span, State, Revision, CreatedAt, UpdatedAt, ArtifactHashes);
}
