using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Domain.ContactV1;

/// <summary>
/// Exact Deep-account ownership boundary for CONTACT-CLIENT-01 local state.
/// Deep account IDs already include the account generation in their normative
/// derivation, so no Session-derived identity belongs in this scope.
/// </summary>
public sealed class ContactStoreScope : IEquatable<ContactStoreScope>
{
    public const int CurrentStoreGeneration = 2;

    public ContactStoreScope(DeepAccountId32 accountId, int storeGeneration)
    {
        AccountId = accountId ?? throw new ArgumentNullException(nameof(accountId));
        if (storeGeneration <= 0)
            throw new ArgumentOutOfRangeException(nameof(storeGeneration));
        StoreGeneration = storeGeneration;
    }

    public DeepAccountId32 AccountId { get; }
    public int StoreGeneration { get; }

    public static ContactStoreScope ForCurrentAccount(DeepAccountId32 accountId) =>
        new(accountId, CurrentStoreGeneration);

    public bool Equals(ContactStoreScope? other) => other is not null
        && StoreGeneration == other.StoreGeneration
        && AccountId.Equals(other.AccountId);
    public override bool Equals(object? obj) => Equals(obj as ContactStoreScope);
    public override int GetHashCode() => HashCode.Combine(AccountId, StoreGeneration);
    public override string ToString() => "[opaque-contact-store-scope]";
}
