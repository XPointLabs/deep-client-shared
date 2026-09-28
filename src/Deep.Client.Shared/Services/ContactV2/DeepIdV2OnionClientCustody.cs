using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.ContactV2;

/// <summary>Account-owned local ONION guards and entropy reservations. It
/// contains no device agreement scalar or node receive-key authority and
/// grants no current network, publication or messaging authority.</summary>
public sealed class DeepIdV2OnionClientCustody
{
    internal DeepIdV2OnionClientCustody(DeepIdV2AccountService owner,
        IProtectedEntryGuardStore guards, IOnionEntropyUniquenessLedger entropy)
    {
        Owner = owner;
        Guards = guards;
        Entropy = entropy;
    }

    internal DeepIdV2AccountService Owner { get; }
    internal IProtectedEntryGuardStore Guards { get; }
    internal IOnionEntropyUniquenessLedger Entropy { get; }
}
