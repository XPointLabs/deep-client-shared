using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.ContactV2;

// Actual owned-operation loan, not an ambient/reentrant lock bypass. No public constructor.
internal sealed class Did2OwnedContactTransportContext(
    DeepIdV2OnionClientCustody custody, VerifiedOnionNetworkContext network, HeldDeepIdV2AccountLease held)
{
    internal DeepIdV2OnionClientCustody Custody { get; } = custody;
    internal VerifiedOnionNetworkContext Network { get; } = network;
    internal void RequireActive() { held.RequireActive(); Network.EnsureCurrent(); }
}
