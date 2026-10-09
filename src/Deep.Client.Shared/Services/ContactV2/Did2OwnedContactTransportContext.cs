using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

// Actual owned-operation loan, not an ambient/reentrant lock bypass. No public constructor.
internal sealed class Did2OwnedContactTransportContext(
    DeepIdV2OnionClientCustody custody, VerifiedOnionNetworkContext network, HeldDeepIdV2AccountLease held,
    VerifiedMailboxRetainedReadRequestV2? retainedReadRequest = null)
{
    internal DeepIdV2OnionClientCustody Custody { get; } = custody;
    internal VerifiedOnionNetworkContext Network { get; } = network;
    // Loaned only by the original publication owner after the actual current
    // host verified this exact request's retained projection and live window.
    internal VerifiedMailboxRetainedReadRequestV2? RetainedReadRequest { get; } = retainedReadRequest;
    internal void RequireActive() { held.RequireActive(); Network.EnsureCurrent(); }
}
