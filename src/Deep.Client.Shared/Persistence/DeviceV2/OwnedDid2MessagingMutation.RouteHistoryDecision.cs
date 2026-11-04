using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class OwnedDid2MessagingMutation
{
    internal static OwnedDid2MessagingMutation RouteHistoryDecision(Did2MessagingSessionScope scope, Did2MessagingFloor stable,
        ProtectedDeepIdV2AccountOwner.QualifiedDid2RouteHistoryDecision qualified)
    {
        ArgumentNullException.ThrowIfNull(qualified);
        var body = qualified.CopyFor(scope, stable);
        try
        {
            var decision = Did2RouteHistoryDecision.Decode(body, scope); decision.RequireBefore(stable);
            var header = HeaderFor(6, 0, 1, stable, stable.RatchetGeneration, stable.RatchetCommitment,
                stable.RatchetHash, decision.Operation(scope, stable), SHA256.HashData(body), new byte[32]);
            return Encode(scope, header, [], [], body, [], []);
        }
        finally { CryptographicOperations.ZeroMemory(body); }
    }
}
