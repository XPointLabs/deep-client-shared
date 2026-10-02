using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Immutable public lookup material, never a retained freshness capability.
internal static class ProtectedDid2MessagingPeerBootstrap
{
    internal const int Bytes = 68 + DeepIdV2Codec.Did2Length;
    internal static string Slot(Did2MessagingSessionScope scope) =>
        "deep.store.v2.messaging.peer." + Convert.ToHexStringLower(scope.Hash);

    internal static byte[] FromSeed(OwnedInitialMessagingSeed seed)
    {
        var scope = Did2MessagingSessionScope.FromSeed(seed);
        var result = new byte[Bytes]; result[0] = 1;
        scope.Hash.CopyTo(result.AsSpan(4));
        seed.ExactPeerCredential.CopyTo(result.AsSpan(68));
        SHA256.HashData(result.AsSpan(68)).CopyTo(result.AsSpan(36));
        _ = Restore(result, scope);
        return result;
    }

    internal static ParsedDid2 Restore(ReadOnlySpan<byte> exact, Did2MessagingSessionScope scope)
    {
        if (exact.Length != Bytes || exact[0] != 1 || exact.Slice(1, 3).IndexOfAnyExcept((byte)0) >= 0 ||
            !Did2MessagingSessionScope.Fixed(exact.Slice(4, 32), scope.Hash) ||
            !Did2MessagingSessionScope.Fixed(exact.Slice(36, 32), SHA256.HashData(exact[68..])))
            throw new CryptographicException("The protected messaging peer bootstrap differs from its registered scope.");
        var did = DeepIdV2Codec.DecodeDid2(exact[68..]);
        if (!Did2MessagingSessionScope.Fixed(did.CanonicalBytes.Span, exact[68..]))
            throw new CryptographicException("The protected messaging peer credential is not canonical.");
        return did;
    }

    internal static void RequireProof(ParsedDid2 did, VerifiedDeepIdV2DirectoryFreshness proof)
    {
        var binding = proof.CurrentCheckpoint?.Binding ??
            throw new CryptographicException("The current peer binding is absent.");
        if (!Did2MessagingSessionScope.Fixed(binding.DeepId.CanonicalBytes.Span, did.CanonicalBytes.Span))
            throw new CryptographicException("The refreshed peer proof has another exact DID2 credential.");
    }
}
