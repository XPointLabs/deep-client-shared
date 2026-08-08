using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Client.Shared.Services;

public static class ProductionMailboxIssuanceIdempotency
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/production-mailbox/issuance-idempotency/v1"u8;

    public static byte[] Compute(
        ReadOnlySpan<byte> authoritySha256,
        ReadOnlySpan<byte> revocationSha256,
        ReadOnlySpan<byte> topologySha256,
        ReadOnlySpan<byte> holderEd25519PublicKey,
        ReadOnlySpan<byte> mailboxOwnerEd25519PublicKey,
        ReadOnlySpan<byte> blindedMailboxId,
        ReadOnlySpan<byte> blindedPlacementId,
        ReadOnlySpan<byte> selectionInputCommitment,
        ProductionMailboxIssuanceIntent intent,
        ProductionMailboxClientPlatform platform,
        ReadOnlySpan<byte> signingCertificateSha256,
        ReadOnlySpan<byte> buildArtifactSha256,
        ReadOnlySpan<byte> entitlementCommitment)
    {
        if (!Enum.IsDefined(intent) || !Enum.IsDefined(platform))
            throw new ArgumentOutOfRangeException(nameof(intent));
        Nonzero(authoritySha256, nameof(authoritySha256));
        Nonzero(revocationSha256, nameof(revocationSha256));
        Nonzero(topologySha256, nameof(topologySha256));
        Nonzero(holderEd25519PublicKey, nameof(holderEd25519PublicKey));
        Nonzero(mailboxOwnerEd25519PublicKey, nameof(mailboxOwnerEd25519PublicKey));
        Fixed(blindedMailboxId, nameof(blindedMailboxId));
        Fixed(blindedPlacementId, nameof(blindedPlacementId));
        Fixed(selectionInputCommitment, nameof(selectionInputCommitment));
        Nonzero(signingCertificateSha256, nameof(signingCertificateSha256));
        Nonzero(buildArtifactSha256, nameof(buildArtifactSha256));
        Fixed(entitlementCommitment, nameof(entitlementCommitment));
        var routeNonzero = new[]
        {
            NonzeroValue(blindedMailboxId),
            NonzeroValue(blindedPlacementId),
            NonzeroValue(selectionInputCommitment)
        };
        if (routeNonzero.Distinct().Count() != 1 ||
            intent == ProductionMailboxIssuanceIntent.LocalOwner && routeNonzero[0] ||
            intent == ProductionMailboxIssuanceIntent.PeerDeposit && !routeNonzero[0])
            throw new ArgumentException("Issuance route fields do not match intent.");

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        hash.AppendData(authoritySha256);
        hash.AppendData(revocationSha256);
        hash.AppendData(topologySha256);
        hash.AppendData(holderEd25519PublicKey);
        hash.AppendData(mailboxOwnerEd25519PublicKey);
        hash.AppendData(blindedMailboxId);
        hash.AppendData(blindedPlacementId);
        hash.AppendData(selectionInputCommitment);
        hash.AppendData([(byte)intent, (byte)platform]);
        hash.AppendData(signingCertificateSha256);
        hash.AppendData(buildArtifactSha256);
        hash.AppendData(entitlementCommitment);
        return hash.GetHashAndReset();
    }

    private static void Nonzero(ReadOnlySpan<byte> value, string parameter)
    {
        Fixed(value, parameter);
        if (!NonzeroValue(value))
            throw new ArgumentException("Issuance field is all zero.", parameter);
    }

    private static void Fixed(ReadOnlySpan<byte> value, string parameter)
    {
        if (value.Length != 32)
            throw new ArgumentException("Issuance field must be exactly 32 bytes.", parameter);
    }

    private static bool NonzeroValue(ReadOnlySpan<byte> value) =>
        value.IndexOfAnyExcept((byte)0) >= 0;
}
