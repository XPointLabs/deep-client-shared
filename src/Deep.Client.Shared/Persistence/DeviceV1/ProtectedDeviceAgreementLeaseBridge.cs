using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV1;

public sealed class ProtectedDeviceAgreementLeaseResult
{
    internal ProtectedDeviceAgreementLeaseResult(
        ProtectedDeviceAgreementDisposition disposition,
        LocalDeviceX25519AgreementLease? lease = null)
    {
        Disposition = disposition;
        Lease = lease;
    }

    public ProtectedDeviceAgreementDisposition Disposition { get; }
    public LocalDeviceX25519AgreementLease? Lease { get; }
}

/// <summary>
/// Typed composition boundary that atomically burns one durable device-agreement
/// operation and redeems it into Protocol's exact-bound, one-shot lease.
/// </summary>
public static class ProtectedDeviceAgreementLeaseIssuer
{
    public static async ValueTask<ProtectedDeviceAgreementLeaseResult> AuthorizeAndRedeemAsync(
        IProtectedCurrentDmd1Store store,
        DeviceOperationId32 operationId,
        Dmd1LineageState verifiedCurrent,
        LocalDeviceX25519AgreementAuthority authority,
        LocalDeviceX25519AgreementPurpose purpose,
        ReadOnlyMemory<byte> operationBinding,
        ReadOnlyMemory<byte> peerPublicKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        var authorization = await store.AuthorizeDeviceAgreementAsync(
                operationId,
                verifiedCurrent,
                authority,
                purpose,
                operationBinding,
                peerPublicKey,
                cancellationToken)
            .ConfigureAwait(false);
        if (authorization.Authorization is null)
            return new ProtectedDeviceAgreementLeaseResult(authorization.Disposition);

        try
        {
            return new ProtectedDeviceAgreementLeaseResult(
                authorization.Disposition,
                ProtectedDeviceAgreementLeaseBridge.Redeem(
                    authorization.Authorization,
                    verifiedCurrent,
                    authority));
        }
        catch
        {
            authorization.Authorization.Dispose();
            throw;
        }
    }
}

/// <summary>
/// The non-public handoff between the durable current-DMD1/operation-burn owner
/// and Protocol's one-shot device-agreement capability.
/// </summary>
internal static class ProtectedDeviceAgreementLeaseBridge
{
    internal static LocalDeviceX25519AgreementLease Redeem(
        ProtectedDeviceAgreementAuthorization authorization,
        Dmd1LineageState verifiedCurrent,
        LocalDeviceX25519AgreementAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(verifiedCurrent);
        ArgumentNullException.ThrowIfNull(authority);

        using var use = authorization.ClaimOnce();
        try
        {
            RequireExactScope(authorization, verifiedCurrent, authority);
            return authority.OpenOperation(
                verifiedCurrent,
                use.Purpose,
                use.OperationBinding,
                use.PeerPublicKey);
        }
        finally
        {
            // ClaimOnce transfers the operation and peer buffers to `use`; its
            // disposal zeroes them after OpenOperation has copied them or failed.
            authorization.Dispose();
        }
    }

    private static void RequireExactScope(
        ProtectedDeviceAgreementAuthorization authorization,
        Dmd1LineageState verifiedCurrent,
        LocalDeviceX25519AgreementAuthority authority)
    {
        var directory = verifiedCurrent.Head.Record;
        if (verifiedCurrent.ForkLatched ||
            authorization.AccountGeneration != authority.AccountGeneration ||
            authorization.DeviceGeneration != authority.DeviceGeneration ||
            authorization.DirectoryGeneration != directory.DirectoryGeneration ||
            !Equal(authorization.NetworkId.Span, authority.NetworkId.Span) ||
            !Equal(authorization.AccountId.Span, authority.AccountId.Span) ||
            !Equal(authorization.DeviceId.Span, authority.DeviceId.Span) ||
            !Equal(authorization.ExactDpd1Hash.Span, authority.ExactDpd1Hash.Span) ||
            !Equal(authorization.NetworkId.Span, directory.NetworkId.Span) ||
            !Equal(authorization.AccountId.Span, directory.DeepAccountId.Span) ||
            authorization.AccountGeneration != directory.AccountGeneration ||
            !Equal(authorization.DirectoryHash.Span, directory.RecordHash.Span))
        {
            throw new RecordException(
                RecordError.InvalidTransition,
                "The protected device-agreement authorization is not bound to the exact current verified DMD1 and local device generation.");
        }
    }

    private static bool Equal(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
