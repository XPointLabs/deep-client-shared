using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services.MessagingV1;

/// <summary>
/// A successfully opened DAO1 is still untrusted as a local delivery until its
/// exact inner record names the current account/device. Ratchet authentication
/// and durable application commit are separate, later requirements for ACK.
/// </summary>
internal static class MessagingV1InboundInnerValidator
{
    internal static void Validate(
        MessagingV1DepositKind kind,
        ReadOnlySpan<byte> exactInner,
        ReadOnlySpan<byte> localNetworkId,
        ReadOnlySpan<byte> localAccountId,
        ReadOnlySpan<byte> localDeviceId,
        ulong localDeviceGeneration)
    {
        if (kind == MessagingV1DepositKind.InitialSession)
        {
            var record = Dph2Codec.Decode(exactInner);
            if (!Fixed(record.NetworkId.Span, localNetworkId) ||
                !Fixed(record.ResponderAccountId.Span, localAccountId) ||
                !Fixed(record.ResponderDeviceId.Span, localDeviceId) ||
                record.ResponderDeviceGeneration != localDeviceGeneration)
                throw new CryptographicException(
                    "Retrieved DPH2 is for another local account/device generation.");
            return;
        }
        if (kind != MessagingV1DepositKind.EstablishedSession)
            throw new CryptographicException("The opened DAO1 inner kind is unknown.");

        var dpe2 = Dpe2Codec.Decode(exactInner);
        if (!Fixed(dpe2.NetworkId.Span, localNetworkId) ||
            !Fixed(dpe2.RecipientDeviceId.Span, localDeviceId))
            throw new CryptographicException(
                "Retrieved DPE2 is for another local device.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
