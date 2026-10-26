using System.Diagnostics.Tracing;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Observation only: no timestamp, plaintext, selector or acknowledgement
// authority crosses this boundary. Random semantic IDs are domain-hashed.
internal enum ClientDeliveryPhase { NativeOutboxDurable = 1, StoreQuorum = 2, RecipientDurableReadable = 3 }
internal sealed record ClientDeliveryObservation(ClientDeliveryPhase Phase, string MessageHash, string DeliveryHash);

[EventSource(Name = "Deep-Client-Delivery")]
internal sealed class ClientDeliveryEvents : EventSource
{
    private static readonly ClientDeliveryEvents Log = new();
    internal static void Initialize() { _ = Log.IsEnabled(); }

    internal static void Reached(ClientDeliveryPhase phase, ReadOnlySpan<byte> exactDmc2)
    {
        if (!Log.IsEnabled()) return;
        try { Reached(phase, ApplicationCoreCodec.DecodeDmc2(exactDmc2)); }
        catch { /* Optional decoding cannot replace the transport result. */ }
    }

    internal static void Reached(ClientDeliveryPhase phase, ParsedDmc2 message)
    { if (Capture(phase, message) is { } observation) Publish(observation); }

    internal static ClientDeliveryObservation? Capture(ClientDeliveryPhase phase, ParsedDmc2 message)
    {
        if (!Log.IsEnabled()) return null;
        if (message.ContentKind != Dmc2ContentKind.MessageCreate &&
            message.ParsedPayload is not GroupDmc2Payload { Record: GroupApplicationMessageRecord }) return null;
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData("deep.delivery.dmc.v1"u8); hash.AppendData(message.NetworkId.Span);
            hash.AppendData(message.SenderDeviceId.Span); hash.AppendData(message.LogicalMessageId.Span);
            var deliveryHash = Convert.ToHexStringLower(hash.GetHashAndReset());
            var messageHash = deliveryHash;
            if (message.ParsedPayload is GroupDmc2Payload { Record: GroupApplicationMessageRecord group })
            {
                hash.AppendData("deep.delivery.group.v1"u8); hash.AppendData(message.NetworkId.Span);
                hash.AppendData(group.Field(2).Span); hash.AppendData(group.Field(5).Span);
                messageHash = Convert.ToHexStringLower(hash.GetHashAndReset());
            }
            return new(phase, messageHash, deliveryHash);
        }
        catch { return null; }
    }

    internal static void Publish(ClientDeliveryObservation observation)
    {
        try { Log.Transition((int)observation.Phase, observation.MessageHash, observation.DeliveryHash); }
        catch { /* Diagnostic observers never change the durable outcome. */ }
    }

    [Event(1, Level = EventLevel.Informational)]
    public void Transition(int phase, string messageHash, string deliveryHash) => WriteEvent(1, phase, messageHash, deliveryHash);
}
