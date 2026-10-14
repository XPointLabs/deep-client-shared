using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Verified journal read-back only, not semantic/transport/ACK authority.</summary>
internal sealed class OwnedDid2MessagingPersistedEvent : IDisposable
{
    private byte[]? envelope, plaintext;
    private readonly byte[] eventHash, envelopeHash, routeProcessing;
    internal int Direction { get; }
    internal ulong Ordinal { get; }
    // Called only by the verified SQL reader, adopting its fresh blob buffers.
    internal OwnedDid2MessagingPersistedEvent(int direction, ulong ordinal, byte[] envelope, byte[] plaintext,
        ReadOnlySpan<byte> eventHash, ReadOnlySpan<byte> routeProcessing)
    {
        Direction = direction; Ordinal = ordinal; this.envelope = envelope; this.plaintext = plaintext;
        this.eventHash = eventHash.ToArray();
        Did2RouteProcessingMetadata.RequireShape(routeProcessing);
        this.routeProcessing = routeProcessing.ToArray();
        envelopeHash = MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(Dpe2Codec.Decode(envelope));
    }
    internal ReadOnlySpan<byte> ExactEnvelope { get { RequireLive(); return envelope; } }
    internal ReadOnlySpan<byte> EnvelopeHash { get { RequireLive(); return envelopeHash; } }
    internal ReadOnlySpan<byte> EventHash { get { RequireLive(); return eventHash; } }
    internal ReadOnlySpan<byte> RouteProcessing { get { RequireLive(); return routeProcessing; } }
    internal OwnedDeepSecret OwnAuthenticatedDmc2()
    {
        RequireLive();
        if (Direction != 2) throw new InvalidOperationException("A sent operation retains no authenticated receive plaintext.");
        return new(plaintext!);
    }
    private void RequireLive() => ObjectDisposedException.ThrowIf(envelope is null, this);
    public void Dispose()
    {
        var cipher = Interlocked.Exchange(ref envelope, null); var plain = Interlocked.Exchange(ref plaintext, null);
        if (cipher is not null) CryptographicOperations.ZeroMemory(cipher);
        if (plain is not null) CryptographicOperations.ZeroMemory(plain);
        GC.SuppressFinalize(this);
    }
    ~OwnedDid2MessagingPersistedEvent() => Dispose();
}
