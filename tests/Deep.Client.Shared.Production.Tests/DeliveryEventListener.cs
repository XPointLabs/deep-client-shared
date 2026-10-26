using System.Diagnostics.Tracing;

namespace Deep.Client.Shared.Production.Tests;

internal sealed class DeliveryEventListener : EventListener
{
    private static readonly AsyncLocal<DeliveryEventListener?> Current = new();
    private readonly DeliveryEventListener? parent;
    internal readonly List<(int Phase, string MessageHash, string DeliveryHash, int AckCalls)> Events = [];
    internal Func<int>? AckCalls;
    internal bool ThrowAfterObservation;
    internal DeliveryEventListener() { parent = Current.Value; Current.Value = this; }
    protected override void OnEventSourceCreated(EventSource source)
    { if (source.Name == "Deep-Client-Delivery") EnableEvents(source, EventLevel.Informational); }
    protected override void OnEventWritten(EventWrittenEventArgs e)
    {
        if (Current.Value != this || e.EventId != 1 || e.Payload?.Count != 3) return;
        Events.Add(((int)e.Payload[0]!, (string)e.Payload[1]!, (string)e.Payload[2]!, AckCalls?.Invoke() ?? -1));
        if (ThrowAfterObservation) throw new IOException("Injected diagnostic observer failure.");
    }
    public override void Dispose() { Current.Value = parent; base.Dispose(); }
}
