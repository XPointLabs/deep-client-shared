using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class RealtimeCallLiveE2ETests
{
    [Fact]
    public async Task RealtimeCallService_RoundTripsCallLifecycleThroughLiveSignaling_WhenConfigured()
    {
        var callUrl = Environment.GetEnvironmentVariable("DEEP_CALL_SIGNALING_BASE_URL")
            ?? Environment.GetEnvironmentVariable("DEEP_CALL_SIGNALING_URL");
        if (string.IsNullOrWhiteSpace(callUrl))
        {
            return;
        }

        var alice = SessionId.CreateNew();
        var bob = SessionId.CreateNew();
        var conversationId = ConversationId.ForOneToOne(bob).Value;
        var aliceCalls = CreateService(callUrl);
        var bobCalls = CreateService(callUrl);

        var outgoing = await aliceCalls.StartOutgoingAsync(alice, bob, conversationId);
        var bobIncoming = await bobCalls.PollAsync(bob);

        var ringing = Assert.Single(bobIncoming);
        Assert.Equal(outgoing.CallId, ringing.CallId);
        Assert.Equal(CallSessionState.Ringing, ringing.State);
        Assert.Equal(alice, ringing.RemoteParty);

        var accepted = await bobCalls.AcceptIncomingAsync(ringing.CallId, bob);
        var aliceUpdated = await aliceCalls.PollAsync(alice);

        Assert.NotNull(accepted);
        Assert.Equal(CallSessionState.Connected, accepted!.State);
        Assert.Contains(aliceUpdated, snapshot =>
            snapshot.CallId == outgoing.CallId &&
            snapshot.State == CallSessionState.Connected);

        await aliceCalls.EndAsync(outgoing.CallId, alice);
        var bobEnded = await bobCalls.PollAsync(bob);

        Assert.Contains(bobEnded, snapshot =>
            snapshot.CallId == outgoing.CallId &&
            snapshot.State == CallSessionState.Ended);
    }

    private static RealtimeCallService CreateService(string callUrl) =>
        new(new HttpCallSignalingTransport(new HttpClient(), new HttpCallSignalingTransportOptions(callUrl)));
}
