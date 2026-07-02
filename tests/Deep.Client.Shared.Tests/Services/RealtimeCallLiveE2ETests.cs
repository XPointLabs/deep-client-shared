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

        var aliceRuntime = Deep.Client.Shared.State.ClientRuntime.CreateStubbed();
        var bobRuntime = Deep.Client.Shared.State.ClientRuntime.CreateStubbed();
        var alice = await aliceRuntime.Accounts.RegisterAsync("Alice");
        var bob = await bobRuntime.Accounts.RegisterAsync("Bob");
        var alicePhrase = await aliceRuntime.Accounts.GetRecoveryPhraseAsync();
        var bobPhrase = await bobRuntime.Accounts.GetRecoveryPhraseAsync();
        var conversationId = ConversationId.ForOneToOne(bob.SessionId).Value;
        var aliceCalls = CreateService(callUrl, alicePhrase);
        var bobCalls = CreateService(callUrl, bobPhrase);

        var outgoing = await aliceCalls.StartOutgoingAsync(alice.SessionId, bob.SessionId, conversationId);
        var bobIncoming = await bobCalls.PollAsync(bob.SessionId);

        var ringing = Assert.Single(bobIncoming);
        Assert.Equal(outgoing.CallId, ringing.CallId);
        Assert.Equal(CallSessionState.Ringing, ringing.State);
        Assert.Equal(alice.SessionId, ringing.RemoteParty);

        var accepted = await bobCalls.AcceptIncomingAsync(ringing.CallId, bob.SessionId);
        var aliceUpdated = await aliceCalls.PollAsync(alice.SessionId);

        Assert.NotNull(accepted);
        Assert.Equal(CallSessionState.Connected, accepted!.State);
        Assert.Contains(aliceUpdated, snapshot =>
            snapshot.CallId == outgoing.CallId &&
            snapshot.State == CallSessionState.Connected);

        await aliceCalls.EndAsync(outgoing.CallId, alice.SessionId);
        var bobEnded = await bobCalls.PollAsync(bob.SessionId);

        Assert.Contains(bobEnded, snapshot =>
            snapshot.CallId == outgoing.CallId &&
            snapshot.State == CallSessionState.Ended);
    }

    private static RealtimeCallService CreateService(string callUrl, string? recoveryPhrase) =>
        new(new HttpCallSignalingTransport(
            new HttpClient(),
            new HttpCallSignalingTransportOptions(callUrl),
            _ => Task.FromResult(recoveryPhrase)));
}
