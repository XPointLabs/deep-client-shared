using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class RealtimeCallTests
{
    [Fact]
    public async Task OutgoingSetupAndTeardown_TransitionsAcrossPeers()
    {
        var transport = new InMemoryCallSignalingTransport();
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-29T00:00:00Z"));
        var aliceService = new RealtimeCallService(transport, clock: clock);
        var bobService = new RealtimeCallService(transport, clock: clock);

        var alice = SessionId.CreateNew();
        var bob = SessionId.CreateNew();
        const string conversationId = "03conversation";

        var outgoing = await aliceService.StartOutgoingAsync(alice, bob, conversationId);
        Assert.Equal(CallSessionState.Connecting, outgoing.State);

        var bobPoll = await bobService.PollAsync(bob);
        Assert.Single(bobPoll);
        Assert.Equal(CallSessionState.Ringing, bobPoll[0].State);
        Assert.Equal(outgoing.CallId, bobPoll[0].CallId);

        var accepted = await bobService.AcceptIncomingAsync(outgoing.CallId, bob);
        Assert.NotNull(accepted);
        Assert.Equal(CallSessionState.Connected, accepted!.State);

        var alicePoll = await aliceService.PollAsync(alice);
        Assert.Single(alicePoll);
        Assert.Equal(CallSessionState.Connected, alicePoll[0].State);

        var ended = await aliceService.EndAsync(outgoing.CallId, alice);
        Assert.NotNull(ended);
        Assert.Equal(CallSessionState.Ended, ended!.State);
        Assert.Equal("local-hangup", ended.FailureReason);

        var bobAfterEnd = await bobService.PollAsync(bob);
        Assert.Single(bobAfterEnd);
        Assert.Equal(CallSessionState.Ended, bobAfterEnd[0].State);
        Assert.Equal("remote-hangup", bobAfterEnd[0].FailureReason);
    }

    [Fact]
    public async Task DegradedSamples_TriggerReconnectAndDiagnostics()
    {
        var transport = new InMemoryCallSignalingTransport();
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-29T01:00:00Z"));
        var options = new ReconnectStrategyOptions(
            MaxAttempts: 3,
            TriggerPoorSamples: 1,
            MaxPacketLossRatio: 0.05,
            MaxRttMs: 200,
            MaxJitterMs: 40,
            MinBitrateKbps: 32);

        var aliceService = new RealtimeCallService(transport, options, clock);
        var bobService = new RealtimeCallService(transport, options, clock);

        var alice = SessionId.CreateNew();
        var bob = SessionId.CreateNew();

        var outgoing = await aliceService.StartOutgoingAsync(alice, bob, "03quality");
        await bobService.PollAsync(bob);
        await bobService.AcceptIncomingAsync(outgoing.CallId, bob);
        await aliceService.PollAsync(alice);

        var sample = new CallNetworkSample(
            RttMs: 450,
            JitterMs: 120,
            PacketLossRatio: 0.2,
            AvailableBitrateKbps: 12);

        var updated = await aliceService.ApplyNetworkSampleAsync(outgoing.CallId, alice, sample);
        Assert.NotNull(updated);
        Assert.Equal(1, updated!.ReconnectAttempts);
        Assert.Equal(CallSessionState.Connecting, updated.State);
        Assert.True(updated.Quality.QualityScore < 100);
        Assert.Contains(updated.Diagnostics, item => item.Reason == "high-rtt");
        Assert.Contains(updated.Diagnostics, item => item.Reason == "high-jitter");
        Assert.Contains(updated.Diagnostics, item => item.Reason == "high-packet-loss");
        Assert.Contains(updated.Diagnostics, item => item.Reason == "low-bitrate");

        var bobReconnect = await bobService.PollAsync(bob);
        Assert.Single(bobReconnect);
        Assert.Equal(CallSessionState.Connected, bobReconnect[0].State);
    }

    [Fact]
    public async Task ReconnectAttemptsExhausted_MarksCallFailed()
    {
        var transport = new InMemoryCallSignalingTransport();
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-29T02:00:00Z"));
        var options = new ReconnectStrategyOptions(MaxAttempts: 1, TriggerPoorSamples: 1);
        var service = new RealtimeCallService(transport, options, clock);

        var local = SessionId.CreateNew();
        var remote = SessionId.CreateNew();
        var outgoing = await service.StartOutgoingAsync(local, remote, "03failure");

        var badSample = new CallNetworkSample(
            RttMs: 900,
            JitterMs: 200,
            PacketLossRatio: 0.5,
            AvailableBitrateKbps: 1);

        var first = await service.ApplyNetworkSampleAsync(outgoing.CallId, local, badSample);
        Assert.NotNull(first);
        Assert.Equal(1, first!.ReconnectAttempts);

        var second = await service.ApplyNetworkSampleAsync(outgoing.CallId, local, badSample);
        Assert.NotNull(second);
        Assert.Equal(CallSessionState.Failed, second!.State);
        Assert.Equal("reconnect-attempts-exhausted", second.FailureReason);
        Assert.Contains(second.Diagnostics, item => item.Reason == "reconnect-attempts-exhausted");
    }
}
