using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Sodium;

namespace Deep.Client.Shared.Services;

public enum CallSessionState
{
    Signaling,
    Ringing,
    Connecting,
    Connected,
    Reconnecting,
    Ended,
    Failed
}

public enum CallSignalType
{
    Offer,
    Answer,
    IceCandidate,
    Reconnect,
    Bye
}

public sealed record CallSignalEnvelope(
    string CallId,
    string ConversationId,
    SessionId Sender,
    SessionId Recipient,
    CallSignalType Type,
    string Payload,
    DateTimeOffset CreatedAt,
    string? SenderEd25519 = null,
    string? Signature = null);

public sealed record CallNetworkSample(
    double RttMs,
    double JitterMs,
    double PacketLossRatio,
    double AvailableBitrateKbps);

public sealed record CallQualityMetrics(
    double QualityScore,
    double AverageRttMs,
    double AverageJitterMs,
    double AveragePacketLossRatio,
    double AvailableBitrateKbps,
    DateTimeOffset UpdatedAt);

public sealed record CallDegradationDiagnostic(
    string Reason,
    string Details,
    DateTimeOffset RecordedAt);

public sealed record CallSessionSnapshot(
    string CallId,
    string ConversationId,
    SessionId LocalParty,
    SessionId RemoteParty,
    CallSessionState State,
    CallQualityMetrics Quality,
    int ReconnectAttempts,
    string? FailureReason,
    IReadOnlyList<CallDegradationDiagnostic> Diagnostics);

public sealed record ReconnectStrategyOptions(
    int MaxAttempts = 3,
    int TriggerPoorSamples = 3,
    double MaxPacketLossRatio = 0.08,
    double MaxRttMs = 350,
    double MaxJitterMs = 80,
    double MinBitrateKbps = 24);

public interface ICallSignalingTransport
{
    Task SendAsync(CallSignalEnvelope envelope, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<CallSignalEnvelope>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default);
}

public sealed record CallIceServer(IReadOnlyList<string> Urls, string? Username = null, string? Credential = null);

public sealed record CallIceConfiguration(IReadOnlyList<CallIceServer> IceServers, DateTimeOffset ExpiresAt);

public interface ICallIceConfigurationProvider
{
    Task<CallIceConfiguration> GetAsync(SessionId recipient, CancellationToken cancellationToken = default);
}

public sealed record HttpCallSignalingTransportOptions(
    string BaseUrl,
    string SignalPath = "/api/calls/signal",
    string InboxPathFormat = "/api/calls/inbox/{recipient}",
    string IceServersPathFormat = "/api/calls/ice-servers/{recipient}");

public sealed class HttpCallSignalingTransport : ICallSignalingTransport, ICallIceConfigurationProvider
{
    private readonly HttpClient _httpClient;
    private readonly HttpCallSignalingTransportOptions _options;
    private readonly Func<CancellationToken, Task<string?>>? _recoveryPhraseProvider;

    public HttpCallSignalingTransport(
        HttpClient httpClient,
        HttpCallSignalingTransportOptions options,
        Func<CancellationToken, Task<string?>>? recoveryPhraseProvider = null)
    {
        _httpClient = httpClient;
        _options = options;
        _recoveryPhraseProvider = recoveryPhraseProvider;

        if (string.IsNullOrWhiteSpace(_options.BaseUrl))
        {
            throw new ArgumentException("Call signaling base URL is required.", nameof(options));
        }

        if (_httpClient.BaseAddress is null)
        {
            _httpClient.BaseAddress = new Uri(_options.BaseUrl.EndsWith('/')
                ? _options.BaseUrl
                : _options.BaseUrl + "/", UriKind.Absolute);
        }
    }

    public async Task SendAsync(CallSignalEnvelope envelope, CancellationToken cancellationToken = default)
    {
        var outgoing = _recoveryPhraseProvider is null
            ? envelope
            : await EncryptAndSignAsync(envelope, cancellationToken).ConfigureAwait(false);
        var response = await _httpClient.PostAsJsonAsync(_options.SignalPath, outgoing, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }

    public async Task<IReadOnlyList<CallSignalEnvelope>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default)
    {
        var path = _options.InboxPathFormat.Replace("{recipient}", Uri.EscapeDataString(recipient.Value), StringComparison.Ordinal);
        List<CallSignalEnvelope> payload;
        SessionIdentityMaterial? recipientIdentity = null;
        if (_recoveryPhraseProvider is null)
        {
            payload = await _httpClient.GetFromJsonAsync<List<CallSignalEnvelope>>(path, cancellationToken).ConfigureAwait(false)
                ?? [];
        }
        else
        {
            var recoveryPhrase = await _recoveryPhraseProvider(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(recoveryPhrase))
            {
                return [];
            }

            recipientIdentity = SessionIdentityMaterial.FromRecoveryPhrase(recoveryPhrase);
            if (recipientIdentity.SessionId != recipient)
            {
                return [];
            }

            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            request.Headers.TryAddWithoutValidation("X-Deep-Ed25519", recipientIdentity.Ed25519PublicKeyHex);
            request.Headers.TryAddWithoutValidation("X-Deep-Timestamp", timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture));
            request.Headers.TryAddWithoutValidation(
                "X-Deep-Signature",
                Convert.ToBase64String(recipientIdentity.SignDetached(CallSignalAuthentication.BuildInboxSigningPayload(recipient, timestamp))));
            using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            payload = await response.Content.ReadFromJsonAsync<List<CallSignalEnvelope>>(cancellationToken: cancellationToken)
                .ConfigureAwait(false) ?? [];
        }

        if (recipientIdentity is null)
        {
            return payload;
        }
        var result = new List<CallSignalEnvelope>(payload.Count);
        foreach (var envelope in payload)
        {
            if (TryVerifyAndDecrypt(envelope, recipientIdentity, out var decrypted))
            {
                result.Add(decrypted);
            }
        }

        return result;
    }

    public async Task<CallIceConfiguration> GetAsync(
        SessionId recipient,
        CancellationToken cancellationToken = default)
    {
        if (_recoveryPhraseProvider is null)
        {
            throw new InvalidOperationException("Authenticated call signaling is required for ICE configuration.");
        }

        var recoveryPhrase = await _recoveryPhraseProvider(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recoveryPhrase))
        {
            throw new InvalidOperationException("An active account is required for ICE configuration.");
        }

        var identity = SessionIdentityMaterial.FromRecoveryPhrase(recoveryPhrase);
        if (identity.SessionId != recipient)
        {
            throw new InvalidOperationException("ICE configuration recipient does not match the active account.");
        }

        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var path = _options.IceServersPathFormat.Replace(
            "{recipient}",
            Uri.EscapeDataString(recipient.Value),
            StringComparison.Ordinal);
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("X-Deep-Ed25519", identity.Ed25519PublicKeyHex);
        request.Headers.TryAddWithoutValidation("X-Deep-Timestamp", timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(
            "X-Deep-Signature",
            Convert.ToBase64String(identity.SignDetached(CallSignalAuthentication.BuildIceSigningPayload(recipient, timestamp))));
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<CallIceConfiguration>(cancellationToken: cancellationToken)
                   .ConfigureAwait(false)
               ?? throw new InvalidOperationException("The call service returned an empty ICE configuration.");
    }

    private async Task<CallSignalEnvelope> EncryptAndSignAsync(
        CallSignalEnvelope envelope,
        CancellationToken cancellationToken)
    {
        var recoveryPhrase = await _recoveryPhraseProvider!(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recoveryPhrase))
        {
            throw new InvalidOperationException("An active account is required for call signaling.");
        }

        var identity = SessionIdentityMaterial.FromRecoveryPhrase(recoveryPhrase);
        if (identity.SessionId != envelope.Sender)
        {
            throw new InvalidOperationException("Call signaling sender does not match the active account.");
        }

        var cipher = SealedPublicKeyBox.Create(
            Encoding.UTF8.GetBytes(envelope.Payload),
            DecodeSessionPublicKey(envelope.Recipient));
        var encrypted = envelope with
        {
            Payload = "sealed-v1:" + Convert.ToBase64String(cipher),
            SenderEd25519 = identity.Ed25519PublicKeyHex,
            Signature = null
        };
        return encrypted with
        {
            Signature = Convert.ToBase64String(identity.SignDetached(CallSignalAuthentication.BuildSigningPayload(encrypted)))
        };
    }

    private static bool TryVerifyAndDecrypt(
        CallSignalEnvelope envelope,
        SessionIdentityMaterial recipient,
        out CallSignalEnvelope decrypted)
    {
        decrypted = default!;
        try
        {
            if (!envelope.Payload.StartsWith("sealed-v1:", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(envelope.SenderEd25519)
                || string.IsNullOrWhiteSpace(envelope.Signature))
            {
                return false;
            }

            var senderEd25519 = Convert.FromHexString(envelope.SenderEd25519);
            var senderX25519 = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(senderEd25519);
            if (!senderX25519.SequenceEqual(DecodeSessionPublicKey(envelope.Sender)))
            {
                return false;
            }

            var unsigned = envelope with { Signature = null };
            if (!PublicKeyAuth.VerifyDetached(
                    Convert.FromBase64String(envelope.Signature),
                    CallSignalAuthentication.BuildSigningPayload(unsigned),
                    senderEd25519))
            {
                return false;
            }

            var cipher = Convert.FromBase64String(envelope.Payload["sealed-v1:".Length..]);
            var plain = SealedPublicKeyBox.Open(cipher, recipient.X25519PrivateKey, recipient.X25519PublicKey);
            decrypted = envelope with { Payload = Encoding.UTF8.GetString(plain) };
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or CryptographicException)
        {
            return false;
        }
    }

    private static byte[] DecodeSessionPublicKey(SessionId sessionId) =>
        Convert.FromHexString(sessionId.Value[2..]);
}

public static class CallSignalAuthentication
{
    private const string Version = "deep-call-signal-v1";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static byte[] BuildSigningPayload(CallSignalEnvelope envelope) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = Version,
            envelope.CallId,
            envelope.ConversationId,
            sender = envelope.Sender.Value,
            recipient = envelope.Recipient.Value,
            type = envelope.Type.ToString(),
            envelope.Payload,
            createdAtUnixMs = envelope.CreatedAt.ToUnixTimeMilliseconds(),
            senderEd25519 = envelope.SenderEd25519
        }, JsonOptions);

    public static byte[] BuildInboxSigningPayload(SessionId recipient, long timestamp) =>
        Encoding.UTF8.GetBytes($"deep-call-inbox-v1\n{recipient.Value}\n{timestamp}");

    public static byte[] BuildIceSigningPayload(SessionId recipient, long timestamp) =>
        Encoding.UTF8.GetBytes($"deep-call-ice-v1\n{recipient.Value}\n{timestamp}");
}

public sealed class InMemoryCallSignalingTransport : ICallSignalingTransport, ICallIceConfigurationProvider
{
    private readonly ConcurrentDictionary<string, ConcurrentQueue<CallSignalEnvelope>> _inboxes = new(StringComparer.Ordinal);

    public Task SendAsync(CallSignalEnvelope envelope, CancellationToken cancellationToken = default)
    {
        _inboxes.GetOrAdd(envelope.Recipient.Value, static _ => new ConcurrentQueue<CallSignalEnvelope>()).Enqueue(envelope);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<CallSignalEnvelope>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default)
    {
        if (!_inboxes.TryGetValue(recipient.Value, out var queue))
        {
            return Task.FromResult<IReadOnlyList<CallSignalEnvelope>>([]);
        }

        var result = new List<CallSignalEnvelope>();
        while (queue.TryDequeue(out var envelope))
        {
            result.Add(envelope);
        }

        return Task.FromResult<IReadOnlyList<CallSignalEnvelope>>(result);
    }

    public Task<CallIceConfiguration> GetAsync(SessionId recipient, CancellationToken cancellationToken = default) =>
        Task.FromResult(new CallIceConfiguration([], DateTimeOffset.MaxValue));
}

public sealed class RealtimeCallService
{
    private readonly ICallSignalingTransport _transport;
    private readonly IClock _clock;
    private readonly ReconnectStrategyOptions _options;
    private readonly ConcurrentDictionary<string, RuntimeCallSession> _sessions = new(StringComparer.Ordinal);

    public RealtimeCallService(
        ICallSignalingTransport transport,
        ReconnectStrategyOptions? options = null,
        IClock? clock = null)
    {
        _transport = transport;
        _options = options ?? new ReconnectStrategyOptions();
        _clock = clock ?? new SystemClock();
    }

    public async Task<CallSessionSnapshot> StartOutgoingAsync(
        SessionId local,
        SessionId remote,
        string conversationId,
        CancellationToken cancellationToken = default)
    {
        var callId = Guid.NewGuid().ToString("N");
        var session = new RuntimeCallSession(callId, conversationId, local, remote, _clock.UtcNow);
        _sessions[callId] = session;

        session.State = CallSessionState.Signaling;
        await SendSignalAsync(session, CallSignalType.Offer, new { sdp = "offer" }, cancellationToken).ConfigureAwait(false);
        session.State = CallSessionState.Connecting;
        session.Touch(_clock.UtcNow);

        return session.ToSnapshot();
    }

    public async Task<IReadOnlyList<CallSessionSnapshot>> PollAsync(SessionId local, CancellationToken cancellationToken = default)
    {
        var inbound = await _transport.ReceiveAsync(local, cancellationToken).ConfigureAwait(false);
        var changed = new List<CallSessionSnapshot>();

        foreach (var envelope in inbound)
        {
            var session = _sessions.GetOrAdd(
                envelope.CallId,
                _ => new RuntimeCallSession(envelope.CallId, envelope.ConversationId, local, envelope.Sender, _clock.UtcNow));

            switch (envelope.Type)
            {
                case CallSignalType.Offer:
                    session.State = CallSessionState.Ringing;
                    session.Touch(_clock.UtcNow);
                    changed.Add(session.ToSnapshot());
                    break;

                case CallSignalType.Answer:
                    session.State = CallSessionState.Connected;
                    session.ConsecutivePoorSamples = 0;
                    session.Touch(_clock.UtcNow);
                    changed.Add(session.ToSnapshot());
                    break;

                case CallSignalType.Reconnect:
                    if (session.State is not (CallSessionState.Ended or CallSessionState.Failed))
                    {
                        session.State = CallSessionState.Reconnecting;
                        session.RecordDiagnostic("reconnect-request", "Peer requested reconnection due to degraded link.", _clock.UtcNow);
                        await SendSignalAsync(session, CallSignalType.Answer, new { sdp = "reconnect-answer" }, cancellationToken).ConfigureAwait(false);
                        session.State = CallSessionState.Connected;
                        session.Touch(_clock.UtcNow);
                        changed.Add(session.ToSnapshot());
                    }

                    break;

                case CallSignalType.Bye:
                    session.State = CallSessionState.Ended;
                    session.FailureReason = "remote-hangup";
                    session.Touch(_clock.UtcNow);
                    changed.Add(session.ToSnapshot());
                    break;
            }
        }

        return changed;
    }

    public async Task<CallSessionSnapshot?> AcceptIncomingAsync(string callId, SessionId local, CancellationToken cancellationToken = default)
    {
        if (!_sessions.TryGetValue(callId, out var session))
        {
            return null;
        }

        if (session.State != CallSessionState.Ringing)
        {
            return session.ToSnapshot();
        }

        session.State = CallSessionState.Connecting;
        await SendSignalAsync(session, CallSignalType.Answer, new { sdp = "answer" }, cancellationToken).ConfigureAwait(false);
        session.State = CallSessionState.Connected;
        session.Touch(_clock.UtcNow);
        return session.ToSnapshot();
    }

    public async Task<CallSessionSnapshot?> EndAsync(
        string callId,
        SessionId local,
        string reason = "local-hangup",
        CancellationToken cancellationToken = default)
    {
        if (!_sessions.TryGetValue(callId, out var session))
        {
            return null;
        }

        session.State = CallSessionState.Ended;
        session.FailureReason = reason;
        session.Touch(_clock.UtcNow);
        await SendSignalAsync(session, CallSignalType.Bye, new { reason }, cancellationToken).ConfigureAwait(false);
        return session.ToSnapshot();
    }

    public async Task<CallSessionSnapshot?> ApplyNetworkSampleAsync(
        string callId,
        SessionId local,
        CallNetworkSample sample,
        CancellationToken cancellationToken = default)
    {
        if (!_sessions.TryGetValue(callId, out var session))
        {
            return null;
        }

        session.ApplyQuality(sample, _clock.UtcNow);

        var reasons = EvaluateDegradation(sample);
        if (reasons.Count == 0)
        {
            session.ConsecutivePoorSamples = 0;
            return session.ToSnapshot();
        }

        session.ConsecutivePoorSamples++;
        foreach (var reason in reasons)
        {
            session.RecordDiagnostic(reason.Reason, reason.Details, _clock.UtcNow);
        }

        if (session.ConsecutivePoorSamples < _options.TriggerPoorSamples)
        {
            return session.ToSnapshot();
        }

        if (session.ReconnectAttempts >= _options.MaxAttempts)
        {
            session.State = CallSessionState.Failed;
            session.FailureReason = "reconnect-attempts-exhausted";
            session.RecordDiagnostic(
                "reconnect-attempts-exhausted",
                "Maximum reconnect attempts exhausted during degraded link handling.",
                _clock.UtcNow);
            return session.ToSnapshot();
        }

        session.ReconnectAttempts++;
        session.State = CallSessionState.Reconnecting;
        await SendSignalAsync(session, CallSignalType.Reconnect, new { attempt = session.ReconnectAttempts }, cancellationToken).ConfigureAwait(false);
        session.State = CallSessionState.Connecting;
        session.Touch(_clock.UtcNow);
        return session.ToSnapshot();
    }

    public CallSessionSnapshot? GetSnapshot(string callId)
    {
        return _sessions.TryGetValue(callId, out var session) ? session.ToSnapshot() : null;
    }

    private async Task SendSignalAsync(RuntimeCallSession session, CallSignalType type, object payload, CancellationToken cancellationToken)
    {
        var envelope = new CallSignalEnvelope(
            session.CallId,
            session.ConversationId,
            session.LocalParty,
            session.RemoteParty,
            type,
            JsonSerializer.Serialize(payload),
            _clock.UtcNow);

        await _transport.SendAsync(envelope, cancellationToken).ConfigureAwait(false);
    }

    private List<(string Reason, string Details)> EvaluateDegradation(CallNetworkSample sample)
    {
        var reasons = new List<(string Reason, string Details)>();

        if (sample.PacketLossRatio > _options.MaxPacketLossRatio)
        {
            reasons.Add(("high-packet-loss", $"Packet loss ratio {sample.PacketLossRatio:P1} exceeds {_options.MaxPacketLossRatio:P1}."));
        }

        if (sample.RttMs > _options.MaxRttMs)
        {
            reasons.Add(("high-rtt", $"RTT {sample.RttMs:F0}ms exceeds {_options.MaxRttMs:F0}ms."));
        }

        if (sample.JitterMs > _options.MaxJitterMs)
        {
            reasons.Add(("high-jitter", $"Jitter {sample.JitterMs:F0}ms exceeds {_options.MaxJitterMs:F0}ms."));
        }

        if (sample.AvailableBitrateKbps < _options.MinBitrateKbps)
        {
            reasons.Add(("low-bitrate", $"Bitrate {sample.AvailableBitrateKbps:F0}kbps below {_options.MinBitrateKbps:F0}kbps."));
        }

        return reasons;
    }

    private sealed class RuntimeCallSession
    {
        private double _samples;
        private double _rttAcc;
        private double _jitterAcc;
        private double _lossAcc;

        public RuntimeCallSession(
            string callId,
            string conversationId,
            SessionId localParty,
            SessionId remoteParty,
            DateTimeOffset now)
        {
            CallId = callId;
            ConversationId = conversationId;
            LocalParty = localParty;
            RemoteParty = remoteParty;
            State = CallSessionState.Signaling;
            Quality = new CallQualityMetrics(100, 0, 0, 0, 0, now);
            Diagnostics = [];
        }

        public string CallId { get; }

        public string ConversationId { get; }

        public SessionId LocalParty { get; }

        public SessionId RemoteParty { get; }

        public CallSessionState State { get; set; }

        public CallQualityMetrics Quality { get; private set; }

        public List<CallDegradationDiagnostic> Diagnostics { get; }

        public int ReconnectAttempts { get; set; }

        public int ConsecutivePoorSamples { get; set; }

        public string? FailureReason { get; set; }

        public void Touch(DateTimeOffset at)
        {
            Quality = Quality with { UpdatedAt = at };
        }

        public void RecordDiagnostic(string reason, string details, DateTimeOffset at)
        {
            Diagnostics.Add(new CallDegradationDiagnostic(reason, details, at));
            if (Diagnostics.Count > 32)
            {
                Diagnostics.RemoveRange(0, Diagnostics.Count - 32);
            }
        }

        public void ApplyQuality(CallNetworkSample sample, DateTimeOffset at)
        {
            _samples += 1;
            _rttAcc += sample.RttMs;
            _jitterAcc += sample.JitterMs;
            _lossAcc += sample.PacketLossRatio;

            var avgRtt = _rttAcc / _samples;
            var avgJitter = _jitterAcc / _samples;
            var avgLoss = _lossAcc / _samples;

            var score = 100d;
            score -= avgLoss * 100d * 1.5d;
            score -= avgRtt / 10d;
            score -= avgJitter / 5d;
            score += Math.Min(sample.AvailableBitrateKbps, 512d) / 64d;
            score = Math.Clamp(score, 1d, 100d);

            Quality = new CallQualityMetrics(
                score,
                avgRtt,
                avgJitter,
                avgLoss,
                sample.AvailableBitrateKbps,
                at);
        }

        public CallSessionSnapshot ToSnapshot()
        {
            return new CallSessionSnapshot(
                CallId,
                ConversationId,
                LocalParty,
                RemoteParty,
                State,
                Quality,
                ReconnectAttempts,
                FailureReason,
                Diagnostics.ToArray());
        }
    }
}
