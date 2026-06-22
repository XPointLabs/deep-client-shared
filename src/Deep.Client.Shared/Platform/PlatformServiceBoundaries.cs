namespace Deep.Client.Shared.Platform;

using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

public enum PermissionKind
{
    Camera,
    Microphone,
    Photos,
    Notifications,
    Contacts
}

public enum PermissionState
{
    Unknown,
    Granted,
    Denied,
    Restricted
}

public sealed record PushRegistration(string Token, string Provider, DateTimeOffset RegisteredAt);

public sealed record MediaTranscodeRequest(string SourcePath, string TargetContentType, long MaxBytes);

public sealed record MediaTranscodeResult(string OutputPath, string ContentType, long SizeBytes);

public sealed record SharePayload(string? Text, IReadOnlyList<string> FilePaths);

public interface IPushNotificationService
{
    Task<PushRegistration?> RegisterAsync(CancellationToken cancellationToken = default);

    Task<PushRegistration?> GetCachedRegistrationAsync(CancellationToken cancellationToken = default);

    Task UnregisterAsync(CancellationToken cancellationToken = default);
}

public interface IMediaCodecService
{
    Task<MediaTranscodeResult> TranscodeAsync(MediaTranscodeRequest request, CancellationToken cancellationToken = default);
}

public interface IPermissionsService
{
    Task<PermissionState> GetAsync(PermissionKind permission, CancellationToken cancellationToken = default);

    Task<PermissionState> RequestAsync(PermissionKind permission, CancellationToken cancellationToken = default);
}

public interface IBackgroundTaskService
{
    Task ScheduleSyncAsync(TimeSpan minimumDelay, CancellationToken cancellationToken = default);
}

public interface IShareExtensionBridge
{
    Task<IReadOnlyList<SharePayload>> DrainPendingSharesAsync(CancellationToken cancellationToken = default);
}

public interface ICallService
{
    bool IsAvailable { get; }

    Task<CallSessionSnapshot> StartAsync(
        SessionId local,
        SessionId remote,
        string conversationId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<CallSessionSnapshot>> PollAsync(
        SessionId local,
        CancellationToken cancellationToken = default);

    Task<CallSessionSnapshot?> AcceptAsync(
        string callId,
        SessionId local,
        CancellationToken cancellationToken = default);

    Task<CallSessionSnapshot?> EndAsync(
        string callId,
        SessionId local,
        string reason = "local-hangup",
        CancellationToken cancellationToken = default);

    Task<CallSessionSnapshot?> ApplyNetworkSampleAsync(
        string callId,
        SessionId local,
        CallNetworkSample sample,
        CancellationToken cancellationToken = default);
}
