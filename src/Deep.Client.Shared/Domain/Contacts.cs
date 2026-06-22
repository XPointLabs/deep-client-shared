namespace Deep.Client.Shared.Domain;

public sealed record Contact(
    SessionId Id,
    string? DisplayName,
    bool IsApproved,
    bool DidApproveMe,
    bool IsTrusted,
    bool IsBlocked,
    DateTimeOffset UpdatedAt)
{
    public static Contact Self(SessionId id, string displayName, DateTimeOffset now) =>
        new(id, displayName, IsApproved: true, DidApproveMe: true, IsTrusted: true, IsBlocked: false, now);

    public static Contact Request(SessionId id, string? displayName, DateTimeOffset now) =>
        new(id, displayName, IsApproved: false, DidApproveMe: false, IsTrusted: false, IsBlocked: false, now);
}
