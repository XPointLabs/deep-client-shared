namespace Deep.Client.Shared.Domain;

public sealed record SessionAccount(
    SessionId SessionId,
    string DisplayName,
    DateTimeOffset RegisteredAt,
    bool IsRestoredAccount = false);
