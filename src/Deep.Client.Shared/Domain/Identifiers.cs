using System.Security.Cryptography;

namespace Deep.Client.Shared.Domain;

public readonly record struct SessionId(string Value)
{
    private static readonly string[] AllowedPrefixes = ["05", "15", "25"];

    public static SessionId Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var normalized = value.Trim().ToLowerInvariant();

        if (normalized.Length != 66 || !AllowedPrefixes.Any(normalized.StartsWith) || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("Session IDs must be 66 hex characters and use a Session account/blinded prefix.", nameof(value));
        }

        return new SessionId(normalized);
    }

    public static SessionId CreateNew()
    {
        var publicKey = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        return new SessionId($"05{publicKey}");
    }

    public override string ToString() => Value;
}

public readonly record struct ConversationId(string Value)
{
    public static ConversationId Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return new ConversationId(value.Trim().ToLowerInvariant());
    }

    public static ConversationId ForOneToOne(SessionId sessionId) => new(sessionId.Value);

    public static ConversationId CreateGroupV2()
    {
        var publicKey = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        return new ConversationId($"03{publicKey}");
    }

    public static ConversationId ForCommunity(string serverUrl, string roomToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverUrl);
        ArgumentException.ThrowIfNullOrWhiteSpace(roomToken);
        return new ConversationId($"{serverUrl.TrimEnd('/').ToLowerInvariant()}/{roomToken.Trim().ToLowerInvariant()}");
    }

    public override string ToString() => Value;
}

public readonly record struct MessageId(string Value)
{
    public static MessageId NewId() => new(Guid.NewGuid().ToString("n"));

    public static MessageId Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return new MessageId(value.Trim());
    }

    public override string ToString() => Value;
}
