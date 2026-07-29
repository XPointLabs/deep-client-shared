namespace Deep.Client.Shared.Persistence;

public enum LocalStateResetRequiredReason
{
    UnsupportedVersion,
    InvalidCurrentSchema,
    UnreadableOrWrongKey
}

public sealed class LocalStateResetRequiredException : Exception
{
    public LocalStateResetRequiredException(
        LocalStateResetRequiredReason reason,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Reason = reason;
    }

    public LocalStateResetRequiredReason Reason { get; }
}
