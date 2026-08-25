namespace Deep.Client.Shared.Services;

public enum ClientMailboxTransportFailure
{
    MalformedRequest = 1,
    AuthenticationRejected = 2,
    AuthorizationRejected = 3,
    ConflictOrExpired = 4,
    PayloadTooLarge = 5,
    UnsupportedMediaType = 6,
    Throttled = 7,
    DependencyUnavailable = 8,
    DeadlineExceeded = 9,
    MethodRejected = 10,
    LengthRequired = 11,
    ProtocolViolation = 12,
    NetworkUnavailable = 13
}

public sealed class ClientMailboxTransportException : IOException
{
    public ClientMailboxTransportException(
        ClientMailboxTransportFailure failure,
        bool retryable,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        if (!Enum.IsDefined(failure))
        {
            throw new ArgumentOutOfRangeException(nameof(failure));
        }

        Failure = failure;
        Retryable = retryable;
    }

    public ClientMailboxTransportFailure Failure { get; }

    public bool Retryable { get; }
}
