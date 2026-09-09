using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Services.ContactV1;

public enum ContactResolverTransportFailureKind
{
    TransientBeforeDispatch = 1,
    OutcomeUnknown = 2,
    Permanent = 3,
}

public sealed class ContactResolverTransportException : Exception
{
    public ContactResolverTransportException(
        ContactResolverTransportFailureKind failure,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        if (!Enum.IsDefined(failure)) throw new ArgumentOutOfRangeException(nameof(failure));
        Failure = failure;
    }

    public ContactResolverTransportFailureKind Failure { get; }
}

public sealed class ContactResolverTransportAttemptId32
{
    private readonly byte[] value;

    internal ContactResolverTransportAttemptId32(ReadOnlySpan<byte> value)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A transport attempt ID must be exactly 32 nonzero bytes.", nameof(value));
        this.value = value.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => value.ToArray();
}

/// <summary>
/// One bounded opaque XIQ1 dispatch. Operation identity lives inside exactXiq1;
/// AttemptId identifies only this transport attempt and changes on retry.
/// </summary>
public sealed class ContactResolverTransportRequest
{
    public const int MaximumExactXiq1Bytes = 65_535;
    private readonly byte[] exactXiq1;

    internal ContactResolverTransportRequest(
        ReadOnlySpan<byte> exactXiq1,
        ContactResolverTransportAttemptId32 attemptId)
    {
        ArgumentNullException.ThrowIfNull(attemptId);
        if (exactXiq1.IsEmpty || exactXiq1.Length > MaximumExactXiq1Bytes)
            throw new ArgumentException("Exact XIQ1 is outside its closed wire bound.", nameof(exactXiq1));
        this.exactXiq1 = exactXiq1.ToArray();
        AttemptId = attemptId;
    }

    public ReadOnlyMemory<byte> ExactXiq1 => exactXiq1.ToArray();
    public ContactResolverTransportAttemptId32 AttemptId { get; }
}

/// <summary>Bounded opaque XIS1 bytes returned by the invite-store transport.</summary>
public sealed class ContactResolverTransportResponse
{
    public const int MaximumExactXis1Bytes = 131_072;
    private readonly byte[] exactXis1;

    public ContactResolverTransportResponse(ReadOnlySpan<byte> exactXis1)
    {
        if (exactXis1.IsEmpty || exactXis1.Length > MaximumExactXis1Bytes)
            throw new ArgumentException("Exact XIS1 is outside its closed wire bound.", nameof(exactXis1));
        this.exactXis1 = exactXis1.ToArray();
    }

    public ReadOnlyMemory<byte> ExactXis1 => exactXis1.ToArray();
}

public interface IContactResolverTransport
{
    ValueTask<ContactResolverTransportResponse> SendXiq1Async(
        ContactResolverTransportRequest request,
        CancellationToken cancellationToken = default);
}
