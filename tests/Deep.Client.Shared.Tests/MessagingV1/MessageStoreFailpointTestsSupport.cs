using Deep.Client.Shared.Persistence.MessagingV1;

namespace Deep.Client.Shared.Tests.MessagingV1;

internal sealed class InjectedMessageStoreCrashException : IOException
{
    internal InjectedMessageStoreCrashException(string window)
        : base($"Injected MSG-01 crash at {window}.") => Window = window;

    internal string Window { get; }
}

internal sealed class ArmableMessageStoreFailpoint : IMessageStoreFailpoint
{
    private string? armedWindow;

    internal void Arm(string window) =>
        Volatile.Write(ref armedWindow, window ?? throw new ArgumentNullException(nameof(window)));

    internal void Disarm() => Volatile.Write(ref armedWindow, null);

    public void Hit(string window)
    {
        if (string.Equals(Interlocked.CompareExchange(ref armedWindow, null, window),
            window, StringComparison.Ordinal))
            throw new InjectedMessageStoreCrashException(window);
    }
}
