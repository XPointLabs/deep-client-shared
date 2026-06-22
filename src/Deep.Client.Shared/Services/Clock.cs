namespace Deep.Client.Shared.Services;

public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

public sealed class FrozenClock(DateTimeOffset initial) : IClock
{
    public DateTimeOffset UtcNow { get; private set; } = initial;

    public void Advance(TimeSpan value) => UtcNow = UtcNow.Add(value);
}
