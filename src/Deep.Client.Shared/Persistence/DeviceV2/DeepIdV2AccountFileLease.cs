using System.Diagnostics;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// A process-independent local mutation lease for the V2 account owner.
/// The lock file is persistent; only its open handle is transient.
/// </summary>
internal sealed class DeepIdV2AccountFileLease
{
    private readonly string path;

    internal DeepIdV2AccountFileLease(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        this.path = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(this.path);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            throw new ArgumentException(
                "The V2 account lease requires an existing private directory.",
                nameof(path));
    }

    internal string ExactPath => path;
    internal HeldDeepIdV2AccountLease? TryAcquire() => HeldDeepIdV2AccountLease.TryAcquire(this);
    internal ValueTask<HeldDeepIdV2AccountLease> AcquireAsync(CancellationToken cancellationToken) =>
        HeldDeepIdV2AccountLease.AcquireAsync(this, cancellationToken);
}

/// <summary>Closed actual file-lock ownership. Read borrows retain the lock even
/// if its owner concurrently disposes; a disposed owner can release no results.</summary>
internal sealed class HeldDeepIdV2AccountLease : IDisposable
{
    private readonly object gate = new();
    private readonly string path;
    private FileStream? stream;
    private bool disposed;
    private int readers;
    private HeldDeepIdV2AccountLease(string path, FileStream stream)
    { this.path = path; this.stream = stream; }

    internal static HeldDeepIdV2AccountLease? TryAcquire(DeepIdV2AccountFileLease owner)
    {
        try { return new(owner.ExactPath, new FileStream(owner.ExactPath, FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None, 1, FileOptions.Asynchronous)); }
        catch (IOException) { return null; }
    }

    internal static async ValueTask<HeldDeepIdV2AccountLease> AcquireAsync(
        DeepIdV2AccountFileLease owner, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(owner);
        var elapsed = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var stream = new FileStream(owner.ExactPath, FileMode.OpenOrCreate,
                    FileAccess.ReadWrite, FileShare.None, 1,
                    FileOptions.Asynchronous);
                return new(owner.ExactPath, stream);
            }
            catch (IOException) when (elapsed.Elapsed < TimeSpan.FromSeconds(30))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (IOException exception)
            {
                throw new TimeoutException(
                    "The V2 account mutation lease did not become available.",
                    exception);
            }
        }
    }

    // Only a network wait may suspend ownership. No borrowed read is allowed
    // to retain the file while another account operation enters.
    internal void SuspendForNetworkWait()
    {
        lock (gate)
        {
            RequireActive();
            if (readers != 0) throw new InvalidOperationException("An account read borrow crossed network handoff.");
            stream!.Dispose(); stream = null;
        }
    }
    internal async Task RejoinAfterNetworkWaitAsync(CancellationToken ct)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (stream is not null) throw new InvalidOperationException("Account lease is already held.");
        }
        using var acquired = await AcquireAsync(new DeepIdV2AccountFileLease(path), ct).ConfigureAwait(false);
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (stream is not null) throw new InvalidOperationException("Account lease rejoined twice.");
            stream = acquired.stream; acquired.stream = null;
        }
    }

    internal void RequireOwner(DeepIdV2AccountFileLease expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed || stream is null, this);
            if (!string.Equals(path, expected.ExactPath, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new System.Security.Cryptography.CryptographicException("The held account lease belongs to another private account.");
        }
    }
    internal void RequireActive()
    {
        lock (gate) ObjectDisposedException.ThrowIf(disposed || stream is null, this);
    }
    internal IDisposable BorrowFor(DeepIdV2AccountFileLease expected)
    {
        lock (gate)
        {
            RequireOwner(expected); readers++;
            return new ReadBorrow(this);
        }
    }
    private void ReleaseRead()
    {
        lock (gate)
        {
            if (--readers < 0) throw new InvalidOperationException("Account read lease was released twice.");
            if (disposed && readers == 0) { stream?.Dispose(); stream = null; }
        }
    }
    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return; disposed = true;
            if (readers == 0) { stream?.Dispose(); stream = null; }
        }
        GC.SuppressFinalize(this);
    }
    ~HeldDeepIdV2AccountLease() => Dispose();
    private sealed class ReadBorrow(HeldDeepIdV2AccountLease owner) : IDisposable
    {
        private HeldDeepIdV2AccountLease? held = owner;
        public void Dispose() => Interlocked.Exchange(ref held, null)?.ReleaseRead();
    }
}
