using System.Diagnostics;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// A process-independent local mutation lease for the V2 account owner.
/// The lock file is persistent; only its open handle is transient.
/// </summary>
internal sealed class DeepIdV2AccountFileLease
{
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMilliseconds(50);
    private static readonly TimeSpan MaximumWait = TimeSpan.FromSeconds(30);
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

    internal async ValueTask<FileStream> AcquireAsync(
        CancellationToken cancellationToken)
    {
        var elapsed = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(path, FileMode.OpenOrCreate,
                    FileAccess.ReadWrite, FileShare.None, 1,
                    FileOptions.Asynchronous);
            }
            catch (IOException) when (elapsed.Elapsed < MaximumWait)
            {
                await Task.Delay(RetryDelay, cancellationToken)
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
}
