using System.Buffers;
using System.Text.Json;
using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Persistence;

public interface ILegacyStateArtifacts
{
    IReadOnlyList<string> EnumerateExistingArtifacts(string legacyStatePath);

    Task<string> ReadAllTextAsync(
        string artifactPath,
        CancellationToken cancellationToken = default);

    Task PurgeAsync(
        string legacyStatePath,
        CancellationToken cancellationToken = default);
}

public sealed class FileSystemLegacyStateArtifacts : ILegacyStateArtifacts
{
    private const int WipeBufferSize = 64 * 1024;

    public static FileSystemLegacyStateArtifacts Instance { get; } = new();

    public IReadOnlyList<string> EnumerateExistingArtifacts(string legacyStatePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(legacyStatePath);

        var primaryPath = Path.GetFullPath(legacyStatePath);
        var backupPath = primaryPath + ".migrated.bak";
        var artifacts = new List<string>();

        AddIfPresent(artifacts, primaryPath);
        AddIfPresent(artifacts, backupPath);

        var directory = Path.GetDirectoryName(primaryPath);
        if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
        {
            var temporaryPrefix = primaryPath + ".";
            var pathComparison = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;

            artifacts.AddRange(Directory
                .EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly)
                .Where(path => path.StartsWith(temporaryPrefix, pathComparison)
                    && path.EndsWith(".tmp", pathComparison))
                .OrderByDescending(GetLastWriteTimeUtcSafely));
        }

        return artifacts
            .Distinct(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal)
            .ToArray();
    }

    public Task<string> ReadAllTextAsync(
        string artifactPath,
        CancellationToken cancellationToken = default) =>
        File.ReadAllTextAsync(artifactPath, cancellationToken);

    public async Task PurgeAsync(
        string legacyStatePath,
        CancellationToken cancellationToken = default)
    {
        var failures = new List<Exception>();
        foreach (var artifactPath in EnumerateExistingArtifacts(legacyStatePath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await WipeAndDeleteAsync(artifactPath, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                failures.Add(new IOException($"Unable to remove legacy state artifact '{artifactPath}'.", exception));
            }
        }

        if (failures.Count != 0)
        {
            throw new AggregateException("One or more plaintext legacy state artifacts could not be removed.", failures);
        }
    }

    private static void AddIfPresent(ICollection<string> artifacts, string path)
    {
        if (File.Exists(path))
        {
            artifacts.Add(path);
        }
    }

    private static DateTime GetLastWriteTimeUtcSafely(string path)
    {
        try
        {
            return File.GetLastWriteTimeUtc(path);
        }
        catch (IOException)
        {
            return DateTime.MinValue;
        }
        catch (UnauthorizedAccessException)
        {
            return DateTime.MinValue;
        }
    }

    private static async Task WipeAndDeleteAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) == 0)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(WipeBufferSize);
            try
            {
                Array.Clear(buffer);
                await using var stream = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Write,
                    FileShare.None,
                    WipeBufferSize,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                var remaining = stream.Length;
                stream.Position = 0;
                while (remaining > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var count = (int)Math.Min(remaining, buffer.Length);
                    await stream.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                    remaining -= count;
                }

                stream.SetLength(0);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            finally
            {
                Array.Clear(buffer);
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        File.Delete(path);
    }
}

public static class LocalStateMigration
{
    private const string MigrationMarkerKey = "migration.legacy.inmemory.completed";
    private const string MigrationMarkerValue = "1";

    public static async Task<bool> MigrateLegacyInMemorySnapshotAsync(
        string legacyStatePath,
        ILocalSessionStore targetStore,
        CancellationToken cancellationToken = default,
        ILegacyStateArtifacts? artifacts = null)
    {
        if (string.IsNullOrWhiteSpace(legacyStatePath))
        {
            return false;
        }

        ArgumentNullException.ThrowIfNull(targetStore);
        artifacts ??= FileSystemLegacyStateArtifacts.Instance;

        if (await MigrationCompletedAsync(targetStore, cancellationToken).ConfigureAwait(false))
        {
            await artifacts.PurgeAsync(legacyStatePath, cancellationToken).ConfigureAwait(false);
            return false;
        }

        var snapshot = await ReadFirstValidSnapshotAsync(
            legacyStatePath,
            artifacts,
            cancellationToken).ConfigureAwait(false);
        if (snapshot is null)
        {
            return false;
        }

        foreach (var conversation in snapshot.Conversations ?? [])
        {
            await targetStore.UpsertAsync(conversation, cancellationToken).ConfigureAwait(false);
        }

        foreach (var contact in snapshot.Contacts ?? [])
        {
            await targetStore.UpsertAsync(contact, cancellationToken).ConfigureAwait(false);
        }

        foreach (var group in snapshot.Groups ?? [])
        {
            await targetStore.UpsertAsync(group, cancellationToken).ConfigureAwait(false);
        }

        foreach (var message in snapshot.Messages ?? [])
        {
            await targetStore.AppendAsync(message, cancellationToken).ConfigureAwait(false);
        }

        foreach (var setting in snapshot.Settings ?? [])
        {
            JsonElement value;
            try
            {
                value = JsonSerializer.Deserialize<JsonElement>(setting.Value);
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException(
                    $"Legacy setting '{setting.Key}' contains an invalid JSON payload.",
                    exception);
            }

            await targetStore.SetAsync(setting.Key, value, cancellationToken).ConfigureAwait(false);
        }

        foreach (var schemaValue in snapshot.SchemaValues ?? [])
        {
            if (string.Equals(schemaValue.Key, MigrationMarkerKey, StringComparison.Ordinal))
            {
                continue;
            }

            await targetStore.SetSchemaValueAsync(
                schemaValue.Key,
                schemaValue.Value,
                cancellationToken).ConfigureAwait(false);
        }

        var targetVersion = Math.Max(
            await targetStore.GetSchemaVersionAsync(cancellationToken).ConfigureAwait(false),
            snapshot.SchemaVersion);
        await targetStore.SetSchemaVersionAsync(targetVersion, cancellationToken).ConfigureAwait(false);
        await targetStore.SetSchemaValueAsync(
            MigrationMarkerKey,
            MigrationMarkerValue,
            cancellationToken).ConfigureAwait(false);

        if (!await MigrationCompletedAsync(targetStore, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("Legacy state import was not durably committed.");
        }

        await artifacts.PurgeAsync(legacyStatePath, cancellationToken).ConfigureAwait(false);
        return true;
    }

    public static Task PurgeLegacyArtifactsAsync(
        string legacyStatePath,
        CancellationToken cancellationToken = default,
        ILegacyStateArtifacts? artifacts = null)
    {
        if (string.IsNullOrWhiteSpace(legacyStatePath))
        {
            return Task.CompletedTask;
        }

        return (artifacts ?? FileSystemLegacyStateArtifacts.Instance)
            .PurgeAsync(legacyStatePath, cancellationToken);
    }

    private static async Task<bool> MigrationCompletedAsync(
        ISchemaStore targetStore,
        CancellationToken cancellationToken) =>
        string.Equals(
            await targetStore.GetSchemaValueAsync(MigrationMarkerKey, cancellationToken).ConfigureAwait(false),
            MigrationMarkerValue,
            StringComparison.Ordinal);

    private static async Task<LegacyInMemorySnapshot?> ReadFirstValidSnapshotAsync(
        string legacyStatePath,
        ILegacyStateArtifacts artifacts,
        CancellationToken cancellationToken)
    {
        var candidates = artifacts.EnumerateExistingArtifacts(legacyStatePath);
        if (candidates.Count == 0)
        {
            return null;
        }

        var failures = new List<Exception>();
        foreach (var candidatePath in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var json = await artifacts.ReadAllTextAsync(candidatePath, cancellationToken).ConfigureAwait(false);
                var snapshot = JsonSerializer.Deserialize<LegacyInMemorySnapshot>(
                    json,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web));
                if (snapshot is not null)
                {
                    return snapshot;
                }

                failures.Add(new JsonException($"Legacy state artifact '{candidatePath}' contained no snapshot."));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException
                or JsonException
                or NotSupportedException)
            {
                failures.Add(exception);
            }
        }

        throw new InvalidDataException(
            "Legacy state artifacts exist, but none contains a valid snapshot. The artifacts were preserved for recovery.",
            failures.Count == 1 ? failures[0] : new AggregateException(failures));
    }

    private sealed record LegacyInMemorySnapshot(
        IReadOnlyList<Conversation>? Conversations,
        IReadOnlyList<Contact>? Contacts,
        IReadOnlyList<Group>? Groups,
        IReadOnlyList<Message>? Messages,
        IReadOnlyList<KeyValuePair<string, string>>? Settings,
        IReadOnlyList<KeyValuePair<string, string>>? SchemaValues,
        int SchemaVersion);
}
