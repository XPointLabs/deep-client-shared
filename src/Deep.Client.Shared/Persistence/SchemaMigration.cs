namespace Deep.Client.Shared.Persistence;

public interface ISchemaStore
{
    Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default);

    Task SetSchemaVersionAsync(int version, CancellationToken cancellationToken = default);

    Task SetSchemaValueAsync(string key, string value, CancellationToken cancellationToken = default);

    Task<string?> GetSchemaValueAsync(string key, CancellationToken cancellationToken = default);
}

public sealed record SchemaMigration(
    int FromVersion,
    int ToVersion,
    string Name,
    Func<ISchemaStore, CancellationToken, Task> ApplyAsync);

public sealed class LocalSchemaMigrator(IReadOnlyList<SchemaMigration> migrations)
{
    public async Task<int> MigrateAsync(ISchemaStore store, CancellationToken cancellationToken = default)
    {
        var version = await store.GetSchemaVersionAsync(cancellationToken).ConfigureAwait(false);

        foreach (var migration in migrations.OrderBy(item => item.FromVersion))
        {
            if (migration.FromVersion != version)
            {
                continue;
            }

            await migration.ApplyAsync(store, cancellationToken).ConfigureAwait(false);
            await store.SetSchemaVersionAsync(migration.ToVersion, cancellationToken).ConfigureAwait(false);
            version = migration.ToVersion;
        }

        return version;
    }
}

public static class LocalSchemaMigrations
{
    public const int LatestVersion = 4;

    public static IReadOnlyList<SchemaMigration> Default { get; } =
    [
        new(0, 1, "Initial conversations contacts groups messages",
            (store, ct) => store.SetSchemaValueAsync("schema.1", "domain-tables", ct)),
        new(1, 2, "Attachment metadata encrypted pointer columns",
            (store, ct) => store.SetSchemaValueAsync("schema.2", "attachment-pointer-metadata", ct)),
        new(2, 3, "Config sync cursors and namespace tracking",
            (store, ct) => store.SetSchemaValueAsync("schema.3", "sync-cursors", ct)),
        new(3, 4, "Installation scoped membership trust records",
            (store, ct) => store.SetSchemaValueAsync("schema.4", "membership-trust-lkg", ct))
    ];
}
