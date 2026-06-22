using System.Text.Json;
using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Persistence;

public static class LocalStateMigration
{
    private const string MigrationMarkerKey = "migration.legacy.inmemory.completed";

    public static async Task<bool> MigrateLegacyInMemorySnapshotAsync(
        string legacyStatePath,
        ILocalSessionStore targetStore,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(legacyStatePath) || !File.Exists(legacyStatePath))
        {
            return false;
        }

        if (string.Equals(await targetStore.GetSchemaValueAsync(MigrationMarkerKey, cancellationToken).ConfigureAwait(false), "1", StringComparison.Ordinal))
        {
            return false;
        }

        var json = await File.ReadAllTextAsync(legacyStatePath, cancellationToken).ConfigureAwait(false);
        var snapshot = JsonSerializer.Deserialize<LegacyInMemorySnapshot>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        if (snapshot is null)
        {
            return false;
        }

        foreach (var conversation in snapshot.Conversations)
        {
            await targetStore.UpsertAsync(conversation, cancellationToken).ConfigureAwait(false);
        }

        foreach (var contact in snapshot.Contacts)
        {
            await targetStore.UpsertAsync(contact, cancellationToken).ConfigureAwait(false);
        }

        foreach (var group in snapshot.Groups)
        {
            await targetStore.UpsertAsync(group, cancellationToken).ConfigureAwait(false);
        }

        foreach (var message in snapshot.Messages)
        {
            await targetStore.AppendAsync(message, cancellationToken).ConfigureAwait(false);
        }

        foreach (var setting in snapshot.Settings)
        {
            await targetStore.SetAsync(setting.Key, setting.Value, cancellationToken).ConfigureAwait(false);
        }

        foreach (var schemaValue in snapshot.SchemaValues)
        {
            await targetStore.SetSchemaValueAsync(schemaValue.Key, schemaValue.Value, cancellationToken).ConfigureAwait(false);
        }

        var targetVersion = Math.Max(await targetStore.GetSchemaVersionAsync(cancellationToken).ConfigureAwait(false), snapshot.SchemaVersion);
        await targetStore.SetSchemaVersionAsync(targetVersion, cancellationToken).ConfigureAwait(false);
        await targetStore.SetSchemaValueAsync(MigrationMarkerKey, "1", cancellationToken).ConfigureAwait(false);

        var backupPath = legacyStatePath + ".migrated.bak";
        File.Copy(legacyStatePath, backupPath, overwrite: true);
        return true;
    }

    private sealed record LegacyInMemorySnapshot(
        IReadOnlyList<Conversation> Conversations,
        IReadOnlyList<Contact> Contacts,
        IReadOnlyList<Group> Groups,
        IReadOnlyList<Message> Messages,
        IReadOnlyList<KeyValuePair<string, string>> Settings,
        IReadOnlyList<KeyValuePair<string, string>> SchemaValues,
        int SchemaVersion);
}
