using System.Diagnostics;
using System.Reflection;
using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class TransportOutboxIteration6RedTests
{
    private const string EncryptionKeyCanary =
        "p11a-iter6-encryption-key-canary-a9d2e5c71f43";

    [Fact]
    public void SqliteOptions_PublicStructuredSurfaceCannotRevealEncryptionKey()
    {
        var options = new SqliteSessionStoreOptions(
            Path.Combine(Path.GetTempPath(), "p11a-iter6-options.db"),
            EncryptionKeyCanary);
        var publicType = typeof(SqliteSessionStoreOptions);

        var keyNamedMembers = publicType
            .GetMembers(BindingFlags.Instance | BindingFlags.Public)
            .Where(member => member.MemberType is
                MemberTypes.Property or MemberTypes.Field or MemberTypes.Method)
            .Where(member => member.Name.Contains("EncryptionKey", StringComparison.OrdinalIgnoreCase))
            .Select(member => $"{member.MemberType}:{member.Name}")
            .ToArray();
        var structuredValues = DestructurePublicValues(options);

        Assert.Empty(keyNamedMembers);
        Assert.DoesNotContain(
            structuredValues,
            pair => pair.Value?.ToString()?.Contains(
                EncryptionKeyCanary,
                StringComparison.Ordinal) == true);
    }

    [Fact]
    public void SqliteOptions_PrivateKeyIsHiddenFromDebuggerExpansion()
    {
        var field = typeof(SqliteSessionStoreOptions).GetField(
            "encryptionKey",
            BindingFlags.Instance | BindingFlags.NonPublic);

        Assert.NotNull(field);
        var debuggerBrowsable = field.GetCustomAttribute<DebuggerBrowsableAttribute>();
        Assert.NotNull(debuggerBrowsable);
        Assert.Equal(DebuggerBrowsableState.Never, debuggerBrowsable.State);
    }

    [Fact]
    public async Task SqliteOptions_PrivateKeyStillOpensAndReopensEncryptedDatabase()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-p11a-iter6-private-key-{Guid.NewGuid():N}.db");
        try
        {
            using (var store = new SqliteSessionStore(
                       new SqliteSessionStoreOptions(path, EncryptionKeyCanary)))
            {
                await store.SetAsync("p11a.iter6.encrypted", "persisted");
            }

            SqliteConnection.ClearAllPools();
            Assert.ThrowsAny<Exception>(() => new SqliteSessionStore(path));

            using var reopened = new SqliteSessionStore(
                new SqliteSessionStoreOptions(path, EncryptionKeyCanary));
            Assert.Equal(
                "persisted",
                await reopened.GetAsync<string>("p11a.iter6.encrypted"));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            {
                if (File.Exists(candidate))
                {
                    File.Delete(candidate);
                }
            }
        }
    }

    private static IReadOnlyDictionary<string, object?> DestructurePublicValues(
        SqliteSessionStoreOptions options)
    {
        var values = new Dictionary<string, object?>(StringComparer.Ordinal);
        var type = options.GetType();
        foreach (var property in type.GetProperties(BindingFlags.Instance | BindingFlags.Public))
        {
            if (property.GetIndexParameters().Length == 0 && property.GetMethod is not null)
            {
                values[$"property:{property.Name}"] = property.GetValue(options);
            }
        }

        foreach (var field in type.GetFields(BindingFlags.Instance | BindingFlags.Public))
        {
            values[$"field:{field.Name}"] = field.GetValue(options);
        }

        foreach (var method in type.GetMethods(BindingFlags.Instance | BindingFlags.Public)
                     .Where(method =>
                         !method.IsSpecialName &&
                         method.GetParameters().Length == 0 &&
                         method.ReturnType != typeof(void)))
        {
            values[$"method:{method.Name}"] = method.Invoke(options, null);
        }

        return values;
    }
}
