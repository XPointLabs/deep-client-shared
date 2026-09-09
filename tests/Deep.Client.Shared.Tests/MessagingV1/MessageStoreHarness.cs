using System.Security.Cryptography;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.MessagingV1;

internal sealed class MessageStoreHarness : IAsyncDisposable
{
    private readonly string kind;
    private readonly string? directory;
    private readonly string? path;
    private readonly byte[]? key;
    private readonly InMemoryMessageStoreBacking? backing;
    private readonly IMessageStoreFailpoint? failpoint;
    private readonly Msg01VerifiedSessionAuthority authority;
    private SharedMessagingV1Composition composition;

    private MessageStoreHarness(
        string kind,
        MessageStoreScope scope,
        SharedMessagingV1Composition composition,
        InMemoryMessageStoreBacking? backing,
        string? directory,
        string? path,
        byte[]? key,
        Msg01VerifiedSessionAuthority authority,
        IMessageStoreFailpoint? failpoint)
    {
        this.kind = kind;
        Scope = scope;
        this.composition = composition;
        this.backing = backing;
        this.directory = directory;
        this.path = path;
        this.key = key;
        this.authority = authority;
        this.failpoint = failpoint;
    }

    internal MessageStoreScope Scope { get; }
    internal SharedMessagingV1Composition Composition => composition;
    internal IMessageTransactionStore Store => composition.Store;
    internal IMessageVerifiedTransportHandoff Capabilities => composition.VerifiedTransport;
    internal IMessageGroupDispatchSafetyHandoff GroupDispatchSafety =>
        composition.GroupDispatchSafety;
    internal string? Path => path;
    internal byte[]? KeyCopy => key?.ToArray();

    internal static MessageStoreHarness Create(string kind, MessageStoreScope? scope = null,
        IMessageStoreFailpoint? failpoint = null)
    {
        scope ??= MessagingV1Fixture.Scope();
        var authority = MessagingV1Fixture.CreateEvidenceAuthority();
        if (kind == "memory")
        {
            var backing = new InMemoryMessageStoreBacking(scope);
            var memoryComposition = SharedMessagingV1Composition.AttachOwned(
                new InMemoryMessageTransactionStore(
                    backing, authority, failpoint));
            return new(kind, scope, memoryComposition,
                backing, null, null, null, authority, failpoint);
        }
        if (kind != "sqlite") throw new ArgumentOutOfRangeException(nameof(kind));
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"deep-msg01-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = System.IO.Path.Combine(directory, "messages.db");
        var key = MessagingV1Fixture.Bytes(32, 0x5151);
        var sqliteComposition = SharedMessagingV1Composition.AttachOwned(
            SqliteMessageStoreBootstrap.Open(new(
                path, key, scope, authority,
                failpoint: failpoint)));
        return new(kind, scope, sqliteComposition, null, directory, path, key, authority, failpoint);
    }

    internal Task ReopenAsync()
    {
        composition.Dispose();
        composition = SharedMessagingV1Composition.AttachOwned(kind == "memory"
            ? new InMemoryMessageTransactionStore(
                backing!, authority, failpoint)
            : SqliteMessageStoreBootstrap.Open(new(
                path!, key!, Scope, authority, allowCreate: false,
                failpoint: failpoint)));
        return Task.CompletedTask;
    }

    internal Task CrashReopenAsync()
    {
        var abandoned = composition;
        composition = SharedMessagingV1Composition.AttachOwned(kind == "memory"
            ? new InMemoryMessageTransactionStore(
                backing!, authority, failpoint)
            : SqliteMessageStoreBootstrap.Open(new(
                path!, key!, Scope, authority, allowCreate: false,
                failpoint: failpoint)));
        abandoned.Dispose();
        return Task.CompletedTask;
    }

    internal IMessageTransactionStore OpenSibling() => kind == "memory"
        ? new InMemoryMessageTransactionStore(
            backing!, authority, failpoint)
        : SqliteMessageStoreBootstrap.Open(new(
            path!, key!, Scope, authority, allowCreate: false));

    internal IMessageTransactionStore OpenSiblingWithEvidenceKey(byte[] evidenceVerificationKey) =>
        kind == "memory"
            ? new InMemoryMessageTransactionStore(backing!,
                Msg01VerifiedSessionAuthority.CreateTestEd25519(evidenceVerificationKey), failpoint)
            : SqliteMessageStoreBootstrap.Open(new(
                path!, key!, Scope,
                Msg01VerifiedSessionAuthority.CreateTestEd25519(evidenceVerificationKey),
                allowCreate: false));

    internal SqliteConnection OpenRawSqlite(byte[]? overrideKey = null)
    {
        if (path is null || key is null) throw new InvalidOperationException();
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Mode = SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private, Pooling = false
        }.ToString());
        connection.Open();
        var selectedKey = overrideKey ?? key;
        if (SQLitePCL.raw.sqlite3_key(connection.Handle, selectedKey) != SQLitePCL.raw.SQLITE_OK)
        {
            connection.Dispose();
            throw new InvalidOperationException("SQLCipher rejected a test key.");
        }
        return connection;
    }

    public async ValueTask DisposeAsync()
    {
        composition.Dispose();
        if (path is not null)
        {
            await SqliteMessageStoreBootstrap.ResetAsync(path);
        }
        if (key is not null) CryptographicOperations.ZeroMemory(key);
        if (directory is not null && Directory.Exists(directory)) Directory.Delete(directory, recursive: false);
    }
}
