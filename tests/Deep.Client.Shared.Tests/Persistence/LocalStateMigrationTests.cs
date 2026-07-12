using System.Reflection;
using System.Runtime.ExceptionServices;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class LocalStateMigrationTests
{
    [Fact]
    public async Task Migration_RestartsAfterEveryTargetStoreFaultWithoutLosingData()
    {
        var exercisedFaults = 0;

        for (var failAtInvocation = 1; failAtInvocation <= 64; failAtInvocation++)
        {
            var directory = CreateTemporaryDirectory();
            var legacyPath = Path.Combine(directory, "client-state.json");
            var targetPath = Path.Combine(directory, "target-state.json");

            try
            {
                var fixture = await CreateLegacySnapshotAsync(legacyPath);
                var target = new InMemorySessionStore(targetPath);
                var faultingTarget = FaultInjectingStoreProxy.Create(target, failAtInvocation, out var fault);

                var firstAttempt = await Record.ExceptionAsync(() =>
                    LocalStateMigration.MigrateLegacyInMemorySnapshotAsync(legacyPath, faultingTarget));

                if (!fault.WasTriggered)
                {
                    Assert.Null(firstAttempt);
                    await AssertImportedAsync(target, fixture);
                    AssertLegacyArtifactsRemoved(legacyPath);
                    break;
                }

                exercisedFaults++;
                Assert.IsType<InjectedMigrationFaultException>(firstAttempt);
                Assert.True(File.Exists(legacyPath));

                var restartedTarget = new InMemorySessionStore(targetPath);
                await LocalStateMigration.MigrateLegacyInMemorySnapshotAsync(legacyPath, restartedTarget);

                await AssertImportedAsync(restartedTarget, fixture);
                AssertLegacyArtifactsRemoved(legacyPath);
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        Assert.True(exercisedFaults >= 10, $"Only {exercisedFaults} migration checkpoints were exercised.");
    }

    [Fact]
    public async Task Migration_UsesValidBackupWhenPrimaryArtifactIsCorrupt()
    {
        var directory = CreateTemporaryDirectory();
        var legacyPath = Path.Combine(directory, "client-state.json");

        try
        {
            var fixture = await CreateLegacySnapshotAsync(legacyPath);
            File.Copy(legacyPath, legacyPath + ".migrated.bak");
            await File.WriteAllTextAsync(legacyPath, "{not-json");

            var target = new InMemorySessionStore();
            var migrated = await LocalStateMigration.MigrateLegacyInMemorySnapshotAsync(legacyPath, target);

            Assert.True(migrated);
            await AssertImportedAsync(target, fixture);
            AssertLegacyArtifactsRemoved(legacyPath);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Migration_RetriesCleanupAfterImportWasCommitted()
    {
        var directory = CreateTemporaryDirectory();
        var legacyPath = Path.Combine(directory, "client-state.json");

        try
        {
            var fixture = await CreateLegacySnapshotAsync(legacyPath);
            File.Copy(legacyPath, legacyPath + ".migrated.bak");
            await File.WriteAllTextAsync(legacyPath + ".stale.tmp", "plaintext-temp-marker");
            var target = new InMemorySessionStore();
            var faultingArtifacts = new ThrowOnceDuringPurgeArtifacts(FileSystemLegacyStateArtifacts.Instance);

            await Assert.ThrowsAsync<InjectedMigrationFaultException>(() =>
                LocalStateMigration.MigrateLegacyInMemorySnapshotAsync(
                    legacyPath,
                    target,
                    artifacts: faultingArtifacts));

            await AssertImportedAsync(target, fixture);
            Assert.True(File.Exists(legacyPath));

            var importedAgain = await LocalStateMigration.MigrateLegacyInMemorySnapshotAsync(legacyPath, target);

            Assert.False(importedAgain);
            await AssertImportedAsync(target, fixture);
            AssertLegacyArtifactsRemoved(legacyPath);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task PurgeLegacyArtifacts_RemovesPrimaryBackupAndInterruptedTemporaryFiles()
    {
        var directory = CreateTemporaryDirectory();
        var legacyPath = Path.Combine(directory, "client-state.json");
        var artifacts = new[]
        {
            legacyPath,
            legacyPath + ".migrated.bak",
            legacyPath + ".a.tmp",
            legacyPath + ".migrated.bak.b.tmp"
        };

        try
        {
            foreach (var artifact in artifacts)
            {
                await File.WriteAllTextAsync(artifact, $"secret:{Path.GetFileName(artifact)}");
            }

            await LocalStateMigration.PurgeLegacyArtifactsAsync(legacyPath);

            Assert.All(artifacts, artifact => Assert.False(File.Exists(artifact), artifact));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Migration_PreservesUnreadableArtifactsInsteadOfMarkingThemComplete()
    {
        var directory = CreateTemporaryDirectory();
        var legacyPath = Path.Combine(directory, "client-state.json");

        try
        {
            await File.WriteAllTextAsync(legacyPath, "not-a-snapshot");
            var target = new InMemorySessionStore();

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                LocalStateMigration.MigrateLegacyInMemorySnapshotAsync(legacyPath, target));

            Assert.True(File.Exists(legacyPath));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string CreateTemporaryDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"deep-legacy-migration-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static async Task<LegacyFixture> CreateLegacySnapshotAsync(string legacyPath)
    {
        var store = new InMemorySessionStore(legacyPath);
        var sender = SessionId.CreateNew();
        var recipient = SessionId.CreateNew();
        var conversationId = ConversationId.ForOneToOne(recipient);
        var messageId = MessageId.NewId();
        var now = DateTimeOffset.Parse("2026-07-11T00:00:00Z");

        await store.UpsertAsync(new Conversation(
            conversationId,
            ConversationKind.OneToOne,
            "Legacy fixture",
            ConversationSettings.Default(ConversationKind.OneToOne),
            now,
            now));
        await store.UpsertAsync(new Contact(
            recipient,
            "Legacy recipient",
            IsApproved: false,
            DidApproveMe: false,
            IsTrusted: true,
            IsBlocked: false,
            now));
        await store.AppendAsync(new Message(
            messageId,
            conversationId,
            sender,
            recipient,
            "legacy-secret-marker",
            MessageDirection.Outgoing,
            MessageDeliveryState.Sent,
            now,
            []));
        await store.SetAsync("legacy.setting", "legacy-value");
        await store.SetSchemaValueAsync("migration.legacy.inmemory.completed", "1");
        await store.SetSchemaValueAsync("legacy.schema", "legacy-schema-value");
        await store.SetSchemaVersionAsync(3);

        return new LegacyFixture(conversationId, messageId, recipient);
    }

    private static async Task AssertImportedAsync(ILocalSessionStore target, LegacyFixture fixture)
    {
        var conversation = await ((IConversationRepository)target).GetAsync(fixture.ConversationId);
        var message = await ((IMessageRepository)target).GetAsync(fixture.MessageId);
        var contact = await ((IContactRepository)target).GetAsync(fixture.ContactId);

        Assert.Equal("Legacy fixture", conversation?.DisplayName);
        Assert.Equal("legacy-secret-marker", message?.Body);
        Assert.Equal("Legacy recipient", contact?.DisplayName);
        Assert.Equal("legacy-value", await target.GetAsync<string>("legacy.setting"));
        Assert.Equal("legacy-schema-value", await target.GetSchemaValueAsync("legacy.schema"));
        Assert.True(await target.GetSchemaVersionAsync() >= 3);
    }

    private static void AssertLegacyArtifactsRemoved(string legacyPath)
    {
        Assert.Empty(FileSystemLegacyStateArtifacts.Instance.EnumerateExistingArtifacts(legacyPath));
        Assert.False(File.Exists(legacyPath));
        Assert.False(File.Exists(legacyPath + ".migrated.bak"));
    }

    private sealed record LegacyFixture(
        ConversationId ConversationId,
        MessageId MessageId,
        SessionId ContactId);

    public class FaultInjectingStoreProxy : DispatchProxy
    {
        private ILocalSessionStore? inner;
        private int failAtInvocation;
        private int invocationCount;

        public bool WasTriggered { get; private set; }

        public static ILocalSessionStore Create(
            ILocalSessionStore inner,
            int failAtInvocation,
            out FaultInjectingStoreProxy controller)
        {
            var proxy = Create<ILocalSessionStore, FaultInjectingStoreProxy>();
            controller = (FaultInjectingStoreProxy)(object)proxy;
            controller.inner = inner;
            controller.failAtInvocation = failAtInvocation;
            return proxy;
        }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            ArgumentNullException.ThrowIfNull(targetMethod);
            if (Interlocked.Increment(ref invocationCount) == failAtInvocation)
            {
                WasTriggered = true;
                throw new InjectedMigrationFaultException($"Injected target-store fault at {targetMethod.Name}.");
            }

            try
            {
                return targetMethod.Invoke(inner, args);
            }
            catch (TargetInvocationException exception) when (exception.InnerException is not null)
            {
                ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
                throw;
            }
        }
    }

    private sealed class ThrowOnceDuringPurgeArtifacts(ILegacyStateArtifacts inner) : ILegacyStateArtifacts
    {
        private int shouldThrow = 1;

        public IReadOnlyList<string> EnumerateExistingArtifacts(string legacyStatePath) =>
            inner.EnumerateExistingArtifacts(legacyStatePath);

        public Task<string> ReadAllTextAsync(
            string artifactPath,
            CancellationToken cancellationToken = default) =>
            inner.ReadAllTextAsync(artifactPath, cancellationToken);

        public Task PurgeAsync(string legacyStatePath, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref shouldThrow, 0) != 0)
            {
                throw new InjectedMigrationFaultException("Injected artifact-cleanup fault.");
            }

            return inner.PurgeAsync(legacyStatePath, cancellationToken);
        }
    }

    private sealed class InjectedMigrationFaultException(string message) : Exception(message);
}
