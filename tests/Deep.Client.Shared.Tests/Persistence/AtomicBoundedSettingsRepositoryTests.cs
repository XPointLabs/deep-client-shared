using System.Buffers;
using System.Text;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class AtomicBoundedSettingsRepositoryTests
{
    private const int MaximumValueBytes = 2048;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CreateReplaceDeleteHaveExactCasParity(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var repository = (IAtomicBoundedSettingsRepository)scope.Store;
        var key = Key("parity");
        var firstValue = JsonBytes(0x11);
        var secondValue = JsonBytes(0x12);

        var missing = await repository.ReadAtomicBoundedSettingAsync(
            key,
            MaximumValueBytes);
        Assert.Equal(AtomicBoundedSettingReadResult.Missing, missing.Result);

        Assert.Equal(
            AtomicBoundedSettingMutationResult.Applied,
            await repository.CreateAtomicBoundedSettingAsync(
                key,
                firstValue,
                MaximumValueBytes));
        Assert.Equal(
            AtomicBoundedSettingMutationResult.Conflict,
            await repository.CreateAtomicBoundedSettingAsync(
                key,
                secondValue,
                MaximumValueBytes));

        var first = await repository.ReadAtomicBoundedSettingAsync(
            key,
            MaximumValueBytes);
        Assert.Equal(AtomicBoundedSettingReadResult.Found, first.Result);
        Assert.Equal(firstValue, first.GetValueCopy());
        Assert.NotNull(first.Revision);
        var wrongRevision = AtomicBoundedSettingRevision.FromBytes(Bytes(16, 0xF1));

        Assert.Equal(
            AtomicBoundedSettingMutationResult.Conflict,
            await repository.ReplaceAtomicBoundedSettingAsync(
                key,
                wrongRevision,
                secondValue,
                MaximumValueBytes));
        Assert.Equal(
            AtomicBoundedSettingMutationResult.Applied,
            await repository.ReplaceAtomicBoundedSettingAsync(
                key,
                first.Revision!,
                secondValue,
                MaximumValueBytes));

        var second = await repository.ReadAtomicBoundedSettingAsync(
            key,
            MaximumValueBytes);
        Assert.Equal(secondValue, second.GetValueCopy());
        Assert.NotEqual(first.Revision, second.Revision);
        Assert.Equal(
            AtomicBoundedSettingMutationResult.Conflict,
            await repository.DeleteAtomicBoundedSettingAsync(
                key,
                first.Revision!,
                MaximumValueBytes));
        Assert.Equal(
            AtomicBoundedSettingMutationResult.Applied,
            await repository.DeleteAtomicBoundedSettingAsync(
                key,
                second.Revision!,
                MaximumValueBytes));
        Assert.Equal(
            AtomicBoundedSettingMutationResult.Missing,
            await repository.DeleteAtomicBoundedSettingAsync(
                key,
                second.Revision!,
                MaximumValueBytes));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentStoresApplyOnlyOneMutationForOneRevision(bool sqlite)
    {
        using var scope = StorePairScope.Create(sqlite);
        var first = (IAtomicBoundedSettingsRepository)scope.First;
        var second = (IAtomicBoundedSettingsRepository)scope.Second;

        for (var iteration = 0; iteration < 12; iteration++)
        {
            var key = Key($"conflict-{iteration}");
            var creates = await Task.WhenAll(
                first.CreateAtomicBoundedSettingAsync(
                    key,
                    JsonBytes(checked((byte)(iteration + 1))),
                    MaximumValueBytes),
                second.CreateAtomicBoundedSettingAsync(
                    key,
                    JsonBytes(checked((byte)(iteration + 32))),
                    MaximumValueBytes));
            Assert.Single(
                creates,
                result => result == AtomicBoundedSettingMutationResult.Applied);
            Assert.Single(
                creates,
                result => result == AtomicBoundedSettingMutationResult.Conflict);

            var read = await first.ReadAtomicBoundedSettingAsync(
                key,
                MaximumValueBytes);
            var replaces = await Task.WhenAll(
                first.ReplaceAtomicBoundedSettingAsync(
                    key,
                    read.Revision!,
                    JsonBytes(0x81),
                    MaximumValueBytes),
                second.ReplaceAtomicBoundedSettingAsync(
                    key,
                    read.Revision!,
                    JsonBytes(0x82),
                    MaximumValueBytes));
            Assert.Single(
                replaces,
                result => result == AtomicBoundedSettingMutationResult.Applied);
            Assert.Single(
                replaces,
                result => result == AtomicBoundedSettingMutationResult.Conflict);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BeforeAndAfterCommitFaultsAreDistinguished(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var repository = (IAtomicBoundedSettingsRepository)scope.Store;
        var beforeKey = Key("before");
        var afterKey = Key("after");

        scope.SetFaultInjector(point =>
        {
            if (point == AtomicBoundedSettingsFaultPoint.BeforeCommit)
            {
                throw new SyntheticProviderException("synthetic-provider-secret");
            }
        });
        var before = await repository.CreateAtomicBoundedSettingAsync(
            beforeKey,
            JsonBytes(0x21),
            MaximumValueBytes);
        Assert.Equal(AtomicBoundedSettingMutationResult.DependencyFailure, before);
        Assert.Equal(
            AtomicBoundedSettingReadResult.Missing,
            (await repository.ReadAtomicBoundedSettingAsync(
                beforeKey,
                MaximumValueBytes)).Result);

        scope.SetFaultInjector(point =>
        {
            if (point == AtomicBoundedSettingsFaultPoint.AfterCommit)
            {
                throw new SyntheticProviderException("synthetic-provider-secret");
            }
        });
        var after = await repository.CreateAtomicBoundedSettingAsync(
            afterKey,
            JsonBytes(0x22),
            MaximumValueBytes);
        Assert.Equal(AtomicBoundedSettingMutationResult.OutcomeUnknown, after);
        Assert.Equal(
            AtomicBoundedSettingReadResult.Found,
            (await repository.ReadAtomicBoundedSettingAsync(
                afterKey,
                MaximumValueBytes)).Result);
        Assert.DoesNotContain(
            "synthetic-provider-secret",
            after.ToString(),
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OversizedStoredValueIsRejectedBeforeEnvelopeDeserialization(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var generic = (ISettingsRepository)scope.Store;
        var repository = (IAtomicBoundedSettingsRepository)scope.Store;
        var key = Key("oversized");
        await generic.SetAsync(key, new string('{', 4096));

        var read = await repository.ReadAtomicBoundedSettingAsync(key, 64);
        var delete = await repository.DeleteAtomicBoundedSettingAsync(
            key,
            AtomicBoundedSettingRevision.FromBytes(Bytes(16, 0x31)),
            64);

        Assert.Equal(AtomicBoundedSettingReadResult.Oversized, read.Result);
        Assert.Empty(read.GetValueCopy());
        Assert.Equal(AtomicBoundedSettingMutationResult.TooLarge, delete);
        Assert.NotNull(await generic.GetAsync<string>(key));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InputLimitsAreCheckedBeforeReadingValueMemory(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var repository = (IAtomicBoundedSettingsRepository)scope.Store;
        using var memory = new ThrowingMemoryManager(
            AtomicBoundedSettingsLimits.MaximumValueUtf8Bytes + 1);

        var result = await repository.CreateAtomicBoundedSettingAsync(
            Key("huge-memory"),
            memory.Memory,
            AtomicBoundedSettingsLimits.MaximumValueUtf8Bytes);
        var hugeKey = new string('k', AtomicBoundedSettingsLimits.MaximumKeyCharacters + 1);
        var keyResult = await repository.CreateAtomicBoundedSettingAsync(
            hugeKey,
            JsonBytes(0x41),
            MaximumValueBytes);

        Assert.Equal(AtomicBoundedSettingMutationResult.TooLarge, result);
        Assert.Equal(AtomicBoundedSettingMutationResult.TooLarge, keyResult);
        Assert.False(memory.SpanRequested);
    }

    [Fact]
    public async Task RevisionsAndOutcomesDoNotExposeOrCorrelateStoredMaterial()
    {
        using var scope = StoreScope.Create(sqlite: false);
        var repository = (IAtomicBoundedSettingsRepository)scope.Store;
        var key = Key("privacy");
        var value = Encoding.UTF8.GetBytes("{\"marker\":\"synthetic-private-value\"}");
        await repository.CreateAtomicBoundedSettingAsync(
            key,
            value,
            MaximumValueBytes);
        var first = await repository.ReadAtomicBoundedSettingAsync(
            key,
            MaximumValueBytes);
        await repository.ReplaceAtomicBoundedSettingAsync(
            key,
            first.Revision!,
            JsonBytes(0x52),
            MaximumValueBytes);
        var second = await repository.ReadAtomicBoundedSettingAsync(
            key,
            MaximumValueBytes);

        var rendered = string.Join(
            "|",
            first,
            second,
            first.Revision,
            second.Revision);
        Assert.DoesNotContain(key, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-private-value", rendered, StringComparison.Ordinal);
        Assert.Equal(first.Revision!.GetHashCode(), second.Revision!.GetHashCode());
        Assert.Empty(
            typeof(AtomicBoundedSettingRevision).GetMethods()
                .Where(method => method.IsPublic && method.Name is "ToArray" or "GetBytes"));
    }

    private static string Key(string suffix) =>
        $"account.synthetic-bounded.{suffix}";

    private static byte[] JsonBytes(byte value) =>
        Encoding.UTF8.GetBytes($"{{\"v\":{value}}}");

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed class SyntheticProviderException(string message) : Exception(message);

    private sealed class ThrowingMemoryManager(int length) : MemoryManager<byte>
    {
        public bool SpanRequested { get; private set; }

        public override Span<byte> GetSpan()
        {
            SpanRequested = true;
            throw new InvalidOperationException("The oversized memory was materialized.");
        }

        public override MemoryHandle Pin(int elementIndex = 0) =>
            throw new InvalidOperationException("The oversized memory was pinned.");

        public override void Unpin()
        {
        }

        protected override void Dispose(bool disposing)
        {
        }

        public override Memory<byte> Memory => CreateMemory(length);
    }

    private sealed class StoreScope : IDisposable
    {
        private readonly string? statePath;

        private StoreScope(ILocalSessionStore store, string? statePath)
        {
            Store = store;
            this.statePath = statePath;
        }

        public ILocalSessionStore Store { get; }

        public static StoreScope Create(bool sqlite)
        {
            if (!sqlite)
            {
                return new(new InMemorySessionStore(), null);
            }

            var path = Path.Combine(
                Path.GetTempPath(),
                $"deep-bounded-settings-{Guid.NewGuid():N}.db");
            return new(new SqliteSessionStore(path), path);
        }

        public void SetFaultInjector(Action<AtomicBoundedSettingsFaultPoint>? injector)
        {
            switch (Store)
            {
                case InMemorySessionStore memory:
                    memory.SetAtomicBoundedSettingsFaultInjectorForTests(injector);
                    break;
                case SqliteSessionStore sqlite:
                    sqlite.SetAtomicBoundedSettingsFaultInjectorForTests(injector);
                    break;
            }
        }

        public void Dispose()
        {
            (Store as IDisposable)?.Dispose();
            if (statePath is not null)
            {
                DeleteSqliteFiles(statePath);
            }
        }
    }

    private sealed class StorePairScope : IDisposable
    {
        private readonly string? statePath;

        private StorePairScope(
            ILocalSessionStore first,
            ILocalSessionStore second,
            string? statePath)
        {
            First = first;
            Second = second;
            this.statePath = statePath;
        }

        public ILocalSessionStore First { get; }
        public ILocalSessionStore Second { get; }

        public static StorePairScope Create(bool sqlite)
        {
            if (!sqlite)
            {
                var store = new InMemorySessionStore();
                return new(store, store, null);
            }

            var path = Path.Combine(
                Path.GetTempPath(),
                $"deep-bounded-settings-pair-{Guid.NewGuid():N}.db");
            return new(
                new SqliteSessionStore(path),
                new SqliteSessionStore(path),
                path);
        }

        public void Dispose()
        {
            (First as IDisposable)?.Dispose();
            if (!ReferenceEquals(First, Second))
            {
                (Second as IDisposable)?.Dispose();
            }
            if (statePath is not null)
            {
                DeleteSqliteFiles(statePath);
            }
        }
    }

    private static void DeleteSqliteFiles(string statePath)
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var path in new[] { statePath, statePath + "-wal", statePath + "-shm" })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
