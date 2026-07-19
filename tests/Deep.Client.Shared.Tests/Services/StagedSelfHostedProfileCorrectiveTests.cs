using System.Buffers;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.Services;

public sealed class StagedSelfHostedProfileCorrectiveTests
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-07-19T00:00:00Z");

    [Fact]
    public async Task TwoServiceInstancesDoNotLoseConcurrentSaves()
    {
        var store = new InMemorySessionStore();
        var first = new StagedSelfHostedProfileService(store);
        var second = new StagedSelfHostedProfileService(store);
        var scope = Scope(0xA1);

        var saves = Enumerable.Range(1, StagedSelfHostedProfileLimits.MaxCandidatesPerAccount)
            .Select(value => (value & 1) == 0
                ? first.SaveAsync(
                    scope,
                    StagedSelfHostedProfileLimits.SchemaVersion,
                    Bytes(128, checked((byte)value)))
                : second.SaveAsync(
                    scope,
                    StagedSelfHostedProfileLimits.SchemaVersion,
                    Bytes(128, checked((byte)value))))
            .ToArray();
        var outcomes = await Task.WhenAll(saves);

        Assert.All(
            outcomes,
            outcome => Assert.Equal(StagedSelfHostedProfileSaveResult.Saved, outcome.Result));
        var listed = await new StagedSelfHostedProfileService(store).ListAsync(scope);
        Assert.Equal(
            StagedSelfHostedProfileLimits.MaxCandidatesPerAccount,
            listed.Candidates.Count);
    }

    [Fact]
    public async Task TwoServiceInstancesDoNotLoseConcurrentSavesAndDeletes()
    {
        var store = new InMemorySessionStore();
        var first = new StagedSelfHostedProfileService(store);
        var second = new StagedSelfHostedProfileService(store);
        var scope = Scope(0xA2);
        var initial = new List<StagedSelfHostedProfileCandidate>();
        for (var value = 1; value <= 8; value++)
        {
            initial.Add((await first.SaveAsync(
                scope,
                StagedSelfHostedProfileLimits.SchemaVersion,
                Bytes(64, checked((byte)value)))).Candidate!);
        }

        var mutations = initial.Take(4)
            .Select(candidate => (Task)first.DeleteAsync(scope, candidate.Id))
            .Concat(Enumerable.Range(9, 4).Select(value =>
                (Task)second.SaveAsync(
                    scope,
                    StagedSelfHostedProfileLimits.SchemaVersion,
                    Bytes(64, checked((byte)value)))))
            .ToArray();
        await Task.WhenAll(mutations);

        var listed = await first.ListAsync(scope);
        Assert.Equal(8, listed.Candidates.Count);
        Assert.All(initial.Skip(4), candidate => Assert.Contains(candidate, listed.Candidates));
        Assert.All(initial.Take(4), candidate => Assert.DoesNotContain(candidate, listed.Candidates));
    }

    [Fact]
    public async Task WrappedRuntimeSignOutJoinsBlockedSaveAndPurgeCannotBeResurrected()
    {
        var rawStore = new InMemorySessionStore();
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var shouldBlock = 1;
        rawStore.SetAtomicBoundedSettingsFaultInjectorForTests(point =>
        {
            if (point == AtomicBoundedSettingsFaultPoint.BeforeCommit
                && Interlocked.Exchange(ref shouldBlock, 0) == 1)
            {
                entered.Set();
                release.Wait(TimeSpan.FromSeconds(10));
            }
        });
        using var runtime = new ClientRuntime(
            rawStore,
            ClientFeatureFlags.Defaults,
            new FrozenClock(Now),
            new StubSessionBackend());
        await runtime.Accounts.RegisterAsync("Synthetic account");
        var scope = Scope(0xA3);
        var service = new StagedSelfHostedProfileService(
            (IAtomicBoundedSettingsRepository)runtime.Store);

        var save = Task.Run(() => service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(256, 0x63)));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        var signOut = runtime.Accounts.SignOutAsync();
        await Task.Delay(100);
        Assert.False(signOut.IsCompleted);

        release.Set();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => save);
        await signOut.WaitAsync(TimeSpan.FromSeconds(10));
        rawStore.SetAtomicBoundedSettingsFaultInjectorForTests(null);

        var afterPurge = await new StagedSelfHostedProfileService(rawStore).ListAsync(scope);
        Assert.Equal(StagedSelfHostedProfileListResult.Success, afterPurge.Result);
        Assert.Empty(afterPurge.Candidates);
    }

    [Fact]
    public async Task OutcomeUnknownSaveIsReconciledAndDependencyFailureIsTyped()
    {
        var store = new InMemorySessionStore();
        var scope = Scope(0xA4);
        var service = new StagedSelfHostedProfileService(store);

        store.SetAtomicBoundedSettingsFaultInjectorForTests(point =>
        {
            if (point == AtomicBoundedSettingsFaultPoint.AfterCommit)
            {
                throw new SyntheticProviderException("synthetic-provider-secret");
            }
        });
        var reconciled = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(64, 0x71));
        Assert.Equal(StagedSelfHostedProfileSaveResult.Saved, reconciled.Result);

        store.SetAtomicBoundedSettingsFaultInjectorForTests(point =>
        {
            if (point == AtomicBoundedSettingsFaultPoint.BeforeCommit)
            {
                throw new SyntheticProviderException("synthetic-provider-secret");
            }
        });
        var failed = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(64, 0x72));
        Assert.Equal(StagedSelfHostedProfileSaveResult.DependencyFailure, failed.Result);
        Assert.DoesNotContain(
            "synthetic-provider-secret",
            failed.ToString(),
            StringComparison.Ordinal);
        Assert.Single((await new StagedSelfHostedProfileService(store).ListAsync(scope)).Candidates);
    }

    [Fact]
    public async Task HugeCandidateIsRejectedBeforeItsMemoryIsRead()
    {
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());
        using var memory = new ThrowingMemoryManager(
            StagedSelfHostedProfileLimits.MaxCandidateBytes + 1);

        var result = await service.SaveAsync(
            Scope(0xA5),
            StagedSelfHostedProfileLimits.SchemaVersion,
            memory.Memory);

        Assert.Equal(StagedSelfHostedProfileSaveResult.InvalidCandidate, result.Result);
        Assert.False(memory.SpanRequested);
    }

    [Fact]
    public async Task ProviderFailuresAreSanitized()
    {
        var service = new StagedSelfHostedProfileService(
            new InMemorySessionStore(),
            new ThrowingStagingProviders("synthetic-crypto-provider-secret"));

        var outcome = await service.SaveAsync(
            Scope(0xA6),
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(64, 0x73));

        Assert.Equal(StagedSelfHostedProfileSaveResult.DependencyFailure, outcome.Result);
        Assert.DoesNotContain(
            "synthetic-crypto-provider-secret",
            outcome.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task RepositoryMutationExceptionTextIsSanitized()
    {
        var service = new StagedSelfHostedProfileService(
            new ThrowingMutationRepository("synthetic-repository-provider-secret"));

        var outcome = await service.SaveAsync(
            Scope(0xA7),
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(64, 0x74));

        Assert.Equal(StagedSelfHostedProfileSaveResult.DependencyFailure, outcome.Result);
        Assert.DoesNotContain(
            "synthetic-repository-provider-secret",
            outcome.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task PublicAndJsonSurfacesCannotRecoverScopeHandleHintOrBytes()
    {
        var scopeBytes = Bytes(StagedSelfHostedProfileLimits.AccountScopeBytes, 0xB1);
        var scope = SelfHostedProfileStagingAccountScope.FromBytes(scopeBytes);
        const string hint = "Synthetic hidden hint";
        var candidateBytes = Encoding.UTF8.GetBytes("synthetic-hidden-candidate");
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var first = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            candidateBytes,
            hint);
        var second = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(32, 0xB2));
        var candidate = first.Candidate!;
        var surfaces = new object[]
        {
            scope,
            candidate.Id,
            candidate,
            first,
            await service.ListAsync(scope),
            await service.ReadAsync(scope, candidate.Id)
        };

        Assert.Null(typeof(SelfHostedProfileStagingAccountScope).GetMethod("ToArray"));
        Assert.Null(typeof(StagedSelfHostedProfileCandidate).GetProperty("DisplayHint"));
        Assert.Equal(candidate.Id.GetHashCode(), second.Candidate!.Id.GetHashCode());
        Assert.Equal(scope.GetHashCode(), Scope(0xB3).GetHashCode());
        foreach (var surface in surfaces)
        {
            var serialized = JsonSerializer.Serialize(surface, surface.GetType());
            var rendered = surface.ToString() ?? string.Empty;
            Assert.DoesNotContain(Convert.ToHexString(scopeBytes), serialized, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(hint, serialized, StringComparison.Ordinal);
            Assert.DoesNotContain("synthetic-hidden-candidate", serialized, StringComparison.Ordinal);
            Assert.DoesNotContain(hint, rendered, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void SourceChecksCharacterLengthBeforeNormalizationAndDocumentsNonActivation()
    {
        var source = File.ReadAllText(Path.Combine(
            FindRepositoryRoot(),
            "src",
            "Deep.Client.Shared",
            "Services",
            "StagedSelfHostedProfileService.cs"));

        var lengthGate = source.IndexOf(
            "MaxDisplayHintCharacters",
            StringComparison.Ordinal);
        var normalization = source.IndexOf(
            ".Normalize(",
            StringComparison.Ordinal);
        Assert.InRange(lengthGate, 0, normalization - 1);
        Assert.Contains("unverified", source, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("non-activating", source, StringComparison.OrdinalIgnoreCase);
    }

    private static SelfHostedProfileStagingAccountScope Scope(byte value) =>
        SelfHostedProfileStagingAccountScope.FromBytes(Bytes(
            StagedSelfHostedProfileLimits.AccountScopeBytes,
            value));

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
               && !File.Exists(Path.Combine(directory.FullName, "Deep.Client.Shared.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new InvalidOperationException("Repository root was not found.");
    }

    private sealed class SyntheticProviderException(string message) : Exception(message);

    private sealed class ThrowingMutationRepository(string message) :
        IAtomicBoundedSettingsRepository
    {
        public Task<AtomicBoundedSettingReadOutcome> ReadAtomicBoundedSettingAsync(
            string key,
            int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new AtomicBoundedSettingReadOutcome(
                AtomicBoundedSettingReadResult.Missing));

        public Task<AtomicBoundedSettingMutationResult> CreateAtomicBoundedSettingAsync(
            string key,
            ReadOnlyMemory<byte> utf8Json,
            int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default) =>
            throw new SyntheticProviderException(message);

        public Task<AtomicBoundedSettingMutationResult> ReplaceAtomicBoundedSettingAsync(
            string key,
            AtomicBoundedSettingRevision expectedRevision,
            ReadOnlyMemory<byte> utf8Json,
            int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default) =>
            throw new SyntheticProviderException(message);

        public Task<AtomicBoundedSettingMutationResult> DeleteAtomicBoundedSettingAsync(
            string key,
            AtomicBoundedSettingRevision expectedRevision,
            int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default) =>
            throw new SyntheticProviderException(message);
    }

    private sealed class ThrowingStagingProviders(string message) :
        IStagedSelfHostedProfileProviders
    {
        public byte[] CreateCandidateId() => throw new SyntheticProviderException(message);

        public byte[] ComputeFingerprint(ReadOnlySpan<byte> value) =>
            throw new SyntheticProviderException(message);
    }

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
}
