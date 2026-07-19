using System.Diagnostics;
using System.Text;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Services;

public sealed class StagedSelfHostedProfileServiceTests
{
    [Fact]
    public async Task AccountsAreIsolatedAndSettingsKeysContainOnlyDerivedOpaqueScope()
    {
        var settings = new RecordingSettingsRepository(new InMemorySessionStore());
        var service = new StagedSelfHostedProfileService(settings);
        var firstScope = Scope(0xA1);
        var secondScope = Scope(0xB2);

        var first = await service.SaveAsync(
            firstScope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(32, 0x31));
        var second = await service.SaveAsync(
            secondScope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(32, 0x31));

        Assert.Equal(StagedSelfHostedProfileSaveResult.Saved, first.Result);
        Assert.Equal(StagedSelfHostedProfileSaveResult.Saved, second.Result);
        Assert.Single((await service.ListAsync(firstScope)).Candidates);
        Assert.Single((await service.ListAsync(secondScope)).Candidates);
        Assert.Equal(2, settings.Keys.Distinct(StringComparer.Ordinal).Count());
        Assert.All(settings.Keys, key =>
        {
            Assert.StartsWith("account.self-hosted-staging.v1.", key, StringComparison.Ordinal);
            Assert.DoesNotContain(
                Convert.ToHexString(firstScope.ToArray()),
                key,
                StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(
                Convert.ToHexString(secondScope.ToArray()),
                key,
                StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("label", key, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public async Task SaveListReadAndExportUseDefensiveCopies()
    {
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var source = Bytes(64, 0x42);
        var expected = source.ToArray();

        var saved = await service.SaveAsync(
            Scope(0x11),
            StagedSelfHostedProfileLimits.SchemaVersion,
            source,
            "Cafe\u0301");
        source.AsSpan().Fill(0xEE);

        Assert.Equal(StagedSelfHostedProfileSaveResult.Saved, saved.Result);
        Assert.Equal("Café", saved.Candidate?.DisplayHint);
        var listed = await service.ListAsync(Scope(0x11));
        var read = await service.ReadAsync(Scope(0x11), saved.Candidate!.Id);
        var exported = await service.ExportAsync(Scope(0x11), saved.Candidate.Id);

        Assert.Equal(StagedSelfHostedProfileListResult.Success, listed.Result);
        Assert.Equal(StagedSelfHostedProfileReadResult.Found, read.Result);
        Assert.Equal(saved.Candidate, Assert.Single(listed.Candidates));
        Assert.Equal(saved.Candidate, read.Candidate);
        Assert.Equal(StagedSelfHostedProfileExportResult.Exported, exported.Result);
        var firstCopy = exported.GetCandidateBytesCopy();
        Assert.Equal(expected, firstCopy);
        firstCopy.AsSpan().Fill(0xDD);
        Assert.Equal(
            expected,
            (await service.ExportAsync(Scope(0x11), saved.Candidate.Id))
                .GetCandidateBytesCopy());
        Assert.Throws<NotSupportedException>(
            () => ((IList<StagedSelfHostedProfileCandidate>)listed.Candidates).Clear());
    }

    [Fact]
    public async Task DuplicateCandidateBytesAreIdempotentWithinOneAccount()
    {
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = Scope(0x12);
        var bytes = Bytes(128, 0x51);

        var first = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            bytes,
            "First hint");
        var duplicate = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            bytes,
            "Ignored duplicate hint");

        Assert.Equal(StagedSelfHostedProfileSaveResult.Saved, first.Result);
        Assert.Equal(StagedSelfHostedProfileSaveResult.Idempotent, duplicate.Result);
        Assert.Equal(first.Candidate, duplicate.Candidate);
        Assert.Single((await service.ListAsync(scope)).Candidates);
    }

    [Fact]
    public async Task ItemCountBoundaryAcceptsSixteenAndRejectsSeventeenth()
    {
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = Scope(0x13);

        for (var value = 1; value <= StagedSelfHostedProfileLimits.MaxCandidatesPerAccount; value++)
        {
            var outcome = await service.SaveAsync(
                scope,
                StagedSelfHostedProfileLimits.SchemaVersion,
                Bytes(1, checked((byte)value)));
            Assert.Equal(StagedSelfHostedProfileSaveResult.Saved, outcome.Result);
        }

        var rejected = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(1, 0xFE));

        Assert.Equal(StagedSelfHostedProfileSaveResult.CapacityExceeded, rejected.Result);
        Assert.Equal(
            StagedSelfHostedProfileLimits.MaxCandidatesPerAccount,
            (await service.ListAsync(scope)).Candidates.Count);
    }

    [Fact]
    public async Task ItemByteBoundaryAcceptsExactLimitAndRejectsOneByteOver()
    {
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());

        var accepted = await service.SaveAsync(
            Scope(0x14),
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(StagedSelfHostedProfileLimits.MaxCandidateBytes, 0x61));
        var rejected = await service.SaveAsync(
            Scope(0x15),
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(StagedSelfHostedProfileLimits.MaxCandidateBytes + 1, 0x62));

        Assert.Equal(StagedSelfHostedProfileSaveResult.Saved, accepted.Result);
        Assert.Equal(StagedSelfHostedProfileSaveResult.InvalidCandidate, rejected.Result);
        Assert.Empty((await service.ListAsync(Scope(0x15))).Candidates);
    }

    [Fact]
    public async Task AccountByteBoundaryAcceptsExactLimitAndRejectsOneByteOver()
    {
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = Scope(0x16);

        for (var value = 1; value <= 8; value++)
        {
            var outcome = await service.SaveAsync(
                scope,
                StagedSelfHostedProfileLimits.SchemaVersion,
                Bytes(StagedSelfHostedProfileLimits.MaxCandidateBytes, checked((byte)value)));
            Assert.Equal(StagedSelfHostedProfileSaveResult.Saved, outcome.Result);
        }

        Assert.Equal(
            StagedSelfHostedProfileLimits.MaxAccountCandidateBytes,
            (await service.ListAsync(scope)).Candidates.Sum(candidate => candidate.CandidateByteLength));
        var rejected = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(1, 0xF1));
        Assert.Equal(StagedSelfHostedProfileSaveResult.CapacityExceeded, rejected.Result);
    }

    [Theory]
    [InlineData(0, null)]
    [InlineData(2, null)]
    [InlineData(1, "line\nbreak")]
    [InlineData(1, "override\u202E")]
    [InlineData(1, "isolate\u2066")]
    public async Task InvalidSchemaEmptyBytesAndUnsafeHintsFailClosed(
        int schemaVersion,
        string? displayHint)
    {
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var bytes = schemaVersion == 0 ? Array.Empty<byte>() : Bytes(1, 0x71);

        var outcome = await service.SaveAsync(Scope(0x17), schemaVersion, bytes, displayHint);

        Assert.Equal(StagedSelfHostedProfileSaveResult.InvalidCandidate, outcome.Result);
        Assert.Empty((await service.ListAsync(Scope(0x17))).Candidates);
    }

    [Fact]
    public async Task DisplayHintUsesUtf8ByteLimit()
    {
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());

        var exact = await service.SaveAsync(
            Scope(0x18),
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(1, 0x72),
            new string('é', 32));
        var over = await service.SaveAsync(
            Scope(0x19),
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(1, 0x73),
            new string('é', 33));

        Assert.Equal(StagedSelfHostedProfileSaveResult.Saved, exact.Result);
        Assert.Equal(StagedSelfHostedProfileSaveResult.InvalidCandidate, over.Result);
    }

    [Fact]
    public async Task CorruptCatalogReturnsTypedBoundedResultsAndIsNotOverwritten()
    {
        var inner = new InMemorySessionStore();
        var settings = new RecordingSettingsRepository(inner);
        var service = new StagedSelfHostedProfileService(settings);
        var scope = Scope(0x20);
        var initial = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(8, 0x74));
        var key = Assert.Single(settings.Keys.Distinct(StringComparer.Ordinal));
        await inner.SetAsync(key, "synthetic-corrupt-value");
        settings.Reset();

        var listed = await service.ListAsync(scope);
        var read = await service.ReadAsync(scope, initial.Candidate!.Id);
        var exported = await service.ExportAsync(scope, initial.Candidate.Id);
        var saved = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(8, 0x75));
        var deleted = await service.DeleteAsync(scope, initial.Candidate.Id);

        Assert.Equal(StagedSelfHostedProfileListResult.Corrupt, listed.Result);
        Assert.Empty(listed.Candidates);
        Assert.Equal(StagedSelfHostedProfileReadResult.Corrupt, read.Result);
        Assert.Null(read.Candidate);
        Assert.Equal(StagedSelfHostedProfileExportResult.Corrupt, exported.Result);
        Assert.Empty(exported.GetCandidateBytesCopy());
        Assert.Equal(StagedSelfHostedProfileSaveResult.Corrupt, saved.Result);
        Assert.Equal(StagedSelfHostedProfileDeleteResult.Corrupt, deleted);
        Assert.Empty(settings.SetKeys);
        Assert.Empty(settings.DeleteKeys);
        Assert.Equal("synthetic-corrupt-value", await inner.GetAsync<string>(key));
    }

    [Fact]
    public async Task UnknownPersistedSchemaAndOversizedPersistedValuesAreCorrupt()
    {
        var inner = new InMemorySessionStore();
        var settings = new RecordingSettingsRepository(inner);
        var service = new StagedSelfHostedProfileService(settings);
        var scope = Scope(0x21);
        await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(1, 0x76));
        var key = Assert.Single(settings.Keys.Distinct(StringComparer.Ordinal));

        await inner.SetAsync(key, new
        {
            Version = StagedSelfHostedProfileLimits.SchemaVersion + 1,
            Items = Array.Empty<object>()
        });
        Assert.Equal(
            StagedSelfHostedProfileListResult.Corrupt,
            (await service.ListAsync(scope)).Result);

        await inner.SetAsync(key, new
        {
            Version = StagedSelfHostedProfileLimits.SchemaVersion,
            Items = new[]
            {
                new
                {
                    Id = Bytes(16, 0x77),
                    Fingerprint = Bytes(32, 0x78),
                    CandidateBytes = Bytes(
                        StagedSelfHostedProfileLimits.MaxCandidateBytes + 1,
                        0x79),
                    DisplayHint = (string?)null
                }
            }
        });
        Assert.Equal(
            StagedSelfHostedProfileListResult.Corrupt,
            (await service.ListAsync(scope)).Result);
    }

    [Fact]
    public async Task ConcurrentMutationsOnOneServiceDoNotLoseCommittedCandidates()
    {
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = Scope(0x22);
        var initial = new List<StagedSelfHostedProfileCandidate>();
        for (var value = 1; value <= 8; value++)
        {
            var saved = await service.SaveAsync(
                scope,
                StagedSelfHostedProfileLimits.SchemaVersion,
                Bytes(32, checked((byte)value)));
            initial.Add(saved.Candidate!);
        }

        var deletes = initial
            .Take(4)
            .Select(candidate => service.DeleteAsync(scope, candidate.Id));
        var saves = Enumerable.Range(9, 4)
            .Select(value => service.SaveAsync(
                scope,
                StagedSelfHostedProfileLimits.SchemaVersion,
                Bytes(32, checked((byte)value))));
        await Task.WhenAll(deletes.Cast<Task>().Concat(saves));

        var listed = await service.ListAsync(scope);
        Assert.Equal(StagedSelfHostedProfileListResult.Success, listed.Result);
        Assert.Equal(8, listed.Candidates.Count);
        Assert.DoesNotContain(listed.Candidates, candidate =>
            initial.Take(4).Any(removed => removed.Id.Equals(candidate.Id)));
        Assert.All(initial.Skip(4), candidate => Assert.Contains(candidate, listed.Candidates));
    }

    [Fact]
    public async Task FailedPersistenceMutationLeavesPreviousCatalogReadable()
    {
        var repository = new FaultingSettingsRepository(new InMemorySessionStore());
        var service = new StagedSelfHostedProfileService(repository);
        var scope = Scope(0x23);
        var first = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(16, 0x81));
        repository.FailNextSet("synthetic-sensitive-fault-text");

        var exception = await Assert.ThrowsAsync<StagedSelfHostedProfilePersistenceException>(
            () => service.SaveAsync(
                scope,
                StagedSelfHostedProfileLimits.SchemaVersion,
                Bytes(16, 0x82)));

        Assert.Equal("Staged self-hosted profile persistence failed.", exception.Message);
        Assert.DoesNotContain("synthetic-sensitive-fault-text", exception.ToString(), StringComparison.Ordinal);
        var listed = await service.ListAsync(scope);
        Assert.Equal(StagedSelfHostedProfileListResult.Success, listed.Result);
        Assert.Equal(first.Candidate, Assert.Single(listed.Candidates));
        Assert.Equal(
            Bytes(16, 0x81),
            (await service.ExportAsync(scope, first.Candidate!.Id)).GetCandidateBytesCopy());
    }

    [Fact]
    public async Task CancellationPropagatesAndDoesNotMutateCatalog()
    {
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = Scope(0x24);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.SaveAsync(
                scope,
                StagedSelfHostedProfileLimits.SchemaVersion,
                Bytes(8, 0x83),
                cancellationToken: cancellation.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.ListAsync(scope, cancellation.Token));

        Assert.Empty((await service.ListAsync(scope)).Candidates);
    }

    [Fact]
    public async Task AccountPurgeRemovesStagedCatalogAcrossServiceInstances()
    {
        var store = new InMemorySessionStore();
        var scope = Scope(0x25);
        var service = new StagedSelfHostedProfileService(store);
        await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            Bytes(8, 0x84));

        await store.PurgeAccountDataAsync();

        var restartedService = new StagedSelfHostedProfileService(store);
        var listed = await restartedService.ListAsync(scope);
        Assert.Equal(StagedSelfHostedProfileListResult.Success, listed.Result);
        Assert.Empty(listed.Candidates);
    }

    [Fact]
    public async Task SqlCipherSettingsProtectSyntheticBytesAndPurgeSurvivesRestart()
    {
        var statePath = Path.Combine(
            Path.GetTempPath(),
            $"deep-staged-profile-{Guid.NewGuid():N}.db");
        var encryptionKey = Convert.ToHexString(Bytes(32, 0x91));
        var scope = Scope(0x27);
        var candidateBytes = Bytes(512, 0x92);
        try
        {
            using (var store = new SqliteSessionStore(
                       new SqliteSessionStoreOptions(statePath, encryptionKey)))
            {
                var service = new StagedSelfHostedProfileService(store);
                var saved = await service.SaveAsync(
                    scope,
                    StagedSelfHostedProfileLimits.SchemaVersion,
                    candidateBytes);
                Assert.Equal(StagedSelfHostedProfileSaveResult.Saved, saved.Result);
                SqliteConnection.ClearAllPools();
                Assert.False(ContainsSequence(File.ReadAllBytes(statePath), candidateBytes));

                await store.PurgeAccountDataAsync();
            }

            using (var restarted = new SqliteSessionStore(
                       new SqliteSessionStoreOptions(statePath, encryptionKey)))
            {
                var listed = await new StagedSelfHostedProfileService(restarted).ListAsync(scope);
                Assert.Equal(StagedSelfHostedProfileListResult.Success, listed.Result);
                Assert.Empty(listed.Candidates);
            }
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task PublicDebugStringAndExceptionSurfacesAreRedacted()
    {
        var service = new StagedSelfHostedProfileService(new InMemorySessionStore());
        var scope = Scope(0x26);
        const string hint = "Synthetic private hint";
        var bytes = Encoding.UTF8.GetBytes("synthetic-candidate-marker");
        var saved = await service.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            bytes,
            hint);
        var candidate = saved.Candidate!;
        var surfaces = new object[]
        {
            scope,
            candidate.Id,
            candidate,
            saved,
            await service.ListAsync(scope),
            await service.ReadAsync(scope, candidate.Id),
            await service.ExportAsync(scope, candidate.Id)
        };

        foreach (var value in surfaces)
        {
            var rendered = value.ToString() ?? string.Empty;
            Assert.DoesNotContain(hint, rendered, StringComparison.Ordinal);
            Assert.DoesNotContain("synthetic-candidate-marker", rendered, StringComparison.Ordinal);
            Assert.DoesNotContain(Convert.ToHexString(scope.ToArray()), rendered, StringComparison.OrdinalIgnoreCase);
            var debuggerDisplay = value.GetType()
                .GetCustomAttributes(typeof(DebuggerDisplayAttribute), inherit: false)
                .Cast<DebuggerDisplayAttribute>()
                .SingleOrDefault()?.Value ?? string.Empty;
            Assert.DoesNotContain(hint, debuggerDisplay, StringComparison.Ordinal);
            Assert.DoesNotContain("Id", debuggerDisplay, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ProductionSourceHasNoVerifierNetworkBillingOrRuntimeCompositionDependency()
    {
        var root = FindRepositoryRoot();
        var source = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Deep.Client.Shared",
            "Services",
            "StagedSelfHostedProfileService.cs"));
        var forbidden = new[]
        {
            "MembershipContractVerifier",
            "ImportSelfHostedGenesis",
            "HttpClient",
            "ISessionMessageTransport",
            "ClientRuntime",
            "wallet",
            "billing",
            "subscription",
            "XPNT",
            "endpoint",
            "Dns",
            "ILogger",
            "Console."
        };

        Assert.All(forbidden, value =>
            Assert.DoesNotContain(value, source, StringComparison.OrdinalIgnoreCase));
    }

    private static SelfHostedProfileStagingAccountScope Scope(byte value) =>
        SelfHostedProfileStagingAccountScope.FromBytes(Bytes(
            StagedSelfHostedProfileLimits.AccountScopeBytes,
            value));

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private static bool ContainsSequence(byte[] source, byte[] candidate) =>
        source.AsSpan().IndexOf(candidate) >= 0;

    private static void DeleteSqliteFiles(string statePath)
    {
        SqliteConnection.ClearAllPools();
        foreach (var path in new[] { statePath, statePath + "-wal", statePath + "-shm" })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

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

    private sealed class RecordingSettingsRepository(ISettingsRepository inner)
        : ISettingsRepository
    {
        private readonly List<string> keys = [];
        private readonly List<string> setKeys = [];
        private readonly List<string> deleteKeys = [];

        public IReadOnlyList<string> Keys => keys;
        public IReadOnlyList<string> SetKeys => setKeys;
        public IReadOnlyList<string> DeleteKeys => deleteKeys;

        public async Task SetAsync<T>(
            string key,
            T value,
            CancellationToken cancellationToken = default)
        {
            keys.Add(key);
            setKeys.Add(key);
            await inner.SetAsync(key, value, cancellationToken);
        }

        public async Task<T?> GetAsync<T>(
            string key,
            CancellationToken cancellationToken = default)
        {
            keys.Add(key);
            return await inner.GetAsync<T>(key, cancellationToken);
        }

        public async Task DeleteAsync(
            string key,
            CancellationToken cancellationToken = default)
        {
            keys.Add(key);
            deleteKeys.Add(key);
            await inner.DeleteAsync(key, cancellationToken);
        }

        public void Reset()
        {
            keys.Clear();
            setKeys.Clear();
            deleteKeys.Clear();
        }
    }

    private sealed class FaultingSettingsRepository(ISettingsRepository inner)
        : ISettingsRepository
    {
        private string? nextSetFailure;

        public void FailNextSet(string message) => nextSetFailure = message;

        public Task SetAsync<T>(
            string key,
            T value,
            CancellationToken cancellationToken = default)
        {
            if (nextSetFailure is { } message)
            {
                nextSetFailure = null;
                throw new IOException(message);
            }

            return inner.SetAsync(key, value, cancellationToken);
        }

        public Task<T?> GetAsync<T>(
            string key,
            CancellationToken cancellationToken = default) =>
            inner.GetAsync<T>(key, cancellationToken);

        public Task DeleteAsync(
            string key,
            CancellationToken cancellationToken = default) =>
            inner.DeleteAsync(key, cancellationToken);
    }
}
