using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Client.Shared.Tests.Services;

public sealed class DormantSelfHostedProfileVerificationCorrectiveC1Tests
{
    private const string BarrierSentinel = "synthetic-account-generation-barrier-secret";
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(10);
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-22T00:00:00Z");

    [Fact]
    public void ExportOutcomeTransfersItsOnlyOwnedSnapshotExactlyOnce()
    {
        var payload = Enumerable.Repeat((byte)0x6d, 4_096).ToArray();
        var outcome = new StagedSelfHostedProfileExportOutcome(
            StagedSelfHostedProfileExportResult.Exported,
            payload);
        var field = typeof(StagedSelfHostedProfileExportOutcome).GetField(
            "candidateBytes",
            BindingFlags.Instance | BindingFlags.NonPublic);
        var transfer = typeof(StagedSelfHostedProfileExportOutcome).GetMethod(
            "TakeCandidateBytesForVerification",
            BindingFlags.Instance | BindingFlags.NonPublic);

        Assert.NotNull(field);
        Assert.NotNull(transfer);
        var originallyOwned = Assert.IsType<byte[]>(field.GetValue(outcome));
        var taken = Assert.IsType<byte[]>(transfer.Invoke(outcome, null));

        Assert.Same(originallyOwned, taken);
        Assert.Equal(payload, taken);
        Assert.Empty(outcome.GetCandidateBytesCopy());
        Assert.Empty(Assert.IsType<byte[]>(transfer.Invoke(outcome, null)));

        CryptographicOperations.ZeroMemory(taken);
        Assert.All(taken, value => Assert.Equal(0, value));
        Assert.Empty(Assert.IsType<byte[]>(field.GetValue(outcome)));
    }

    [Fact]
    public async Task SignOutBarrierCancellationIsAFixedSanitizedCancellation()
    {
        var inner = new InMemorySessionStore();
        var blockingStore = BlockingAtomicReadStoreProxy.Create(inner, out var controller);
        using var runtime = new ClientRuntime(
            blockingStore,
            ClientFeatureFlags.Defaults,
            new FrozenClock(Now),
            new StubSessionBackend());
        await runtime.Accounts.RegisterAsync("Synthetic P14A2 account");
        var staging = new StagedSelfHostedProfileService(
            (IAtomicBoundedSettingsRepository)runtime.Store);
        var scope = P14A2TestSupport.Scope(0xa1);
        var saved = await staging.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            P14A2TestSupport.Fixture("accepted-eff4523-default.dpf"));
        var service = new DormantSelfHostedProfileVerificationService(
            staging,
            new P14A2DeterministicVerifier());
        controller.BlockNextAtomicRead();

        var verification = service.VerifyAsync(
            scope,
            saved.Candidate!.Id,
            P14A2TestSupport.Parameters());
        await controller.ReadStarted.WaitAsync(TestTimeout);
        var signOut = runtime.Accounts.SignOutAsync();

        var exception = await Assert.ThrowsAsync<OperationCanceledException>(
            () => verification.WaitAsync(TestTimeout));
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain(BarrierSentinel, exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Account-generation operation was canceled",
            exception.ToString(),
            StringComparison.Ordinal);
        await signOut.WaitAsync(TestTimeout);
        Assert.Empty((await new StagedSelfHostedProfileService(inner).ListAsync(scope)).Candidates);
    }

    [Fact]
    public async Task GatePrecedesExportAndBoundsQueuedSnapshots()
    {
        var inner = new InMemorySessionStore();
        var seed = new StagedSelfHostedProfileService(inner);
        var scope = P14A2TestSupport.Scope(0xa2);
        var saved = await seed.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            P14A2TestSupport.Fixture("accepted-eff4523-max-49152.dpf"));
        var repository = new ConcurrentReadProbeRepository(inner);
        using var enteredVerifier = new ManualResetEventSlim();
        using var releaseVerifier = new ManualResetEventSlim();
        var service = new DormantSelfHostedProfileVerificationService(
            new StagedSelfHostedProfileService(repository),
            new BlockingVerifier(
                new P14A2DeterministicVerifier(),
                enteredVerifier,
                releaseVerifier));

        var verifications = Enumerable.Range(0, 32).Select(_ => Task.Run(() =>
            service.VerifyAsync(
                scope,
                saved.Candidate!.Id,
                P14A2TestSupport.Parameters()))).ToArray();
        Assert.True(enteredVerifier.Wait(TestTimeout));
        await Task.Delay(250);

        Assert.Equal(1, repository.Reads);
        Assert.Equal(1, repository.MaximumActiveReads);
        Assert.Equal(31, verifications.Count(task => !task.IsCompleted));

        releaseVerifier.Set();
        var outcomes = await Task.WhenAll(verifications).WaitAsync(TestTimeout);
        Assert.All(outcomes, outcome => Assert.Equal(
            DormantSelfHostedProfileVerificationStatus.Verified,
            outcome.Status));
        Assert.Equal(32, repository.Reads);
        Assert.Equal(1, repository.MaximumActiveReads);
    }

    [Fact]
    public async Task CorruptAndDependencyStagingAreFixedServiceStatuses()
    {
        var inner = new InMemorySessionStore();
        var capture = new KeyCapturingRepository(inner);
        var staging = new StagedSelfHostedProfileService(capture);
        var scope = P14A2TestSupport.Scope(0xa3);
        var saved = await staging.SaveAsync(
            scope,
            StagedSelfHostedProfileLimits.SchemaVersion,
            P14A2TestSupport.Fixture("accepted-eff4523-default.dpf"));
        var persisted = await inner.ReadAtomicBoundedSettingAsync(
            capture.Key!,
            AtomicBoundedSettingsLimits.MaximumValueUtf8Bytes);
        Assert.Equal(AtomicBoundedSettingMutationResult.Applied,
            await inner.ReplaceAtomicBoundedSettingAsync(
                capture.Key!,
                persisted.Revision!,
                JsonSerializer.SerializeToUtf8Bytes("synthetic-corrupt-catalog"),
                AtomicBoundedSettingsLimits.MaximumValueUtf8Bytes));

        var corruptService = new DormantSelfHostedProfileVerificationService(
            staging,
            new P14A2DeterministicVerifier());
        Assert.Equal(DormantSelfHostedProfileVerificationStatus.CorruptStaging,
            (await corruptService.VerifyAsync(
                scope,
                saved.Candidate!.Id,
                P14A2TestSupport.Parameters())).Status);

        var dependencyService = new DormantSelfHostedProfileVerificationService(
            new StagedSelfHostedProfileService(new DependencyReadRepository()),
            new P14A2DeterministicVerifier());
        Assert.Equal(DormantSelfHostedProfileVerificationStatus.DependencyFailure,
            (await dependencyService.VerifyAsync(
                scope,
                saved.Candidate.Id,
                P14A2TestSupport.Parameters())).Status);
    }

    [Fact]
    public void ServiceOwnsAndZerosTransferredSnapshotOnEveryVerifierExit()
    {
        var source = File.ReadAllText(Path.Combine(
            P14A2PackageAndStaticGateTests.RepositoryRoot(),
            "src",
            "Deep.Client.Shared",
            "Services",
            "DormantSelfHostedProfileVerificationService.cs"));

        Assert.Contains("TakeCandidateBytesForVerification", source, StringComparison.Ordinal);
        Assert.Contains("CryptographicOperations.ZeroMemory(candidateBytes)", source, StringComparison.Ordinal);
        Assert.Contains("catch (OutOfMemoryException)", source, StringComparison.Ordinal);
        Assert.Contains("finally", source, StringComparison.Ordinal);
        Assert.True(
            source.IndexOf("verificationGate.WaitAsync", StringComparison.Ordinal)
            < source.IndexOf("staging.ExportAsync", StringComparison.Ordinal));
    }

    private sealed class BlockingVerifier(
        IMembershipSignatureVerifier inner,
        ManualResetEventSlim entered,
        ManualResetEventSlim release) : IMembershipSignatureVerifier
    {
        private int first = 1;

        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            if (Interlocked.Exchange(ref first, 0) == 1)
            {
                entered.Set();
                release.Wait(TestTimeout);
            }
            return inner.Verify(signerId, publicKey, domain, signingBytes, signature);
        }
    }

    private sealed class ConcurrentReadProbeRepository(IAtomicBoundedSettingsRepository inner) :
        IAtomicBoundedSettingsRepository
    {
        private int activeReads;
        private int maximumActiveReads;
        private int reads;

        public int Reads => Volatile.Read(ref reads);
        public int MaximumActiveReads => Volatile.Read(ref maximumActiveReads);

        public async Task<AtomicBoundedSettingReadOutcome> ReadAtomicBoundedSettingAsync(
            string key,
            int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref reads);
            var active = Interlocked.Increment(ref activeReads);
            UpdateMaximum(ref maximumActiveReads, active);
            try
            {
                await Task.Yield();
                return await inner.ReadAtomicBoundedSettingAsync(
                    key,
                    maximumValueUtf8Bytes,
                    cancellationToken);
            }
            finally
            {
                Interlocked.Decrement(ref activeReads);
            }
        }

        public Task<AtomicBoundedSettingMutationResult> CreateAtomicBoundedSettingAsync(
            string key, ReadOnlyMemory<byte> utf8Json, int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default) =>
            inner.CreateAtomicBoundedSettingAsync(
                key, utf8Json, maximumValueUtf8Bytes, cancellationToken);

        public Task<AtomicBoundedSettingMutationResult> ReplaceAtomicBoundedSettingAsync(
            string key, AtomicBoundedSettingRevision expectedRevision,
            ReadOnlyMemory<byte> utf8Json, int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default) =>
            inner.ReplaceAtomicBoundedSettingAsync(
                key, expectedRevision, utf8Json, maximumValueUtf8Bytes, cancellationToken);

        public Task<AtomicBoundedSettingMutationResult> DeleteAtomicBoundedSettingAsync(
            string key, AtomicBoundedSettingRevision expectedRevision,
            int maximumValueUtf8Bytes, CancellationToken cancellationToken = default) =>
            inner.DeleteAtomicBoundedSettingAsync(
                key, expectedRevision, maximumValueUtf8Bytes, cancellationToken);
    }

    private sealed class KeyCapturingRepository(IAtomicBoundedSettingsRepository inner) :
        IAtomicBoundedSettingsRepository
    {
        public string? Key { get; private set; }

        public Task<AtomicBoundedSettingReadOutcome> ReadAtomicBoundedSettingAsync(
            string key, int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default)
        {
            Key = key;
            return inner.ReadAtomicBoundedSettingAsync(key, maximumValueUtf8Bytes, cancellationToken);
        }

        public Task<AtomicBoundedSettingMutationResult> CreateAtomicBoundedSettingAsync(
            string key, ReadOnlyMemory<byte> utf8Json, int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default)
        {
            Key = key;
            return inner.CreateAtomicBoundedSettingAsync(
                key, utf8Json, maximumValueUtf8Bytes, cancellationToken);
        }

        public Task<AtomicBoundedSettingMutationResult> ReplaceAtomicBoundedSettingAsync(
            string key, AtomicBoundedSettingRevision expectedRevision,
            ReadOnlyMemory<byte> utf8Json, int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default) =>
            inner.ReplaceAtomicBoundedSettingAsync(
                key, expectedRevision, utf8Json, maximumValueUtf8Bytes, cancellationToken);

        public Task<AtomicBoundedSettingMutationResult> DeleteAtomicBoundedSettingAsync(
            string key, AtomicBoundedSettingRevision expectedRevision,
            int maximumValueUtf8Bytes, CancellationToken cancellationToken = default) =>
            inner.DeleteAtomicBoundedSettingAsync(
                key, expectedRevision, maximumValueUtf8Bytes, cancellationToken);
    }

    private sealed class DependencyReadRepository : IAtomicBoundedSettingsRepository
    {
        public Task<AtomicBoundedSettingReadOutcome> ReadAtomicBoundedSettingAsync(
            string key, int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new AtomicBoundedSettingReadOutcome(
                AtomicBoundedSettingReadResult.DependencyFailure));

        public Task<AtomicBoundedSettingMutationResult> CreateAtomicBoundedSettingAsync(
            string key, ReadOnlyMemory<byte> utf8Json, int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Mutation was not expected.");

        public Task<AtomicBoundedSettingMutationResult> ReplaceAtomicBoundedSettingAsync(
            string key, AtomicBoundedSettingRevision expectedRevision,
            ReadOnlyMemory<byte> utf8Json, int maximumValueUtf8Bytes,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Mutation was not expected.");

        public Task<AtomicBoundedSettingMutationResult> DeleteAtomicBoundedSettingAsync(
            string key, AtomicBoundedSettingRevision expectedRevision,
            int maximumValueUtf8Bytes, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Mutation was not expected.");
    }

    private class BlockingAtomicReadStoreProxy : DispatchProxy
    {
        private ILocalSessionStore? inner;
        private TaskCompletionSource readStarted = NewCompletion();
        private int blockNextAtomicRead;

        public Task ReadStarted => readStarted.Task;

        public static ILocalSessionStore Create(
            ILocalSessionStore inner,
            out BlockingAtomicReadStoreProxy controller)
        {
            var proxy = Create<ILocalSessionStore, BlockingAtomicReadStoreProxy>();
            controller = (BlockingAtomicReadStoreProxy)(object)proxy;
            controller.inner = inner;
            return proxy;
        }

        public void BlockNextAtomicRead()
        {
            readStarted = NewCompletion();
            Volatile.Write(ref blockNextAtomicRead, 1);
        }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            ArgumentNullException.ThrowIfNull(targetMethod);
            args ??= [];
            if (targetMethod.Name == nameof(
                    IAtomicBoundedSettingsRepository.ReadAtomicBoundedSettingAsync)
                && Interlocked.Exchange(ref blockNextAtomicRead, 0) != 0)
            {
                readStarted.TrySetResult();
                return CompleteCanceledReadAsync((CancellationToken)args[2]!);
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

        private static async Task<AtomicBoundedSettingReadOutcome> CompleteCanceledReadAsync(
            CancellationToken cancellationToken)
        {
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("Infinite delay completed unexpectedly.");
            }
            catch (OperationCanceledException)
            {
                throw new OperationCanceledException(BarrierSentinel, cancellationToken);
            }
        }

        private static TaskCompletionSource NewCompletion() =>
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private static void UpdateMaximum(ref int maximum, int value)
    {
        var observed = Volatile.Read(ref maximum);
        while (value > observed)
            observed = Interlocked.CompareExchange(ref maximum, value, observed);
    }
}
