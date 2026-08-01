using System.Reflection;
using System.Runtime.ExceptionServices;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.Services;

public sealed class AccountGenerationLifecycleTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(5);
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-12T00:00:00Z");

    [Fact]
    public async Task SignOutWaitsForActiveMutationThenPurgesItAndRejectsLateWrites()
    {
        var inner = new InMemorySessionStore();
        var store = BlockingMutationStoreProxy.Create(inner, out var controller);
        using var runtime = new ClientRuntime(
            store,
            ClientFeatureFlags.Defaults,
            new FrozenClock(Now),
            new StubSessionBackend());
        await runtime.Accounts.RegisterAsync("Alice");
        var recoveryPhrase = await runtime.Accounts.GetRecoveryPhraseAsync()
            ?? throw new InvalidOperationException("The test account has no recovery phrase.");
        controller.BlockNextConversationUpsert();

        var conversation = NewConversation("blocked-before-purge");
        var mutation = runtime.Store.UpsertAsync(conversation);
        await controller.MutationStarted.WaitAsync(TestTimeout);

        var signOut = runtime.Accounts.SignOutAsync();
        await Task.Delay(50);

        Assert.False(signOut.IsCompleted);
        controller.ReleaseMutation();
        await mutation.WaitAsync(TestTimeout);
        await signOut.WaitAsync(TestTimeout);

        Assert.Null(await ((IConversationRepository)inner).GetAsync(conversation.Id));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => runtime.Store.UpsertAsync(NewConversation("late-old-generation")));

        await runtime.Accounts.LoginAsync(recoveryPhrase, "Alice");
        var resumed = NewConversation("new-generation");
        await runtime.Store.UpsertAsync(resumed);

        Assert.NotNull(await ((IConversationRepository)inner).GetAsync(resumed.Id));
    }

    [Fact]
    public async Task SignOutWaitsForActiveReadThenPurgesItAndRejectsLateReads()
    {
        var inner = new InMemorySessionStore();
        var store = BlockingMutationStoreProxy.Create(inner, out var controller);
        using var runtime = new ClientRuntime(
            store,
            ClientFeatureFlags.Defaults,
            new FrozenClock(Now),
            new StubSessionBackend());
        await runtime.Accounts.RegisterAsync("Alice");
        var recoveryPhrase = await runtime.Accounts.GetRecoveryPhraseAsync()
            ?? throw new InvalidOperationException("The test account has no recovery phrase.");
        var conversation = NewConversation("blocked-read");
        await runtime.Store.UpsertAsync(conversation);
        controller.BlockNextConversationRead();

        var read = ((IConversationRepository)runtime.Store).GetAsync(conversation.Id);
        await controller.ReadStarted.WaitAsync(TestTimeout);

        var signOut = runtime.Accounts.SignOutAsync();
        await Task.Delay(50);

        Assert.False(signOut.IsCompleted);
        controller.ReleaseRead();
        Assert.Equal(conversation, await read.WaitAsync(TestTimeout));
        await signOut.WaitAsync(TestTimeout);

        Assert.Null(await ((IConversationRepository)inner).GetAsync(conversation.Id));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ((IConversationRepository)runtime.Store).GetAsync(conversation.Id));

        await runtime.Accounts.LoginAsync(recoveryPhrase, "Alice");
        Assert.Null(await ((IConversationRepository)runtime.Store).GetAsync(conversation.Id));
    }

    [Fact]
    public async Task SignOutKeepsEnumerationScopedUntilEnumeratorIsDisposed()
    {
        var inner = new InMemorySessionStore();
        var store = BlockingMutationStoreProxy.Create(inner, out var controller);
        using var runtime = new ClientRuntime(
            store,
            ClientFeatureFlags.Defaults,
            new FrozenClock(Now),
            new StubSessionBackend());
        await runtime.Accounts.RegisterAsync("Alice");
        var recoveryPhrase = await runtime.Accounts.GetRecoveryPhraseAsync()
            ?? throw new InvalidOperationException("The test account has no recovery phrase.");
        await runtime.Store.UpsertAsync(NewConversation("blocked-enumeration"));
        controller.BlockNextConversationEnumeration();

        var enumerator = ((IConversationRepository)runtime.Store)
            .ListAsync()
            .GetAsyncEnumerator();
        var moveNext = enumerator.MoveNextAsync().AsTask();
        await controller.EnumerationStarted.WaitAsync(TestTimeout);

        var signOut = runtime.Accounts.SignOutAsync();
        await Task.Delay(50);

        Assert.False(signOut.IsCompleted);
        controller.ReleaseEnumeration();
        Assert.True(await moveNext.WaitAsync(TestTimeout));
        Assert.False(signOut.IsCompleted);

        await enumerator.DisposeAsync();
        await signOut.WaitAsync(TestTimeout);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await ToListAsync(((IConversationRepository)runtime.Store).ListAsync()));

        await runtime.Accounts.LoginAsync(recoveryPhrase, "Alice");
        Assert.Empty(await ToListAsync(((IConversationRepository)runtime.Store).ListAsync()));
    }

    [Fact]
    public async Task StoreBoundTransportLifecycleResetsOnLogoutAndResumesEachAccountGeneration()
    {
        var transport = new LifecycleTransport();
        using var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            ClientFeatureFlags.Defaults,
            new FrozenClock(Now),
            transport);

        await runtime.Accounts.RegisterAsync("Alice");
        var alice = await runtime.Accounts.GetActiveAccountAsync()
            ?? throw new InvalidOperationException("Alice was not activated.");
        var alicePhrase = await runtime.Accounts.GetRecoveryPhraseAsync()
            ?? throw new InvalidOperationException("Alice has no recovery phrase.");
        await runtime.Accounts.SignOutAsync();
        await runtime.Accounts.LoginAsync(alicePhrase, "Alice again");
        await runtime.Accounts.SignOutAsync();
        await runtime.Accounts.RegisterAsync("Bob");
        var bob = await runtime.Accounts.GetActiveAccountAsync()
            ?? throw new InvalidOperationException("Bob was not activated.");

        Assert.Equal([alice.SessionId, alice.SessionId], transport.StoppedAccounts);
        Assert.Equal([alice.SessionId, alice.SessionId, bob.SessionId],
            transport.ResumedAccounts);
    }

    private static Conversation NewConversation(string displayName) =>
        new(
            ConversationId.ForOneToOne(SessionId.CreateNew()),
            ConversationKind.OneToOne,
            displayName,
            ConversationSettings.Default(ConversationKind.OneToOne),
            Now,
            Now);

    private sealed class LifecycleTransport :
        ISessionMessageTransport,
        IAccountGenerationLifecycle
    {
        public List<SessionId> StoppedAccounts { get; } = [];
        public List<SessionId> ResumedAccounts { get; } = [];

        public Task SendAsync(
            OutboundMessageEnvelope envelope,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);

        public Task StopAsync(
            SessionId account,
            CancellationToken cancellationToken = default)
        {
            StoppedAccounts.Add(account);
            return Task.CompletedTask;
        }

        public void Resume(SessionId account) => ResumedAccounts.Add(account);
    }

    public class BlockingMutationStoreProxy : DispatchProxy
    {
        private ILocalSessionStore? inner;
        private TaskCompletionSource mutationStarted = NewCompletion();
        private TaskCompletionSource mutationRelease = NewCompletion();
        private TaskCompletionSource readStarted = NewCompletion();
        private TaskCompletionSource readRelease = NewCompletion();
        private TaskCompletionSource enumerationStarted = NewCompletion();
        private TaskCompletionSource enumerationRelease = NewCompletion();
        private int blockNextConversation;
        private int blockNextConversationRead;
        private int blockNextConversationEnumeration;

        public Task MutationStarted => mutationStarted.Task;

        public Task ReadStarted => readStarted.Task;

        public Task EnumerationStarted => enumerationStarted.Task;

        public static ILocalSessionStore Create(
            ILocalSessionStore inner,
            out BlockingMutationStoreProxy controller)
        {
            var proxy = Create<ILocalSessionStore, BlockingMutationStoreProxy>();
            controller = (BlockingMutationStoreProxy)(object)proxy;
            controller.inner = inner;
            return proxy;
        }

        public void BlockNextConversationUpsert()
        {
            mutationStarted = NewCompletion();
            mutationRelease = NewCompletion();
            Volatile.Write(ref blockNextConversation, 1);
        }

        public void ReleaseMutation() => mutationRelease.TrySetResult();

        public void BlockNextConversationRead()
        {
            readStarted = NewCompletion();
            readRelease = NewCompletion();
            Volatile.Write(ref blockNextConversationRead, 1);
        }

        public void ReleaseRead() => readRelease.TrySetResult();

        public void BlockNextConversationEnumeration()
        {
            enumerationStarted = NewCompletion();
            enumerationRelease = NewCompletion();
            Volatile.Write(ref blockNextConversationEnumeration, 1);
        }

        public void ReleaseEnumeration() => enumerationRelease.TrySetResult();

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            ArgumentNullException.ThrowIfNull(targetMethod);
            args ??= [];
            if (targetMethod.Name == nameof(IConversationRepository.UpsertAsync)
                && args.FirstOrDefault() is Conversation conversation
                && Interlocked.Exchange(ref blockNextConversation, 0) != 0)
            {
                mutationStarted.TrySetResult();
                return CompleteBlockedMutationAsync(conversation);
            }

            if (targetMethod.Name == nameof(IConversationRepository.GetAsync)
                && args.FirstOrDefault() is ConversationId conversationId
                && Interlocked.Exchange(ref blockNextConversationRead, 0) != 0)
            {
                readStarted.TrySetResult();
                return CompleteBlockedReadAsync(conversationId);
            }

            if (targetMethod.Name == nameof(IConversationRepository.ListAsync)
                && targetMethod.ReturnType == typeof(IAsyncEnumerable<Conversation>)
                && Interlocked.Exchange(ref blockNextConversationEnumeration, 0) != 0)
            {
                enumerationStarted.TrySetResult();
                return CompleteBlockedEnumerationAsync();
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

        private async Task CompleteBlockedMutationAsync(Conversation conversation)
        {
            await mutationRelease.Task.ConfigureAwait(false);
            await inner!.UpsertAsync(conversation, CancellationToken.None).ConfigureAwait(false);
        }

        private async Task<Conversation?> CompleteBlockedReadAsync(ConversationId conversationId)
        {
            await readRelease.Task.ConfigureAwait(false);
            return await ((IConversationRepository)inner!)
                .GetAsync(conversationId, CancellationToken.None)
                .ConfigureAwait(false);
        }

        private async IAsyncEnumerable<Conversation> CompleteBlockedEnumerationAsync()
        {
            await enumerationRelease.Task.ConfigureAwait(false);
            await foreach (var conversation in ((IConversationRepository)inner!)
                               .ListAsync(CancellationToken.None))
            {
                yield return conversation;
            }
        }

        private static TaskCompletionSource NewCompletion() =>
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private static async Task<IReadOnlyList<T>> ToListAsync<T>(IAsyncEnumerable<T> source)
    {
        var items = new List<T>();
        await foreach (var item in source)
        {
            items.Add(item);
        }

        return items;
    }
}
