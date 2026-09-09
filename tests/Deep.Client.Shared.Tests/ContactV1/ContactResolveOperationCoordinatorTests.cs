using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Tests.ContactV1;

public sealed class ContactResolveOperationCoordinatorTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(10);

    [Fact]
    public void ProductionCannotMintPlacementContextOrRawResolverCommand()
    {
        var context = typeof(VerifiedContactResolverPlacementContext);
        Assert.True(context.IsPublic && context.IsSealed);
        Assert.Empty(context.GetConstructors());
        var factory = Assert.Single(context.GetMethods(
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static),
            method => method.ReturnType == context);
        Assert.Equal("Create", factory.Name);
        Assert.Contains(factory.GetParameters(), parameter =>
            parameter.ParameterType == typeof(VerifiedContactServicePlacement));
        Assert.DoesNotContain(factory.GetParameters(), parameter =>
            parameter.ParameterType == typeof(byte[]) ||
            parameter.ParameterType == typeof(ReadOnlyMemory<byte>));
        Assert.Empty(typeof(ContactResolverCommand).GetConstructors());
        Assert.Null(context.Assembly.GetType(
            "Deep.Client.Shared.Services.ContactV1.IContactResolverPlacementAuthorityBoundary"));
    }

    [Fact]
    public async Task PlacementBridgeRejectsWrongRequestKindAndLocator()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var pending = await ImportAsync(store, 0x19);
        var locator = ContactCodecHash.OneTimeOrPermanentLocator(pending.Address);
        try
        {
            var wrongKind = Placement(pending.Address.NetworkId.Span,
                ContactServiceRequestKind.ClaimPreKey, locator, 0x31, 0x41, 1_000);
            Assert.Throws<CryptographicException>(() =>
                VerifiedContactResolverPlacementContext.CreateForTests(store.Scope, pending, wrongKind, Now));

            var wrongLocator = Placement(pending.Address.NetworkId.Span,
                ContactServiceRequestKind.ResolveInvite,
                ContactResolverClientOrchestrationTests.B(32, 0xFE), 0x32, 0x42, 1_000);
            Assert.Throws<CryptographicException>(() =>
                VerifiedContactResolverPlacementContext.CreateForTests(store.Scope, pending, wrongLocator, Now));

            var wrongNetwork = Placement(
                ContactResolverClientOrchestrationTests.B(16, 0xEF),
                ContactServiceRequestKind.ResolveInvite,
                locator,
                0x33,
                0x43,
                1_000);
            Assert.Throws<CryptographicException>(() =>
                VerifiedContactResolverPlacementContext.CreateForTests(store.Scope, pending, wrongNetwork, Now));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(locator);
        }
    }

    [Fact]
    public async Task ExpiredPlacementRejectsBeforeJournalOrNetwork()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var pending = await ImportAsync(store, 0x1A);
        var context = Context(store.Scope, pending, 0x33, 0x43, validUntilUnixSeconds: 11, now: Now);
        var transport = new RecordingTransport(_ =>
            throw new Xunit.Sdk.XunitException("expired placement must not dispatch"));
        var coordinator = new ContactResolveOperationCoordinator(
            store,
            transport,
            new RejectingVerifier(),
            new ContactResolverClientOptions(1, TimeSpan.Zero, 64),
            new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(11)));

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await coordinator.StartAsync(pending, context));

        Assert.Empty(await ((IContactResolveOperationStore)store).ReadResolveOperationsAsync());
        Assert.Empty(transport.Requests);
    }

    [Fact]
    public async Task ContextForAnotherPendingAddressRejectsBeforeJournalOrNetwork()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var authorized = await ImportAsync(store, 0x1D);
        var different = await ImportAsync(store, 0x1E);
        var context = Context(store.Scope, authorized, 0x37, 0x47, 1_000, Now);
        var transport = new RecordingTransport(_ =>
            throw new Xunit.Sdk.XunitException("cross-address context must not dispatch"));

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await Coordinator(store, transport).StartAsync(different, context));

        Assert.Empty(await ((IContactResolveOperationStore)store).ReadResolveOperationsAsync());
        Assert.Empty(transport.Requests);
    }

    [Fact]
    public async Task XiqExpiryIsClippedToRequestInvitationAndPlacementIntersection()
    {
        var permanentStore = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var permanent = await ImportAsync(permanentStore, 0x1B);
        var placementBound = Context(permanentStore.Scope, permanent, 0x34, 0x44, 25, Now);
        var permanentTransport = new RecordingTransport(request =>
            ContactResolverClientOrchestrationTests.Failure(request, Xis1Status.NotFound));

        await Coordinator(permanentStore, permanentTransport).StartAsync(
            permanent,
            placementBound,
            new ContactResolveRequestParameters(TimeSpan.FromMinutes(1)));

        var placementClipped = Xiq1Codec.Decode(Assert.Single(permanentTransport.Requests));
        Assert.Equal(10UL, placementClipped.IssuedAtUnixSeconds);
        Assert.Equal(25UL, placementClipped.ExpiresAtUnixSeconds);

        var invitationStore = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var dia = ContactCodec.Decode("DIA1", ContactResolverClientOrchestrationTests.Dia1(20));
        var invitation = (await new ContactAddressImportService(
            invitationStore,
            ContactResolverClientOrchestrationTests.Network,
            new FixedTimeProvider(Now)).ImportAsync(DeepInvitationTextCodec.EncodeCanonical(dia))).PendingAddress;
        var invitationBound = Context(invitationStore.Scope, invitation, 0x35, 0x45, 30, Now);
        var invitationTransport = new RecordingTransport(request =>
            ContactResolverClientOrchestrationTests.Failure(request, Xis1Status.NotFound));

        await Coordinator(invitationStore, invitationTransport).StartAsync(
            invitation,
            invitationBound,
            new ContactResolveRequestParameters(TimeSpan.FromMinutes(1)));

        var invitationClipped = Xiq1Codec.Decode(Assert.Single(invitationTransport.Requests));
        Assert.Equal(20UL, invitationClipped.ExpiresAtUnixSeconds);
    }

    [Fact]
    public async Task PlacementContextOwnsDefensiveHashCopiesAndBindsAccountAndPendingAddress()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var pending = await ImportAsync(store, 0x1C);
        var expectedView = ContactResolverClientOrchestrationTests.B(32, 0x36);
        var expectedPlacement = ContactResolverClientOrchestrationTests.B(32, 0x46);
        var locator = ContactCodecHash.OneTimeOrPermanentLocator(pending.Address);
        var placement = Placement(
            pending.Address.NetworkId.Span,
            ContactServiceRequestKind.ResolveInvite,
            locator,
            expectedView,
            expectedPlacement,
            1_000);
        var context = VerifiedContactResolverPlacementContext.CreateForTests(store.Scope, pending, placement, Now);

        MemoryMarshal.AsMemory(placement.ViewHash).Span.Clear();
        MemoryMarshal.AsMemory(placement.PlacementHash).Span.Clear();
        locator.AsSpan().Clear();

        var transport = new RecordingTransport(request =>
            ContactResolverClientOrchestrationTests.Failure(request, Xis1Status.NotFound));
        await Coordinator(store, transport).StartAsync(pending, context);
        var request = Xiq1Codec.Decode(Assert.Single(transport.Requests));
        Assert.Equal(expectedView, request.ViewHash.ToArray());
        Assert.Equal(expectedPlacement, request.PlacementHash.ToArray());

        var otherScope = ContactStoreScope.ForCurrentAccount(
            Deep.Protocol.Identity.DeepAccountIdentityCapability.FromVerifiedInputs(
                Deep.Protocol.Identity.DeepNetworkId16.FromVerifiedBytes(ContactResolverClientOrchestrationTests.Network),
                1,
                Deep.Protocol.Identity.AccountEd25519PublicKey32.FromVerifiedBytes(
                    ContactResolverClientOrchestrationTests.B(32, 0xF1))).AccountId);
        var otherStore = new InMemoryContactStateStore(otherScope);
        var blockedTransport = new RecordingTransport(_ =>
            throw new Xunit.Sdk.XunitException("cross-account context must not dispatch"));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await Coordinator(otherStore, blockedTransport).StartAsync(pending, context));
        Assert.Empty(await ((IContactResolveOperationStore)otherStore).ReadResolveOperationsAsync());
        Assert.Empty(blockedTransport.Requests);
    }

    [Fact]
    public async Task SqlCipherRestartRetriesByteIdenticalPreparedOperation()
    {
        using var fixture = StoreFixture.Create();
        byte[] operationId;
        byte[] firstRequest;
        using (var store = new SqliteContactStateStore(fixture.Options))
        {
            var pending = await ImportAsync(store, 0x21);
            var context = await ContextAsync(store.Scope, pending, 0x31, 0x41);
            var firstTransport = new RecordingTransport(_ => throw new ContactResolverTransportException(
                ContactResolverTransportFailureKind.OutcomeUnknown, "synthetic lost completion"));
            var coordinator = Coordinator(store, firstTransport);

            var first = await coordinator.StartAsync(pending, context);

            Assert.Equal(ContactResolveOperationState.RetryPending, first.DurableState.State);
            Assert.Equal(ContactResolverDisposition.TransportUnavailable, first.Result.Disposition);
            operationId = first.DurableState.OperationId.ToArray();
            firstRequest = Assert.Single(firstTransport.Requests);
        }

        using var reopened = new SqliteContactStateStore(fixture.Options);
        var secondTransport = new RecordingTransport(request =>
            ContactResolverClientOrchestrationTests.Failure(request, Xis1Status.NotFound));
        var resumed = await Coordinator(reopened, secondTransport).ResumeAsync(operationId);

        Assert.Equal(ContactResolveOperationState.Terminal, resumed.DurableState.State);
        Assert.Equal(ContactResolverDisposition.NotFound, resumed.Result.Disposition);
        Assert.Equal(firstRequest, Assert.Single(secondTransport.Requests));
        Assert.Equal(2UL, resumed.DurableState.DispatchCount);
        Assert.Equal(2UL, resumed.DurableState.TransportAttemptCount);
        Assert.Equal(Xiq1Codec.Decode(firstRequest).CanonicalBytes.ToArray(), resumed.DurableState.ExactXiq1.ToArray());
    }

    [Fact]
    public async Task OutcomeUnknownPersistsExactXisAndRetriesSameOperation()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var pending = await ImportAsync(store, 0x22);
        var context = await ContextAsync(store.Scope, pending, 0x32, 0x42);
        var call = 0;
        var transport = new RecordingTransport(request =>
            ContactResolverClientOrchestrationTests.Failure(
                request, ++call == 1 ? Xis1Status.OutcomeUnknown : Xis1Status.NotFound));
        var coordinator = Coordinator(store, transport);

        var first = await coordinator.StartAsync(pending, context);
        var second = await coordinator.ResumeAsync(first.DurableState.OperationId);

        Assert.Equal(ContactResolveOperationState.RetryPending, first.DurableState.State);
        Assert.Equal(ContactResolverDisposition.OutcomeUnknown, first.DurableState.LastDisposition);
        Assert.NotEmpty(first.DurableState.ExactXis1.ToArray());
        Assert.Equal(7u, first.DurableState.RetryAfterSeconds);
        Assert.Equal(ContactResolveOperationState.Terminal, second.DurableState.State);
        Assert.Equal(transport.Requests[0], transport.Requests[1]);
        Assert.Equal(first.DurableState.OperationId.ToArray(), second.DurableState.OperationId.ToArray());
    }

    [Fact]
    public async Task StaleViewRequiresVerifiedDifferentContextAndCreatesNewOperation()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var pending = await ImportAsync(store, 0x23);
        var firstContext = await ContextAsync(store.Scope, pending, 0x33, 0x43);
        var staleTransport = new RecordingTransport(request =>
            ContactResolverClientOrchestrationTests.Failure(request, Xis1Status.StaleView));
        var firstCoordinator = Coordinator(store, staleTransport);
        var stale = await firstCoordinator.StartAsync(pending, firstContext);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await firstCoordinator.RestartAfterStaleViewAsync(
                stale.DurableState.OperationId, firstContext));

        var refreshed = await ContextAsync(store.Scope, pending, 0x34, 0x44);
        var freshTransport = new RecordingTransport(request =>
            ContactResolverClientOrchestrationTests.Failure(request, Xis1Status.NotFound));
        var replacement = await Coordinator(store, freshTransport).RestartAfterStaleViewAsync(
            stale.DurableState.OperationId, refreshed);

        Assert.Equal(ContactResolveOperationState.AwaitingRefreshedContext, stale.DurableState.State);
        Assert.Equal(ContactResolverClientOrchestrationTests.B(32, 0x73),
            stale.DurableState.RequiredViewHash.ToArray());
        Assert.NotEqual(stale.DurableState.OperationId.ToArray(), replacement.DurableState.OperationId.ToArray());
        Assert.Equal(stale.DurableState.RelationshipId, replacement.DurableState.RelationshipId);
        Assert.NotEqual(stale.DurableState.ExactXiq1.ToArray(), replacement.DurableState.ExactXiq1.ToArray());
        Assert.Equal(ContactResolveOperationState.Terminal, replacement.DurableState.State);
    }

    [Fact]
    public async Task DurableJournalRejectsOperationIdBodyDriftBeforeDispatch()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var pending = await ImportAsync(store, 0x24);
        var operation = ContactMutationId32.FromBytes(ContactResolverClientOrchestrationTests.B(32, 0x51));
        var relationship = ContactRelationshipId32.FromBytes(ContactResolverClientOrchestrationTests.B(32, 0x52));
        var first = ContactResolverCommand.CreateUnverifiedForTests(pending, operation, relationship,
            ContactResolverClientOrchestrationTests.B(32, 0x53),
            ContactResolverClientOrchestrationTests.B(32, 0x54), 10, 100);
        var changed = ContactResolverCommand.CreateUnverifiedForTests(pending, operation, relationship,
            ContactResolverClientOrchestrationTests.B(32, 0x55),
            ContactResolverClientOrchestrationTests.B(32, 0x54), 10, 100);
        var journal = (IContactResolveOperationStore)store;
        _ = await journal.StageResolveOperationAsync(
            new ContactResolveOperationIntent(pending, relationship,
                ContactResolverClient.BuildExactXiq1(first)), Now);

        await Assert.ThrowsAsync<ContactResolveOperationConflictException>(async () =>
            await journal.StageResolveOperationAsync(
                new ContactResolveOperationIntent(pending, relationship,
                    ContactResolverClient.BuildExactXiq1(changed)), Now));

        Assert.Single(await journal.ReadResolveOperationsAsync());
    }

    [Fact]
    public async Task CallerCancellationLeavesDurablePreparedOperationForRestart()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var pending = await ImportAsync(store, 0x25);
        var context = await ContextAsync(store.Scope, pending, 0x35, 0x45);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstTransport = new AsyncRecordingTransport(async request =>
        {
            entered.TrySetResult();
            await release.Task;
            return ContactResolverClientOrchestrationTests.Failure(request, Xis1Status.NotFound);
        });
        using var cancellation = new CancellationTokenSource();
        var running = Coordinator(store, firstTransport)
            .StartAsync(pending, context, cancellationToken: cancellation.Token).AsTask();
        await entered.Task;
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
        var durable = Assert.Single(await ((IContactResolveOperationStore)store).ReadResolveOperationsAsync());
        Assert.Equal(ContactResolveOperationState.Prepared, durable.State);
        Assert.Equal(1UL, durable.DispatchCount);
        Assert.Null(durable.LastDisposition);
        release.TrySetResult();
        await firstTransport.Completed.Task;

        var secondTransport = new RecordingTransport(request =>
            ContactResolverClientOrchestrationTests.Failure(request, Xis1Status.NotFound));
        var resumed = await Coordinator(store, secondTransport).ResumeAsync(durable.OperationId);

        Assert.Equal(firstTransport.Requests[0], Assert.Single(secondTransport.Requests));
        Assert.Equal(ContactResolveOperationState.Terminal, resumed.DurableState.State);
    }

    [Fact]
    public async Task PreCanceledStartDoesNotAllocateOrJournalOperation()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var pending = await ImportAsync(store, 0x29);
        var context = await ContextAsync(store.Scope, pending, 0x39, 0x49);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await Coordinator(store, new RecordingTransport(_ => throw new Xunit.Sdk.XunitException("must not dispatch")))
                .StartAsync(pending, context, cancellationToken: cancellation.Token));

        Assert.Empty(await ((IContactResolveOperationStore)store).ReadResolveOperationsAsync());
    }

    [Fact]
    public async Task VerifiedRelationshipIsLinkedOnceAndResumeDoesNotRedispatch()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var pending = await ImportAsync(store, 0x26);
        var context = await ContextAsync(store.Scope, pending, 0x36, 0x46);
        var transport = new RecordingTransport(ContactResolverClientOrchestrationTests.Success);
        var coordinator = Coordinator(store, transport,
            new ContactResolverClientOrchestrationTests.TestTrustedVerifier(
                ContactResolverClientOrchestrationTests.B(32, 0xB0)));

        var first = await coordinator.StartAsync(pending, context);
        var resumed = await coordinator.ResumeAsync(first.DurableState.OperationId);

        Assert.Equal(ContactResolveOperationState.RelationshipLinked, first.DurableState.State);
        Assert.Equal(ContactResolverDisposition.Verified, resumed.Result.Disposition);
        Assert.Equal(ContactRelationshipCommitDisposition.Idempotent, resumed.Result.Commit!.Disposition);
        Assert.Single(await store.ReadRelationshipsAsync());
        Assert.Single(transport.Requests);
    }

    [Fact]
    public async Task TrustedVerificationRejectionIsDurableAndVisibleWithoutRelationship()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var pending = await ImportAsync(store, 0x27);
        var context = await ContextAsync(store.Scope, pending, 0x37, 0x47);
        var transport = new RecordingTransport(ContactResolverClientOrchestrationTests.Success);
        var coordinator = Coordinator(store, transport);

        var failure = await Assert.ThrowsAsync<ContactResolveOperationFailClosedException>(async () =>
            await coordinator.StartAsync(pending, context));

        Assert.Equal(ContactResolveOperationState.FailClosed, failure.DurableState.State);
        Assert.Equal(ContactResolverDisposition.ProtocolRejected, failure.DurableState.LastDisposition);
        Assert.Equal(ContactResolverRetryClassification.FailClosed, failure.DurableState.LastRetry);
        Assert.NotEmpty(failure.DurableState.ExactXis1.ToArray());
        Assert.Empty(await store.ReadRelationshipsAsync());
        var resumed = await coordinator.ResumeAsync(failure.DurableState.OperationId);
        Assert.Equal(ContactResolverDisposition.ProtocolRejected, resumed.Result.Disposition);
        Assert.Single(transport.Requests);
    }

    [Fact]
    public async Task UncorrelatedXisFailsClosedAndPersistsNoForgedOutcome()
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var pending = await ImportAsync(store, 0x28);
        var context = await ContextAsync(store.Scope, pending, 0x38, 0x48);
        var transport = new RecordingTransport(request =>
        {
            var actual = Xiq1Codec.Decode(request.ExactXiq1.Span);
            var otherOperation = ContactResolverClientOrchestrationTests.B(32, 0x79);
            var otherRequest = Xiq1Codec.Encode(
                actual.NetworkId.Span,
                otherOperation,
                actual.ViewHash.Span,
                actual.PlacementHash.Span,
                actual.IssuedAtUnixSeconds,
                actual.ExpiresAtUnixSeconds,
                actual.LocatorHash.Span,
                actual.RequestedGeneration,
                actual.AntiSpamTokenType,
                actual.AntiSpamToken.Span,
                actual.ResponsePaddingClass);
            return new ContactResolverTransportResponse(Xis1Codec.Encode(
                otherRequest,
                Xis1Status.NotFound,
                ContactServiceMutationOutcome.None,
                50,
                0,
                ContactServicePaddingClass.Bytes256,
                []));
        });

        var failure = await Assert.ThrowsAsync<ContactResolveOperationFailClosedException>(async () =>
            await Coordinator(store, transport).StartAsync(pending, context));

        Assert.Equal(ContactResolveOperationState.FailClosed, failure.DurableState.State);
        Assert.Equal(ContactResolverDisposition.ProtocolRejected, failure.DurableState.LastDisposition);
        Assert.Empty(failure.DurableState.ExactXis1.ToArray());
        Assert.Empty(await store.ReadRelationshipsAsync());
    }

    private static ContactResolveOperationCoordinator Coordinator(
        IContactStateStore store,
        IContactResolverTransport transport,
        IContactResolverTrustedVerifier? verifier = null) => new(
            store,
            transport,
            verifier ?? new RejectingVerifier(),
            new ContactResolverClientOptions(1, TimeSpan.Zero, 64),
            new FixedTimeProvider(Now));

    private static async Task<PendingContactAddress> ImportAsync(IContactStateStore store, byte marker)
    {
        var addressKey = ContactResolverClientOrchestrationTests.B(32, marker);
        var read = ContactResolverClientOrchestrationTests.B(16, checked((byte)(marker + 1)));
        var did = ApplicationCoreCodec.AuthorDid1(addressKey, read);
        return (await new ContactAddressImportService(
            store, ContactResolverClientOrchestrationTests.Network,
            new FixedTimeProvider(Now)).ImportAsync(did.Text)).PendingAddress;
    }

    private static ValueTask<VerifiedContactResolverPlacementContext> ContextAsync(
        ContactStoreScope scope,
        PendingContactAddress pending,
        byte viewMarker,
        byte placementMarker) => ValueTask.FromResult(
            Context(scope, pending, viewMarker, placementMarker, 1_000, Now));

    private static VerifiedContactResolverPlacementContext Context(
        ContactStoreScope scope,
        PendingContactAddress pending,
        byte viewMarker,
        byte placementMarker,
        ulong validUntilUnixSeconds,
        DateTimeOffset now)
    {
        var locator = ContactCodecHash.OneTimeOrPermanentLocator(pending.Address);
        try
        {
            return VerifiedContactResolverPlacementContext.CreateForTests(
                scope,
                pending,
                Placement(
                    pending.Address.NetworkId.Span,
                    ContactServiceRequestKind.ResolveInvite,
                    locator,
                    viewMarker,
                    placementMarker,
                    validUntilUnixSeconds),
                now);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(locator);
        }
    }

    private static VerifiedContactServicePlacement Placement(
        ReadOnlySpan<byte> networkId,
        ContactServiceRequestKind requestKind,
        ReadOnlySpan<byte> shardKey,
        byte viewMarker,
        byte placementMarker,
        ulong validUntilUnixSeconds) => Placement(
            networkId,
            requestKind,
            shardKey,
            ContactResolverClientOrchestrationTests.B(32, viewMarker),
            ContactResolverClientOrchestrationTests.B(32, placementMarker),
            validUntilUnixSeconds);

    private static VerifiedContactServicePlacement Placement(
        ReadOnlySpan<byte> networkId,
        ContactServiceRequestKind requestKind,
        ReadOnlySpan<byte> shardKey,
        byte[] viewHash,
        byte[] placementHash,
        ulong validUntilUnixSeconds)
    {
        var network = CreateNetworkContext(networkId);
        return CreatePlacement(
            network,
            requestKind,
            requestKind == ContactServiceRequestKind.ClaimPreKey
                ? ContactServiceClass.PreKeyClaim
                : ContactServiceClass.InviteResolver,
            viewHash,
            placementHash,
            shardKey,
            7,
            validUntilUnixSeconds,
            [ContactResolverClientOrchestrationTests.B(32, 0x71), ContactResolverClientOrchestrationTests.B(32, 0x72)]);
    }

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedOnionNetworkContext CreateNetworkContext(ReadOnlySpan<byte> networkId);

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedContactServicePlacement CreatePlacement(
        VerifiedOnionNetworkContext network,
        ContactServiceRequestKind requestKind,
        ContactServiceClass serviceClass,
        ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> placementHash,
        ReadOnlySpan<byte> shardKey,
        ulong selectionEpoch,
        ulong validUntilUnixSeconds,
        IEnumerable<byte[]> rankedReplicaNodeIds);

    private sealed class RecordingTransport(
        Func<ContactResolverTransportRequest, ContactResolverTransportResponse> response)
        : IContactResolverTransport
    {
        public List<byte[]> Requests { get; } = [];

        public ValueTask<ContactResolverTransportResponse> SendXiq1Async(
            ContactResolverTransportRequest request,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(request.ExactXiq1.ToArray());
            return ValueTask.FromResult(response(request));
        }
    }

    private sealed class AsyncRecordingTransport(
        Func<ContactResolverTransportRequest, Task<ContactResolverTransportResponse>> response)
        : IContactResolverTransport
    {
        public List<byte[]> Requests { get; } = [];
        public TaskCompletionSource Completed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<ContactResolverTransportResponse> SendXiq1Async(
            ContactResolverTransportRequest request,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(request.ExactXiq1.ToArray());
            try { return await response(request); }
            finally { Completed.TrySetResult(); }
        }
    }

    private sealed class RejectingVerifier : IContactResolverTrustedVerifier
    {
        public ValueTask<ContactResolverTrustedVerificationResult> VerifyAsync(
            ContactResolverVerificationInput input,
            ContactStoreScope localScope,
            ContactRelationshipId32 relationshipId,
            CancellationToken cancellationToken = default) =>
            throw new CryptographicException("A success response is not expected in this fixture.");
    }

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }

    private sealed class StoreFixture : IDisposable
    {
        private StoreFixture(string directory)
        {
            Directory = directory;
            Options = new SqliteContactStateStoreOptions(
                Path.Combine(directory, "contact.db"),
                ContactResolverClientOrchestrationTests.B(32, 0xE1),
                ContactResolverClientOrchestrationTests.Scope());
        }

        private string Directory { get; }
        internal SqliteContactStateStoreOptions Options { get; }

        internal static StoreFixture Create()
        {
            var directory = Path.Combine(Path.GetTempPath(),
                "deep-contact-resolve-tests", Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(directory);
            return new StoreFixture(directory);
        }

        public void Dispose()
        {
            Options.Dispose();
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, recursive: true);
        }
    }
}
