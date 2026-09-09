using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.MessagingV1;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.MessagingV1;

public sealed class Msg01FinalReviewTests
{
    public static TheoryData<string> Backends => new() { "memory", "sqlite" };

    [Fact]
    public void DirectMessagingStorageFacadeKeepsPersistenceAuthoritiesOpaque()
    {
        var facade = typeof(DeepDirectMessagingStorageFacade);
        Assert.True(facade.IsPublic && facade.IsSealed);

        var publicSurface = facade.GetMembers(BindingFlags.Public |
                                               BindingFlags.Instance |
                                               BindingFlags.Static)
            .Select(static member => member.ToString() ?? string.Empty)
            .ToArray();
        Assert.DoesNotContain(publicSurface, static signature =>
            signature.Contains("Persistence.", StringComparison.Ordinal) ||
            signature.Contains("Sqlite", StringComparison.Ordinal) ||
            signature.Contains("PreKeyV1SecretOwner", StringComparison.Ordinal) ||
            signature.Contains("MessagingCryptoV1Store", StringComparison.Ordinal) ||
            signature.Contains("Delegate", StringComparison.Ordinal));

        var exported = facade.Assembly.GetExportedTypes();
        Assert.DoesNotContain(exported, static type =>
            type.Name is "DeepDirectMessagingStorageOwner" or
                "DeepDirectMessagingSessionStoreBinding" or
                "SqlitePreKeyV1SecretOwner" or
                "SqliteMessagingCryptoV1Store");
    }

    [Fact]
    public async Task CapabilitiesHaveNoFriendAssemblyConstructionOrDerivationPathAndRejectForgedReferences()
    {
        var bases = new[]
        {
            typeof(VerifiedTransportTargetOutcome),
            typeof(VerifiedTransportAttemptUncertainty),
            typeof(VerifiedTransportAttemptReconciliation),
            typeof(VerifiedLateMaterializationReceipt),
            typeof(InboxMaterializationRequest)
        };
        var sharedTypes = typeof(MessageStoreAuthorityBinding).Assembly.GetTypes();

        foreach (var capabilityBase in bases)
        {
            Assert.True(capabilityBase.IsAbstract);
            var baseConstructors = capabilityBase.GetConstructors(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            Assert.NotEmpty(baseConstructors);
            Assert.All(baseConstructors, constructor => Assert.True(constructor.IsFamilyAndAssembly));

            var implementation = Assert.Single(sharedTypes, type =>
                type != capabilityBase && capabilityBase.IsAssignableFrom(type));
            Assert.True(implementation.IsSealed);
            Assert.True(implementation.IsNestedPrivate);
            Assert.Equal(typeof(MessageStoreAuthorityBinding), implementation.DeclaringType);
            Assert.All(implementation.GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic),
                constructor => Assert.True(constructor.IsPrivate));
        }

        var authorityType = typeof(Msg01VerifiedSessionAuthority);
        Assert.True(authorityType.IsSealed);
        Assert.Empty(authorityType.GetConstructors(BindingFlags.Instance | BindingFlags.Public));
        var reflectedAuthority = (Msg01VerifiedSessionAuthority)Assert.Single(
            authorityType.GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic))
            .Invoke(null);
        var uninitializedAuthority = (Msg01VerifiedSessionAuthority)
            RuntimeHelpers.GetUninitializedObject(authorityType);
        Assert.Throws<CryptographicException>(() => _ = reflectedAuthority.Fingerprint);
        Assert.Throws<CryptographicException>(() => _ = uninitializedAuthority.Fingerprint);

        await using var harness = MessageStoreHarness.Create("memory");
        var seed = MessagingV1Fixture.Seed(semantic: 901, scope: harness.Scope);
        var head = (await harness.Store.BeginOutboundAsync(
            MessagingV1Fixture.Operation(901), Claim(seed), seed, default)).Snapshot!;
        var target = MessagingV1Fixture.Target(901, 902);
        head = (await harness.Store.ApplyAsync(
            PreparedMessageMutation.PrepareFanout(head, MessagingV1Fixture.Operation(902),
                [MessagingV1Fixture.Fanout(target, 901)], At(1)), default)).Snapshot!;
        var attempt = MessagingV1Fixture.Attempt(901);
        head = (await harness.Store.ApplyAsync(
            PreparedMessageMutation.StartSending(head, MessagingV1Fixture.Operation(903),
                [MessagingV1Fixture.AttemptPlan(head, target, attempt, 901)], At(2)), default)).Snapshot!;

        var forgedOutcomeType = sharedTypes.Single(type =>
            type != typeof(VerifiedTransportTargetOutcome)
            && typeof(VerifiedTransportTargetOutcome).IsAssignableFrom(type));
        var forgedOutcome = (VerifiedTransportTargetOutcome)
            RuntimeHelpers.GetUninitializedObject(forgedOutcomeType);
        Assert.Throws<CryptographicException>(() =>
            PreparedMessageMutation.FromVerifiedOutcome(head, forgedOutcome, At(3)));

        var forgedInboundType = sharedTypes.Single(type =>
            type != typeof(InboxMaterializationRequest)
            && typeof(InboxMaterializationRequest).IsAssignableFrom(type));
        var forgedInbound = (InboxMaterializationRequest)
            RuntimeHelpers.GetUninitializedObject(forgedInboundType);
        await Assert.ThrowsAsync<CryptographicException>(() =>
            harness.Store.MaterializeInboundAsync(forgedInbound, default).AsTask());

        await using var foreign = MessageStoreHarness.Create("memory", harness.Scope);
        var foreignOutcome = MessagingV1Fixture.Outcome(
            foreign.Capabilities, head, target, attempt, VerifiedTargetOutcomeKind.Accepted);
        var foreignPlan = PreparedMessageMutation.FromVerifiedOutcome(head, foreignOutcome, At(3));
        await Assert.ThrowsAsync<CryptographicException>(() =>
            harness.Store.ApplyAsync(foreignPlan, default).AsTask());
    }

    [Fact]
    public void ProductionCompositionOwnsAndDisposesStoreTrustRoot()
    {
        var scope = MessagingV1Fixture.Scope(instance: 910);
        var composition = SharedMessagingV1Composition.CreateInMemory(
            scope, MessagingV1Fixture.CreateEvidenceAuthority());
        var handoff = composition.VerifiedTransport;
        var claim = MessagingV1Fixture.Claim(semantic: 910);
        var context = new MessageCapabilityTrustedContext(
            MessageEvidencePurpose.AttemptReconciliation, scope, claim.Key,
            MessagingV1Fixture.Target(910, 911), MessagingV1Fixture.Attempt(910),
            VerifiedTargetOutcomeKind.NotAccepted,
            targetOperationId: MessagingV1Fixture.TargetOperation(910),
            bindingHash: MessagingV1Fixture.Binding(911),
            requestHash: MessagingV1Fixture.Bytes(32, 912),
            envelopeHash: MessagingV1Fixture.Bytes(32, 913),
            ratchetBeforeHash: MessagingV1Fixture.Bytes(32, 914),
            ratchetAfterHash: MessagingV1Fixture.Bytes(32, 915),
            replayCounter: 1,
            replayNonce: MessagingV1Fixture.Bytes(32, 916));
        var authenticatedEvidence = MessagingV1Fixture.Authenticate(
            context, MessagingV1Fixture.Bytes(32, 910));
        Assert.IsAssignableFrom<VerifiedTransportAttemptReconciliation>(
            handoff.VerifyReconciliation(context, authenticatedEvidence));

        composition.Dispose();
        composition.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            handoff.VerifyReconciliation(context, authenticatedEvidence));
    }

    [Fact]
    public async Task FailedConstructorSidecarValidationDisposesConnectionBeforeReturning()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"deep-msg-constructor-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "messages.db");
        var key = MessagingV1Fixture.Bytes(32, 920);
        var scope = MessagingV1Fixture.Scope(instance: 920);
        try
        {
            await using (var store = SqliteMessageStoreBootstrap.Open(new(
                path, key, scope, MessagingV1Fixture.CreateEvidenceAuthority())))
            {
                var seed = MessagingV1Fixture.Seed(semantic: 920, scope: scope);
                await store.BeginOutboundAsync(
                    MessagingV1Fixture.Operation(920), Claim(seed), seed, default);
            }

            for (var attempt = 0; attempt < 3; attempt++)
            {
                Assert.Throws<InjectedConstructorValidationFailure>(() =>
                    SqliteMessageStoreBootstrap.Open(new(
                        path, key, scope, MessagingV1Fixture.CreateEvidenceAuthority(), allowCreate: false,
                        failpoint: new ConstructorValidationFailpoint())));

                using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                }

                File.WriteAllBytes(path + "-wal", [0x01]);
                Assert.Throws<MessageStoreResetRequiredException>(() => SqliteMessageStoreBootstrap.Open(new(
                    path, key, scope, MessagingV1Fixture.CreateEvidenceAuthority(), allowCreate: false,
                    failpoint: null)));

                using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                }
                File.Delete(path + "-wal");

                await using var reopened = SqliteMessageStoreBootstrap.Open(
                    new(path, key, scope, MessagingV1Fixture.CreateEvidenceAuthority(), allowCreate: false));
                Assert.NotNull(await reopened.ReadAsync(
                    new(scope.LocalAccountId, MessagingV1Fixture.Conversation(),
                        MessagingV1Fixture.Semantic(920)), default));
            }
        }
        finally
        {
            await SqliteMessageStoreBootstrap.ResetAsync(path);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: false);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    [Theory, MemberData(nameof(Backends))]
    public async Task EqualTimestampRecoveryAndReceiptSubsetsUseCanonicalBinaryTieBreakersAcrossRestart(
        string backend)
    {
        await using var harness = MessageStoreHarness.Create(backend);
        int[] insertionOrder = [40, 10, 30, 20];

        foreach (var marker in insertionOrder)
        {
            var seed = MessagingV1Fixture.Seed(semantic: marker, scope: harness.Scope);
            await harness.Store.BeginOutboundAsync(
                MessagingV1Fixture.Operation(1_000 + marker), Claim(seed), seed, default);

            await harness.Store.MaterializeInboundAsync(
                MessagingV1Fixture.Inbound(
                    harness.Capabilities,
                    harness.Scope,
                    authorDevice: 2_000 + marker,
                    semantic: 3_000 + marker,
                    canonicalMarker: 4_000 + marker,
                    session: 5_000 + marker,
                    receipt: marker,
                    authorAccount: 6_000 + marker,
                    occurredAt: At(10)),
                default);
        }

        var owner = MessagingV1Fixture.RecoveryOwner(930);
        var expectedClaims = insertionOrder
            .Select(MessagingV1Fixture.Semantic)
            .OrderBy(static value => value)
            .Take(2)
            .Select(static value => Convert.ToHexString(value.ToArray()))
            .ToArray();
        var expectedReceipts = insertionOrder
            .Select(MessagingV1Fixture.Receipt)
            .OrderBy(static value => value)
            .Take(2)
            .Select(static value => Convert.ToHexString(value.ToArray()))
            .ToArray();

        var firstClaims = await harness.Store.ClaimRecoveryAsync(owner, At(20), 2, default);
        var firstReceipts = await harness.Store.ClaimPendingReceiptsAsync(owner, At(20), 2, default);
        Assert.Equal(expectedClaims, ClaimIds(firstClaims));
        Assert.Equal(expectedReceipts, ReceiptIds(firstReceipts));

        await harness.ReopenAsync();

        var restartedClaims = await harness.Store.ClaimRecoveryAsync(owner, At(21), 2, default);
        var restartedReceipts = await harness.Store.ClaimPendingReceiptsAsync(owner, At(21), 2, default);
        Assert.Equal(expectedClaims, ClaimIds(restartedClaims));
        Assert.Equal(expectedReceipts, ReceiptIds(restartedReceipts));
    }

    [Theory, MemberData(nameof(Backends))]
    public async Task InboundAndReceiptBuffersCannotMutateStoredState(string backend)
    {
        await using var harness = MessageStoreHarness.Create(backend);
        var canonical = MessagingV1Fixture.Bytes(128, 940);
        var expectedCanonical = canonical.ToArray();
        var sealedRatchet = MessagingV1Fixture.Bytes(96, 941);
        var authenticatedReceipt = MessagingV1Fixture.Bytes(80, 942);
        var claim = new SemanticClaimCandidate(
            MessagingV1Fixture.Account(940), MessagingV1Fixture.Device(941),
            MessagingV1Fixture.Conversation(942), MessagingV1Fixture.Semantic(943),
            MessageEventHash32.FromBytes(SHA256.HashData(canonical)));
        var context = new MessageCapabilityTrustedContext(
            MessageEvidencePurpose.InboundMaterialization,
            harness.Scope,
            claim.Key,
            receiptId: MessagingV1Fixture.Receipt(944),
            requestHash: SHA256.HashData(canonical),
            envelopeHash: claim.EventHash.ToArray(),
            ratchetBeforeHash: MessagingV1Fixture.RatchetHash(946).ToArray(),
            ratchetAfterHash: SHA256.HashData(sealedRatchet),
            replayCounter: 945,
            replayNonce: MessagingV1Fixture.Bytes(32, 947),
            ratchetSessionId: MessagingV1Fixture.RatchetSession(945));
        var sealedEvidence = MessagingV1Fixture.Authenticate(context, authenticatedReceipt);
        var expectedReceipt = sealedEvidence.ToArray();
        var request = harness.Capabilities.VerifyInbound(
            context,
            claim,
            canonical,
            MessagingV1Fixture.RatchetSession(945),
            MessagingV1Fixture.RatchetHash(946),
            RatchetStateHash32.FromBytes(SHA256.HashData(sealedRatchet)),
            sealedRatchet,
            At(40),
            sealedEvidence);

        Array.Fill(canonical, (byte)0xFF);
        Array.Fill(sealedRatchet, (byte)0xFF);
        Array.Fill(authenticatedReceipt, (byte)0xFF);
        var materialized = (await harness.Store.MaterializeInboundAsync(request, default))!;
        var escapedEvent = materialized.CanonicalEvent;
        Array.Fill(escapedEvent, (byte)0xEE);

        var reread = (await harness.Store.ReadInboxAsync(claim.Key, default))!;
        Assert.Equal(expectedCanonical, reread.CanonicalEvent);

        var owner = MessagingV1Fixture.RecoveryOwner(947);
        var receipt = Assert.Single(await harness.Store.ClaimPendingReceiptsAsync(
            owner, At(41), 1, default));
        Assert.Equal(expectedReceipt, receipt.AuthenticatedReceipt);
        var escapedReceipt = receipt.AuthenticatedReceipt;
        Array.Fill(escapedReceipt, (byte)0xDD);

        var reclaimed = Assert.Single(await harness.Store.ClaimPendingReceiptsAsync(
            owner, At(42), 1, default));
        Assert.Equal(expectedReceipt, reclaimed.AuthenticatedReceipt);
    }

    [Fact]
    public async Task ClientRuntimeAtomicallyOwnsAndDisposesAuthoritativeMsg01Transport()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"deep-msg-runtime-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var statePath = Path.Combine(directory, "messages.db");
        var raw = new TestVerifiedMsg01Transport();
        try
        {
            var runtime = new ClientRuntime(
                new InMemorySessionStore(),
                ClientFeatureFlags.Defaults,
                new SystemClock(),
                raw,
                requireE2eeTransport: true,
                mailboxDeliveryPolicy: new DirectP2pMailboxDeliveryPolicy(),
                ownsMessageTransport: true,
                messagingV1Persistence: new MessagingV1PersistenceOptions(
                    statePath, new string('A', 64)));
            Assert.Equal("Msg01AuthoritativeTransport", runtime.MessageTransport.GetType().Name);

            await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(runtime.Dispose)));
            Assert.True(runtime.IsDisposed);
            Assert.Equal(1, raw.DisposeCount);
            await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                runtime.MessageTransport.ReceiveAsync(SessionId.CreateNew()));
        }
        finally
        {
            await SqliteMessageStoreBootstrap.ResetAsync(statePath);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: false);
        }
    }

    [Fact]
    public void ProductionRuntimeRejectsCompletedNoOpTransportWithoutAuthenticatedEvidenceAuthority()
    {
        var exception = Assert.Throws<MessagingV1CryptoUnavailableException>(() => new ClientRuntime(
            new InMemorySessionStore(),
            ClientFeatureFlags.ReleaseDefaults with { MetadataPrivateTransportRequired = false },
            new SystemClock(),
            new DisposableAuthenticatedTransport(),
            requireE2eeTransport: true,
            mailboxDeliveryPolicy: new DirectP2pMailboxDeliveryPolicy(),
            messagingV1Persistence: new MessagingV1PersistenceOptions(
                Path.Combine(Path.GetTempPath(), $"deep-msg-noop-{Guid.NewGuid():N}.db"),
                new string('A', 64))));

        Assert.Equal(MessagingV1CryptoUnavailableException.ProductionCapabilityUnavailable,
            exception.Code);
        Assert.Contains("no production E2EE-01 authority", exception.Message,
            StringComparison.Ordinal);
    }

    [Theory, MemberData(nameof(Backends))]
    public async Task CanonicalPayloadAndCiphertextHaveCloneParityAcrossMutationAndRestart(string backend)
    {
        await using var harness = MessageStoreHarness.Create(backend);
        var payload = MessagingV1Fixture.Payload(960);
        var expectedPayload = payload.ToArray();
        var seed = LogicalOutboxSeed.CreateOutbound(
            harness.Scope,
            MessagingV1Fixture.Device(960),
            MessagingV1Fixture.Conversation(960),
            MessagingV1Fixture.Semantic(960),
            MessageEventHash32.FromBytes(SHA256.HashData(payload)),
            payload,
            At(1),
            At(1).AddDays(1));
        Array.Fill(payload, (byte)0xA5);

        var head = (await harness.Store.BeginOutboundAsync(
            MessagingV1Fixture.Operation(960), Claim(seed), seed, default)).Snapshot!;
        var escapedPayload = head.CanonicalPayload;
        Array.Fill(escapedPayload, (byte)0xB6);
        Assert.Equal(expectedPayload, (await harness.Store.ReadAsync(seed.ClaimKey, default))!.CanonicalPayload);

        var target = MessagingV1Fixture.Target(960, 961);
        head = (await harness.Store.ApplyAsync(
            PreparedMessageMutation.PrepareFanout(head, MessagingV1Fixture.Operation(961),
                [MessagingV1Fixture.Fanout(target, 960)], At(2)), default)).Snapshot!;
        var ciphertext = MessagingV1Fixture.Bytes(512, 962);
        var expectedCiphertext = ciphertext.ToArray();
        var attempt = MessagingV1Fixture.Attempt(962);
        var targetHead = Assert.Single(head.Targets);
        var attemptPlan = new TargetAttemptPlan(
            target, attempt,
            TransportRequestHash32.FromBytes(SHA256.HashData(ciphertext)),
            MessagingV1Fixture.RatchetHash(963),
            MessagingV1Fixture.Transition(964),
            targetHead.DirectoryHeadHash,
            targetHead.OperationId!,
            targetHead.BindingHash!,
            ciphertext);
        Array.Fill(ciphertext, (byte)0xC7);
        head = (await harness.Store.ApplyAsync(
            PreparedMessageMutation.StartSending(head, MessagingV1Fixture.Operation(965),
                [attemptPlan], At(3)), default)).Snapshot!;
        var escapedCiphertext = Assert.Single(head.Targets).Ciphertext!;
        Array.Fill(escapedCiphertext, (byte)0xD8);

        await harness.ReopenAsync();
        var reopened = (await harness.Store.ReadAsync(seed.ClaimKey, default))!;
        Assert.Equal(expectedPayload, reopened.CanonicalPayload);
        Assert.Equal(expectedCiphertext, Assert.Single(reopened.Targets).Ciphertext);
    }

    [Theory, MemberData(nameof(Backends))]
    public async Task CrashRecoveryPreservesPerTargetCommitUnknownAttemptAndAckIntent(string backend)
    {
        await using var harness = MessageStoreHarness.Create(backend);
        var seed = MessagingV1Fixture.Seed(semantic: 970, scope: harness.Scope);
        var head = (await harness.Store.BeginOutboundAsync(
            MessagingV1Fixture.Operation(970), Claim(seed), seed, default)).Snapshot!;
        var first = MessagingV1Fixture.Target(970, 971);
        var second = MessagingV1Fixture.Target(972, 973);
        head = (await harness.Store.ApplyAsync(
            PreparedMessageMutation.PrepareFanout(head, MessagingV1Fixture.Operation(971),
                [MessagingV1Fixture.Fanout(first, 970), MessagingV1Fixture.Fanout(second, 972)], At(2)), default)).Snapshot!;
        var firstAttempt = MessagingV1Fixture.Attempt(970);
        var secondAttempt = MessagingV1Fixture.Attempt(971);
        head = (await harness.Store.ApplyAsync(
            PreparedMessageMutation.StartSending(head, MessagingV1Fixture.Operation(972),
                [MessagingV1Fixture.AttemptPlan(head, first, firstAttempt, 970),
                 MessagingV1Fixture.AttemptPlan(head, second, secondAttempt, 972)], At(3)), default)).Snapshot!;
        head = (await harness.Store.ApplyAsync(
            PreparedMessageMutation.FromVerifiedOutcome(head,
                MessagingV1Fixture.Outcome(harness.Capabilities, head, first, firstAttempt,
                    VerifiedTargetOutcomeKind.Accepted), At(4)), default)).Snapshot!;
        Assert.Equal(LogicalOutboxState.PartiallyAccepted, head.State);

        var uncertaintyContext = MessagingV1Fixture.TargetContext(
            MessageEvidencePurpose.AttemptUncertainty, head, second, secondAttempt);
        var uncertainty = harness.Capabilities.VerifyAttemptUncertainty(
            uncertaintyContext,
            MessagingV1Fixture.Authenticate(uncertaintyContext, MessagingV1Fixture.Bytes(32, 974)));
        head = (await harness.Store.ApplyAsync(
            PreparedMessageMutation.MarkOutcomeUnknown(head, uncertainty, At(5)), default)).Snapshot!;
        await harness.ReopenAsync();

        head = (await harness.Store.ReadAsync(seed.ClaimKey, default))!;
        Assert.Equal(LogicalOutboxState.OutcomeUnknown, head.State);
        Assert.Equal(LogicalTargetState.Accepted, head.Targets.Single(x => x.Target.Equals(first)).State);
        Assert.Equal(secondAttempt, head.Targets.Single(x => x.Target.Equals(second)).ActiveAttemptId);
        head = (await harness.Store.ApplyAsync(
            PreparedMessageMutation.ReconcileOutcomeUnknown(head,
                MessagingV1Fixture.Reconciliation(harness.Capabilities, head, secondAttempt,
                    VerifiedTargetOutcomeKind.NotAccepted), At(6)), default)).Snapshot!;
        Assert.Equal(LogicalOutboxState.PartiallyAccepted, head.State);
        Assert.Null(head.Targets.Single(x => x.Target.Equals(second)).ActiveAttemptId);

        var freshAttempt = MessagingV1Fixture.Attempt(975);
        Assert.NotEqual(secondAttempt, freshAttempt);
        head = (await harness.Store.ApplyAsync(
            PreparedMessageMutation.StartSending(head, MessagingV1Fixture.Operation(976),
                [MessagingV1Fixture.AttemptPlan(head, second, freshAttempt, 976)], At(7)), default)).Snapshot!;
        head = (await harness.Store.ApplyAsync(
            PreparedMessageMutation.FromVerifiedOutcome(head,
                MessagingV1Fixture.Outcome(harness.Capabilities, head, second, freshAttempt,
                    VerifiedTargetOutcomeKind.Accepted), At(8)), default)).Snapshot!;
        Assert.Equal(LogicalOutboxState.Accepted, head.State);

        var inbound = MessagingV1Fixture.Inbound(
            harness.Capabilities, harness.Scope, semantic: 980, receipt: 981,
            occurredAt: At(9));
        await harness.Store.MaterializeInboundAsync(inbound, default);
        var ackOwner = MessagingV1Fixture.RecoveryOwner(982);
        var claimed = Assert.Single(await harness.Store.ClaimPendingReceiptsAsync(
            ackOwner, At(10), 1, default));
        await harness.ReopenAsync(); // remote ACK could have completed before this crash
        var reclaimed = Assert.Single(await harness.Store.ClaimPendingReceiptsAsync(
            ackOwner, At(11), 1, default));
        Assert.Equal(claimed.ReceiptId, reclaimed.ReceiptId);
        Assert.Equal(claimed.AuthenticatedReceipt, reclaimed.AuthenticatedReceipt);
        Assert.Equal(MessageCommitResult.Applied,
            await harness.Store.CompletePendingReceiptAsync(
                reclaimed.ReceiptId, ackOwner, At(12), default));
        Assert.Empty(await harness.Store.ClaimPendingReceiptsAsync(
            ackOwner, At(13), 1, default));
    }

    [Theory, MemberData(nameof(Backends))]
    public async Task PersistedStoreRejectsForeignEvidenceAuthorityAfterRestart(string backend)
    {
        await using var harness = MessageStoreHarness.Create(backend);
        var seed = MessagingV1Fixture.Seed(semantic: 990, scope: harness.Scope);
        await harness.Store.BeginOutboundAsync(
            MessagingV1Fixture.Operation(990), Claim(seed), seed, default);
        var foreignKey = MessagingV1Fixture.Bytes(32, 0x7F7F);

        if (backend == "sqlite")
        {
            var exception = Assert.Throws<MessageStoreResetRequiredException>(() =>
                harness.OpenSiblingWithEvidenceKey(foreignKey));
            Assert.Equal(MessageStoreResetRequiredReason.AuthorityMismatch, exception.Reason);
        }
        else
        {
            Assert.Throws<CryptographicException>(() =>
                harness.OpenSiblingWithEvidenceKey(foreignKey));
        }
    }

    [Fact]
    public async Task AsyncRuntimeDisposalCancelsAndAwaitsActiveMsg01DispatchBeforeDisposingTransport()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"deep-msg-quiesce-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "messages.db");
        var raw = new BlockingAuthenticatedTransport();
        try
        {
            var runtime = new ClientRuntime(
                new InMemorySessionStore(),
                ClientFeatureFlags.ReleaseDefaults with { MetadataPrivateTransportRequired = false },
                new SystemClock(), raw,
                requireE2eeTransport: true,
                mailboxDeliveryPolicy: new DirectP2pMailboxDeliveryPolicy(),
                ownsMessageTransport: true,
                messagingV1Persistence: new MessagingV1PersistenceOptions(path, new string('A', 64)));
            var sender = SessionId.CreateNew();
            var send = runtime.MessageTransport.SendAsync(new OutboundMessageEnvelope(
                sender, SessionId.CreateNew(), "quiesce", [], At(20), At(20).AddDays(1),
                MessageId.NewId()));
            await raw.DispatchEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

            await runtime.DisposeAsync();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => send);
            Assert.Equal(1, raw.DisposeCount);
            Assert.True(runtime.IsDisposed);
        }
        finally
        {
            await SqliteMessageStoreBootstrap.ResetAsync(path);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: false);
        }
    }

    private static string[] ClaimIds(IEnumerable<MessageStoreRecoveryItem> items) => items
        .Select(static item => Convert.ToHexString(
            item.Snapshot.ClaimKey.SemanticMessageId.ToArray()))
        .ToArray();

    private static string[] ReceiptIds(IEnumerable<PendingMessageReceipt> receipts) => receipts
        .Select(static receipt => Convert.ToHexString(receipt.ReceiptId.ToArray()))
        .ToArray();

    private static SemanticClaimCandidate Claim(LogicalOutboxSeed seed) => new(
        seed.AuthorAccountId, seed.AuthorDeviceId, seed.ConversationId,
        seed.SemanticMessageId, seed.EventHash);

    private static DateTimeOffset At(int seconds) =>
        MessagingV1Fixture.CreatedAt.AddSeconds(seconds);

    private sealed class ConstructorValidationFailpoint : IMessageStoreFailpoint
    {
        public void Hit(string window)
        {
            if (window == "constructor.before-encrypted-file-validation")
            {
                throw new InjectedConstructorValidationFailure();
            }
        }
    }

    private sealed class InjectedConstructorValidationFailure : Exception;

    private sealed class DisposableAuthenticatedTransport :
        IDirectP2pSessionMessageTransport,
        IAuthenticatedInboxTransport,
        IDisposable
    {
        private int disposeCount;
        internal int DisposeCount => Volatile.Read(ref disposeCount);
        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(SessionIdentityProvider identity, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
        public void Dispose() => Interlocked.Increment(ref disposeCount);
    }

    private sealed class BlockingAuthenticatedTransport :
        IDirectP2pSessionMessageTransport,
        IAuthenticatedInboxTransport,
        IMsg01AuthenticatedEvidenceSource,
        IDisposable
    {
        private readonly Msg01VerifiedSessionAuthority evidenceAuthority =
            MessagingV1Fixture.CreateEvidenceAuthority();
        private int disposeCount;
        internal int DisposeCount => Volatile.Read(ref disposeCount);
        internal TaskCompletionSource<bool> DispatchEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Msg01VerifiedSessionAuthority EvidenceAuthority => evidenceAuthority;
        public ValueTask<SessionId> GetLocalAccountAsync(CancellationToken cancellationToken) =>
            ValueTask.FromException<SessionId>(new InvalidOperationException());
        public ValueTask<DirectoryHeadHash32> ResolveFanoutTargetAsync(
            Msg01ResolveFanoutTargetRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(MessagingV1Fixture.Directory(995));
        }
        public ValueTask<Msg01PreparedTransportAttempt> PrepareAttemptAsync(
            Msg01PrepareAttemptRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new Msg01PreparedTransportAttempt(
                MessagingV1Fixture.Directory(995), MessagingV1Fixture.RatchetHash(996),
                MessagingV1Fixture.Transition(997), request.CanonicalPayload.Span));
        }
        public async ValueTask<Msg01AuthenticatedDispatchResult> DispatchPreparedAsync(
            Msg01DispatchEvidenceRequest request, CancellationToken cancellationToken)
        {
            DispatchEntered.TrySetResult(true);
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("Unreachable after infinite cancellable wait.");
        }
        public ValueTask<Msg01AuthenticatedDispatchResult> ReconcilePreparedAsync(
            Msg01DispatchEvidenceRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromException<Msg01AuthenticatedDispatchResult>(new NotSupportedException());
        public ValueTask<Msg01AuthenticatedInboundResult> GetInboundResultAsync(
            Msg01InboundEvidenceRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromException<Msg01AuthenticatedInboundResult>(new NotSupportedException());
        public ValueTask AcknowledgeReceiptAsync(
            ReadOnlyMemory<byte> authenticatedReceipt, CancellationToken cancellationToken) =>
            ValueTask.FromException(new NotSupportedException());
        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity, CancellationToken cancellationToken = default) =>
            ReceiveAsync(identity.SessionId, cancellationToken);
        public void Dispose() => Interlocked.Increment(ref disposeCount);
    }
}
