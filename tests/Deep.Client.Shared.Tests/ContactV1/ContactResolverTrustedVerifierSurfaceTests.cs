using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Tests.ContactV1;

public sealed class ContactResolverTrustedVerifierSurfaceTests
{
    [Fact]
    public void ReverifySurface_ReturnsOnlyFreshProtocolAuthorityAndHasNoPublicMintingConstructor()
    {
        var method = typeof(ContactResolverTrustedVerifier).GetMethod(
            nameof(ContactResolverTrustedVerifier.ReverifyAsync));

        Assert.NotNull(method);
        Assert.Equal(typeof(ValueTask<ContactResolverReverifiedPeerAuthority>), method.ReturnType);
        Assert.Equal(
            [typeof(ContactVerifiedPeerPackageEvidence), typeof(CancellationToken)],
            method.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.Empty(typeof(ContactResolverReverifiedPeerAuthority)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public async Task Reverify_DecodesPersistedExactTranscriptBeforeCurrentCapabilityLookup()
    {
        var input = await PermanentStructuralSuccessInputAsync();
        var source = new ThrowingSource(new InvalidOperationException("current authority unavailable"));
        var verifier = new ContactResolverTrustedVerifier(source);
        var package = RecoveryPackage(input, 0x61);

        var error = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await verifier.ReverifyAsync(package));

        Assert.IsType<InvalidOperationException>(error.InnerException);
        Assert.Equal(1, source.CallCount);
    }

    [Fact]
    public async Task Reverify_MalformedPersistedTranscriptFailsBeforeCapabilityLookup()
    {
        var input = await PermanentStructuralSuccessInputAsync();
        var source = new RecordingSource();
        var verifier = new ContactResolverTrustedVerifier(source);
        var valid = RecoveryPackage(input, 0x62);
        var malformed = new ContactVerifiedPeerPackageEvidence(
            valid.Scope,
            valid.RelationshipId,
            valid.ConversationId,
            valid.RemoteAccountId,
            valid.AddressKind,
            valid.NetworkId.Span,
            valid.ExactCanonicalAddress.Span,
            [0x01],
            valid.ExactXis1.Span,
            valid.ExactDcr1.Span,
            valid.ExactDcb1.Span,
            valid.ExactDmd1.Span,
            valid.Devices,
            valid.ExactRouteClosure.Span);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await verifier.ReverifyAsync(malformed));
        Assert.Equal(0, source.CallCount);
    }

    [Fact]
    public void ProductionFactory_HasOnlyProtectedPathAuthorityInput()
    {
        var factory = typeof(ContactResolverTrustedVerifierFactory).GetMethod(
            nameof(ContactResolverTrustedVerifierFactory.CreateProduction));
        Assert.NotNull(factory);
        var parameter = Assert.Single(factory.GetParameters());

        Assert.Equal(typeof(IContactResolvePathAuthoritySource), parameter.ParameterType);
        Assert.Equal(typeof(ContactResolverTrustedVerifier), factory.ReturnType);
        var verifier = ContactResolverTrustedVerifierFactory.CreateProduction(new RecordingPathAuthority());
        Assert.IsType<ContactResolverTrustedVerifier>(verifier);
    }

    [Fact]
    public void ProductionCapabilitySource_PublicConstructorHasNoRawOrVerifiedInjection()
    {
        var constructor = Assert.Single(typeof(ProductionContactResolverVerifiedCapabilitySource)
            .GetConstructors());
        var parameter = Assert.Single(constructor.GetParameters());

        Assert.Equal(typeof(IContactResolvePathAuthoritySource), parameter.ParameterType);
        Assert.Empty(typeof(ContactResolverVerifiedCapabilitySet).GetConstructors());
    }

    [Fact]
    public void CapabilitySource_IsOneAtomicTypedClosureOperation()
    {
        var method = Assert.Single(typeof(IContactResolverVerifiedCapabilitySource).GetMethods());
        Assert.Equal(nameof(IContactResolverVerifiedCapabilitySource.VerifyAsync), method.Name);
        Assert.Equal(typeof(ValueTask<ContactResolverVerifiedCapabilitySet>), method.ReturnType);
        Assert.DoesNotContain(method.GetParameters(), parameter =>
            parameter.ParameterType == typeof(bool) ||
            parameter.Name?.Contains("key", StringComparison.OrdinalIgnoreCase) == true ||
            parameter.Name?.Contains("receipt", StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact]
    public async Task PermanentProductionBundle_RequiresTargetedPermanentPathAuthority()
    {
        var path = new RecordingPathAuthority();
        var source = new ProductionContactResolverVerifiedCapabilitySource(path);
        var input = await PermanentStructuralSuccessInputAsync();

        var error = await Assert.ThrowsAsync<ContactResolverCapabilityUnavailableException>(async () =>
            await source.VerifyAsync(input));

        Assert.Equal(ContactResolverCapabilityUnavailableException.PermanentPathAuthorityUnavailable,
            error.Code);
        Assert.Contains("targeted current-value permanent DID1", error.Message, StringComparison.Ordinal);
        Assert.Equal(0, path.CallCount);
    }

    [Fact]
    public async Task PermanentProductionResolve_DoesNotUsePlacementOnlyPathAsIdentityAuthority()
    {
        var path = new RecordingPathAuthority();
        var source = new ProductionContactResolverVerifiedCapabilitySource(path);
        var input = await PermanentStructuralSuccessInputAsync();

        var error = await Assert.ThrowsAsync<ContactResolverCapabilityUnavailableException>(async () =>
            await source.VerifyAsync(input));

        Assert.Equal(ContactResolverCapabilityUnavailableException.PermanentPathAuthorityUnavailable,
            error.Code);
        Assert.Equal(0, path.CallCount);
    }

    [Fact]
    public async Task PermanentResolve_DoesNotFallBackToPlacementOnlyPath()
    {
        var failure = new InvalidOperationException("durable path authority unavailable");
        var path = new RecordingPathAuthority(failure);
        var source = new ProductionContactResolverVerifiedCapabilitySource(path);
        var input = await PermanentStructuralSuccessInputAsync();

        var error = await Assert.ThrowsAsync<ContactResolverCapabilityUnavailableException>(async () =>
            await source.VerifyAsync(input));

        Assert.Equal(ContactResolverCapabilityUnavailableException.PermanentPathAuthorityUnavailable,
            error.Code);
        Assert.Equal(0, path.CallCount);
    }

    [Fact]
    public async Task ProductionPlacement_CrossNetworkTranscriptFailsBeforePathAuthority()
    {
        var path = new RecordingPathAuthority();
        var source = new ProductionContactResolverVerifiedCapabilitySource(path);
        var input = await PermanentStructuralSuccessInputAsync();
        var wrongRequest = Xiq1Codec.Decode(Xiq1Codec.Encode(
            ContactResolverClientOrchestrationTests.B(16, 0x99),
            input.Request.OperationId.Span,
            input.Request.ViewHash.Span,
            input.Request.PlacementHash.Span,
            input.Request.IssuedAtUnixSeconds,
            input.Request.ExpiresAtUnixSeconds,
            input.Request.LocatorHash.Span,
            input.Request.RequestedGeneration,
            input.Request.AntiSpamTokenType,
            input.Request.AntiSpamToken.Span,
            input.Request.ResponsePaddingClass));
        var mismatched = new ContactResolverVerificationInput(
            input.Address, wrongRequest, input.Result);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.VerifyAsync(mismatched));

        Assert.Equal(0, path.CallCount);
    }

    [Fact]
    public async Task ProductionPlacement_CancellationFailsBeforePathAuthority()
    {
        var path = new RecordingPathAuthority();
        var source = new ProductionContactResolverVerifiedCapabilitySource(path);
        var input = await PermanentStructuralSuccessInputAsync();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await source.VerifyAsync(input, cancellation.Token));

        Assert.Equal(0, path.CallCount);
    }

    [Fact]
    public async Task OneTimeProductionResolve_RequiresTargetedCurrentValuePathAuthority()
    {
        var path = new RecordingPathAuthority();
        var source = new ProductionContactResolverVerifiedCapabilitySource(path);
        var input = await StructuralSuccessInputAsync(oneTimeAddress: true, consumingResult: true);

        var error = await Assert.ThrowsAsync<ContactResolverCapabilityUnavailableException>(async () =>
            await source.VerifyAsync(input));

        Assert.Equal(ContactResolverCapabilityUnavailableException.ClaimPathAuthorityUnavailable,
            error.Code);
        Assert.Equal(0, path.CallCount);
    }

    [Fact]
    public async Task ChangedDia1FailsBeforeClaimPathAuthorityLookup()
    {
        var path = new RecordingPathAuthority();
        var source = new ProductionContactResolverVerifiedCapabilitySource(path);
        var input = await StructuralSuccessInputAsync(oneTimeAddress: true, consumingResult: true);
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var dia = ContactCodec.Decode(
            "DIA1", ContactResolverClientOrchestrationTests.Dia1(2_000_000_000));
        var fields = Enumerable.Range(1, 9).Select(dia.Field).ToArray();
        fields[1] = ContactResolverClientOrchestrationTests.B(32, 0xe1);
        var changedText = DeepInvitationTextCodec.EncodeCanonical(
            ContactCodec.Decode("DIA1",
                ContactResolverClientOrchestrationTests.Write("DIA1", fields)));
        var changedAddress = (await new ContactAddressImportService(
            store, ContactResolverClientOrchestrationTests.Network)
            .ImportAsync(changedText)).PendingAddress.Address;
        var changed = new ContactResolverVerificationInput(changedAddress, input.Request, input.Result);

        await Assert.ThrowsAnyAsync<CryptographicException>(async () => await source.VerifyAsync(changed));

        Assert.Equal(0, path.CallCount);
    }

    [Fact]
    public void ProductionComposition_UsesTheClosedProtocolCapabilitySignature()
    {
        Func<ContactResolverVerificationInput, ContactStoreScope, ContactRelationshipId32,
            VerifiedContactBundleClosure, VerifiedContactRouteClosure, VerifiedContactServicePlacement,
            VerifiedXis1InviteClaimReceipt?, VerifiedContactBundleEvidence> accept =
            ContactResolverTrustedVerification.Accept;

        Assert.NotNull(accept);
    }

    [Fact]
    public async Task Cancellation_FailsBeforeAnyCapabilitySourceIsCalled()
    {
        var source = new RecordingSource();
        var verifier = new ContactResolverTrustedVerifier(source);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await verifier.VerifyAsync(null!, null!, null!, cancellation.Token));

        Assert.Equal(0, source.CallCount);
    }

    [Fact]
    public void CapabilitySourceContract_HasNoCallerKeyOrTrustDecisionArguments()
    {
        IContactResolverVerifiedCapabilitySource source = new RecordingSource();
        Func<ContactResolverVerificationInput, CancellationToken,
            ValueTask<ContactResolverVerifiedCapabilitySet>> verify = source.VerifyAsync;

        Assert.NotNull(verify);
    }

    [Fact]
    public async Task StructuralSuccessXis1_WithoutProtocolCapabilities_FailsClosedBeforeEvidence()
    {
        var source = new ThrowingSource(new InvalidOperationException("unverified structural XIS1"));
        var verifier = new ContactResolverTrustedVerifier(source);
        var input = await PermanentStructuralSuccessInputAsync();

        var error = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await verifier.VerifyAsync(input, ContactResolverClientOrchestrationTests.Scope(),
                ContactRelationshipId32.FromBytes(ContactResolverClientOrchestrationTests.B(32, 0x70))));

        Assert.IsType<InvalidOperationException>(error.InnerException);
        Assert.Equal(1, source.CallCount);
        Assert.Equal("verify", Assert.Single(source.Calls));
    }

    [Fact]
    public async Task SourceCancellationWithoutCallerCancellation_FailsClosed()
    {
        var source = new ThrowingSource(new OperationCanceledException("source cancellation"));
        var verifier = new ContactResolverTrustedVerifier(source);
        var input = await PermanentStructuralSuccessInputAsync();

        var error = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await verifier.VerifyAsync(input, ContactResolverClientOrchestrationTests.Scope(),
                ContactRelationshipId32.FromBytes(ContactResolverClientOrchestrationTests.B(32, 0x71))));

        Assert.IsType<OperationCanceledException>(error.InnerException);
        Assert.Equal(new[] { "verify" }, source.Calls);
    }

    [Fact]
    public async Task OneTimeAddress_WithNonConsumingSuccess_FailsBeforeCapabilityLookup()
    {
        var source = new RecordingSource();
        var verifier = new ContactResolverTrustedVerifier(source);
        var input = await StructuralSuccessInputAsync(oneTimeAddress: true, consumingResult: false);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await verifier.VerifyAsync(input, ContactResolverClientOrchestrationTests.Scope(),
                ContactRelationshipId32.FromBytes(ContactResolverClientOrchestrationTests.B(32, 0x72))));

        Assert.Equal(0, source.CallCount);
    }

    [Fact]
    public async Task PermanentAddress_WithConsumingSuccess_FailsBeforeCapabilityLookup()
    {
        var source = new RecordingSource();
        var verifier = new ContactResolverTrustedVerifier(source);
        var input = await StructuralSuccessInputAsync(oneTimeAddress: false, consumingResult: true);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await verifier.VerifyAsync(input, ContactResolverClientOrchestrationTests.Scope(),
                ContactRelationshipId32.FromBytes(ContactResolverClientOrchestrationTests.B(32, 0x73))));

        Assert.Equal(0, source.CallCount);
    }

    [Fact]
    public async Task VerificationInput_ProtocolValuesExposeDefensiveCopies()
    {
        var input = await PermanentStructuralSuccessInputAsync();
        var expectedRequest = input.Request.CanonicalBytes.ToArray();
        var expectedResult = input.Result.CanonicalBytes.ToArray();
        var expectedAddress = input.Address.CanonicalBytes.ToArray();

        OverwriteFirstByte(input.Request.CanonicalBytes);
        OverwriteFirstByte(input.Result.CanonicalBytes);
        OverwriteFirstByte(input.Address.CanonicalBytes);

        Assert.Equal(expectedRequest, input.Request.CanonicalBytes.ToArray());
        Assert.Equal(expectedResult, input.Result.CanonicalBytes.ToArray());
        Assert.Equal(expectedAddress, input.Address.CanonicalBytes.ToArray());
    }

    private static void OverwriteFirstByte(ReadOnlyMemory<byte> value)
    {
        Assert.True(MemoryMarshal.TryGetArray(value, out var segment));
        segment.Array![segment.Offset] = 0;
    }

    private static ContactVerifiedPeerPackageEvidence RecoveryPackage(
        ContactResolverVerificationInput input,
        byte marker)
    {
        var scope = ContactResolverClientOrchestrationTests.Scope();
        var relationship = ContactRelationshipId32.FromBytes(
            ContactResolverClientOrchestrationTests.B(32, marker));
        var evidence = ContactTrustedVerifierBoundary.BundleVerified(
            scope,
            input.Address,
            ContactResolverClientOrchestrationTests.B(32, unchecked((byte)(marker + 1))),
            relationship,
            Enum.GetValues<ContactVerifiedArtifactKind>().ToDictionary(
                static kind => kind,
                kind => (ReadOnlyMemory<byte>)ContactResolverClientOrchestrationTests.B(
                    32, unchecked((byte)(0x80 + (int)kind)))),
            ContactResolverClientOrchestrationTests.B(32, unchecked((byte)(marker + 2))));
        return new ContactVerifiedPeerPackageEvidence(
            scope,
            relationship,
            evidence.ConversationId,
            evidence.RemoteAccountId,
            input.Address.Kind,
            input.Address.NetworkId.Span,
            input.Address.CanonicalBytes.Span,
            input.Request.WireBytes.Span,
            input.Result.WireBytes.Span,
            [0x41],
            [0x42],
            [0x43],
            [new ContactVerifiedPeerDeviceEvidence(
                ContactResolverClientOrchestrationTests.B(32, 0x44),
                ContactResolverClientOrchestrationTests.B(776, 0x45))],
            input.Result.Field(21).Span);
    }

    private static Task<ContactResolverVerificationInput> PermanentStructuralSuccessInputAsync() =>
        StructuralSuccessInputAsync(oneTimeAddress: false, consumingResult: false);

    private static async Task<ContactResolverVerificationInput> StructuralSuccessInputAsync(
        bool oneTimeAddress,
        bool consumingResult)
    {
        var store = new InMemoryContactStateStore(ContactResolverClientOrchestrationTests.Scope());
        var addressText = oneTimeAddress
            ? DeepInvitationTextCodec.EncodeCanonical(ContactCodec.Decode(
                "DIA1", ContactResolverClientOrchestrationTests.Dia1(2_000_000_000)))
            : ApplicationCoreCodec.AuthorDid1(
                ContactResolverClientOrchestrationTests.B(32, 0x81),
                ContactResolverClientOrchestrationTests.B(16, 0x82)).Text;
        var pending = (await new ContactAddressImportService(
            store, ContactResolverClientOrchestrationTests.Network)
            .ImportAsync(addressText)).PendingAddress;
        var locator = ContactCodecHash.OneTimeOrPermanentLocator(pending.Address);
        byte[] exactXiq1;
        try
        {
            exactXiq1 = Xiq1Codec.Encode(
                ContactResolverClientOrchestrationTests.Network,
                ContactResolverClientOrchestrationTests.B(32, 0x83),
                ContactResolverClientOrchestrationTests.B(32, 0x84),
                ContactResolverClientOrchestrationTests.B(32, 0x85),
                10,
                100,
                locator,
                0,
                Xiq1AntiSpamTokenType.None,
                ReadOnlySpan<byte>.Empty,
                ContactServicePaddingClass.Bytes16384);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(locator);
        }
        var route = ContactResolverClientOrchestrationTests.RouteClosure();
        var cipher = ContactResolverClientOrchestrationTests.B(40, 0x88);
        var payload = new List<ReadOnlyMemory<byte>>
        {
            U64(0), U64(90), SHA256.HashData(cipher), cipher, SHA256.HashData(route), route,
        };
        var outcome = ContactServiceMutationOutcome.None;
        if (consumingResult)
        {
            payload.Add(U64(1));
            payload.Add(FakeReceipts());
            outcome = ContactServiceMutationOutcome.DurablyCommitted;
        }
        else
        {
            payload.Add(FakeReceipts());
        }
        var exactXis1 = Xis1Codec.Encode(exactXiq1, Xis1Status.Success, outcome, 50, 0,
            ContactServicePaddingClass.Bytes16384, payload);
        return new ContactResolverVerificationInput(
            pending.Address, Xiq1Codec.Decode(exactXiq1), Xis1Codec.Decode(exactXis1, exactXiq1));
    }

    private static byte[] FakeReceipts()
    {
        var receipts = new byte[193];
        receipts[0] = 2;
        ContactResolverClientOrchestrationTests.B(32, 0x11).CopyTo(receipts, 1);
        ContactResolverClientOrchestrationTests.B(64, 0x31).CopyTo(receipts, 33);
        ContactResolverClientOrchestrationTests.B(32, 0x22).CopyTo(receipts, 97);
        ContactResolverClientOrchestrationTests.B(64, 0x41).CopyTo(receipts, 129);
        return receipts;
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private sealed class RecordingSource : IContactResolverVerifiedCapabilitySource
    {
        public int CallCount { get; private set; }

        public ValueTask<ContactResolverVerifiedCapabilitySet> VerifyAsync(
            ContactResolverVerificationInput input,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            throw new Xunit.Sdk.XunitException("Capability source must not run after cancellation.");
        }
    }

    private sealed class ThrowingSource(Exception failure) : IContactResolverVerifiedCapabilitySource
    {
        public List<string> Calls { get; } = [];
        public int CallCount => Calls.Count;

        public ValueTask<ContactResolverVerifiedCapabilitySet> VerifyAsync(
            ContactResolverVerificationInput input,
            CancellationToken cancellationToken = default)
        {
            Calls.Add("verify");
            return ValueTask.FromException<ContactResolverVerifiedCapabilitySet>(failure);
        }
    }

    private sealed class RecordingPathAuthority(Exception? failure = null)
        : IContactResolvePathAuthoritySource
    {
        public int CallCount { get; private set; }
        public Xiq1Request? LastRequest { get; private set; }

        public ValueTask<ContactResolvePathAuthority> GetCurrentAsync(
            Xiq1Request request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            LastRequest = request;
            return failure is null
                ? ValueTask.FromException<ContactResolvePathAuthority>(
                    new InvalidOperationException("No forged verified path capability is supplied by this test."))
                : ValueTask.FromException<ContactResolvePathAuthority>(failure);
        }
    }
}
