using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.ContactV1;

public sealed class ContactAddressPublicationOrchestratorTests
{
    [Fact]
    public void ProductionApiCannotMintOrImplementDirectoryAuthorizationCapability()
    {
        var capabilityType = typeof(DirectoryAuthorizedXpu1);
        var authorityType = typeof(IContactDirectoryPublicationAuthorityBoundary);

        Assert.True(capabilityType.IsPublic && capabilityType.IsSealed);
        Assert.Empty(capabilityType.GetConstructors());
        Assert.DoesNotContain(capabilityType.GetMethods(
                System.Reflection.BindingFlags.Public |
                System.Reflection.BindingFlags.Static),
            method => method.ReturnType == capabilityType);
        Assert.False(authorityType.IsPublic || authorityType.IsNestedPublic);

        var admission = Assert.Single(capabilityType.GetMethods(
                System.Reflection.BindingFlags.NonPublic |
                System.Reflection.BindingFlags.Static),
            method => method.Name == "AdmitAsync");
        Assert.True(admission.IsAssembly);
    }

    [Fact]
    public async Task ExactReplayConfirmsAndSubsequentCallDoesNotTouchTransport()
    {
        var scope = Scope();
        var exactXpu1 = DirectoryAuthorityFixture.Xpu(marker: 0x31);
        var authorized = await AuthorizeAsync(scope, exactXpu1);
        var transport = new ScriptedTransport(request => Confirmed(
            request.Span, Xpo1Status.ExactReplay));
        var service = new ContactAddressPublicationOrchestrator(
            new InMemoryContactAddressPublicationStore(scope), transport);

        var first = await service.PublishAsync(authorized);
        var second = await service.PublishAsync(authorized);

        Assert.Equal(ContactAddressPublicationDisposition.Confirmed, first.Disposition);
        Assert.Equal(Xpo1Status.ExactReplay, first.Status);
        Assert.Equal(ContactAddressPublicationState.Confirmed, first.DurableState.State);
        Assert.Equal(ContactAddressPublicationDisposition.AlreadyConfirmed, second.Disposition);
        Assert.Equal(1, transport.CallCount);
    }

    [Fact]
    public async Task OutcomeUnknownRetriesTheSameDurableBytesUntilExactReplay()
    {
        var scope = Scope();
        var exactXpu1 = DirectoryAuthorityFixture.Xpu(marker: 0x32);
        var authorized = await AuthorizeAsync(scope, exactXpu1);
        var resultIndex = 0;
        var transport = new ScriptedTransport(request => transportCallResult(request));
        ReadOnlyMemory<byte> transportCallResult(ReadOnlyMemory<byte> request)
        {
            resultIndex++;
            var actual = resultIndex == 1
                ? Xpo1Status.OutcomeUnknown
                : Xpo1Status.ExactReplay;
            return actual == Xpo1Status.OutcomeUnknown
                ? Xpo1Codec.Encode(request.Span, actual,
                    ContactServiceMutationOutcome.OutcomeUnknown, 101, 7,
                    ContactServicePaddingClass.Bytes256, [])
                : Confirmed(request.Span, actual);
        }
        var store = new InMemoryContactAddressPublicationStore(scope);
        var service = new ContactAddressPublicationOrchestrator(store, transport);

        var first = await service.PublishAsync(authorized);
        var second = await service.PublishAsync(authorized);

        Assert.Equal(ContactAddressPublicationDisposition.RetryRequired, first.Disposition);
        Assert.Equal(Xpo1Status.OutcomeUnknown, first.Status);
        Assert.Equal(7u, first.RetryAfterSeconds);
        Assert.Equal(ContactAddressPublicationDisposition.Confirmed, second.Disposition);
        Assert.Equal(2, transport.Requests.Count);
        Assert.Equal(transport.Requests[0], transport.Requests[1]);
        Assert.Equal(exactXpu1, transport.Requests[0]);
        Assert.Equal(2UL, second.DurableState.AttemptCount);
    }

    [Fact]
    public async Task ChangedBodyWithTheSameOperationIsRejectedBeforeSecondTransportCall()
    {
        var scope = Scope();
        var firstXpu1 = DirectoryAuthorityFixture.Xpu(marker: 0x41, operationMarker: 0x51);
        var changedXpu1 = DirectoryAuthorityFixture.Xpu(marker: 0x42, operationMarker: 0x51);
        var first = await AuthorizeAsync(scope, firstXpu1);
        var changed = await AuthorizeAsync(scope, changedXpu1);
        var transport = new ScriptedTransport(request => Xpo1Codec.Encode(
            request.Span, Xpo1Status.OutcomeUnknown,
            ContactServiceMutationOutcome.OutcomeUnknown, 101, 5,
            ContactServicePaddingClass.Bytes256, []));
        var service = new ContactAddressPublicationOrchestrator(
            new InMemoryContactAddressPublicationStore(scope), transport);

        _ = await service.PublishAsync(first);
        await Assert.ThrowsAsync<ContactAddressPublicationConflictException>(async () =>
            await service.PublishAsync(changed));

        Assert.Equal(1, transport.CallCount);
        Assert.NotEqual(firstXpu1, changedXpu1);
    }

    [Fact]
    public async Task SqlCipherRestartRecoversPendingOperationAndSendsIdenticalBytes()
    {
        using var fixture = PublicationStoreFixture.Create();
        var exactXpu1 = DirectoryAuthorityFixture.Xpu(marker: 0x61);
        var authorized = await AuthorizeAsync(fixture.Options.Scope, exactXpu1);
        byte[] beforeRestart;

        using (var firstStore = new SqliteContactAddressPublicationStore(fixture.Options))
        {
            var losingTransport = new ScriptedTransport(request =>
                throw new IOException("Synthetic ambiguous completion."));
            var firstService = new ContactAddressPublicationOrchestrator(
                firstStore, losingTransport);
            await Assert.ThrowsAsync<IOException>(async () =>
                await firstService.PublishAsync(authorized));
            beforeRestart = Assert.Single(losingTransport.Requests);
        }

        using var reopened = new SqliteContactAddressPublicationStore(fixture.Options);
        var recoveryTransport = new ScriptedTransport(request => Confirmed(
            request.Span, Xpo1Status.ExactReplay));
        var recovered = await new ContactAddressPublicationOrchestrator(
            reopened, recoveryTransport).PublishAsync(authorized);

        Assert.Equal(ContactAddressPublicationDisposition.Confirmed, recovered.Disposition);
        Assert.Equal(beforeRestart, Assert.Single(recoveryTransport.Requests));
        Assert.Equal(exactXpu1, beforeRestart);
        Assert.Equal(2UL, recovered.DurableState.AttemptCount);
        var operationId = Xpu1Codec.Decode(exactXpu1).OperationId;
        Assert.Equal(ContactAddressPublicationState.Confirmed,
            (await reopened.ReadAsync(operationId))!.State);
    }

    [Fact]
    public async Task MalformedOrUncorrelatedResultLeavesTheExactOperationPending()
    {
        var scope = Scope();
        var exactXpu1 = DirectoryAuthorityFixture.Xpu(marker: 0x71);
        var otherXpu1 = DirectoryAuthorityFixture.Xpu(marker: 0x72);
        var uncorrelated = Xpo1Codec.Encode(
            otherXpu1, Xpo1Status.Expired, ContactServiceMutationOutcome.None,
            101, 0, ContactServicePaddingClass.Bytes256, []);
        var store = new InMemoryContactAddressPublicationStore(scope);
        var service = new ContactAddressPublicationOrchestrator(
            store, new ScriptedTransport(_ => uncorrelated));

        var failure = await Assert.ThrowsAsync<ContactAddressPublicationException>(async () =>
            await service.PublishAsync(await AuthorizeAsync(scope, exactXpu1)));

        Assert.Equal(ContactAddressPublicationFailure.MalformedServiceResult, failure.Failure);
        var operationId = Xpu1Codec.Decode(exactXpu1).OperationId;
        var pending = Assert.IsType<ContactAddressPublicationSnapshot>(
            await store.ReadAsync(operationId));
        Assert.Equal(ContactAddressPublicationState.Pending, pending.State);
        Assert.Empty(pending.ExactXpo1.ToArray());
    }

    [Fact]
    public async Task DirectoryAuthorityRejectionFailsClosedBeforeJournalAndTransport()
    {
        var scope = Scope();
        var exactXpu1 = DirectoryAuthorityFixture.Xpu(marker: 0x73);
        var authority = new FixedAuthorityBoundary(
            ContactDirectoryAuthorizationVerdict.Indeterminate);

        var failure = await Assert.ThrowsAsync<ContactAddressPublicationException>(async () =>
            await DirectoryAuthorizedXpu1.AdmitAsync(authority, scope, exactXpu1));

        Assert.Equal(ContactAddressPublicationFailure.DirectoryAuthorizationRejected,
            failure.Failure);
        Assert.Equal(1, authority.CallCount);
    }

    private static ValueTask<DirectoryAuthorizedXpu1> AuthorizeAsync(
        ContactStoreScope scope,
        byte[] exactXpu1) => DirectoryAuthorizedXpu1.AdmitAsync(
            new FixedAuthorityBoundary(ContactDirectoryAuthorizationVerdict.Authorized),
            scope,
            exactXpu1);

    private static byte[] Confirmed(ReadOnlySpan<byte> exactXpu1, Xpo1Status status) =>
        Xpo1Codec.Encode(
            exactXpu1,
            status,
            ContactServiceMutationOutcome.DurablyCommitted,
            101,
            0,
            ContactServicePaddingClass.Bytes1024,
            [U64(0), Bytes(32, 0x91), U64(7), ReplicaReceipts()]);

    private static ContactStoreScope Scope(byte marker = 0x21) =>
        ContactStoreScope.ForCurrentAccount(
            DeepAccountIdentityCapability.FromVerifiedInputs(
                DeepNetworkId16.FromVerifiedBytes(Bytes(16, 0x11)),
                1,
                AccountEd25519PublicKey32.FromVerifiedBytes(Bytes(32, marker)))
            .AccountId);

    private sealed class FixedAuthorityBoundary(ContactDirectoryAuthorizationVerdict verdict)
        : IContactDirectoryPublicationAuthorityBoundary
    {
        public int CallCount { get; private set; }

        public ValueTask<ContactDirectoryAuthorizationVerdict> VerifyPermanentAddressAuthorizedXpu1Async(
            ContactStoreScope accountScope,
            ReadOnlyMemory<byte> exactXpu1,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return ValueTask.FromResult(verdict);
        }
    }

    private sealed class ScriptedTransport(
        Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> response)
        : IOpaqueContactAddressPublicationTransport
    {
        public List<byte[]> Requests { get; } = [];
        public int CallCount => Requests.Count;

        public ValueTask<ReadOnlyMemory<byte>> PublishAsync(
            ReadOnlyMemory<byte> exactXpu1,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(exactXpu1.ToArray());
            return ValueTask.FromResult(response(exactXpu1));
        }
    }

    private sealed class PublicationStoreFixture : IDisposable
    {
        private PublicationStoreFixture(
            string directory,
            SqliteContactAddressPublicationStoreOptions options)
        {
            Directory = directory;
            Options = options;
        }

        public string Directory { get; }
        public SqliteContactAddressPublicationStoreOptions Options { get; }

        public static PublicationStoreFixture Create()
        {
            var directory = Path.Combine(Path.GetTempPath(),
                "deep-contact-publication-tests", Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(directory);
            var options = new SqliteContactAddressPublicationStoreOptions(
                Path.Combine(directory, "publication.db"),
                Bytes(32, 0xE1),
                Scope());
            return new PublicationStoreFixture(directory, options);
        }

        public void Dispose()
        {
            Options.Dispose();
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, recursive: true);
        }
    }

    /// <summary>
    /// Opaque, structurally valid authority-owned wire fixture. These tests do not
    /// implement, sign, or claim to verify directory threshold authorization.
    /// </summary>
    private static class DirectoryAuthorityFixture
    {
        internal static byte[] Xpu(byte marker, byte? operationMarker = null)
        {
            var network = Bytes(16, 1);
            var operation = Bytes(32, operationMarker ?? marker);
            var view = Bytes(32, 3);
            var placement = Bytes(32, 4);
            var locator = Bytes(32, 5);
            var xir = Bytes(32, 6);
            var ciphertext = Bytes(40, marker);
            const ulong effectiveExpiresAt = 80;
            var bodyHash = Xpu1Codec.ComputeAuthorizedBodyHash(
                network, operation, view, placement, 10, 20, locator, xir, 0,
                new byte[32], ciphertext, 0, effectiveExpiresAt);
            var witnessRows = new byte[192];
            Bytes(32, 1).CopyTo(witnessRows, 0);
            Bytes(64, 3).CopyTo(witnessRows, 32);
            Bytes(32, 2).CopyTo(witnessRows, 96);
            Bytes(64, 4).CopyTo(witnessRows, 128);
            var exactXpa1 = Record("XPA1",
            [
                (1, network), (2, Bytes(32, 8)), (3, operation), (4, locator),
                (5, new byte[] { 1 }), (6, Bytes(32, 9)), (7, Bytes(32, 10)), (8, xir),
                (9, U64(0)), (10, new byte[32]), (11, SHA256.HashData(ciphertext)),
                (12, U32(0)), (13, U64(effectiveExpiresAt)), (14, Bytes(32, 11)),
                (15, U64(9)), (16, U64(10)), (17, U64(20)), (18, Bytes(32, 12)),
                (19, bodyHash), (20, new byte[] { 2 }), (21, witnessRows),
            ]);
            return Xpu1Codec.Encode(
                network, operation, view, placement, 10, 20, locator, xir, 0,
                new byte[32], ciphertext, 0, effectiveExpiresAt, exactXpa1);
        }
    }

    private static byte[] ReplicaReceipts()
    {
        var receipts = new byte[193];
        receipts[0] = 2;
        Bytes(32, 1).CopyTo(receipts, 1);
        Bytes(64, 10).CopyTo(receipts, 33);
        Bytes(32, 2).CopyTo(receipts, 97);
        Bytes(64, 11).CopyTo(receipts, 129);
        return receipts;
    }

    private static byte[] Record(
        string magic,
        IReadOnlyList<(ushort Tag, byte[] Value)> fields)
    {
        var size = 12 + fields.Sum(static field => 8 + field.Value.Length);
        var bytes = new byte[size];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        foreach (var field in fields)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), field.Tag);
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 4),
                checked((uint)field.Value.Length));
            offset += 8;
            field.Value.CopyTo(bytes, offset);
            offset += field.Value.Length;
        }
        return bytes;
    }

    private static byte[] Bytes(int length, byte marker)
    {
        var result = new byte[length];
        for (var index = 0; index < result.Length; index++)
            result[index] = checked((byte)(marker + index % 17));
        return result;
    }

    private static byte[] U32(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }
}
