using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.ContactV1;

public sealed class ContactClient01ALocalCoreTests
{
    private static readonly byte[] Network = Bytes(16, 0x11);

    [Fact]
    public async Task CanonicalPermanentDidIsStoredOnlyAsPendingAddress()
    {
        var store = new InMemoryContactStateStore(Scope());
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_900_000_000));
        var service = new ContactAddressImportService(store, Network, clock);
        var did = ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x21), Bytes(16, 0x22));

        var result = await service.ImportAsync(did.Text);

        Assert.Equal(PendingContactAddressWriteDisposition.Added, result.Disposition);
        Assert.Equal(ContactAddressKind.PermanentDeepId, result.PendingAddress.Address.Kind);
        Assert.Equal(did.CanonicalBytes.ToArray(), result.PendingAddress.Address.CanonicalBytes.ToArray());
        Assert.Equal(did.Text, result.PendingAddress.Address.CanonicalText);
        Assert.Null(result.PendingAddress.Address.ExpiresAtUnixSeconds);
        Assert.Equal(ContactRelationshipState.Absent, result.PendingAddress.RelationshipState);
        Assert.Null(result.PendingAddress.RelationshipId);
        Assert.Null(result.PendingAddress.ConversationId);
        Assert.False(result.PendingAddress.BundleVerified);
        Assert.Equal(clock.GetUtcNow(), result.PendingAddress.ImportedAt);
    }

    [Fact]
    public async Task CanonicalDiaIsStoredWithoutResolutionOrVerification()
    {
        var invitation = ContactCodec.Decode("DIA1", Dia1(Network, 2_000_000_000));
        var text = DeepInvitationTextCodec.EncodeCanonical(invitation);
        var store = new InMemoryContactStateStore(Scope());
        var service = new ContactAddressImportService(store, Network);

        var result = await service.ImportAsync(text);

        Assert.Equal(ContactAddressKind.OneTimeInvitation, result.PendingAddress.Address.Kind);
        Assert.Equal(invitation.CanonicalBytes.ToArray(), result.PendingAddress.Address.CanonicalBytes.ToArray());
        Assert.Equal(2_000_000_000UL, result.PendingAddress.Address.ExpiresAtUnixSeconds);
        Assert.False(result.PendingAddress.BundleVerified);
        Assert.Single(await store.ReadPendingAddressesAsync());
    }

    [Theory]
    [InlineData("Alice")]
    [InlineData("05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("CMI1:YWJj")]
    [InlineData("cmi1:YWJj")]
    [InlineData("DCR1")]
    public async Task LegacyAndNonAddressInputsRejectWithoutMutation(string input)
    {
        var store = new InMemoryContactStateStore(Scope());
        var service = new ContactAddressImportService(store, Network);

        var error = await Assert.ThrowsAsync<ContactAddressImportException>(async () =>
            await service.ImportAsync(input));

        Assert.Equal(ContactAddressImportFailure.NonCanonicalOrUnsupported, error.Failure);
        Assert.Empty(await store.ReadPendingAddressesAsync());
    }

    [Fact]
    public async Task EmbeddedDcrDisguisedAsInvitationRejectsWithoutMutation()
    {
        var bytes = Dia1(Network, 2_000_000_000);
        Encoding.ASCII.GetBytes("DCR1").CopyTo(bytes, 0);
        var input = "deepinvite:" + Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_');
        var store = new InMemoryContactStateStore(Scope());
        var service = new ContactAddressImportService(store, Network);

        var error = await Assert.ThrowsAsync<ContactAddressImportException>(async () =>
            await service.ImportAsync(input));

        Assert.Equal(ContactAddressImportFailure.NonCanonicalOrUnsupported, error.Failure);
        Assert.Empty(await store.ReadPendingAddressesAsync());
    }

    [Fact]
    public async Task NonCanonicalDidVariantsRejectWithoutMutation()
    {
        var did = ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x31), Bytes(16, 0x32)).Text;
        var store = new InMemoryContactStateStore(Scope());
        var service = new ContactAddressImportService(store, Network);

        foreach (var input in new[] { did.ToUpperInvariant(), " " + did, did + " ", did + "ignored" })
        {
            var error = await Assert.ThrowsAsync<ContactAddressImportException>(async () =>
                await service.ImportAsync(input));
            Assert.Equal(ContactAddressImportFailure.NonCanonicalOrUnsupported, error.Failure);
        }
        Assert.Empty(await store.ReadPendingAddressesAsync());
    }

    [Fact]
    public async Task InvitationForAnotherNetworkRejectsBeforeStoreMutation()
    {
        var input = DeepInvitationTextCodec.EncodeCanonical(
            ContactCodec.Decode("DIA1", Dia1(Bytes(16, 0x77), 2_000_000_000)));
        var store = new InMemoryContactStateStore(Scope());
        var service = new ContactAddressImportService(store, Network);

        var error = await Assert.ThrowsAsync<ContactAddressImportException>(async () =>
            await service.ImportAsync(input));

        Assert.Equal(ContactAddressImportFailure.WrongNetwork, error.Failure);
        Assert.Empty(await store.ReadPendingAddressesAsync());
    }

    [Fact]
    public async Task DuplicateImportIsIdempotentAndPreservesFirstTimestamp()
    {
        var firstTime = DateTimeOffset.FromUnixTimeSeconds(1_900_000_000);
        var clock = new MutableTimeProvider(firstTime);
        var store = new InMemoryContactStateStore(Scope());
        var service = new ContactAddressImportService(store, Network, clock);
        var did = ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x41), Bytes(16, 0x42)).Text;

        var first = await service.ImportAsync(did);
        clock.UtcNow = firstTime.AddDays(1);
        var replay = await service.ImportAsync(did);

        Assert.Equal(PendingContactAddressWriteDisposition.Added, first.Disposition);
        Assert.Equal(PendingContactAddressWriteDisposition.Idempotent, replay.Disposition);
        Assert.Equal(firstTime, replay.PendingAddress.ImportedAt);
        Assert.Single(await store.ReadPendingAddressesAsync());
    }

    [Fact]
    public async Task BoundedStoreFailsClosedWithoutEvictingExistingAddress()
    {
        var store = new InMemoryContactStateStore(Scope(), maximumPendingAddresses: 1);
        var service = new ContactAddressImportService(store, Network);
        var first = ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x51), Bytes(16, 0x52));
        var second = ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x53), Bytes(16, 0x54));
        await service.ImportAsync(first.Text);

        var error = await Assert.ThrowsAsync<ContactAddressImportException>(async () =>
            await service.ImportAsync(second.Text));

        Assert.Equal(ContactAddressImportFailure.LocalCapacityExceeded, error.Failure);
        var addresses = await store.ReadPendingAddressesAsync();
        Assert.Single(addresses);
        Assert.Equal(first.CanonicalBytes.ToArray(), addresses[0].Address.CanonicalBytes.ToArray());
    }

    [Fact]
    public async Task ConcurrentSameAddressImportCreatesOnePendingRecord()
    {
        var store = new InMemoryContactStateStore(Scope());
        var service = new ContactAddressImportService(store, Network);
        var did = ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x61), Bytes(16, 0x62)).Text;

        var results = await Task.WhenAll(Enumerable.Range(0, 16)
            .Select(async _ => await service.ImportAsync(did)));

        Assert.Single(results, static result => result.Disposition == PendingContactAddressWriteDisposition.Added);
        Assert.Equal(15, results.Count(static result => result.Disposition == PendingContactAddressWriteDisposition.Idempotent));
        Assert.Single(await store.ReadPendingAddressesAsync());
    }

    [Fact]
    public void ConversationIdUsesOnlyNormativeDomainAndSortedAccounts()
    {
        var relationship = ContactRelationshipId32.FromBytes(Bytes(32, 0x71));
        var accountA = Bytes(32, 0x81);
        var accountB = Bytes(32, 0x72);

        var forward = ContactConversationId32.Derive(Network, relationship, accountA, accountB);
        var reverse = ContactConversationId32.Derive(Network, relationship, accountB, accountA);

        Assert.Equal(ExpectedConversationId(Network, relationship.ToArray(), accountB, accountA), forward.ToArray());
        Assert.Equal(forward, reverse);
        Assert.DoesNotContain("Alice", forward.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void ImportServiceCompositionHasNoNetworkCallbackDependency()
    {
        var constructor = Assert.Single(typeof(ContactAddressImportService).GetConstructors());
        var parameterTypes = constructor.GetParameters().Select(static parameter => parameter.ParameterType).ToArray();

        Assert.Equal(new[] { typeof(IContactStateStore), typeof(ReadOnlyMemory<byte>), typeof(TimeProvider) }, parameterTypes);
        Assert.DoesNotContain(parameterTypes, static type =>
            type.Name.Contains("Transport", StringComparison.Ordinal)
            || type.Name.Contains("Resolver", StringComparison.Ordinal)
            || type == typeof(HttpClient));
    }

    private static byte[] ExpectedConversationId(byte[] network, byte[] relationship, byte[] first, byte[] second)
    {
        var material = network.Concat(relationship).Concat(first).Concat(second).ToArray();
        var label = Encoding.ASCII.GetBytes(ContactConversationId32.DerivationDomain);
        var preimage = new byte[label.Length + 5 + material.Length];
        label.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(preimage.AsSpan(label.Length + 1), checked((uint)material.Length));
        material.CopyTo(preimage, label.Length + 5);
        return SHA256.HashData(preimage);
    }

    private static byte[] Dia1(byte[] network, ulong expiresAt)
    {
        ReadOnlyMemory<byte>[] fields =
        [
            network,
            Bytes(32, 0x91),
            new byte[] { 2 },
            U16(1),
            Bytes(16, 0x92),
            Bytes(32, 0x93),
            Bytes(32, 0x94),
            U64(expiresAt),
            U16(1),
        ];
        var output = new byte[12 + fields.Sum(static field => 8 + field.Length)];
        Encoding.ASCII.GetBytes("DIA1").CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Length));
        var offset = 12;
        for (var index = 0; index < fields.Length; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            fields[index].Span.CopyTo(output.AsSpan(offset + 8));
            offset += 8 + fields[index].Length;
        }
        return output;
    }

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static ContactStoreScope Scope(byte marker = 0xA1) => ContactStoreScope.ForCurrentAccount(
        DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Network),
            accountGeneration: 1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Bytes(32, marker))).AccountId);
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
