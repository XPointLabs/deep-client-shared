using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.MessagingV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed class UnsolicitedInitialSessionStoreResolverTests
{
    [Fact]
    public void StagedResultCannotBeForgedByAConsumer()
    {
        Assert.Empty(typeof(DeepDirectMessagingUnsolicitedCommitResult)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public async Task FinalReplayUsesOnlyTheMatchingExistingSessionAcrossRestart()
    {
        var root = Path.Combine(Path.GetTempPath(),
            "deep-unsolicited-replay-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        await using var accountStore = new InMemoryDeepAccountStore();
        using var secrets = new InMemoryDeepSecureStorage();
        var network = Bytes(16, 0x11);
        var accounts = new DeepAccountService(accountStore, secrets,
            new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_900_000_000)), network);
        try
        {
            var identity = (await accounts.CreateAsync("Alice")).Identity;
            var authority = DeepDirectMessagingLocalAuthorityBinding.CreateForTests(
                identity, Bytes(32, 0x71));
            var remoteAccount = Bytes(32, 0x31);
            var remoteDevice = Bytes(32, 0x32);
            var dph2 = Dph2(network, remoteAccount, remoteDevice,
                identity.Account.AccountIdentity.AccountId.Bytes.Span,
                identity.Device.DeviceId.Bytes.Span,
                identity.Device.DeviceGeneration);
            var initiation = VerifiedForStoreResolutionOnly(dph2);
            var conversation = ContactConversationId32.FromBytes(Bytes(32, 0x41));
            var existing = DeepDirectMessagingVerifiedSessionBinding.CreateForTests(
                network, remoteAccount, 1, remoteDevice, 1, conversation,
                dph2.SessionId.Span);

            await using (var first = await DeepDirectMessagingStorageOwner.OpenAsync(
                             root, secrets, accounts, identity, authority))
            {
                Assert.NotNull(await first.TryOpenSessionAsync(existing, true));
                var resolver = new DeepDirectMessagingStorageOwner
                    .UnsolicitedInitialSessionStoreResolver(first, initiation, dph2);
                Assert.NotNull(await resolver.ResolveAsync(
                    ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty,
                    CancellationToken.None));
                Assert.Equal(existing.ConversationId.ToArray(),
                    resolver.Session!.ConversationId.ToArray());
                Assert.Single(await first.ReadCatalogAsync());
            }

            await using (var restarted = await DeepDirectMessagingStorageOwner.OpenAsync(
                             root, secrets, accounts, identity, authority))
            {
                var resolver = new DeepDirectMessagingStorageOwner
                    .UnsolicitedInitialSessionStoreResolver(restarted, initiation, dph2);
                Assert.NotNull(await resolver.ResolveAsync(
                    ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty,
                    CancellationToken.None));
                Assert.Single(await restarted.ReadCatalogAsync());

                var foreign = Dph2(network, remoteAccount, Bytes(32, 0x33),
                    identity.Account.AccountIdentity.AccountId.Bytes.Span,
                    identity.Device.DeviceId.Bytes.Span,
                    identity.Device.DeviceGeneration);
                var missing = new DeepDirectMessagingStorageOwner
                    .UnsolicitedInitialSessionStoreResolver(
                        restarted, VerifiedForStoreResolutionOnly(foreign), foreign);
                Assert.Null(await missing.ResolveAsync(
                    ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty,
                    CancellationToken.None));
                Assert.Single(await restarted.ReadCatalogAsync());
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CatalogRejectsSecondConversationForSameDph2BeforeReplay()
    {
        var root = Path.Combine(Path.GetTempPath(),
            "deep-unsolicited-ambiguous-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        await using var accountStore = new InMemoryDeepAccountStore();
        using var secrets = new InMemoryDeepSecureStorage();
        var network = Bytes(16, 0x11);
        var accounts = new DeepAccountService(accountStore, secrets,
            new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_900_000_000)), network);
        try
        {
            var identity = (await accounts.CreateAsync("Alice")).Identity;
            var authority = DeepDirectMessagingLocalAuthorityBinding.CreateForTests(
                identity, Bytes(32, 0x71));
            var remoteAccount = Bytes(32, 0x31);
            var remoteDevice = Bytes(32, 0x32);
            var dph2 = Dph2(network, remoteAccount, remoteDevice,
                identity.Account.AccountIdentity.AccountId.Bytes.Span,
                identity.Device.DeviceId.Bytes.Span,
                identity.Device.DeviceGeneration);
            await using var owner = await DeepDirectMessagingStorageOwner.OpenAsync(
                root, secrets, accounts, identity, authority);
            var incomplete = new DeepDirectMessagingStorageOwner
                .UnsolicitedInitialSessionStoreResolver(
                    owner, VerifiedForStoreResolutionOnly(dph2), dph2);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await incomplete.ResolveAsync(
                    new byte[] { 1 }, ReadOnlyMemory<byte>.Empty,
                    CancellationToken.None));
            Assert.Empty(await owner.ReadCatalogAsync());
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await incomplete.ResolveAsync(
                    new byte[] { 1 }, new byte[] { 2 },
                    CancellationToken.None));
            Assert.Empty(await owner.ReadCatalogAsync());
            var first = DeepDirectMessagingVerifiedSessionBinding.CreateForTests(
                network, remoteAccount, 1, remoteDevice, 1,
                ContactConversationId32.FromBytes(Bytes(32, 0x41)),
                dph2.SessionId.Span);
            Assert.NotNull(await owner.TryOpenSessionAsync(first, true));
            var conflicting = DeepDirectMessagingVerifiedSessionBinding.CreateForTests(
                network, remoteAccount, 1, remoteDevice, 1,
                ContactConversationId32.FromBytes(Bytes(32, 0x42)),
                dph2.SessionId.Span);
            await Assert.ThrowsAsync<SqliteException>(async () =>
                await owner.TryOpenSessionAsync(conflicting, true));
            var resolver = new DeepDirectMessagingStorageOwner
                .UnsolicitedInitialSessionStoreResolver(
                    owner, VerifiedForStoreResolutionOnly(dph2), dph2);
            Assert.NotNull(await resolver.ResolveAsync(
                ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty,
                CancellationToken.None));
            Assert.Equal(first.ConversationId.ToArray(),
                resolver.Session!.ConversationId.ToArray());
            Assert.Single(await owner.ReadCatalogAsync());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task EstablishedInboundSelectsOnlyExactActiveLocalSessionAfterRestart()
    {
        var root = Path.Combine(Path.GetTempPath(),
            "deep-established-inbound-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        await using var accountStore = new InMemoryDeepAccountStore();
        using var secrets = new InMemoryDeepSecureStorage();
        var network = Bytes(16, 0x11);
        var accounts = new DeepAccountService(accountStore, secrets,
            new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_900_000_000)), network);
        try
        {
            var identity = (await accounts.CreateAsync("Alice")).Identity;
            var authority = DeepDirectMessagingLocalAuthorityBinding.CreateForTests(
                identity, Bytes(32, 0x71));
            var remoteAccount = Bytes(32, 0x31);
            var remoteDevice = Bytes(32, 0x32);
            var localDevice = identity.Device.DeviceId.Bytes.ToArray();
            var sessionId = Bytes(32, 0x52);
            var session = DeepDirectMessagingVerifiedSessionBinding.CreateForTests(
                network, remoteAccount, 1, remoteDevice, 1,
                ContactConversationId32.FromBytes(Bytes(32, 0x41)), sessionId);

            await using (var first = await DeepDirectMessagingStorageOwner.OpenAsync(
                             root, secrets, accounts, identity, authority))
            {
                Assert.Null(await first.TryResolveEstablishedInboundSessionAsync(
                    Dpe2(network, sessionId, remoteDevice, localDevice)));
                Assert.NotNull(await first.TryOpenSessionAsync(session, true));
            }

            await using (var restarted = await DeepDirectMessagingStorageOwner.OpenAsync(
                             root, secrets, accounts, identity, authority))
            {
                var selected = await restarted.TryResolveEstablishedInboundSessionAsync(
                    Dpe2(network, sessionId, remoteDevice, localDevice));
                Assert.NotNull(selected);
                Assert.Equal(session.ConversationId.ToArray(), selected.ConversationId.ToArray());
                Assert.Equal(session.RemoteAccountId.ToArray(), selected.RemoteAccountId.ToArray());
                Assert.Null(await restarted.TryResolveEstablishedInboundSessionAsync(
                    Dpe2(network, Bytes(32, 0x53), remoteDevice, localDevice)));
                Assert.Null(await restarted.TryResolveEstablishedInboundSessionAsync(
                    Dpe2(network, sessionId, Bytes(32, 0x33), localDevice)));
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await restarted.TryResolveEstablishedInboundSessionAsync(
                        Dpe2(network, sessionId, remoteDevice, Bytes(32, 0x34))));
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static byte[] Dpe2(
        byte[] network,
        byte[] sessionId,
        byte[] senderDevice,
        byte[] recipientDevice)
    {
        var header = new Dtr2Record(network, Bytes(32, 0x91), 0,
            1, 1, 0, 1, 1, Dtr2BraidMessage.None());
        return Dpe2Codec.Encode(new Dpe2Record(
            network, sessionId, senderDevice, recipientDevice,
            Bytes(32, 0x93), header,
            Dpe2Ciphertext.Import(Bytes(4112, 0x94))));
    }

    private static VerifiedDph2Initiation VerifiedForStoreResolutionOnly(Dph2Record dph2)
    {
        // The resolver is tested after the Protocol verifier boundary. This
        // synthetic object cannot be used to exercise claim verification.
        var value = (VerifiedDph2Initiation)RuntimeHelpers.GetUninitializedObject(
            typeof(VerifiedDph2Initiation));
        typeof(VerifiedDph2Initiation).GetField("<Record>k__BackingField",
            BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(value, dph2);
        return value;
    }

    private static Dph2Record Dph2(
        byte[] network,
        byte[] initiatorAccount,
        byte[] initiatorDevice,
        ReadOnlySpan<byte> responderAccount,
        ReadOnlySpan<byte> responderDevice,
        ulong responderGeneration)
    {
        var dpd1 = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(dpd1, (ushort)ArtifactType.Dpd1);
        BinaryPrimitives.WriteUInt32BigEndian(dpd1.AsSpan(2), 776);
        Bytes(32, 0x51).CopyTo(dpd1, 6);
        return new Dph2Record(
            network, initiatorAccount, initiatorDevice, 1, dpd1,
            Deep.Protocol.ApplicationCore.ApplicationCoreCodec.AuthorDid1(
                Bytes(32, 0x61), Bytes(16, 0x62)).CanonicalBytes.Span,
            responderAccount, responderDevice, responderGeneration,
            Bytes(32, 0x52), Bytes(32, 0x53), Bytes(32, 0x54), 1,
            Bytes(32, 0x55), Bytes(32, 0x56),
            Dph2SelectedPrekey.LastResort(Bytes(32, 0x57), Bytes(32, 0x58)),
            Bytes(1088, 0x59), Bytes(32, 0x5a), Bytes(24, 0x5b),
            Dph2InitialCiphertext.Import(Bytes(4112, 0x5c)));
    }

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();
}
