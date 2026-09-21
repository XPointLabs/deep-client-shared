using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.MessagingV1;
using Deep.Client.Shared.Tests.Services.MessagingV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ReachabilityMetadataSealingKeyAuthorityTests
{
    [Fact]
    public async Task AccountOwnerOpensOnlyDao1ForItsCurrentRecipient()
    {
        var root = Path.Combine(
            Path.GetTempPath(), "deep-dao1-local-owner", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var secrets = new InMemoryDeepSecureStorage();
        var network = Bytes(16, 0x11);
        var accounts = new DeepAccountService(
            new InMemoryDeepAccountStore(), secrets,
            new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000)),
            network);
        try
        {
            var identity = (await accounts.CreateAsync("Alice")).Identity;
            var keys = new ReachabilityMetadataSealingKeyAuthority(secrets);
            var pmt2Reference = Bytes(38, 0x75);
            var binding = await keys.OpenOrCreateForTestsAsync(identity, pmt2Reference);
            var route = Route(
                network, identity.Device.DeviceId.Bytes.Span,
                Bytes(32, 0x71), pmt2Reference, binding);
            var localAuthority = DeepDirectMessagingLocalAuthorityBinding.CreateForTests(
                identity, Bytes(32, 0x72));
            await using var owner = await DeepDirectMessagingStorageOwner.OpenAsync(
                root, secrets, accounts, identity, localAuthority);
            using var fixture = new PrivacyRoutedMessagingTransportTests.Fixture();
            var recipient = VerifiedMessagingRecipientDeposit.CreateForTests(
                fixture.Scope, fixture.RecipientSelector, fixture.RecipientSigner,
                network, identity.Account.AccountIdentity.AccountId.Bytes.Span,
                identity.Account.AccountIdentity.AccountGeneration, 1,
                identity.Device.DeviceId.Bytes.Span, identity.Device.DeviceGeneration,
                binding.KeyId.Span, binding.X25519PublicKey.Span, 1_800_003_600);
            using var pending = fixture.PendingDph2(
                identity.Device.DeviceId.Bytes.ToArray(),
                identity.Account.AccountIdentity.AccountId.Bytes.ToArray());
            using var dao1 = fixture.Sealer.Seal(
                fixture.Local, recipient, pending.ExactDph2.Span);

            using var opened = await owner.OpenInboundDepositAsync(route, dao1.Canonical);
            Assert.Equal(DeepDirectMessagingInboundKind.InitialSession, opened.Kind);
            Assert.Equal(pending.ExactDph2.ToArray(), opened.ExactInner.ToArray());
            Assert.Equal(SHA256.HashData(dao1.Canonical.Span),
                opened.ExactDao1Hash.ToArray());

            const ulong now = 1_800_000_000;
            var policy = new MailboxClientDecodePolicy
            {
                NowUnixSeconds = now,
                EpochWindow = new MailboxEpochWindow
                {
                    CurrentEpoch = 1,
                    NextEpoch = 2,
                    CurrentNotBeforeUnixSeconds = now - 100,
                    NextNotBeforeUnixSeconds = now - 50,
                    CurrentExpiresAtUnixSeconds = now + 1_000,
                    NextExpiresAtUnixSeconds = now + 2_000,
                },
                CapabilityPolicy = new MailboxCapabilityDecodePolicy
                {
                    CurrentBucket = 1,
                    MinimumGeneration = 1,
                },
            };
            var mailboxEnvelope = fixture.MailboxEnvelope(dao1.Canonical.Span, 1);
            using var openedMailboxItem = await owner.OpenInboundMailboxEntryAsync(
                route, fixture.Mailbox.Route, 1,
                MailboxClientCodec.EncodeEncryptedEnvelope(mailboxEnvelope.Envelope),
                mailboxEnvelope.Envelope.DeduplicationDigest, policy);
            Assert.Equal(pending.ExactDph2.ToArray(),
                openedMailboxItem.ExactInner.ToArray());
            Assert.Empty(await owner.ReadCatalogAsync());

            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await owner.OpenInboundMailboxEntryAsync(
                    route, fixture.Mailbox.Route, 1,
                    MailboxClientCodec.EncodeEncryptedEnvelope(mailboxEnvelope.Envelope),
                    Bytes(MailboxClientLimits.DigestLength, 0x70), policy));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await owner.OpenInboundMailboxEntryAsync(
                    route, fixture.Mailbox.Route, 0,
                    MailboxClientCodec.EncodeEncryptedEnvelope(mailboxEnvelope.Envelope),
                    mailboxEnvelope.Envelope.DeduplicationDigest, policy));

            var changedOperation = mailboxEnvelope.Envelope with
            {
                OperationId = Bytes(MailboxClientLimits.OperationIdLength, 0x73)
            };
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await owner.OpenInboundMailboxEntryAsync(
                    route, fixture.Mailbox.Route, 1,
                    MailboxClientCodec.EncodeEncryptedEnvelope(changedOperation),
                    changedOperation.DeduplicationDigest, policy));
            var changedDigest = mailboxEnvelope.Envelope with
            {
                DeduplicationDigest = Bytes(MailboxClientLimits.DigestLength, 0x74)
            };
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await owner.OpenInboundMailboxEntryAsync(
                    route, fixture.Mailbox.Route, 1,
                    MailboxClientCodec.EncodeEncryptedEnvelope(changedDigest),
                    changedDigest.DeduplicationDigest, policy));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await owner.OpenInboundMailboxEntryAsync(
                    route, fixture.Mailbox.Route with { Epoch = 2 }, 1,
                    MailboxClientCodec.EncodeEncryptedEnvelope(mailboxEnvelope.Envelope),
                    mailboxEnvelope.Envelope.DeduplicationDigest, policy));
            Assert.Empty(await owner.ReadCatalogAsync());

            var exactDpe2 = fixture.ExactInboundDpe2(
                recipient: identity.Device.DeviceId.Bytes.ToArray());
            using var establishedDao1 = fixture.Sealer.Seal(
                fixture.RemoteLocal, recipient, exactDpe2);
            using var established = await owner.OpenInboundDepositAsync(
                route, establishedDao1.Canonical);
            Assert.Equal(DeepDirectMessagingInboundKind.EstablishedSession,
                established.Kind);
            Assert.Equal(exactDpe2, established.ExactInner.ToArray());

            var wrongRecipient = VerifiedMessagingRecipientDeposit.CreateForTests(
                fixture.Scope, fixture.RecipientSelector, fixture.RecipientSigner,
                network, fixture.RemoteAccount, 1, 1, fixture.RemoteDevice, 1,
                binding.KeyId.Span, binding.X25519PublicKey.Span, 1_800_003_600);
            using var wrongPending = fixture.PendingDph2();
            using var wrongDao1 = fixture.Sealer.Seal(
                fixture.Local, wrongRecipient, wrongPending.ExactDph2.Span);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await owner.OpenInboundDepositAsync(route, wrongDao1.Canonical));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task KeySurvivesRestartAndOnlyOpensForMatchingCurrentXra1()
    {
        using var secrets = new InMemoryDeepSecureStorage();
        var network = Bytes(16, 0x11);
        var accounts = new DeepAccountService(
            new InMemoryDeepAccountStore(), secrets,
            new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000)),
            network);
        var identity = (await accounts.CreateAsync("Alice")).Identity;
        var authorizationId = Bytes(32, 0x71);
        var pmt2Reference = Bytes(38, 0x75);
        var first = new ReachabilityMetadataSealingKeyAuthority(secrets);
        var authored = await first.OpenOrCreateForTestsAsync(
            identity, pmt2Reference);

        var restarted = new ReachabilityMetadataSealingKeyAuthority(secrets);
        var recovered = await restarted.OpenOrCreateForTestsAsync(
            identity, pmt2Reference);
        Assert.Equal(authored.KeyId.ToArray(), recovered.KeyId.ToArray());
        Assert.Equal(authored.X25519PublicKey.ToArray(), recovered.X25519PublicKey.ToArray());

        using var opener = await restarted.OpenForCurrentRouteAsync(
            identity, Route(identity.NetworkId.Span, identity.Device.DeviceId.Bytes.Span,
                authorizationId, pmt2Reference, authored));
        using var transportFixture = new PrivacyRoutedMessagingTransportTests.Fixture();
        var recipient = VerifiedMessagingRecipientDeposit.CreateForTests(
            transportFixture.Scope, transportFixture.RecipientSelector,
            transportFixture.RecipientSigner,
            transportFixture.Network, transportFixture.RemoteAccount, 1, 1,
            transportFixture.RemoteDevice, 1,
            authored.KeyId.Span, authored.X25519PublicKey.Span,
            1_800_003_600);
        using var pending = transportFixture.PendingDph2();
        using var sealedDao1 = transportFixture.Sealer.Seal(
            transportFixture.Local, recipient, pending.ExactDph2.Span);
        using var openedDao1 = await opener.OpenAsync(sealedDao1.Canonical);
        Assert.Equal(pending.ExactDph2.ToArray(), openedDao1.ExactInner.ToArray());

        var wrongPublic = new MetadataSealingPublicBinding(
            authored.KeyId.Span, Bytes(32, 0x72));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restarted.OpenForCurrentRouteAsync(
                identity, Route(identity.NetworkId.Span, identity.Device.DeviceId.Bytes.Span,
                    authorizationId, pmt2Reference, wrongPublic)));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restarted.OpenForCurrentRouteAsync(
                identity, Route(identity.NetworkId.Span, identity.Device.DeviceId.Bytes.Span,
                    authorizationId, Bytes(38, 0x73), authored)));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restarted.OpenForCurrentRouteAsync(
                identity, Route(identity.NetworkId.Span, Bytes(32, 0x74),
                    authorizationId, pmt2Reference, authored)));

        var anotherRoute = await restarted.OpenOrCreateForTestsAsync(
            identity, Bytes(38, 0x76));
        Assert.NotEqual(authored.X25519PublicKey.ToArray(),
            anotherRoute.X25519PublicKey.ToArray());
    }

    private static VerifiedContactRouteClosure Route(
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> device,
        ReadOnlySpan<byte> authorizationId,
        ReadOnlySpan<byte> pmt2Reference,
        MetadataSealingPublicBinding binding)
    {
        var fields = Enumerable.Range(0, 16)
            .Select(static _ => Bytes(32, 0x21))
            .ToArray();
        fields[0] = network.ToArray();
        fields[1] = authorizationId.ToArray();
        fields[2] = new byte[8];
        fields[4] = pmt2Reference.ToArray();
        fields[9] = binding.KeyId.ToArray();
        fields[10] = binding.X25519PublicKey.ToArray();
        fields[13] = device.ToArray();
        var xra1 = CreateRecord("XRA1", Bytes(550, 0x31), fields, null, null, []);
        var placeholder = CreateRecord(
            "XRR1", Bytes(64, 0x32), [network.ToArray()], null, null, []);
        return CreateRoute(
            placeholder, placeholder, xra1, placeholder, placeholder,
            placeholder, placeholder,
            (VerifiedContactNetworkAuthority)RuntimeHelpers.GetUninitializedObject(
                typeof(VerifiedContactNetworkAuthority)));
    }

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern ContactRecord CreateRecord(
        string magic,
        byte[] canonical,
        byte[][] fields,
        string? signatureDomain,
        string? coreDomain,
        int[] projectionTags);

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedContactRouteClosure CreateRoute(
        ContactRecord invite,
        ContactRecord reachability,
        ContactRecord authorization,
        ContactRecord route,
        ContactRecord successor,
        ContactRecord projection,
        ContactRecord selection,
        VerifiedContactNetworkAuthority authority);
}
