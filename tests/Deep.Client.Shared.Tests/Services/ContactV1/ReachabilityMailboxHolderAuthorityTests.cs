using System.Runtime.CompilerServices;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.Identity;
using Sodium;

namespace Deep.Client.Shared.Tests.Services.ContactV1;

public sealed class ReachabilityMailboxHolderAuthorityTests
{
    [Fact]
    public async Task ProtectedHolder_IsStableRoleSeparatedAndScopeBound()
    {
        using var storage = new InMemoryDeepSecureStorage();
        var owner = new ReachabilityMailboxHolderAuthority(storage);
        var network = Bytes(16, 0x11);
        var route = Route(network, Bytes(32, 0x41));
        var identity = Identity(network, 1, 0x31);
        var locator = Bytes(32, 0x51);

        byte[] depositPublicKey;
        await using (var first = new AsyncSigner(await owner.OpenOrCreateAsync(
            identity, route, locator, MailboxCapabilityDomain.Deposit)))
        {
            depositPublicKey = first.Value.Ed25519PublicKey.ToArray();
            var authored = await MailboxGrantRequestAuthor.AuthorDepositAsync(
                route, locator, first.Value, 100, 220);
            ContactCodec.VerifyMailboxGrantHolderSignature(authored.Record);

            var grant = Grant(network, depositPublicKey, MailboxCapabilityDomain.Deposit);
            var presentation = Presentation(grant, MailboxAuthenticatedOperation.Store);
            var transcript = MailboxAuthenticatedCapabilityCodec
                .GetPresentationSigningBytes(presentation);
            var signature = first.Value.SignMailboxPresentation(
                MailboxAuthenticatedOperation.Store, transcript);
            Assert.True(PublicKeyAuth.VerifyDetached(
                signature, transcript, depositPublicKey));

            var foreign = Grant(
                network, Bytes(32, 0x7a), MailboxCapabilityDomain.Deposit);
            var foreignTranscript = MailboxAuthenticatedCapabilityCodec
                .GetPresentationSigningBytes(Presentation(
                    foreign, MailboxAuthenticatedOperation.Store));
            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
                first.Value.SignMailboxPresentation(
                    MailboxAuthenticatedOperation.Store, foreignTranscript));
        }

        using (var reopened = await owner.OpenOrCreateAsync(
            identity, route, locator, MailboxCapabilityDomain.Deposit))
        {
            Assert.Equal(depositPublicKey, reopened.Ed25519PublicKey.ToArray());
        }

        using (var retrieve = await owner.OpenOrCreateAsync(
            identity, route, locator, MailboxCapabilityDomain.Retrieve))
        {
            Assert.NotEqual(depositPublicKey, retrieve.Ed25519PublicKey.ToArray());
        }

        var nextGeneration = Identity(network, 2, 0x31);
        using var rotated = await owner.OpenOrCreateAsync(
            nextGeneration, route, locator, MailboxCapabilityDomain.Deposit);
        Assert.NotEqual(depositPublicKey, rotated.Ed25519PublicKey.ToArray());
    }

    private static DeepLocalIdentitySnapshot Identity(
        byte[] network,
        ulong generation,
        byte keyMarker)
    {
        var accountIdentity = DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(network),
            generation,
            AccountEd25519PublicKey32.FromVerifiedBytes(Bytes(32, keyMarker)));
        var account = new DeepAccount(
            DeepPermanentIdV1.Create(Bytes(32, 0x21), Bytes(16, 0x22)),
            accountIdentity,
            "Mr. X",
            DateTimeOffset.UnixEpoch,
            DeepAccountActivationState.ActiveLocal,
            null!);
        return new DeepLocalIdentitySnapshot(
            1, network, account, null!, null!, null!);
    }

    private static VerifiedContactRouteClosure Route(
        byte[] network,
        byte[] depositCapability)
    {
        var reachabilityFields = Enumerable.Range(0, 20)
            .Select(static _ => Bytes(32, 0x01))
            .ToArray();
        reachabilityFields[0] = network;
        reachabilityFields[9] = depositCapability;
        var reachability = Record("XRR1", Bytes(64, 0x31), reachabilityFields);
        var projection = Record("PMT2", Bytes(64, 0x32), [network]);
        var selection = Record("PMS2", Bytes(64, 0x33), [network]);
        var placeholder = Record("XIR1", Bytes(64, 0x34), [network]);
        return CreateRoute(
            placeholder,
            reachability,
            placeholder,
            placeholder,
            placeholder,
            projection,
            selection,
            (VerifiedContactNetworkAuthority)RuntimeHelpers.GetUninitializedObject(
                typeof(VerifiedContactNetworkAuthority)));
    }

    private static MailboxAuthenticatedGrant Grant(
        byte[] network,
        byte[] holder,
        MailboxCapabilityDomain domain) => new()
    {
        Domain = domain,
        Lifecycle = MailboxCapabilityLifecycle.Active,
        NetworkId = network,
        Epoch = 7,
        Generation = 3,
        Serial = Bytes(16, 0x61),
        NotBeforeUnixSeconds = 90,
        ExpiresAtUnixSeconds = 240,
        OverlapUntilUnixSeconds = 0,
        PlacementCommitment = Bytes(32, 0x62),
        MembershipCommitment = Bytes(32, 0x63),
        IssuerPublicKey = Bytes(32, 0x64),
        HolderPublicKey = holder,
        IssuerSignature = Bytes(64, 0x65),
    };

    private static MailboxAuthenticatedPresentation Presentation(
        MailboxAuthenticatedGrant grant,
        MailboxAuthenticatedOperation operation) => new()
    {
        Operation = operation,
        OperationId = Bytes(16, 0x71),
        ReplayCounter = 1,
        RequestDigest = Bytes(32, 0x72),
        Grant = grant,
        HolderSignature = Bytes(64, 0x73),
    };

    private static ContactRecord Record(
        string magic,
        byte[] canonical,
        byte[][] fields) => CreateRecord(
            magic, canonical, fields, null, null, []);

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

    private sealed class AsyncSigner(
        ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner value) :
        IAsyncDisposable
    {
        internal ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner Value { get; } = value;

        public ValueTask DisposeAsync()
        {
            Value.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
