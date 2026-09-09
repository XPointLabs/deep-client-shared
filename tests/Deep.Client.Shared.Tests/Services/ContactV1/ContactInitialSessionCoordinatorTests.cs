using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Persistence.PreKeyV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Tests.Persistence.PreKeyV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Tests.Services.ContactV1;

[Trait("RequiresApprovedMlKemRuntime", "true")]
public sealed class ContactInitialSessionCoordinatorTests
{
    [Theory]
    [InlineData((int)Dpk2PrekeyKind.OneTime)]
    [InlineData((int)Dpk2PrekeyKind.LastResort)]
    public async Task UnavailableAccountKeyOwnerDoesNotConsumeVerifiedClaimOrPreKey(int kindValue)
    {
        var kind = (Dpk2PrekeyKind)kindValue;
        using var fixture = new Fixture(kind, kind == Dpk2PrekeyKind.LastResort ? (ushort)1 : (ushort)0);
        await fixture.ProvisionAsync();
        await using var owner = fixture.OpenOwner();
        await using var sessions = fixture.OpenSessions();
        var coordinator = fixture.Coordinator(owner, sessions);
        var pair = fixture.Pair();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            coordinator.CommitAsync(pair.Receipt, pair.Initiation).AsTask());

        using var verifiedClaim = pair.Receipt.BindForInitialSession(pair.Initiation);
        using var reservation = verifiedClaim.ConsumeForDevicePreKeyOwner();
        using var capability = PreKeyV1ClaimCapability.ConsumeVerified(reservation);
        var reserve = await owner.ReserveAndRestoreForTestsAsync(capability);

        Assert.Equal(PreKeyV1ClaimDisposition.Reserved, reserve.Disposition);
        Assert.True(reserve.SecretCallbackInvoked);
    }

    [Theory]
    [InlineData((int)Dpk2PrekeyKind.OneTime)]
    [InlineData((int)Dpk2PrekeyKind.LastResort)]
    public async Task DeviceWideSagaPreservesExactReplayForBothPreKeyKinds(int kindValue)
    {
        var kind = (Dpk2PrekeyKind)kindValue;
        var counter = kind == Dpk2PrekeyKind.LastResort ? (ushort)1 : (ushort)0;
        using var fixture = new Fixture(kind, counter);
        await fixture.ProvisionAsync();
        await using var owner = fixture.OpenOwner();
        await using var sessions = fixture.OpenSessions();
        var initialized = await owner.CommitInitialSessionSagaForTestsAsync(
            fixture.TestClaim(), sessions, fixture.Trs1(0x61));
        var replay = await owner.CommitInitialSessionSagaForTestsAsync(
            fixture.TestClaim(), sessions, fixture.Trs1(0x61));

        Assert.Equal(PreKeyV1InitialSessionSagaDisposition.Initialized, initialized.Disposition);
        Assert.Equal(PreKeyV1InitialSessionSagaDisposition.ExactReplay, replay.Disposition);
    }

    [Fact]
    public async Task RelationshipMismatchFailsBeforeAccountOrPreKeySecretUse()
    {
        using var fixture = new Fixture(Dpk2PrekeyKind.OneTime);
        await fixture.ProvisionAsync();
        var mismatched = fixture.Evidence(Bytes(32, 0xe1));
        await using var owner = fixture.OpenOwner();
        await using var sessions = fixture.OpenSessions(mismatched);
        var coordinator = fixture.Coordinator(owner, sessions, mismatched);
        var pair = fixture.Pair();

        await Assert.ThrowsAsync<CryptographicException>(() =>
            coordinator.CommitAsync(pair.Receipt, pair.Initiation).AsTask());

        using var verifiedClaim = pair.Receipt.BindForInitialSession(pair.Initiation);
        using var reservation = verifiedClaim.ConsumeForDevicePreKeyOwner();
        Assert.Equal(pair.Initiation.SessionId.ToArray(), reservation.SessionId.ToArray());
    }

    [Fact]
    public async Task AccountOwnedFactoryRejectsForeignSnapshotBeforeOpeningSecrets()
    {
        await using var firstStore = new InMemoryDeepAccountStore();
        await using var secondStore = new InMemoryDeepAccountStore();
        using var firstSecrets = new InMemoryDeepSecureStorage();
        using var secondSecrets = new InMemoryDeepSecureStorage();
        var first = AccountService(firstStore, firstSecrets);
        var second = AccountService(secondStore, secondSecrets);
        var firstIdentity = (await CreateConfirmedAsync(first)).Identity;
        var secondIdentity = (await CreateConfirmedAsync(second)).Identity;

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            first.OpenCurrentResponderIdentitySecretLeaseAsync(secondIdentity, 128));

        using var lease = await first.OpenCurrentResponderIdentitySecretLeaseAsync(firstIdentity, 128);
        using var factory = lease.OpenFactory();
    }

    [Fact]
    public async Task AccountOwnedFactoryDisposalClearsProtocolOwnedStaticSecrets()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secrets = new InMemoryDeepSecureStorage();
        var service = AccountService(store, secrets);
        var identity = (await CreateConfirmedAsync(service)).Identity;
        using var lease = await service.OpenCurrentResponderIdentitySecretLeaseAsync(identity, 128);
        var factory = lease.OpenFactory();

        factory.Dispose();

        var type = typeof(ManagedResponderInitialSessionFactory);
        Assert.True((bool)(type.GetField("_disposed", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(factory) ?? false));
        Assert.Null(type.GetField("_responderIdentityPrivate", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(factory));
        Assert.Null(type.GetField("_responderSignedPreKeyPrivate", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(factory));
    }

    [Fact]
    public async Task MissingProductionAccountFailsClosedWithoutCreatingFactory()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secrets = new InMemoryDeepSecureStorage();
        var service = AccountService(store, secrets);
        var unavailable = (DeepLocalIdentitySnapshot)
            RuntimeHelpers.GetUninitializedObject(typeof(DeepLocalIdentitySnapshot));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.OpenCurrentResponderIdentitySecretLeaseAsync(unavailable, 128));
    }

    [Fact]
    public void ProductionSurfaceHasNoCallerProvidedFactoryOrRawSecretParameter()
    {
        var constructor = Assert.Single(typeof(ContactInitialSessionCoordinator)
            .GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic));
        Assert.Equal(
            [
                typeof(SqlitePreKeyV1SecretOwner), typeof(SqliteMessagingCryptoV1Store),
                typeof(VerifiedContactBundleEvidence), typeof(DeepAccountService),
                typeof(DeepLocalIdentitySnapshot), typeof(int)
            ],
            constructor.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.DoesNotContain(constructor.GetParameters(), static parameter =>
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType));

        var commit = Assert.Single(
            typeof(ContactInitialSessionCoordinator).GetMethods(BindingFlags.Instance | BindingFlags.NonPublic),
            static method => method.Name == "CommitAsync");
        Assert.Equal(
            [typeof(VerifiedXpc1PreKeyClaimReceipt), typeof(VerifiedDph2Initiation), typeof(CancellationToken)],
            commit.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.Empty(typeof(VerifiedXpc1PreKeyClaimReceipt).GetConstructors());
        Assert.Empty(typeof(VerifiedDph2Initiation).GetConstructors());
    }

    private sealed class Fixture : IDisposable
    {
        private readonly OpaquePreKeyV1AuthoringFixture authoring;
        private readonly AuthoredDpk2Offering offering;
        private readonly string directory = Path.Combine(
            Path.GetTempPath(), "deep-contact-initial-session", Guid.NewGuid().ToString("N"));
        private readonly byte[] key = Bytes(32, 0x11);
        private readonly byte[] messagingKey = Bytes(32, 0x12);
        private readonly byte[] dpkHash;
        private readonly byte[] claimReceiptHash = Bytes(32, 0x43);
        private readonly byte[] xpcReplayHash = Bytes(32, 0x44);
        private readonly InMemoryDeepAccountStore accountStore = new();
        private readonly InMemoryDeepSecureStorage accountSecrets = new();

        internal Fixture(Dpk2PrekeyKind kind, ushort lastResortCounter = 0)
        {
            authoring = OpaquePreKeyV1AuthoringFixture.CreateAsync().GetAwaiter().GetResult();
            Directory.CreateDirectory(directory);
            Kind = kind;
            LastResortCounter = lastResortCounter;
            NetworkId = authoring.NetworkId.ToArray();
            LocalAccount = authoring.AccountIdentity;
            RemoteAccount = Account(NetworkId, 0x32);
            LocalDeviceId = authoring.DeviceId.ToArray();
            RemoteDeviceId = Bytes(32, 0x34);
            LocalDpd1Hash = authoring.Dpd1Hash.ToArray();
            LocalDpd1Reference = authoring.Dpd1Reference.ToArray();
            offering = authoring.Author(kind, inventoryEpoch: 19, reuseLimit: 4);
            Dpk2 = offering.Record;
            ExactDpk2 = offering.ExactDpk2.ToArray();
            dpkHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(Dpk2);
            Dph2 = BuildDph2();
            EvidenceValue = Evidence(RemoteAccount.AccountId.Bytes.Span);
            AccountService = new DeepAccountService(
                accountStore, accountSecrets, new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(100)), NetworkId);
            UnavailableIdentity = (DeepLocalIdentitySnapshot)
                RuntimeHelpers.GetUninitializedObject(typeof(DeepLocalIdentitySnapshot));
        }

        internal Dpk2PrekeyKind Kind { get; }
        internal ushort LastResortCounter { get; }
        internal byte[] NetworkId { get; }
        internal DeepAccountIdentityCapability LocalAccount { get; }
        internal DeepAccountIdentityCapability RemoteAccount { get; }
        internal byte[] LocalDeviceId { get; }
        internal byte[] RemoteDeviceId { get; }
        internal byte[] LocalDpd1Hash { get; }
        internal byte[] LocalDpd1Reference { get; }
        internal Dpk2Record Dpk2 { get; }
        internal byte[] ExactDpk2 { get; }
        internal Dph2Record Dph2 { get; }
        internal VerifiedContactBundleEvidence EvidenceValue { get; }
        internal DeepAccountService AccountService { get; }
        internal DeepLocalIdentitySnapshot UnavailableIdentity { get; }
        private string PreKeyPath => Path.Combine(directory, "prekeys.db");
        private string MessagingPath => Path.Combine(directory, "messages.db");

        internal async Task ProvisionAsync()
        {
            await using var owner = OpenOwner();
            using var capability = owner.SealAuthored(offering);
            Assert.Equal(PreKeyV1ProvisionDisposition.Provisioned, await owner.ProvisionAsync(capability));
        }

        internal SqlitePreKeyV1SecretOwner OpenOwner(bool allowCreate = true)
        {
            using var options = new PreKeyV1StoreOptions(PreKeyPath, key, PreKeyScope(), allowCreate);
            return new SqlitePreKeyV1SecretOwner(options);
        }

        internal SqliteMessagingCryptoV1Store OpenSessions(VerifiedContactBundleEvidence? evidence = null)
        {
            evidence ??= EvidenceValue;
            using var options = new MessagingCryptoV1StoreOptions(
                MessagingPath, messagingKey,
                new MessagingCryptoV1StoreScope(
                    LocalAccount.AccountId.Bytes.Span, 1, LocalDeviceId,
                    authoring.DeviceGeneration,
                    evidence.ConversationId.Span, Dph2.SessionId.Span, 29));
            return new SqliteMessagingCryptoV1Store(options);
        }

        internal ContactInitialSessionCoordinator Coordinator(
            SqlitePreKeyV1SecretOwner owner,
            SqliteMessagingCryptoV1Store sessions,
            VerifiedContactBundleEvidence? evidence = null) =>
            new(owner, sessions, evidence ?? EvidenceValue, AccountService, UnavailableIdentity, 128);

        internal PreKeyV1ClaimCapability TestClaim() => PreKeyV1ClaimCapability.CreateForTests(
            Kind, LastResortCounter, Dph2.ClaimOperationId.Span, Dph2.SessionId.Span,
            dpkHash, xpcReplayHash, MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(Dph2),
            Kind == Dpk2PrekeyKind.OneTime ? Dpk2.OneTimeX25519PrekeyId.Span : [],
            Dpk2.MlKemPrekeyId.Span);

        internal (VerifiedXpc1PreKeyClaimReceipt Receipt, VerifiedDph2Initiation Initiation) Pair()
        {
            var receipt = Uninitialized<VerifiedXpc1PreKeyClaimReceipt>();
            Set(receipt, "_networkId", NetworkId.ToArray());
            Set(receipt, "_operationId", Dph2.ClaimOperationId.ToArray());
            Set(receipt, "_requestHash", Bytes(32, 0x45));
            Set(receipt, "_claimReceiptHash", claimReceiptHash.ToArray());
            Set(receipt, "_exactDpk2Hash", dpkHash.ToArray());
            Set(receipt, "_responderAccountId", LocalAccount.AccountId.Bytes.ToArray());
            Set(receipt, "_responderDeviceId", LocalDeviceId.ToArray());
            Set(receipt, "_signedX25519PrekeyId", Dpk2.SignedX25519PrekeyId.ToArray());
            Set(receipt, "_selectedOneTimePrekeyId",
                Kind == Dpk2PrekeyKind.OneTime ? Dpk2.OneTimeX25519PrekeyId.ToArray() : new byte[32]);
            Set(receipt, "_mlKemPrekeyId", Dpk2.MlKemPrekeyId.ToArray());
            Set(receipt, "_senderEphemeralCommitment", MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(Dph2));
            Set(receipt, "_fullExactReplayHash", xpcReplayHash.ToArray());
            Set(receipt, "<ResponderDeviceGeneration>k__BackingField", authoring.DeviceGeneration);
            Set(receipt, "<PrekeyKind>k__BackingField", Kind);
            Set(receipt, "<LastResortUseCounter>k__BackingField", LastResortCounter);

            var initiation = Uninitialized<VerifiedDph2Initiation>();
            Set(initiation, "<Record>k__BackingField", Dph2);
            Set(initiation, "_transcriptHash", Bytes(32, 0x46));
            Set(initiation, "_fullReplayHash", MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(Dph2));
            Set(initiation, "_claimBinding", Bytes(32, 0x47));
            return (receipt, initiation);
        }

        internal VerifiedContactBundleEvidence Evidence(ReadOnlySpan<byte> remoteAccountId)
        {
            var did = ApplicationCoreCodec.AuthorDid1(Bytes(32, 0x48), Bytes(16, 0x49));
            var address = new ImportedContactAddress(
                ContactAddressKind.PermanentDeepId, NetworkId, did.CanonicalBytes.Span, did.Text, null);
            var hashes = Enum.GetValues<ContactVerifiedArtifactKind>().ToDictionary(
                static kind => kind,
                static kind => (ReadOnlyMemory<byte>)Bytes(32, 0x50 + (int)kind));
            return ContactTrustedVerifierBoundary.BundleVerified(
                ContactStoreScope.ForCurrentAccount(LocalAccount.AccountId), address, remoteAccountId,
                ContactRelationshipId32.FromBytes(Bytes(32, 0x4a)), hashes, Bytes(32, 0x4b));
        }

        internal byte[] Trs1(byte seed)
        {
            var result = new byte[601];
            "TRS1"u8.CopyTo(result); result[4] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(5), 0x0201);
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8), checked((uint)result.Length));
            Dph2.SessionId.Span.CopyTo(result.AsSpan(12, 32));
            Fill(result.AsSpan(44, 64), seed); LocalDeviceId.CopyTo(result, 108);
            BinaryPrimitives.WriteUInt64BigEndian(
                result.AsSpan(140), authoring.DeviceGeneration);
            Fill(result.AsSpan(148, 32), seed + 1); RemoteDeviceId.CopyTo(result, 180);
            BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(212), 13);
            Fill(result.AsSpan(220, 32), seed + 2);
            BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(252), 1);
            Fill(result.AsSpan(260, 32), seed + 3);
            BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(292), 1);
            Fill(result.AsSpan(300, 32), seed + 4);
            BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(332), 1);
            Fill(result.AsSpan(348, 32), seed + 5); Fill(result.AsSpan(404, 32), seed + 6);
            Fill(result.AsSpan(460, 32), seed + 7); Fill(result.AsSpan(492, 32), seed + 8);
            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(524), 100);
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(528), 1);
            result[536] = (byte)(seed + 9); Fill(result.AsSpan(537, 32), seed + 10);
            var checksum = MessagingCryptoV1Trs1.Sha256Domain(
                "Deep/LocalState/V1/triple-ratchet-state-checksum", result.AsSpan(0, result.Length - 32));
            checksum.CopyTo(result, result.Length - 32);
            CryptographicOperations.ZeroMemory(checksum);
            return result;
        }

        private Dph2Record BuildDph2() => new(
            NetworkId, RemoteAccount.AccountId.Bytes.Span, RemoteDeviceId, 13,
            ArtifactReference(ArtifactType.Dpd1, 776, Bytes(32, 0x51)),
            LocalAccount.AccountId.Bytes.Span, LocalDeviceId,
            authoring.DeviceGeneration, dpkHash,
            Bytes(32, 0x52), claimReceiptHash, LastResortCounter,
            Bytes(32, 0x53), Bytes(32, 0x54),
            Kind == Dpk2PrekeyKind.OneTime
                ? Dph2SelectedPrekey.OneTime(
                    Dpk2.SignedX25519PrekeyId.Span, Dpk2.OneTimeX25519PrekeyId.Span, Dpk2.MlKemPrekeyId.Span)
                : Dph2SelectedPrekey.LastResort(Dpk2.SignedX25519PrekeyId.Span, Dpk2.MlKemPrekeyId.Span),
            Bytes(1088, 0x55), Bytes(32, 0x56), Bytes(24, 0x57),
            Dph2InitialCiphertext.Import(Bytes(4112, 0x58)));

        private PreKeyV1StoreScope PreKeyScope() => new(
            NetworkId, LocalAccount.AccountId.Bytes.Span, 1, LocalDeviceId,
            authoring.DeviceGeneration,
            LocalDpd1Reference, LocalDpd1Hash, 31);

        public void Dispose()
        {
            accountStore.DisposeAsync().AsTask().GetAwaiter().GetResult();
            accountSecrets.Dispose();
            offering.Dispose();
            authoring.Dispose();
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(messagingKey);
            CryptographicOperations.ZeroMemory(dpkHash);
            CryptographicOperations.ZeroMemory(ExactDpk2);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static DeepAccountService AccountService(IDeepAccountStore store, IDeepSecureStorage storage) =>
        new(store, storage, new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(100)), Bytes(16, 0x21));

    private static async Task<DeepAccountCreationResult> CreateConfirmedAsync(DeepAccountService service)
    {
        using var draft = service.PrepareCreate("Alice");
        byte[]? phrase = null;
        draft.RevealCanonicalPhraseOnce(value => phrase = value.ToArray());
        try
        {
            using var confirmation = DeepOwnedRecoveryPhraseUtf8.CopyFrom(phrase!);
            return await service.CommitPreparedAsync(draft, confirmation);
        }
        finally
        {
            if (phrase is not null) CryptographicOperations.ZeroMemory(phrase);
        }
    }

    private static DeepAccountIdentityCapability Account(ReadOnlySpan<byte> networkId, byte seed) =>
        DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(networkId), 1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Bytes(32, seed)));

    private static byte[] ArtifactReference(ArtifactType type, uint length, ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(result, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(2), length);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private static byte[] ApplicationReference(string magic, ReadOnlySpan<byte> hash)
    {
        var value = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        hash.CopyTo(value.AsSpan(6));
        return value;
    }

    private static T Uninitialized<T>() where T : class =>
        (T)RuntimeHelpers.GetUninitializedObject(typeof(T));

    private static void Set<T>(object target, string fieldName, T value)
    {
        var field = target.GetType().GetField(fieldName, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingFieldException(target.GetType().FullName, fieldName);
        field.SetValue(target, value);
    }

    private static void Fill(Span<byte> destination, int value) =>
        destination.Fill(unchecked((byte)(value == 0 ? 1 : value)));

    private static byte[] Bytes(int length, int seed)
    {
        var result = new byte[length];
        for (var index = 0; index < result.Length; index++)
            result[index] = unchecked((byte)(seed + index * 17 + 1));
        return result;
    }
}
