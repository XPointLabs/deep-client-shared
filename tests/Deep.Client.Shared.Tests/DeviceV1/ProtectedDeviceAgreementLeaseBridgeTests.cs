using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.DeviceV1;

public sealed class ProtectedDeviceAgreementLeaseBridgeTests
{
    private const string Mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    [Fact]
    public void Redeem_BindsExactScopeAndZeroizesBothCapabilityLifetimes()
    {
        using var fixture = BridgeFixture.Create(0x11);
        var operationBinding = SHA256.HashData("bridge/success"u8);
        var peerPrivate = Enumerable.Repeat((byte)0x71, 32).ToArray();
        var peerPublic = DeepIdentityCrypto.DeriveX25519PublicKey(peerPrivate);
        try
        {
            using var authorization = Authorization(
                fixture, fixture.Current, 0x80, operationBinding, peerPublic);
            var authorizationOperation = PrivateArray(authorization, "operationBinding");
            var authorizationPeer = PrivateArray(authorization, "peerPublicKey");

            var lease = ProtectedDeviceAgreementLeaseBridge.Redeem(
                authorization, fixture.Current, fixture.Authority);
            Assert.Equal(fixture.Current.Head.Record.NetworkId.ToArray(), lease.NetworkId.ToArray());
            Assert.Equal(fixture.Current.Head.Record.DeepAccountId.ToArray(), lease.AccountId.ToArray());
            Assert.Equal(fixture.Device.DeviceId.Bytes.ToArray(), lease.DeviceId.ToArray());
            Assert.Equal(fixture.Current.Head.Record.RecordHash.ToArray(), lease.ExactDirectoryHash.ToArray());
            Assert.Equal(operationBinding, lease.OperationBinding.ToArray());
            AssertZero(authorizationOperation);
            AssertZero(authorizationPeer);
            Assert.Throws<InvalidOperationException>(() =>
                ProtectedDeviceAgreementLeaseBridge.Redeem(
                    authorization, fixture.Current, fixture.Authority));

            var leaseOperation = PrivateArray(lease, "_operationBinding");
            var leasePeer = PrivateArray(lease, "_peerPublicKey");
            var leaseDirectory = PrivateArray(lease, "_directoryHash");
            lease.Dispose();
            AssertZero(leaseOperation);
            AssertZero(leasePeer);
            AssertZero(leaseDirectory);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
            CryptographicOperations.ZeroMemory(peerPublic);
            CryptographicOperations.ZeroMemory(operationBinding);
        }
    }

    [Fact]
    public void Redeem_HostileScopeAndCurrentSubstitutionsBurnAuthorization()
    {
        using var fixture = BridgeFixture.Create(0x21);
        using var foreign = BridgeFixture.Create(0x41);
        var operationBinding = SHA256.HashData("bridge/hostile-scope"u8);
        var peerPrivate = Enumerable.Repeat((byte)0x72, 32).ToArray();
        var peerPublic = DeepIdentityCrypto.DeriveX25519PublicKey(peerPrivate);
        try
        {
            var wrongBindings = new[]
            {
                LocalDeviceAgreementBinding.ForTesting(
                    fixture.Authority.NetworkId.Span, fixture.Authority.AccountId.Span,
                    fixture.Authority.AccountGeneration, Bytes(32, 0x93),
                    fixture.Authority.DeviceGeneration, fixture.Authority.ExactDpd1Hash.Span,
                    fixture.Authority.AgreementPublicKey.Span),
                LocalDeviceAgreementBinding.ForTesting(
                    fixture.Authority.NetworkId.Span, fixture.Authority.AccountId.Span,
                    fixture.Authority.AccountGeneration, fixture.Authority.DeviceId.Span,
                    fixture.Authority.DeviceGeneration + 1, fixture.Authority.ExactDpd1Hash.Span,
                    fixture.Authority.AgreementPublicKey.Span),
                LocalDeviceAgreementBinding.ForTesting(
                    fixture.Authority.NetworkId.Span, fixture.Authority.AccountId.Span,
                    fixture.Authority.AccountGeneration, fixture.Authority.DeviceId.Span,
                    fixture.Authority.DeviceGeneration, Bytes(32, 0x94),
                    fixture.Authority.AgreementPublicKey.Span)
            };

            foreach (var binding in wrongBindings)
            {
                using var authorization = Authorization(
                    fixture.Current, binding, 0x81, operationBinding, peerPublic);
                AssertBurnedAfterScopeRejection(
                    authorization, fixture.Current, fixture.Authority);
            }

            using (var stale = Authorization(
                fixture, fixture.Current, 0x82, operationBinding, peerPublic))
            {
                AssertBurnedAfterScopeRejection(stale, fixture.Successor, fixture.Authority);
            }

            using (var wrongAuthority = Authorization(
                fixture, fixture.Current, 0x83, operationBinding, peerPublic))
            {
                AssertBurnedAfterScopeRejection(
                    wrongAuthority, foreign.Current, foreign.Authority);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
            CryptographicOperations.ZeroMemory(peerPublic);
            CryptographicOperations.ZeroMemory(operationBinding);
        }
    }

    [Fact]
    public async Task Redeem_IsSingleWinnerUnderConcurrency()
    {
        using var fixture = BridgeFixture.Create(0x51);
        var operationBinding = SHA256.HashData("bridge/concurrent-replay"u8);
        var peerPrivate = Enumerable.Repeat((byte)0x73, 32).ToArray();
        var peerPublic = DeepIdentityCrypto.DeriveX25519PublicKey(peerPrivate);
        try
        {
            using var authorization = Authorization(
                fixture, fixture.Current, 0x84, operationBinding, peerPublic);
            var attempts = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ => Task.Run(() =>
            {
                try
                {
                    return (Lease: ProtectedDeviceAgreementLeaseBridge.Redeem(
                        authorization, fixture.Current, fixture.Authority), Error: (Exception?)null);
                }
                catch (Exception exception)
                {
                    return (Lease: (LocalDeviceX25519AgreementLease?)null, Error: exception);
                }
            })));

            var winner = Assert.Single(attempts, static attempt => attempt.Lease is not null).Lease!;
            Assert.Equal(23, attempts.Count(static attempt => attempt.Error is InvalidOperationException));
            winner.Dispose();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
            CryptographicOperations.ZeroMemory(peerPublic);
            CryptographicOperations.ZeroMemory(operationBinding);
        }
    }

    [Fact]
    public void Redeem_DisposedAuthorityBurnsAndZeroizesAuthorization()
    {
        using var fixture = BridgeFixture.Create(0x61);
        var operationBinding = SHA256.HashData("bridge/disposed-authority"u8);
        var peerPrivate = Enumerable.Repeat((byte)0x74, 32).ToArray();
        var peerPublic = DeepIdentityCrypto.DeriveX25519PublicKey(peerPrivate);
        try
        {
            using var authorization = Authorization(
                fixture, fixture.Current, 0x85, operationBinding, peerPublic);
            var transferredOperation = PrivateArray(authorization, "operationBinding");
            var transferredPeer = PrivateArray(authorization, "peerPublicKey");
            fixture.Authority.Dispose();

            Assert.Throws<ObjectDisposedException>(() =>
                ProtectedDeviceAgreementLeaseBridge.Redeem(
                    authorization, fixture.Current, fixture.Authority));
            AssertZero(transferredOperation);
            AssertZero(transferredPeer);
            Assert.Throws<InvalidOperationException>(() =>
                ProtectedDeviceAgreementLeaseBridge.Redeem(
                    authorization, fixture.Current, fixture.Authority));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerPrivate);
            CryptographicOperations.ZeroMemory(peerPublic);
            CryptographicOperations.ZeroMemory(operationBinding);
        }
    }

    [Fact]
    public void Bridge_IsNonPublicAndHasNoRawKeyTrustFlagProviderOrSessionSeam()
    {
        var bridge = typeof(ProtectedDeviceAgreementLeaseBridge);
        Assert.False(bridge.IsPublic);
        var redeem = Assert.Single(bridge.GetMethods(
            BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly),
            static method => method.Name == "Redeem");
        Assert.Equal(typeof(LocalDeviceX25519AgreementLease), redeem.ReturnType);
        Assert.Equal(
            [
                typeof(ProtectedDeviceAgreementAuthorization),
                typeof(Dmd1LineageState),
                typeof(LocalDeviceX25519AgreementAuthority)
            ],
            redeem.GetParameters().Select(static parameter => parameter.ParameterType).ToArray());
        Assert.DoesNotContain(redeem.GetParameters(), static parameter =>
            parameter.ParameterType == typeof(byte[]) ||
            parameter.ParameterType == typeof(bool) ||
            typeof(Delegate).IsAssignableFrom(parameter.ParameterType) ||
            parameter.ParameterType.Name.Contains("Session", StringComparison.OrdinalIgnoreCase) ||
            parameter.Name!.Contains("trust", StringComparison.OrdinalIgnoreCase) ||
            parameter.Name.Contains("private", StringComparison.OrdinalIgnoreCase));
    }

    private static void AssertBurnedAfterScopeRejection(
        ProtectedDeviceAgreementAuthorization authorization,
        Dmd1LineageState current,
        LocalDeviceX25519AgreementAuthority authority)
    {
        var operation = PrivateArray(authorization, "operationBinding");
        var peer = PrivateArray(authorization, "peerPublicKey");
        Assert.Throws<RecordException>(() =>
            ProtectedDeviceAgreementLeaseBridge.Redeem(authorization, current, authority));
        AssertZero(operation);
        AssertZero(peer);
        Assert.Throws<InvalidOperationException>(() =>
            ProtectedDeviceAgreementLeaseBridge.Redeem(authorization, current, authority));
    }

    private static ProtectedDeviceAgreementAuthorization Authorization(
        BridgeFixture fixture,
        Dmd1LineageState current,
        byte operation,
        ReadOnlySpan<byte> operationBinding,
        ReadOnlySpan<byte> peerPublicKey) => Authorization(
            current,
            LocalDeviceAgreementBinding.FromAuthority(fixture.Authority),
            operation,
            operationBinding,
            peerPublicKey);

    private static ProtectedDeviceAgreementAuthorization Authorization(
        Dmd1LineageState current,
        LocalDeviceAgreementBinding binding,
        byte operation,
        ReadOnlySpan<byte> operationBinding,
        ReadOnlySpan<byte> peerPublicKey) => new(
            DeviceV1Fixture.Operation(operation),
            CurrentDmd1Evidence.FromVerified(current),
            binding,
            LocalDeviceX25519AgreementPurpose.Dph2InitiatorDh1,
            operationBinding,
            peerPublicKey);

    private static byte[] PrivateArray(object owner, string fieldName) =>
        Assert.IsType<byte[]>(owner.GetType().GetField(
            fieldName, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(owner));

    private static void AssertZero(byte[] value) =>
        Assert.All(value, static item => Assert.Equal(0, item));

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();

    private sealed class BridgeFixture : IDisposable
    {
        private BridgeFixture(
            DeepRecoveryAccountCapabilities recovery,
            OwnedGenesisDeviceSecrets device,
            LocalDeviceX25519AgreementAuthority authority,
            Dmd1LineageState current,
            Dmd1LineageState successor)
        {
            Recovery = recovery;
            Device = device;
            Authority = authority;
            Current = current;
            Successor = successor;
        }

        internal DeepRecoveryAccountCapabilities Recovery { get; }
        internal OwnedGenesisDeviceSecrets Device { get; }
        internal LocalDeviceX25519AgreementAuthority Authority { get; }
        internal Dmd1LineageState Current { get; }
        internal Dmd1LineageState Successor { get; }

        internal static BridgeFixture Create(byte networkMarker)
        {
            var network = Bytes(16, networkMarker);
            var mnemonic = Encoding.ASCII.GetBytes(Mnemonic);
            DeepRecoveryAccountCapabilities? recovery = null;
            OwnedGenesisDeviceSecrets? device = null;
            LocalDeviceX25519AgreementAuthority? authority = null;
            try
            {
                using (var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(mnemonic))
                    recovery = DeepRecoveryV1.DeriveAccountCapabilities(phrase, network, 1);
                var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
                    recovery, 1_900_000_000, 1);
                var identity = Assert.IsType<VerifiedIdentityRelative>(
                    typeof(GenesisAccountAuthoringResult).GetProperty(
                        "Identity", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(account));
                device = new OwnedGenesisDeviceSecrets();
                var certificate = DeviceCertificate(identity, device);
                var verifiedDevice = Assert.IsType<VerifiedDevice>(Activator.CreateInstance(
                    typeof(VerifiedDevice),
                    BindingFlags.Instance | BindingFlags.NonPublic,
                    binder: null,
                    args: [certificate, identity.Revocations, null],
                    culture: null));
                var relative = Assert.IsType<VerifiedDeviceRelative>(Activator.CreateInstance(
                    typeof(VerifiedDeviceRelative),
                    BindingFlags.Instance | BindingFlags.NonPublic,
                    binder: null,
                    args: [identity, verifiedDevice],
                    culture: null));
                authority = Assert.IsType<LocalDeviceX25519AgreementAuthority>(
                    typeof(OwnedGenesisDeviceSecrets).GetMethod(
                        "CreateAgreementAuthority",
                        BindingFlags.Instance | BindingFlags.NonPublic,
                        binder: null,
                        types: [typeof(VerifiedDeviceRelative)],
                        modifiers: null)!.Invoke(device, [relative]));

                var closure = ApplicationCoreVerifier.CreateIdentityClosure(identity, [relative]);
                var firstVerified = VerifiedDirectory(closure, relative, 1, new byte[32]);
                var current = ApplicationCoreVerifier.StartDmd1Lineage(firstVerified).Next;
                var nextVerified = VerifiedDirectory(
                    closure, relative, 2, current.Head.Record.RecordHash.ToArray());
                var successor = ApplicationCoreVerifier.PrepareDmd1Transition(current, nextVerified).Next;
                return new BridgeFixture(recovery, device, authority, current, successor);
            }
            catch
            {
                authority?.Dispose();
                device?.Dispose();
                recovery?.Dispose();
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(mnemonic);
                CryptographicOperations.ZeroMemory(network);
            }
        }

        public void Dispose()
        {
            Authority.Dispose();
            Device.Dispose();
            Recovery.Dispose();
        }

        private static DeviceCertificate DeviceCertificate(
            VerifiedIdentityRelative identity,
            OwnedGenesisDeviceSecrets device)
        {
            var account = identity.Account;
            var revocations = identity.Revocations.Snapshot;
            var fields = new ReadOnlyMemory<byte>[]
            {
                account.Certificate.NetworkId,
                account.DeepAccountIdHash,
                U64(account.Certificate.AccountGeneration),
                device.DeviceId.Bytes,
                U64(1),
                device.SigningPublicKey.Bytes,
                device.AgreementPublicKey.Bytes,
                device.RevocationHandle.Bytes,
                U64(0),
                new byte[38],
                Bytes(32, 0x31),
                U64(revocations.Revision),
                ReferenceBytes(ArtifactType.Drs1, revocations.CanonicalBytes, revocations.CanonicalHash),
                U64(revocations.EntryCount),
                revocations.CurrentHead,
                U64(1_900_000_100),
                U64(1_900_172_900),
                U64((ulong)DeviceCapabilities.MailboxRoleIssuer),
                U16(1),
                new byte[38],
                Bytes(32, 0x32),
                Bytes(64, 0x33),
                Bytes(64, 0x34)
            };

            var assembly = typeof(IdentityCodec).Assembly;
            var definitions = assembly.GetType(
                "Deep.Protocol.DeepNative.RecordDefinitions", throwOnError: true)!;
            var definition = definitions.GetProperty(
                "Dpd1", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
            var grammar = assembly.GetType(
                "Deep.Protocol.DeepNative.CanonicalGrammar", throwOnError: true)!;
            var encode = grammar.GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
                .Single(static method => method.Name == "Encode" && method.GetParameters().Length == 2);
            var canonical = Assert.IsType<byte[]>(encode.Invoke(null, [definition, fields]));
            return IdentityCodec.DecodeDeviceCertificate(canonical);
        }

        private static VerifiedDmd1 VerifiedDirectory(
            VerifiedApplicationIdentityClosure closure,
            VerifiedDeviceRelative device,
            ulong generation,
            ReadOnlySpan<byte> predecessor)
        {
            var record = ApplicationCoreCodec.AuthorDmd1(
                closure.Account.Certificate.NetworkId.Span,
                closure.Account.DeepAccountIdHash.Span,
                closure.Account.Certificate.AccountGeneration,
                Reference(
                    ArtifactType.Dpa1,
                    closure.Account.Certificate.CanonicalBytes,
                    closure.Account.Certificate.CanonicalHash),
                Reference(
                    ArtifactType.Drs1,
                    closure.Revocations.Snapshot.CanonicalBytes,
                    closure.Revocations.Snapshot.CanonicalHash),
                generation,
                predecessor,
                [new DeviceDirectoryEntry(
                    device.Certificate.DeviceId.Span,
                    Reference(
                        ArtifactType.Dpd1,
                        device.Certificate.CanonicalBytes,
                        device.Certificate.CanonicalHash))],
                1_900_000_200 + generation,
                Bytes(64, 0x35));
            return Assert.IsType<VerifiedDmd1>(Activator.CreateInstance(
                typeof(VerifiedDmd1),
                BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null,
                args: [record, closure],
                culture: null));
        }

        private static ApplicationArtifactReference Reference(
            ArtifactType type,
            ReadOnlyMemory<byte> canonical,
            ReadOnlyMemory<byte> hash) =>
            ApplicationCoreCodec.CreateArtifactReference(
                (ushort)type, checked((uint)canonical.Length), hash.Span);

        private static byte[] ReferenceBytes(
            ArtifactType type,
            ReadOnlyMemory<byte> canonical,
            ReadOnlyMemory<byte> hash)
        {
            var encoded = new byte[38];
            BinaryPrimitives.WriteUInt16BigEndian(encoded, (ushort)type);
            BinaryPrimitives.WriteUInt32BigEndian(
                encoded.AsSpan(2), checked((uint)canonical.Length));
            hash.Span.CopyTo(encoded.AsSpan(6));
            return encoded;
        }

        private static byte[] U64(ulong value)
        {
            var encoded = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
            return encoded;
        }

        private static byte[] U16(ushort value)
        {
            var encoded = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(encoded, value);
            return encoded;
        }
    }
}
