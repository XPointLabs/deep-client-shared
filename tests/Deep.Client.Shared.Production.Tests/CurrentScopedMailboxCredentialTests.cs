using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Client.Shared.Production.Tests;

public sealed class CurrentScopedMailboxCredentialTests
{
    [Fact]
    public async Task CurrentGrantSurvivesRestartAndPreparedMau2ResumesExactly()
    {
        using var fixture = new Fixture();
        using (var store = fixture.Open())
            await store.InstallCurrentScopedCredentialAsync(
                fixture.Credential, fixture.Authority);

        byte[] exact;
        using (var store = fixture.Open())
        {
            Assert.Equal(
                fixture.Credential.Current.Epoch,
                (await store.ReadScopedMailboxRouteAsync(
                    fixture.Selector, fixture.Authority)).Epoch);
            var prepared = await store.PrepareScopedMailboxBatchAsync(
                fixture.PrepareRequest,
                fixture.Signer,
                fixture.Authority);
            exact = Assert.Single(prepared.Frames).GetCanonicalMau2Copy();
        }

        using (var store = fixture.Open())
        {
            var resumed = await store.TryResumeScopedMailboxBatchAsync(
                fixture.ResumeRequest,
                fixture.Signer,
                fixture.Authority);
            Assert.NotNull(resumed);
            Assert.Equal(
                exact,
                Assert.Single(resumed!.Frames).GetCanonicalMau2Copy());
            await store.InstallCurrentScopedCredentialAsync(
                fixture.Credential, fixture.Authority);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                store.InstallCurrentScopedCredentialAsync(
                    fixture.CreateCredential(epoch: 6, marker: 0x70),
                    fixture.Authority));
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = Path.Combine(
            Path.GetTempPath(), "deep-current-mailbox-" + Guid.NewGuid().ToString("N"));
        private readonly byte[] key = Bytes(32, 0x91);
        private readonly byte[] issuerSeed = Bytes(32, 0x11);
        private readonly byte[] holderSeed = Bytes(32, 0x21);
        private readonly SodiumMailboxCapabilityCrypto crypto = new();

        internal Fixture()
        {
            Directory.CreateDirectory(directory);
            Account = OutboxAccountScope.FromBytes(Bytes(32, 0x31));
            Selector = new MailboxCredentialSelector(
                Account,
                MailboxCredentialScopeKind.Self,
                Bytes(32, 0x41),
                Bytes(32, 0x51));
            var issuerKey = crypto.GetPublicKey(issuerSeed);
            Clock = new FixedTimeProvider(1050);
            Authority = new VerifiedOfficialMailboxAuthority(
                Bytes(16, 0x61),
                1,
                [new MailboxCapabilityIssuerAuthority
                {
                    PublicKey = issuerKey,
                    Domain = MailboxCapabilityDomain.Retrieve,
                    AllowedLifecycle = MailboxCapabilityLifecycle.Active,
                    MinimumGeneration = 1,
                    MaximumGeneration = ulong.MaxValue,
                    ValidFromUnixSeconds = 1,
                    ValidUntilUnixSeconds = ulong.MaxValue
                }],
                requiresManagedEntitlement: false,
                static () => true,
                new NoRevocations(),
                Clock);
            Signer = new OperationSigner(holderSeed, crypto.GetPublicKey(holderSeed));
            Credential = CreateCredential(7, 0x71);
            var operationId = Bytes(16, 0x81);
            var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
                Credential.Current.Epoch,
                operationId,
                new BlindedMailboxId(Credential.MailboxId.Span),
                new BlindedPlacementId(Credential.Current.PlacementId.Span),
                0,
                25,
                []);
            var logical = new ScopedMailboxBatchSelector(
                Selector,
                new MailboxWireMessageId(operationId),
                MailboxAuthenticatedOperation.Retrieve);
            PrepareRequest = new ScopedMailboxPrepareBatchRequest(
                Account,
                operationId,
                operationId,
                [logical],
                [new ScopedMailboxBatchTarget(Selector, binding)],
                DateTimeOffset.FromUnixTimeSeconds(Clock.Seconds));
            ResumeRequest = new ScopedMailboxResumeBatchRequest(
                Account, operationId, operationId, [logical]);
        }

        internal OutboxAccountScope Account { get; }
        internal MailboxCredentialSelector Selector { get; }
        internal VerifiedOfficialMailboxAuthority Authority { get; }
        internal FixedTimeProvider Clock { get; }
        internal OperationSigner Signer { get; }
        internal ScopedCurrentMailboxCredential Credential { get; }
        internal ScopedMailboxPrepareBatchRequest PrepareRequest { get; }
        internal ScopedMailboxResumeBatchRequest ResumeRequest { get; }

        internal SqliteDeepMailboxStore Open() => new(
            new SqliteDeepMailboxStoreOptions(
                Path.Combine(directory, "mailbox.db"), key));

        internal ScopedCurrentMailboxCredential CreateCredential(
            ulong epoch,
            byte marker)
        {
            var placement = new BlindedPlacementId(Bytes(32, marker));
            var value = new MailboxCredentialEpoch(
                epoch,
                900,
                1200,
                Bytes(32, unchecked((byte)(marker + 1))),
                placement.Bytes.Span,
                MailboxPlacementCommitment.Compute(placement));
            var unsigned = new MailboxAuthenticatedGrant
            {
                Domain = MailboxCapabilityDomain.Retrieve,
                Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = Authority.NetworkId,
                Epoch = epoch,
                Generation = epoch,
                Serial = Bytes(16, unchecked((byte)(marker + 2))),
                NotBeforeUnixSeconds = value.NotBeforeUnixSeconds,
                ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds,
                OverlapUntilUnixSeconds = 0,
                PlacementCommitment = value.PlacementCommitment,
                MembershipCommitment = value.MembershipCommitment,
                IssuerPublicKey = crypto.GetPublicKey(issuerSeed),
                HolderPublicKey = crypto.GetPublicKey(holderSeed),
                IssuerSignature = new byte[64]
            };
            var grant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(
                crypto.SignGrant(unsigned, issuerSeed));
            return new ScopedCurrentMailboxCredential(
                Selector,
                SHA256.HashData(grant),
                crypto.GetPublicKey(holderSeed),
                Bytes(32, unchecked((byte)(marker + 3))),
                value,
                new CurrentMailboxCredentialGrants(retrieveGrant: grant),
                new MailboxCredentialReplicaPair(
                    Bytes(32, 0xa1), Bytes(32, 0xb1),
                    Bytes(32, 0xc1), Bytes(32, 0xd1)));
        }

        public void Dispose()
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(issuerSeed);
            CryptographicOperations.ZeroMemory(holderSeed);
        }
    }

    private sealed class OperationSigner(byte[] seed, byte[] publicKey) :
        IMailboxOperationSigner
    {
        public byte[] GetEd25519PublicKey() => publicKey.ToArray();

        public byte[] SignMailboxPresentation(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> canonicalPresentationSigningBytes)
        {
            var pair = PublicKeyAuth.GenerateKeyPair(seed);
            try
            {
                return PublicKeyAuth.SignDetached(
                    canonicalPresentationSigningBytes.ToArray(),
                    pair.PrivateKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pair.PrivateKey);
            }
        }
    }

    private sealed class NoRevocations : IFreshMailboxCapabilityRevocationSource
    {
        public void ValidateFreshness() { }
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
    }

    internal sealed class FixedTimeProvider(long seconds) : TimeProvider
    {
        internal long Seconds { get; } = seconds;
        public override DateTimeOffset GetUtcNow() =>
            DateTimeOffset.FromUnixTimeSeconds(Seconds);
    }

    private static byte[] Bytes(int count, byte start)
    {
        var value = new byte[count];
        for (var index = 0; index < count; index++)
            value[index] = unchecked((byte)(start + index));
        return value;
    }
}
