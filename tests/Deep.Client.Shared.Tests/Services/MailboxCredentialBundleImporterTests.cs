using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class MailboxCredentialBundleImporterTests
{
    private const string AlicePhrase =
        "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed";
    private const string BobPhrase =
        "update vague zinger boxes ornament renting glass gained island nabbing afield calamity nabbing";
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-08-01T10:00:00Z");

    [Fact]
    public async Task ExactAtomicPairImportsSelfAndPeerInOneCleanBreakBaseline()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        using var store = new SqliteSessionStore(fixture.DatabasePath);

        var imported = await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, fixture.AndroidOptions,
            MailboxInfrastructureOwnership.UserManaged);

        Assert.Equal(identity.SessionId, imported.LocalSessionId);
        Assert.Equal(fixture.BobSessionId, imported.PeerSessionId);
        Assert.Equal(MailboxInfrastructureOwnership.UserManaged, imported.Ownership);
        Assert.Equal(fixture.Coordinator, imported.Coordinator);
        Assert.NotNull(await store.ReadScopedMailboxRouteAsync(
            imported.SelfSelector, imported.Authority));
        Assert.NotNull(await store.ReadScopedMailboxRouteAsync(
            imported.PeerSelector, imported.Authority));

        var repeated = await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, fixture.AndroidOptions,
            MailboxInfrastructureOwnership.UserManaged);
        Assert.Equal(imported.SelfSelector.ScopeId.ToArray(),
            repeated.SelfSelector.ScopeId.ToArray());
    }

    [Fact]
    public async Task WholePairRollbackOrSubstitutionFailsAgainstSignedGenerationPins()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        using var store = new SqliteSessionStore(fixture.DatabasePath);
        var options = fixture.AndroidOptions with
        {
            ExpectedPairGeneration = Bytes(32, 0x7a)
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            MailboxCredentialBundleImporter.ImportAsync(
                store, identity, options,
                MailboxInfrastructureOwnership.UserManaged));
    }

    [Fact]
    public async Task CurrentIdentityAndPeerPinsAreCheckedBeforeSqliteCommit()
    {
        using var fixture = Fixture.Create();
        using var wrongIdentity = new SessionIdentityProvider(BobPhrase);
        using var store = new SqliteSessionStore(fixture.DatabasePath);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            MailboxCredentialBundleImporter.ImportAsync(
                store, wrongIdentity, fixture.AndroidOptions,
                MailboxInfrastructureOwnership.UserManaged));
    }

    [Fact]
    public async Task MrXPolicySignatureAndPinnedApprovalKeyAreRequired()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        using var store = new SqliteSessionStore(fixture.DatabasePath);
        var options = fixture.AndroidOptions with
        {
            MrXApproval = fixture.AndroidOptions.MrXApproval with
            {
                Signature = Bytes(64, 0x5a)
            }
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            MailboxCredentialBundleImporter.ImportAsync(
                store, identity, options,
                MailboxInfrastructureOwnership.UserManaged));
    }

    [Fact]
    public async Task ExpiredOrUnpinnedRevocationSnapshotFailsClosed()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        using var store = new SqliteSessionStore(fixture.DatabasePath);
        var options = fixture.AndroidOptions with
        {
            ExpectedRevocationSnapshotSha256 = Bytes(32, 0x55)
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            MailboxCredentialBundleImporter.ImportAsync(
                store, identity, options,
                MailboxInfrastructureOwnership.UserManaged));
    }

    [Fact]
    public async Task OfficialManagedImportRequiresLiveEntitlementButUserManagedDoesNot()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        using var store = new SqliteSessionStore(fixture.DatabasePath);
        var deniedOfficial = fixture.OfficialAndroidOptions with
        {
            ManagedEntitlement = static () => false
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            MailboxCredentialBundleImporter.ImportAsync(
                store, identity, deniedOfficial,
                MailboxInfrastructureOwnership.OfficialManaged));

        var deniedUser = fixture.AndroidOptions with
        {
            ManagedEntitlement = static () => false
        };
        var imported = await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, deniedUser,
            MailboxInfrastructureOwnership.UserManaged);
        Assert.False(imported.Authority.RequiresManagedEntitlement);
        Assert.True(imported.Authority.IsEntitled);
    }

    [Fact]
    public async Task DurableReceiptAllowsExactReplayAndRejectsSameEpochPolicyReplacement()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        using var store = new SqliteSessionStore(fixture.DatabasePath);
        await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, fixture.AndroidOptions,
            MailboxInfrastructureOwnership.UserManaged);
        var replacement = fixture.OfficialAndroidOptions with
        {
            ManagedEntitlement = static () => true
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            MailboxCredentialBundleImporter.ImportAsync(
                store, identity, replacement,
                MailboxInfrastructureOwnership.OfficialManaged));
    }

    private static byte[] Bytes(int count, byte value) =>
        Enumerable.Repeat(value, count).ToArray();

    private sealed class Fixture : IDisposable
    {
        private readonly string root;
        private Fixture(
            string root,
            string databasePath,
            MailboxCredentialBundleImportOptions androidOptions,
            MailboxCredentialBundleImportOptions officialAndroidOptions,
            SessionId bobSessionId,
            Uri coordinator)
        {
            this.root = root;
            DatabasePath = databasePath;
            AndroidOptions = androidOptions;
            OfficialAndroidOptions = officialAndroidOptions;
            BobSessionId = bobSessionId;
            Coordinator = coordinator;
        }

        public string DatabasePath { get; }
        public MailboxCredentialBundleImportOptions AndroidOptions { get; }
        public MailboxCredentialBundleImportOptions OfficialAndroidOptions { get; }
        public SessionId BobSessionId { get; }
        public Uri Coordinator { get; }

        public static Fixture Create()
        {
            var root = Path.Combine(Path.GetTempPath(), $"deep-mailbox-import-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            var pairRoot = Path.Combine(root, "pair");
            Directory.CreateDirectory(pairRoot);
            using var alice = new SessionIdentityProvider(AlicePhrase);
            using var bob = new SessionIdentityProvider(BobPhrase);
            var aliceHolder = alice.GetEd25519PublicKey();
            var bobHolder = bob.GetEd25519PublicKey();
            var crypto = new SodiumMailboxCapabilityCrypto();
            var issuerSeed = Bytes(32, 0x41);
            var issuer = crypto.GetPublicKey(issuerSeed);
            var network = Bytes(16, 0x42);
            var replicas = new[]
            {
                new { id = Hex(Bytes(32, 0x51)), signingPublicKey = Hex(Bytes(32, 0x61)) },
                new { id = Hex(Bytes(32, 0x52)), signingPublicKey = Hex(Bytes(32, 0x62)) }
            };
            var current = Epoch(7, Now.AddMinutes(-5), Now.AddMinutes(30), 0x71);
            var next = Epoch(8, Now.AddMinutes(20), Now.AddMinutes(60), 0x72);
            var coordinator = new Uri("http://192.168.1.44:41801");
            var authorityObject = new
            {
                schemaVersion = 2,
                scope = "DEV-LOCAL-ONLY",
                protocol = "P10E/MCP2/MAU2/MIP1/RIP1/PRQ2",
                networkId = Hex(network),
                issuerPublicKey = Hex(issuer),
                minimumGeneration = 7UL,
                maximumGeneration = 8UL,
                issuerValidFromUnixSeconds = current.notBeforeUnixSeconds,
                issuerValidUntilUnixSeconds = next.expiresAtUnixSeconds,
                coordinatorUrl = coordinator.ToString().TrimEnd('/'),
                replicaIds = replicas.Select(value => value.id),
                replicaSigningPublicKeys = replicas.Select(value => value.signingPublicKey),
                epochs = new[]
                {
                    AuthorityEpoch(current), AuthorityEpoch(next)
                },
                selections = Array.Empty<object>()
            };
            var authorityBytes = Json(authorityObject, indented: true);
            var authorityPath = Path.Combine(root, "authority.public.json");
            File.WriteAllBytes(authorityPath, authorityBytes);
            var authorityHash = SHA256.HashData(authorityBytes);
            var aliceMailbox = Bytes(32, 0x81);
            var bobMailbox = Bytes(32, 0x82);
            var androidBytes = Bundle(
                "android", authorityHash, network, issuer, coordinator,
                aliceHolder, bobHolder, aliceMailbox, bobMailbox,
                current, next, replicas, crypto, issuerSeed, 0x11);
            var windowsBytes = Bundle(
                "windows", authorityHash, network, issuer, coordinator,
                bobHolder, aliceHolder, bobMailbox, aliceMailbox,
                current, next, replicas, crypto, issuerSeed, 0x31);
            var androidHash = SHA256.HashData(androidBytes);
            var windowsHash = SHA256.HashData(windowsBytes);
            var generation = SHA256.HashData(Encoding.UTF8.GetBytes(
                $"deep.mailbox-pair-generation.v1\n{Hex(authorityHash)}\n" +
                $"{Hex(androidHash)}\n{Hex(windowsHash)}\n"));
            var generationHex = Hex(generation);
            var directory = Path.Combine(pairRoot, "generations", generationHex);
            Directory.CreateDirectory(directory);
            File.WriteAllBytes(Path.Combine(directory, "android.mailbox-credentials.v1.json"), androidBytes);
            File.WriteAllBytes(Path.Combine(directory, "windows.mailbox-credentials.v1.json"), windowsBytes);
            var manifestBytes = Json(new
            {
                schemaVersion = 1,
                developmentOnly = true,
                generation = generationHex,
                authoritySha256 = Hex(authorityHash),
                issuerPublicKey = Hex(issuer),
                androidHolderPublicKey = Hex(aliceHolder),
                windowsHolderPublicKey = Hex(bobHolder),
                files = new { android = Hex(androidHash), windows = Hex(windowsHash) }
            });
            var manifestHash = SHA256.HashData(manifestBytes);
            File.WriteAllBytes(Path.Combine(directory, "pair-manifest.v1.json"), manifestBytes);
            File.WriteAllBytes(Path.Combine(pairRoot, "current-generation.json"), Json(new
            {
                schemaVersion = 1,
                developmentOnly = true,
                generation = generationHex,
                pairManifestSha256 = Hex(manifestHash)
            }));
            var revocationPath = Path.Combine(root, "revocations.v1.json");
            var revocationBytes = Json(new
            {
                schemaVersion = 1,
                authoritySha256 = Hex(authorityHash),
                issuerPublicKey = Hex(issuer),
                generatedAtUnixSeconds = checked((ulong)Now.AddMinutes(-1).ToUnixTimeSeconds()),
                expiresAtUnixSeconds = checked((ulong)Now.AddMinutes(20).ToUnixTimeSeconds()),
                revoked = Array.Empty<object>()
            });
            File.WriteAllBytes(revocationPath, revocationBytes);
            using var mrX = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x91));
            MrXSignedMailboxPolicyApproval Approval(string ownership)
            {
                var payload = Json(new
                {
                    schemaVersion = 1,
                    developmentOnly = true,
                    lane = "android-windows-pair",
                    platform = "android",
                    ownership,
                    authoritySha256 = Hex(authorityHash),
                    issuerPublicKey = Hex(issuer),
                    androidHolderPublicKey = Hex(aliceHolder),
                    windowsHolderPublicKey = Hex(bobHolder),
                    androidSessionId = alice.SessionId.Value,
                    windowsSessionId = bob.SessionId.Value,
                    pairGeneration = Hex(generation),
                    pairManifestSha256 = Hex(manifestHash),
                    revocationSnapshotSha256 = Hex(SHA256.HashData(revocationBytes))
                });
                return new MrXSignedMailboxPolicyApproval(
                    payload,
                    PublicKeyAuth.SignDetached(payload, mrX.PrivateKey),
                    mrX.PublicKey,
                    SHA256.HashData(mrX.PublicKey));
            }
            var options = new MailboxCredentialBundleImportOptions(
                pairRoot,
                authorityPath,
                MailboxClientPlatform.Android,
                authorityHash,
                issuer,
                generation,
                manifestHash,
                bobHolder,
                bob.SessionId,
                revocationPath,
                SHA256.HashData(revocationBytes),
                Approval("user-managed"),
                DevelopmentOnly: true,
                ManagedEntitlement: null,
                new FrozenTimeProvider(Now));
            var officialOptions = options with
            {
                MrXApproval = Approval("official-managed")
            };
            CryptographicOperations.ZeroMemory(issuerSeed);
            return new Fixture(
                root, Path.Combine(root, "state.db"), options, officialOptions,
                bob.SessionId, coordinator);
        }

        public void Dispose()
        {
            try { Directory.Delete(root, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private static object AuthorityEpoch(dynamic epoch) => new
        {
            epoch = (ulong)epoch.epoch,
            notBeforeUnixSeconds = (ulong)epoch.notBeforeUnixSeconds,
            expiresAtUnixSeconds = (ulong)epoch.expiresAtUnixSeconds,
            membershipCommitment = (string)epoch.membershipCommitment,
            placementId = (string)epoch.placementId,
            placementCommitment = (string)epoch.placementCommitment,
            replicas = Array.Empty<object>()
        };

        private static dynamic Epoch(
            ulong epoch,
            DateTimeOffset notBefore,
            DateTimeOffset expires,
            byte seed)
        {
            var placement = Bytes(32, seed);
            return new
            {
                epoch,
                notBeforeUnixSeconds = checked((ulong)notBefore.ToUnixTimeSeconds()),
                expiresAtUnixSeconds = checked((ulong)expires.ToUnixTimeSeconds()),
                membershipCommitment = Hex(Bytes(32, checked((byte)(seed + 1)))),
                placementId = Hex(placement),
                placementCommitment = Hex(MailboxPlacementCommitment.Compute(
                    new BlindedPlacementId(placement)))
            };
        }

        private static byte[] Bundle(
            string identity,
            byte[] authorityHash,
            byte[] network,
            byte[] issuer,
            Uri coordinator,
            byte[] holder,
            byte[] peerHolder,
            byte[] ownMailbox,
            byte[] peerMailbox,
            dynamic current,
            dynamic next,
            object[] replicas,
            SodiumMailboxCapabilityCrypto crypto,
            byte[] issuerSeed,
            byte serial)
        {
            object Grants(MailboxCapabilityDomain domain, byte firstSerial) => new[]
            {
                Grant(current, domain, firstSerial, network, issuer, holder, crypto, issuerSeed),
                Grant(next, domain, checked((byte)(firstSerial + 1)), network, issuer, holder, crypto, issuerSeed)
            };
            return Json(new
            {
                schemaVersion = 1,
                developmentOnly = true,
                authorityHashSha256 = Hex(authorityHash),
                identity,
                networkId = Hex(network),
                issuerPublicKey = Hex(issuer),
                coordinatorLanUrl = coordinator.ToString().TrimEnd('/'),
                holderPublicKey = Hex(holder),
                currentEpoch = current,
                nextEpoch = next,
                replicas,
                ownMailbox = new
                {
                    blindedMailboxId = Hex(ownMailbox),
                    retrieveAndAcknowledgeGrants = Grants(MailboxCapabilityDomain.Retrieve, serial),
                    depositGrants = Grants(MailboxCapabilityDomain.Deposit, checked((byte)(serial + 2)))
                },
                peerMailboxRoute = new
                {
                    holderPublicKey = Hex(peerHolder),
                    blindedMailboxId = Hex(peerMailbox),
                    depositGrants = Grants(MailboxCapabilityDomain.Deposit, checked((byte)(serial + 4)))
                },
                hashes = new { mailboxRouteSha256 = Hex(SHA256.HashData(ownMailbox)) }
            });
        }

        private static object Grant(
            dynamic epoch,
            MailboxCapabilityDomain domain,
            byte serial,
            byte[] network,
            byte[] issuer,
            byte[] holder,
            SodiumMailboxCapabilityCrypto crypto,
            byte[] issuerSeed)
        {
            var unsigned = new MailboxAuthenticatedGrant
            {
                Domain = domain,
                Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = network,
                Epoch = (ulong)epoch.epoch,
                Generation = (ulong)epoch.epoch,
                Serial = Bytes(16, serial),
                NotBeforeUnixSeconds = (ulong)epoch.notBeforeUnixSeconds,
                ExpiresAtUnixSeconds = (ulong)epoch.expiresAtUnixSeconds,
                OverlapUntilUnixSeconds = 0,
                PlacementCommitment = Convert.FromHexString((string)epoch.placementCommitment),
                MembershipCommitment = Convert.FromHexString((string)epoch.membershipCommitment),
                IssuerPublicKey = issuer,
                HolderPublicKey = holder,
                IssuerSignature = new byte[64]
            };
            var encoded = MailboxAuthenticatedCapabilityCodec.EncodeGrant(
                crypto.SignGrant(unsigned, issuerSeed));
            return new
            {
                epoch = (ulong)epoch.epoch,
                canonicalGrant = Convert.ToBase64String(encoded),
                sha256 = Hex(SHA256.HashData(encoded))
            };
        }

        private static byte[] Json<T>(T value, bool indented = false) =>
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(
                value, new JsonSerializerOptions { WriteIndented = indented }) + "\n");

        private static string Hex(ReadOnlySpan<byte> value) =>
            Convert.ToHexStringLower(value);
    }

    private sealed class FrozenTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
