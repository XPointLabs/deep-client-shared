using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed partial class MailboxCredentialBundleImporterTests
{
    [Fact]
    public void Revocation_source_expires_fail_closed_and_replaces_monotonically()
    {
        var clock = new MutableTimeProvider(DateTimeOffset.FromUnixTimeSeconds(100));
        var source = new DurableMailboxRevocationSnapshot(
            new ParsedMailboxRevocationSnapshot(
                90, 110, new HashSet<string>(StringComparer.Ordinal)),
            clock);
        source.ValidateFreshness();
        clock.Set(DateTimeOffset.FromUnixTimeSeconds(111));
        Assert.Throws<InvalidOperationException>(source.ValidateFreshness);

        source.ReplaceMonotonic(new ParsedMailboxRevocationSnapshot(
            111, 130, new HashSet<string>(StringComparer.Ordinal)));
        source.ValidateFreshness();
        Assert.Throws<InvalidDataException>(() => source.ReplaceMonotonic(
            new ParsedMailboxRevocationSnapshot(
                109, 140, new HashSet<string>(StringComparer.Ordinal))));
    }

    [Fact]
    public void Decode_policy_reads_current_time_for_every_verification_snapshot()
    {
        var clock = new MutableTimeProvider(DateTimeOffset.FromUnixTimeSeconds(100));
        var provider = new TimeProviderMailboxClientDecodePolicyProvider(
            new MailboxEpochWindow
            {
                CurrentEpoch = 7,
                NextEpoch = 8,
                CurrentNotBeforeUnixSeconds = 90,
                NextNotBeforeUnixSeconds = 105,
                CurrentExpiresAtUnixSeconds = 110,
                NextExpiresAtUnixSeconds = 130
            },
            new MailboxCapabilityDecodePolicy
            {
                CurrentBucket = 7,
                MinimumGeneration = 7
            },
            clock);

        Assert.Equal(100UL, provider.GetCurrent().NowUnixSeconds);
        clock.Set(DateTimeOffset.FromUnixTimeSeconds(112));
        Assert.Equal(112UL, provider.GetCurrent().NowUnixSeconds);
    }
    private const string AlicePhrase =
        "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed faxed";
    private const string BobPhrase =
        "update vague zinger boxes ornament renting glass gained island nabbing afield calamity nabbing";
    private const string CharliePhrase =
        "sickness rhino tilt yeti innocent network dogs boat feast ionic subtly zodiac ionic";
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
    public async Task Commit_fault_publishes_neither_credentials_receipts_nor_live_policy()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        var failBeforeCommit = true;
        using var store = new SqliteSessionStore(
            new SqliteSessionStoreOptions(fixture.DatabasePath),
            point =>
            {
                if (failBeforeCommit && point == ClientMailboxCommitFaultPoint.BeforeCommit)
                    throw new InjectedCommitFaultException();
            });

        await Assert.ThrowsAsync<InjectedCommitFaultException>(() =>
            MailboxCredentialBundleImporter.ImportAsync(
                store, identity, fixture.AndroidOptions,
                MailboxInfrastructureOwnership.UserManaged));
        Assert.Null(await store.GetAsync<JsonElement?>(
            "deep.mailbox.bundle-import.v1:android:" + identity.SessionId.Value + ":" +
            fixture.BobSessionId.Value));
        Assert.Equal(0, CountRows(fixture.DatabasePath, "mailbox_credential_scopes"));

        failBeforeCommit = false;
        var imported = await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, fixture.AndroidOptions,
            MailboxInfrastructureOwnership.UserManaged);
        Assert.Equal(2, CountRows(fixture.DatabasePath, "mailbox_credential_scopes"));
        imported.Authority.Validate();
    }

    [Fact]
    public async Task Existing_authority_reloads_external_committed_revocation_checkpoint()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        using var store = new SqliteSessionStore(fixture.DatabasePath);
        var imported = await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, fixture.AndroidOptions,
            MailboxInfrastructureOwnership.UserManaged);
        imported.Authority.Validate();

        using (var connection = new SqliteConnection(
            $"Data Source={fixture.DatabasePath};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                UPDATE settings
                SET payload_json=$payload
                WHERE key LIKE 'deep.mailbox.revocation-import.v1:%';
                """;
            command.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(
                new MailboxRevocationRuntimeCheckpoint(
                    1,
                    checked((ulong)Now.AddMinutes(-10).ToUnixTimeSeconds()),
                    checked((ulong)Now.AddMinutes(-1).ToUnixTimeSeconds()),
                    new string('a', 64),
                    [])));
            Assert.Equal(1, command.ExecuteNonQuery());
        }

        Assert.Throws<InvalidOperationException>(imported.Authority.Validate);
    }

    private static int CountRows(string path, string table)
    {
        using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT count(*) FROM {table};";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private static MailboxRevocationRuntimeCheckpoint ReadImportedRevocation(
        string path)
    {
        using var connection = new SqliteConnection(
            $"Data Source={path};Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT payload_json FROM settings
            WHERE key LIKE 'deep.mailbox.revocation-import.v1:%';
            """;
        return JsonSerializer.Deserialize<MailboxRevocationRuntimeCheckpoint>(
            Assert.IsType<string>(command.ExecuteScalar()),
            new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
    }

    private sealed class InjectedCommitFaultException : Exception;

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

    [Fact]
    public async Task Importer_AppliesNewerSameEpochRevocations_ThenRealPairRotation()
    {
        using var initial = Fixture.Create(revocationVersion: 0);
        using var newerRevocations = Fixture.Create(
            databasePath: initial.DatabasePath,
            revocationVersion: 1);
        using var rotated = Fixture.Create(
            currentEpoch: 8,
            databasePath: initial.DatabasePath,
            revocationVersion: 2);
        using var identity = new SessionIdentityProvider(AlicePhrase);
        using var store = new SqliteSessionStore(initial.DatabasePath);

        var first = await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, initial.AndroidOptions,
            MailboxInfrastructureOwnership.UserManaged);
        var sameEpoch = await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, newerRevocations.AndroidOptions,
            MailboxInfrastructureOwnership.UserManaged);
        first.Authority.Validate();
        Assert.Equal(
            checked((ulong)Now.AddMinutes(-1).ToUnixTimeSeconds()),
            ReadImportedRevocation(initial.DatabasePath).GeneratedAtUnixSeconds);
        Assert.Equal(7UL, (await store.ReadScopedMailboxRouteAsync(
            sameEpoch.SelfSelector, sameEpoch.Authority)).Epoch);

        var next = await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, rotated.AndroidOptions with
            {
                TimeProvider = new FrozenTimeProvider(Now.AddMinutes(20))
            },
            MailboxInfrastructureOwnership.UserManaged);
        first.Authority.Validate();
        sameEpoch.Authority.Validate();
        Assert.Equal(8UL, (await store.ReadScopedMailboxRouteAsync(
            next.SelfSelector, next.Authority)).Epoch);
        Assert.Equal(4, CountRows(
            initial.DatabasePath, "mailbox_credential_epochs"));
        Assert.Equal(
            checked((ulong)Now.ToUnixTimeSeconds()),
            ReadImportedRevocation(initial.DatabasePath).GeneratedAtUnixSeconds);
        Assert.Equal(
            rotated.AndroidOptions.ExpectedPairGeneration.ToArray(),
            Convert.FromHexString((await store.GetAsync<
                MailboxBundleRuntimeCheckpoint>(
                    "deep.mailbox.bundle-import.v1:android:" +
                    identity.SessionId.Value + ":" + rotated.BobSessionId.Value))!
                .PairGeneration));
    }

    [Fact]
    public async Task SameEpochNewPeerUsesDistinctScopeAndKeepsExistingPeerRoute()
    {
        using var initial = Fixture.Create();
        using var replacement = Fixture.Create(
            databasePath: initial.DatabasePath,
            peerPhrase: CharliePhrase);
        using var identity = new SessionIdentityProvider(AlicePhrase);
        using var store = new SqliteSessionStore(initial.DatabasePath);

        var first = await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, initial.AndroidOptions,
            MailboxInfrastructureOwnership.UserManaged);
        var second = await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, replacement.AndroidOptions,
            MailboxInfrastructureOwnership.UserManaged);

        Assert.NotEqual(first.PeerSessionId, second.PeerSessionId);
        Assert.NotNull(await store.ReadScopedMailboxRouteAsync(
            first.PeerSelector, second.Authority));
        Assert.NotNull(await store.ReadScopedMailboxRouteAsync(
            second.PeerSelector, second.Authority));
        Assert.NotNull(await store.GetAsync<MailboxBundleRuntimeCheckpoint>(
            "deep.mailbox.bundle-import.v1:android:" + identity.SessionId.Value + ":" +
            first.PeerSessionId.Value));
        Assert.NotNull(await store.GetAsync<MailboxBundleRuntimeCheckpoint>(
            "deep.mailbox.bundle-import.v1:android:" + identity.SessionId.Value + ":" +
            second.PeerSessionId.Value));
    }

    private static byte[] Bytes(int count, byte value) =>
        Enumerable.Repeat(value, count).ToArray();

    [Fact]
    public async Task Import_allows_platform_indirection_above_the_protected_root()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        var aliasContainer = Path.Combine(
            Path.GetTempPath(), $"deep-mailbox-platform-alias-{Guid.NewGuid():N}");
        Directory.CreateDirectory(aliasContainer);
        var originalRoot = fixture.AndroidOptions.AuthorityProtectedRoot;
        var originalParent = Directory.GetParent(originalRoot)!.FullName;
        var platformAlias = Path.Combine(aliasContainer, "platform-root");
        Directory.CreateSymbolicLink(platformAlias, originalParent);
        try
        {
            var aliasedRoot = Path.Combine(
                platformAlias, Path.GetFileName(originalRoot));
            var options = fixture.AndroidOptions with
            {
                PairRoot = Path.Combine(aliasedRoot, "pair"),
                AuthorityProtectedRoot = aliasedRoot,
                AuthorityPublicPath = Path.Combine(
                    aliasedRoot, Path.GetFileName(fixture.AndroidOptions.AuthorityPublicPath)),
                RevocationProtectedRoot = aliasedRoot,
                RevocationSnapshotPath = Path.Combine(
                    aliasedRoot, Path.GetFileName(fixture.AndroidOptions.RevocationSnapshotPath))
            };
            using var store = new SqliteSessionStore(Path.Combine(aliasContainer, "state.db"));

            var imported = await MailboxCredentialBundleImporter.ImportAsync(
                store, identity, options, MailboxInfrastructureOwnership.UserManaged);

            Assert.Equal(identity.SessionId, imported.LocalSessionId);
            Assert.Equal(fixture.BobSessionId, imported.PeerSessionId);
        }
        finally
        {
            Directory.Delete(platformAlias);
            Directory.Delete(aliasContainer, recursive: true);
        }
    }

    [Fact]
    public async Task Import_rejects_reparse_points_inside_the_protected_root()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        var root = fixture.AndroidOptions.AuthorityProtectedRoot;
        var pairAlias = Path.Combine(root, "pair-link");
        Directory.CreateSymbolicLink(pairAlias, fixture.AndroidOptions.PairRoot);
        using var pairStore = new SqliteSessionStore(Path.Combine(root, "pair-link-state.db"));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            MailboxCredentialBundleImporter.ImportAsync(
                pairStore, identity,
                fixture.AndroidOptions with { PairRoot = pairAlias },
                MailboxInfrastructureOwnership.UserManaged));

        var authorityAlias = Path.Combine(root, "authority-link.json");
        File.CreateSymbolicLink(
            authorityAlias, fixture.AndroidOptions.AuthorityPublicPath);
        using var authorityStore = new SqliteSessionStore(
            Path.Combine(root, "authority-link-state.db"));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            MailboxCredentialBundleImporter.ImportAsync(
                authorityStore, identity,
                fixture.AndroidOptions with { AuthorityPublicPath = authorityAlias },
                MailboxInfrastructureOwnership.UserManaged));
    }

    [Fact]
    public async Task Import_accepts_trailing_separators_but_rejects_filesystem_root()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        var separator = Path.DirectorySeparatorChar.ToString();
        var options = fixture.AndroidOptions with
        {
            PairRoot = fixture.AndroidOptions.PairRoot + separator,
            AuthorityProtectedRoot =
                fixture.AndroidOptions.AuthorityProtectedRoot + separator,
            RevocationProtectedRoot =
                fixture.AndroidOptions.RevocationProtectedRoot + separator
        };
        using var store = new SqliteSessionStore(Path.Combine(
            fixture.AndroidOptions.AuthorityProtectedRoot, "trailing-state.db"));
        var imported = await MailboxCredentialBundleImporter.ImportAsync(
            store, identity, options, MailboxInfrastructureOwnership.UserManaged);
        Assert.Equal(identity.SessionId, imported.LocalSessionId);
        Assert.Equal(fixture.BobSessionId, imported.PeerSessionId);

        var filesystemRoot = Path.GetPathRoot(
            fixture.AndroidOptions.AuthorityProtectedRoot)!;
        using var rejectedStore = new SqliteSessionStore(Path.Combine(
            fixture.AndroidOptions.AuthorityProtectedRoot, "root-state.db"));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            MailboxCredentialBundleImporter.ImportAsync(
                rejectedStore, identity,
                fixture.AndroidOptions with { AuthorityProtectedRoot = filesystemRoot },
                MailboxInfrastructureOwnership.UserManaged));
    }

    [Fact]
    public async Task Import_rejects_missing_or_escaped_protected_roots()
    {
        using var fixture = Fixture.Create();
        using var identity = new SessionIdentityProvider(AlicePhrase);
        var root = fixture.AndroidOptions.AuthorityProtectedRoot;
        using var missingStore = new SqliteSessionStore(Path.Combine(root, "missing-state.db"));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            MailboxCredentialBundleImporter.ImportAsync(
                missingStore, identity,
                fixture.AndroidOptions with
                {
                    AuthorityProtectedRoot = Path.Combine(root, "missing")
                },
                MailboxInfrastructureOwnership.UserManaged));

        var escapedRoot = Path.Combine(
            Path.GetTempPath(), $"deep-mailbox-escape-{Guid.NewGuid():N}");
        Directory.CreateDirectory(escapedRoot);
        try
        {
            using var escapedStore = new SqliteSessionStore(Path.Combine(
                root, "escaped-state.db"));
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                MailboxCredentialBundleImporter.ImportAsync(
                    escapedStore, identity,
                    fixture.AndroidOptions with { PairRoot = escapedRoot },
                    MailboxInfrastructureOwnership.UserManaged));
        }
        finally
        {
            Directory.Delete(escapedRoot);
        }
    }

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

        public static Fixture Create(
            ulong currentEpoch = 7,
            string? databasePath = null,
            int revocationVersion = 0,
            string peerPhrase = BobPhrase,
            int revocationLifetimeMinutes = 20)
        {
            if (currentEpoch is < 7 or > 100 ||
                revocationVersion is < 0 or > 2 ||
                revocationLifetimeMinutes is < 20 or > 120)
                throw new ArgumentOutOfRangeException();
            var epochOffset = checked((int)(currentEpoch - 7));
            var root = Path.Combine(Path.GetTempPath(), $"deep-mailbox-import-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            var pairRoot = Path.Combine(root, "pair");
            Directory.CreateDirectory(pairRoot);
            using var alice = new SessionIdentityProvider(AlicePhrase);
            using var bob = new SessionIdentityProvider(peerPhrase);
            var aliceHolder = alice.GetEd25519PublicKey();
            var bobHolder = bob.GetEd25519PublicKey();
            var crypto = new SodiumMailboxCapabilityCrypto();
            var issuerSeed = Bytes(32, 0x41);
            var issuer = crypto.GetPublicKey(issuerSeed);
            var network = Bytes(16, 0x42);
            var replicaCrypto = new SodiumMailboxPeerReplicationCrypto();
            var replicas = new[]
            {
                new
                {
                    id = Hex(Bytes(32, 0x51)),
                    signingPublicKey = Hex(replicaCrypto.GetPublicKey(Bytes(32, 0x61)))
                },
                new
                {
                    id = Hex(Bytes(32, 0x52)),
                    signingPublicKey = Hex(replicaCrypto.GetPublicKey(Bytes(32, 0x62)))
                }
            };
            var current = Epoch(
                currentEpoch,
                Now.AddMinutes(-5 + 25 * epochOffset),
                Now.AddMinutes(30 + 30 * epochOffset),
                checked((byte)(0x71 + epochOffset)));
            var next = Epoch(
                checked(currentEpoch + 1),
                Now.AddMinutes(-5 + 25 * (epochOffset + 1)),
                Now.AddMinutes(30 + 30 * (epochOffset + 1)),
                checked((byte)(0x71 + epochOffset + 1)));
            var coordinator = new Uri("http://192.168.1.44:41801");
            var authorityObject = new
            {
                schemaVersion = 2,
                scope = "DEV-LOCAL-ONLY",
                protocol = "P10E/MCP2/MAU2/MIP1/RIP1/PRQ2",
                networkId = Hex(network),
                issuerPublicKey = Hex(issuer),
                minimumGeneration = currentEpoch,
                maximumGeneration = checked(currentEpoch + 1),
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
            var peerVariant = string.Equals(peerPhrase, BobPhrase, StringComparison.Ordinal)
                ? (byte)0
                : (byte)1;
            var bobMailbox = Bytes(32, checked((byte)(0x82 + peerVariant)));
            var androidBytes = Bundle(
                "android", authorityHash, network, issuer, coordinator,
                aliceHolder, bobHolder, aliceMailbox, bobMailbox,
                current, next, replicas, crypto, issuerSeed,
                checked((byte)(0x11 + epochOffset)),
                checked((byte)(0x31 + epochOffset + 4 * peerVariant)));
            var windowsBytes = Bundle(
                "windows", authorityHash, network, issuer, coordinator,
                bobHolder, aliceHolder, bobMailbox, aliceMailbox,
                current, next, replicas, crypto, issuerSeed,
                checked((byte)(0x71 + epochOffset + peerVariant)));
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
                generatedAtUnixSeconds = checked((ulong)Now.AddMinutes(
                    -2 + revocationVersion).ToUnixTimeSeconds()),
                expiresAtUnixSeconds = checked((ulong)Now.AddMinutes(
                    revocationLifetimeMinutes + revocationVersion).ToUnixTimeSeconds()),
                revoked = Array.Empty<object>()
            });
            File.WriteAllBytes(revocationPath, revocationBytes);
            using var mrX = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x91));
            var trustedMrXPublicKeySha256 = SHA256.HashData(mrX.PublicKey);
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
                    mrX.PublicKey);
            }
            var options = new MailboxCredentialBundleImportOptions(
                pairRoot,
                root,
                authorityPath,
                MailboxClientPlatform.Android,
                authorityHash,
                issuer,
                generation,
                manifestHash,
                bobHolder,
                bob.SessionId,
                root,
                revocationPath,
                SHA256.HashData(revocationBytes),
                trustedMrXPublicKeySha256,
                Approval("user-managed"),
                DevelopmentOnly: true,
                ManagedEntitlement: null,
                new FrozenTimeProvider(Now));
            var officialOptions = options with
            {
                MrXApproval = Approval("official-managed")
            };
            CryptographicOperations.ZeroMemory(issuerSeed);
            ProtectFixtureTree(root);
            return new Fixture(
                root, databasePath ?? Path.Combine(root, "state.db"),
                options, officialOptions,
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
            byte serial,
            byte? peerSerial = null)
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
                    depositGrants = Grants(MailboxCapabilityDomain.Deposit,
                        checked((byte)(serial + 0x10)))
                },
                peerMailboxRoute = new
                {
                    holderPublicKey = Hex(peerHolder),
                    blindedMailboxId = Hex(peerMailbox),
                    depositGrants = Grants(MailboxCapabilityDomain.Deposit,
                        peerSerial ?? checked((byte)(serial + 0x20)))
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

        private static void ProtectFixtureTree(string root)
        {
            if (OperatingSystem.IsWindows())
            {
                foreach (var file in Directory.EnumerateFiles(
                    root, "*", SearchOption.AllDirectories))
                    SetExclusiveWindowsAcl(file, isDirectory: false);
                foreach (var directory in Directory.EnumerateDirectories(
                    root, "*", SearchOption.AllDirectories).Prepend(root))
                    SetExclusiveWindowsAcl(directory, isDirectory: true);
                return;
            }

            foreach (var file in Directory.EnumerateFiles(
                root, "*", SearchOption.AllDirectories))
                File.SetUnixFileMode(
                    file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            foreach (var directory in Directory.EnumerateDirectories(
                root, "*", SearchOption.AllDirectories).Prepend(root))
                File.SetUnixFileMode(
                    directory,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.UserExecute);
        }

        [SupportedOSPlatform("windows")]
        private static void SetExclusiveWindowsAcl(string path, bool isDirectory)
        {
            var current = WindowsIdentity.GetCurrent().User
                ?? throw new InvalidDataException("Test identity has no SID.");
            var system = new SecurityIdentifier(
                WellKnownSidType.LocalSystemSid, null);
            var administrators = new SecurityIdentifier(
                WellKnownSidType.BuiltinAdministratorsSid, null);
            FileSystemSecurity security = isDirectory
                ? new DirectorySecurity()
                : new FileSecurity();
            security.SetOwner(current);
            security.SetAccessRuleProtection(isProtected: true,
                preserveInheritance: false);
            foreach (var sid in new[] { current, system, administrators })
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    sid,
                    FileSystemRights.FullControl,
                    isDirectory
                        ? InheritanceFlags.ContainerInherit |
                          InheritanceFlags.ObjectInherit
                        : InheritanceFlags.None,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }
            if (isDirectory)
                new DirectoryInfo(path).SetAccessControl(
                    (DirectorySecurity)security);
            else
                new FileInfo(path).SetAccessControl((FileSecurity)security);
        }
    }

    private sealed class FrozenTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
        public void Set(DateTimeOffset value) => now = value;
    }
}
