using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Client.Shared.Services;

public enum MailboxClientPlatform
{
    Android = 1,
    Windows = 2
}

public sealed record MrXSignedMailboxPolicyApproval(
    ReadOnlyMemory<byte> CanonicalPayload,
    ReadOnlyMemory<byte> Signature,
    ReadOnlyMemory<byte> PublicKey);

public sealed record MailboxHolderIdentity(
    SessionId SessionId,
    ReadOnlyMemory<byte> Ed25519PublicKey);

public sealed record MailboxCredentialBundleImportOptions(
    string PairRoot,
    string AuthorityProtectedRoot,
    string AuthorityPublicPath,
    MailboxClientPlatform Platform,
    ReadOnlyMemory<byte> ExpectedAuthoritySha256,
    ReadOnlyMemory<byte> ExpectedIssuerPublicKey,
    ReadOnlyMemory<byte> ExpectedPairGeneration,
    ReadOnlyMemory<byte> ExpectedPairManifestSha256,
    ReadOnlyMemory<byte> ExpectedPeerHolderPublicKey,
    SessionId ExpectedPeerSessionId,
    string RevocationProtectedRoot,
    string RevocationSnapshotPath,
    ReadOnlyMemory<byte> ExpectedRevocationSnapshotSha256,
    ReadOnlyMemory<byte> ExpectedPrivacyRoutesSha256,
    ReadOnlyMemory<byte> TrustedMrXPublicKeySha256,
    MrXSignedMailboxPolicyApproval MrXApproval,
    bool DevelopmentOnly,
    Func<bool>? ManagedEntitlement,
    TimeProvider TimeProvider);

public sealed class ImportedMailboxRuntimeMaterial
{
    internal ImportedMailboxRuntimeMaterial(
        VerifiedOfficialMailboxAuthority authority,
        ClientMailboxActivation activation,
        IMailboxClientDecodePolicyProvider decodePolicies,
        Uri coordinator,
        MailboxCredentialSelector selfSelector,
        MailboxCredentialSelector peerSelector,
        SessionId localSessionId,
        SessionId peerSessionId,
        MailboxInfrastructureOwnership ownership)
    {
        Authority = authority;
        Activation = activation;
        DecodePolicies = decodePolicies;
        Coordinator = coordinator;
        SelfSelector = selfSelector;
        PeerSelector = peerSelector;
        LocalSessionId = localSessionId;
        PeerSessionId = peerSessionId;
        Ownership = ownership;
    }

    public VerifiedOfficialMailboxAuthority Authority { get; }
    public ClientMailboxActivation Activation { get; }
    public IMailboxClientDecodePolicyProvider DecodePolicies { get; }
    public Uri Coordinator { get; }
    public MailboxCredentialSelector SelfSelector { get; }
    public MailboxCredentialSelector PeerSelector { get; }
    public SessionId LocalSessionId { get; }
    public SessionId PeerSessionId { get; }
    public MailboxInfrastructureOwnership Ownership { get; }
}

/// <summary>
/// Clean-break schema-v1 importer for the atomic DEV-local Android/Windows mailbox pair.
/// It reads the generation pointer exactly once and never searches for another generation.
/// </summary>
public static class MailboxCredentialBundleImporter
{
    private const int MaximumJsonBytes = 4 * 1024 * 1024;
    private static readonly string[] PointerProperties =
        ["schemaVersion", "developmentOnly", "generation", "pairManifestSha256"];
    private static readonly string[] ManifestProperties =
        ["schemaVersion", "developmentOnly", "generation", "authoritySha256",
         "issuerPublicKey", "androidHolderPublicKey", "windowsHolderPublicKey", "files"];
    private static readonly string[] BundleProperties =
        ["schemaVersion", "developmentOnly", "authorityHashSha256", "identity", "networkId",
         "issuerPublicKey", "coordinatorLanUrl", "holderPublicKey", "currentEpoch", "nextEpoch",
         "replicas", "ownMailbox", "peerMailboxRoute", "hashes"];
    private static readonly string[] PublicAuthorityProperties =
        ["schemaVersion", "scope", "protocol", "networkId", "issuerPublicKey",
         "minimumGeneration", "maximumGeneration", "issuerValidFromUnixSeconds",
         "issuerValidUntilUnixSeconds", "coordinatorUrl", "replicaIds",
         "replicaSigningPublicKeys", "epochs", "selections"];
    private static readonly string[] ApprovalProperties =
        ["schemaVersion", "developmentOnly", "lane", "platform", "ownership",
         "authoritySha256", "issuerPublicKey", "androidHolderPublicKey",
         "windowsHolderPublicKey", "androidSessionId", "windowsSessionId",
         "pairGeneration", "pairManifestSha256", "revocationSnapshotSha256",
         "privacyRoutesSha256"];
    private static readonly ConditionalWeakTable<SqliteSessionStore, SemaphoreSlim>
        ImportGates = new();

    public static async Task<ImportedMailboxRuntimeMaterial> ImportAsync(
        SqliteSessionStore store,
        SessionIdentityProvider identity,
        MailboxCredentialBundleImportOptions options,
        MailboxInfrastructureOwnership ownership,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var holder = identity.GetEd25519PublicKey();
        try
        {
            return await ImportAsync(
                store,
                new MailboxHolderIdentity(identity.SessionId, holder),
                options,
                ownership,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(holder);
        }
    }

    public static async Task<ImportedMailboxRuntimeMaterial> ImportAsync(
        SqliteSessionStore store,
        MailboxHolderIdentity identity,
        MailboxCredentialBundleImportOptions options,
        MailboxInfrastructureOwnership ownership,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(options);
        if (!Enum.IsDefined(options.Platform))
            throw new ArgumentOutOfRangeException(nameof(options), "Mailbox client platform is undefined.");
        if (!options.DevelopmentOnly ||
            ownership is not (MailboxInfrastructureOwnership.UserManaged or
                MailboxInfrastructureOwnership.OfficialManaged))
            throw new InvalidOperationException("Schema-v1 mailbox bundles are DEV-local only.");
        var expectedAuthority = ExactBytes(options.ExpectedAuthoritySha256.Span, 32, "authority pin");
        var expectedIssuer = ExactBytes(options.ExpectedIssuerPublicKey.Span, 32, "issuer pin");
        var expectedRevocation = ExactBytes(
            options.ExpectedRevocationSnapshotSha256.Span, 32, "revocation snapshot pin");
        var expectedPrivacyRoutes = ExactBytes(
            options.ExpectedPrivacyRoutesSha256.Span, 32, "privacy routes pin");
        var trustedMrX = ExactBytes(
            options.TrustedMrXPublicKeySha256.Span, 32, "trusted Mr. X public-key pin");
        var expectedGeneration = ExactBytes(options.ExpectedPairGeneration.Span, 32, "pair generation pin");
        var expectedManifest = ExactBytes(options.ExpectedPairManifestSha256.Span, 32, "pair manifest pin");
        var expectedPeerHolder = ExactBytes(options.ExpectedPeerHolderPublicKey.Span, 32, "peer holder pin");
        var timeProvider = options.TimeProvider ?? throw new ArgumentNullException(nameof(options.TimeProvider));
        var holder = ExactBytes(identity.Ed25519PublicKey.Span, 32, "holder public key");
        ParsedMrXApproval? approval = null;
        SemaphoreSlim? importGate = null;
        IMailboxRuntimePolicyLease? publicationLease = null;
        var gateHeld = false;
        try
        {
            approval = ValidateMrXApproval(
                options, ownership, holder, identity.SessionId, trustedMrX,
                expectedPrivacyRoutes);
            importGate = ImportGates.GetValue(store, static _ => new SemaphoreSlim(1, 1));
            await importGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            gateHeld = true;
            var authorityRoot = RequireSafeRoot(options.AuthorityProtectedRoot);
            var root = RequireSafeRoot(authorityRoot, options.PairRoot);
            var revocationRoot = RequireSafeRoot(
                authorityRoot, options.RevocationProtectedRoot);
            var authorityPath = RequireSafeFile(
                authorityRoot, options.AuthorityPublicPath);
            var authorityBytes = ReadStableBounded(authorityRoot, authorityPath);
            Require(Fixed(SHA256.HashData(authorityBytes), expectedAuthority),
                "Public authority file differs from its independent pin.");
            using var publicAuthorityDocument = Parse(authorityBytes, "public authority");
            var publicAuthority = ParsePublicAuthority(
                publicAuthorityDocument.RootElement, expectedIssuer);
            var pointerBytes = ReadStableBounded(
                root, SafeChild(root, "current-generation.json"));
            using var pointerDocument = Parse(pointerBytes, "generation pointer");
            var pointer = pointerDocument.RootElement;
            RequireExactProperties(pointer, PointerProperties, "generation pointer");
            Require(pointer.GetProperty("schemaVersion").GetInt32() == 1 &&
                    pointer.GetProperty("developmentOnly").GetBoolean(),
                "Generation pointer is not DEV-local schema v1.");
            var generation = LowerHex(pointer.GetProperty("generation"), 32, "generation");
            var manifestHash = LowerHex(
                pointer.GetProperty("pairManifestSha256"), 32, "manifest hash");
            Require(Fixed(generation, expectedGeneration) && Fixed(manifestHash, expectedManifest),
                "Generation pointer differs from the independently signed pair pins.");
            var generationDirectory = SafeChild(
                root, "generations", Convert.ToHexStringLower(generation));
            RequireSafeDirectory(root, generationDirectory);

            var manifestBytes = ReadStableBounded(
                root, SafeChild(generationDirectory, "pair-manifest.v1.json"));
            Require(Fixed(SHA256.HashData(manifestBytes), manifestHash),
                "Pair manifest hash differs from the single resolved pointer.");
            using var manifestDocument = Parse(manifestBytes, "pair manifest");
            var manifest = manifestDocument.RootElement;
            RequireExactProperties(manifest, ManifestProperties, "pair manifest");
            Require(manifest.GetProperty("schemaVersion").GetInt32() == 1 &&
                    manifest.GetProperty("developmentOnly").GetBoolean() &&
                    Fixed(LowerHex(manifest.GetProperty("generation"), 32, "manifest generation"), generation) &&
                    Fixed(LowerHex(manifest.GetProperty("authoritySha256"), 32, "manifest authority"), expectedAuthority) &&
                    Fixed(LowerHex(manifest.GetProperty("issuerPublicKey"), 32, "manifest issuer"), expectedIssuer),
                "Pair manifest does not match independently pinned authority.");
            var files = manifest.GetProperty("files");
            RequireExactProperties(files, ["android", "windows"], "pair files");

            var androidBytes = ReadStableBounded(
                root, SafeChild(generationDirectory, "android.mailbox-credentials.v1.json"));
            var windowsBytes = ReadStableBounded(
                root, SafeChild(generationDirectory, "windows.mailbox-credentials.v1.json"));
            var androidHash = SHA256.HashData(androidBytes);
            var windowsHash = SHA256.HashData(windowsBytes);
            Require(Fixed(androidHash, LowerHex(files.GetProperty("android"), 32, "android bundle hash")) &&
                    Fixed(windowsHash, LowerHex(files.GetProperty("windows"), 32, "windows bundle hash")) &&
                    Fixed(generation, PairGeneration(expectedAuthority, androidHash, windowsHash)),
                "Credential bundles do not match the atomic pair manifest.");

            using var androidDocument = Parse(androidBytes, "android bundle");
            using var windowsDocument = Parse(windowsBytes, "windows bundle");
            var android = ParseBundle(androidDocument.RootElement, "android", expectedAuthority, expectedIssuer);
            var windows = ParseBundle(windowsDocument.RootElement, "windows", expectedAuthority, expectedIssuer);
            ValidatePair(manifest, android, windows);
            ValidatePublicAuthority(publicAuthority, android);
            ValidatePublicAuthority(publicAuthority, windows);
            var selected = options.Platform == MailboxClientPlatform.Android ? android : windows;
            var peer = options.Platform == MailboxClientPlatform.Android ? windows : android;
            Require(Fixed(selected.Holder, holder),
                "Credential bundle holder does not match the current Session identity.");
            Require(Fixed(selected.PeerHolder, expectedPeerHolder),
                "Credential bundle peer holder does not match the independently signed pin.");
            var derivedLocalSession = SessionIdFromEd25519(holder);
            var derivedPeerSession = SessionIdFromEd25519(selected.PeerHolder);
            Require(derivedLocalSession == identity.SessionId &&
                    derivedPeerSession == options.ExpectedPeerSessionId,
                "Mailbox holder keys do not map to the independently pinned Session IDs.");

            var parsedRevocations = LoadRevocations(
                revocationRoot,
                options.RevocationSnapshotPath, expectedRevocation, expectedAuthority,
                expectedIssuer, publicAuthority.MinimumGeneration,
                publicAuthority.MaximumGeneration, timeProvider);
            var issuers = new[]
            {
                Issuer(expectedIssuer, MailboxCapabilityDomain.Deposit, publicAuthority),
                Issuer(expectedIssuer, MailboxCapabilityDomain.Retrieve, publicAuthority)
            };
            if (ownership == MailboxInfrastructureOwnership.OfficialManaged &&
                options.ManagedEntitlement is null)
            {
                throw new InvalidOperationException(
                    "Official-managed MAU2 requires an explicit entitlement source.");
            }
            var account = OutboxAccountScope.FromBytes(DomainHash(
                "deep.mailbox.account-scope.v1", holder));
            var issuerContext = DomainHash(
                "deep.mailbox.stable-authority-id.v1",
                [(byte)ownership], selected.NetworkId, expectedIssuer);
            var coordinator = MailboxRuntimePolicyCoordinator.For(
                store.CanonicalStateIdentity, issuerContext);
            var selfSelector = new MailboxCredentialSelector(
                account, MailboxCredentialScopeKind.Self,
                holder, issuerContext);
            var peerSelector = new MailboxCredentialSelector(
                account, MailboxCredentialScopeKind.Peer,
                selected.PeerHolder, issuerContext);
            var epochs = (Current: ToEpoch(selected.Current), Next: ToEpoch(selected.Next));
            var replicas = new MailboxCredentialReplicaPair(
                selected.Replicas[0].Id, selected.Replicas[0].SigningKey,
                selected.Replicas[1].Id, selected.Replicas[1].SigningKey);
            var ownRetrieve = new MailboxCredentialGrantSet(
                MailboxAuthenticatedCapabilityCodec.EncodeGrant(selected.OwnRetrieve.Current),
                MailboxAuthenticatedCapabilityCodec.EncodeGrant(selected.OwnRetrieve.Next));
            var ownDeposit = new MailboxCredentialGrantSet(
                MailboxAuthenticatedCapabilityCodec.EncodeGrant(selected.OwnDeposit.Current),
                MailboxAuthenticatedCapabilityCodec.EncodeGrant(selected.OwnDeposit.Next));
            var peerDeposit = new MailboxCredentialGrantSet(
                MailboxAuthenticatedCapabilityCodec.EncodeGrant(selected.PeerDeposit.Current),
                MailboxAuthenticatedCapabilityCodec.EncodeGrant(selected.PeerDeposit.Next));
            var imports = new[]
            {
                new ScopedMailboxCredentialGeneration(
                    selfSelector,
                    ScopedGeneration(
                        selfSelector, holder, selected.OwnMailbox,
                        epochs.Current, epochs.Next, ownRetrieve, ownDeposit, replicas),
                    holder,
                    selected.OwnMailbox,
                    epochs.Current,
                    epochs.Next,
                    ownRetrieve,
                    ownDeposit,
                    replicas,
                    replicas),
                new ScopedMailboxCredentialGeneration(
                    peerSelector,
                    ScopedGeneration(
                        peerSelector, holder, selected.PeerMailbox,
                        epochs.Current, epochs.Next, null, peerDeposit, replicas),
                    holder,
                    selected.PeerMailbox,
                    epochs.Current,
                    epochs.Next,
                    Retrieve: null,
                    peerDeposit,
                    replicas,
                    replicas)
            };
            var receiptKey = "deep.mailbox.bundle-import.v1:" +
                options.Platform.ToString().ToLowerInvariant() + ":" +
                identity.SessionId.Value + ":" + derivedPeerSession.Value;
            var receipt = new MailboxBundleRuntimeCheckpoint(
                1,
                "android-windows-pair",
                options.Platform.ToString().ToLowerInvariant(),
                ownership.ToString(),
                selected.Current.Epoch,
                Convert.ToHexStringLower(generation));
            var revocationReceiptKey = "deep.mailbox.revocation-import.v1:" +
                Convert.ToHexStringLower(issuerContext);
            var revocationReceipt = new MailboxRevocationRuntimeCheckpoint(
                1,
                parsedRevocations.GeneratedAtUnixSeconds,
                parsedRevocations.ExpiresAtUnixSeconds,
                Convert.ToHexStringLower(expectedRevocation),
                parsedRevocations.Revoked.OrderBy(static key => key,
                    StringComparer.Ordinal).ToArray());
            var candidateRevocations = new SqliteMailboxRevocationSource(
                store, revocationReceiptKey, revocationReceipt, timeProvider);
            var candidateAuthority = new VerifiedOfficialMailboxAuthority(
                selected.NetworkId,
                publicAuthority.MinimumGeneration,
                issuers,
                requiresManagedEntitlement:
                    ownership == MailboxInfrastructureOwnership.OfficialManaged,
                options.ManagedEntitlement ?? (static () => true),
                candidateRevocations,
                timeProvider,
                coordinator);
            var decodePolicies = new TimeProviderMailboxClientDecodePolicyProvider(
                new MailboxEpochWindow
                {
                    CurrentEpoch = selected.Current.Epoch,
                    NextEpoch = selected.Next.Epoch,
                    CurrentNotBeforeUnixSeconds = selected.Current.NotBefore,
                    NextNotBeforeUnixSeconds = selected.Next.NotBefore,
                    CurrentExpiresAtUnixSeconds = selected.Current.ExpiresAt,
                    NextExpiresAtUnixSeconds = selected.Next.ExpiresAt
                },
                new MailboxCapabilityDecodePolicy
                {
                    CurrentBucket = checked((uint)selected.Current.Epoch),
                    MinimumGeneration = selected.Current.Epoch
                },
                timeProvider);
            // Build every fallible runtime object before the credential transaction commits.
            _ = decodePolicies.GetCurrent();
            var preparedMaterial = new ImportedMailboxRuntimeMaterial(
                candidateAuthority,
                new ClientMailboxActivation(true, issuerContext, ingressConfigured: true),
                decodePolicies,
                selected.Coordinator,
                selfSelector,
                peerSelector,
                derivedLocalSession,
                derivedPeerSession,
                ownership);
            publicationLease = await coordinator.AcquirePublicationAsync(
                cancellationToken).ConfigureAwait(false);
            var committedActivation = new MailboxRuntimeCommitActivation(
                candidateRevocations, publicationLease);
            var checkpoint = new MailboxRuntimeSnapshotCheckpoint(
                receiptKey, receipt, revocationReceiptKey, revocationReceipt);
            if (options.DevelopmentOnly)
            {
                await store.ApplyDevelopmentMailboxRuntimeSnapshotAsync(
                    imports,
                    candidateAuthority,
                    checkpoint,
                    committedActivation,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await store.ApplyScopedMailboxRuntimeSnapshotAsync(
                    imports,
                    candidateAuthority,
                    checkpoint,
                    committedActivation,
                    cancellationToken).ConfigureAwait(false);
            }
            return preparedMaterial;
        }
        finally
        {
            publicationLease?.Dispose();
            if (gateHeld) importGate!.Release();
            CryptographicOperations.ZeroMemory(holder);
            if (approval is not null)
                CryptographicOperations.ZeroMemory(approval.PayloadSha256);
            CryptographicOperations.ZeroMemory(expectedAuthority);
            CryptographicOperations.ZeroMemory(expectedIssuer);
            CryptographicOperations.ZeroMemory(expectedRevocation);
            CryptographicOperations.ZeroMemory(expectedPrivacyRoutes);
            CryptographicOperations.ZeroMemory(trustedMrX);
            CryptographicOperations.ZeroMemory(expectedGeneration);
            CryptographicOperations.ZeroMemory(expectedManifest);
            CryptographicOperations.ZeroMemory(expectedPeerHolder);
        }
    }

    private static ParsedMrXApproval ValidateMrXApproval(
        MailboxCredentialBundleImportOptions options,
        MailboxInfrastructureOwnership ownership,
        byte[] localHolder,
        SessionId localSessionId,
        byte[] trustedMrXPublicKeySha256,
        byte[] expectedPrivacyRoutesSha256)
    {
        var approval = options.MrXApproval ?? throw new ArgumentNullException(
            nameof(options.MrXApproval));
        var payload = approval.CanonicalPayload.ToArray();
        var signature = ExactBytes(approval.Signature.Span, 64, "Mr. X policy signature");
        var publicKey = ExactBytes(approval.PublicKey.Span, 32, "Mr. X policy public key");
        try
        {
            Require(payload.Length is > 0 and <= 16 * 1024 &&
                    Fixed(SHA256.HashData(publicKey), trustedMrXPublicKeySha256) &&
                    PublicKeyAuth.VerifyDetached(signature, payload, publicKey),
                "Mr. X mailbox policy signature or public-key pin is invalid.");
            using var document = Parse(payload, "Mr. X mailbox policy");
            var root = document.RootElement;
            RequireExactProperties(root, ApprovalProperties, "Mr. X mailbox policy");
            var platform = options.Platform.ToString().ToLowerInvariant();
            var ownershipText = ownership switch
            {
                MailboxInfrastructureOwnership.UserManaged => "user-managed",
                MailboxInfrastructureOwnership.OfficialManaged => "official-managed",
                _ => throw new InvalidOperationException(
                    "Mr. X mailbox policy supports only authenticated MAU2 ownership.")
            };
            Require(root.GetProperty("schemaVersion").GetInt32() == 1 &&
                    root.GetProperty("developmentOnly").GetBoolean() &&
                    string.Equals(root.GetProperty("lane").GetString(),
                        "android-windows-pair", StringComparison.Ordinal) &&
                    string.Equals(root.GetProperty("platform").GetString(), platform,
                        StringComparison.Ordinal) &&
                    string.Equals(root.GetProperty("ownership").GetString(), ownershipText,
                        StringComparison.Ordinal) &&
                    Fixed(LowerHex(root.GetProperty("authoritySha256"), 32, "policy authority"),
                        options.ExpectedAuthoritySha256.Span) &&
                    Fixed(LowerHex(root.GetProperty("issuerPublicKey"), 32, "policy issuer"),
                        options.ExpectedIssuerPublicKey.Span) &&
                    Fixed(LowerHex(root.GetProperty("pairGeneration"), 32, "policy generation"),
                        options.ExpectedPairGeneration.Span) &&
                    Fixed(LowerHex(root.GetProperty("pairManifestSha256"), 32, "policy manifest"),
                        options.ExpectedPairManifestSha256.Span) &&
                    Fixed(LowerHex(root.GetProperty("revocationSnapshotSha256"), 32,
                        "policy revocations"), options.ExpectedRevocationSnapshotSha256.Span) &&
                    Fixed(LowerHex(root.GetProperty("privacyRoutesSha256"), 32,
                        "policy privacy routes"), expectedPrivacyRoutesSha256),
                "Mr. X mailbox policy differs from the configured independent pins.");
            var androidHolder = LowerHex(
                root.GetProperty("androidHolderPublicKey"), 32, "policy Android holder");
            var windowsHolder = LowerHex(
                root.GetProperty("windowsHolderPublicKey"), 32, "policy Windows holder");
            var androidSession = SessionId.Parse(
                root.GetProperty("androidSessionId").GetString() ?? "");
            var windowsSession = SessionId.Parse(
                root.GetProperty("windowsSessionId").GetString() ?? "");
            var selectedHolder = options.Platform == MailboxClientPlatform.Android
                ? androidHolder : windowsHolder;
            var peerHolder = options.Platform == MailboxClientPlatform.Android
                ? windowsHolder : androidHolder;
            var selectedSession = options.Platform == MailboxClientPlatform.Android
                ? androidSession : windowsSession;
            var peerSession = options.Platform == MailboxClientPlatform.Android
                ? windowsSession : androidSession;
            Require(Fixed(selectedHolder, localHolder) && selectedSession == localSessionId &&
                    Fixed(peerHolder, options.ExpectedPeerHolderPublicKey.Span) &&
                    peerSession == options.ExpectedPeerSessionId,
                "Mr. X mailbox policy does not bind the exact local/peer holder pair.");
            return new ParsedMrXApproval(SHA256.HashData(payload));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static ParsedBundle ParseBundle(
        JsonElement value,
        string identity,
        byte[] expectedAuthority,
        byte[] expectedIssuer)
    {
        RequireExactProperties(value, BundleProperties, $"{identity} bundle");
        Require(value.GetProperty("schemaVersion").GetInt32() == 1 &&
                value.GetProperty("developmentOnly").GetBoolean() &&
                string.Equals(value.GetProperty("identity").GetString(), identity, StringComparison.Ordinal) &&
                Fixed(LowerHex(value.GetProperty("authorityHashSha256"), 32, "bundle authority"), expectedAuthority) &&
                Fixed(LowerHex(value.GetProperty("issuerPublicKey"), 32, "bundle issuer"), expectedIssuer),
            $"{identity} bundle identity or authority binding is invalid.");
        var coordinatorText = value.GetProperty("coordinatorLanUrl").GetString();
        Require(Uri.TryCreate(coordinatorText, UriKind.Absolute, out var coordinator) &&
                coordinator is not null && string.IsNullOrEmpty(coordinator.UserInfo) &&
                string.IsNullOrEmpty(coordinator.Query) && string.IsNullOrEmpty(coordinator.Fragment),
            "Mailbox coordinator origin is invalid.");
        var replicasElement = value.GetProperty("replicas");
        Require(replicasElement.ValueKind == JsonValueKind.Array && replicasElement.GetArrayLength() == 2,
            "Mailbox bundle must contain exactly two replicas.");
        var replicas = replicasElement.EnumerateArray().Select(replica =>
        {
            RequireExactProperties(replica, ["id", "signingPublicKey"], "replica");
            return new ParsedReplica(
                LowerHex(replica.GetProperty("id"), 32, "replica id"),
                LowerHex(replica.GetProperty("signingPublicKey"), 32, "replica key"));
        }).ToArray();
        Require(!Fixed(replicas[0].Id, replicas[1].Id) &&
                !Fixed(replicas[0].SigningKey, replicas[1].SigningKey),
            "Mailbox replicas must be distinct.");
        var own = value.GetProperty("ownMailbox");
        RequireExactProperties(own,
            ["blindedMailboxId", "retrieveAndAcknowledgeGrants", "depositGrants"], "own mailbox");
        var peer = value.GetProperty("peerMailboxRoute");
        RequireExactProperties(peer,
            ["holderPublicKey", "blindedMailboxId", "depositGrants"], "peer mailbox");
        var current = ParseEpoch(value.GetProperty("currentEpoch"), "current epoch");
        var next = ParseEpoch(value.GetProperty("nextEpoch"), "next epoch");
        Require(next.Epoch == current.Epoch + 1 && current.NotBefore < next.NotBefore &&
                next.NotBefore <= current.ExpiresAt && current.ExpiresAt < next.ExpiresAt,
            "Mailbox epoch pair is not exact E/E+1.");
        var parsed = new ParsedBundle(
            identity,
            LowerHex(value.GetProperty("networkId"), 16, "network id"),
            LowerHex(value.GetProperty("holderPublicKey"), 32, "holder"),
            LowerHex(peer.GetProperty("holderPublicKey"), 32, "peer holder"),
            LowerHex(own.GetProperty("blindedMailboxId"), 32, "own mailbox"),
            LowerHex(peer.GetProperty("blindedMailboxId"), 32, "peer mailbox"),
            coordinator!, current, next, replicas,
            ParseGrantSet(own.GetProperty("retrieveAndAcknowledgeGrants"), "own retrieve"),
            ParseGrantSet(own.GetProperty("depositGrants"), "own deposit"),
            ParseGrantSet(peer.GetProperty("depositGrants"), "peer deposit"));
        var hashes = value.GetProperty("hashes");
        RequireExactProperties(hashes, ["mailboxRouteSha256"], "bundle hashes");
        Require(Fixed(LowerHex(hashes.GetProperty("mailboxRouteSha256"), 32,
                    "mailbox route hash"), SHA256.HashData(parsed.OwnMailbox)),
            "Mailbox route hash is invalid.");
        ValidateGrantSet(parsed, parsed.OwnRetrieve, MailboxCapabilityDomain.Retrieve, parsed.OwnMailbox);
        ValidateGrantSet(parsed, parsed.OwnDeposit, MailboxCapabilityDomain.Deposit, parsed.OwnMailbox);
        ValidateGrantSet(parsed, parsed.PeerDeposit, MailboxCapabilityDomain.Deposit, parsed.PeerMailbox);
        var serials = parsed.AllGrants.Select(grant => Convert.ToHexString(grant.Serial.Span))
            .ToHashSet(StringComparer.Ordinal);
        Require(serials.Count == 6, "Mailbox grant serials must be unique across all scopes and epochs.");
        return parsed;
    }

    private static ParsedPublicAuthority ParsePublicAuthority(
        JsonElement value,
        byte[] expectedIssuer)
    {
        RequireExactProperties(value, PublicAuthorityProperties, "public authority");
        Require(value.GetProperty("schemaVersion").GetInt32() == 2 &&
                string.Equals(value.GetProperty("scope").GetString(), "DEV-LOCAL-ONLY", StringComparison.Ordinal) &&
                string.Equals(value.GetProperty("protocol").GetString(),
                    "P10E/MCP2/MAU2/MIP1/RIP1/PRQ2", StringComparison.Ordinal) &&
                Fixed(LowerHex(value.GetProperty("issuerPublicKey"), 32, "authority issuer"), expectedIssuer),
            "Public authority header is invalid.");
        var ids = value.GetProperty("replicaIds").EnumerateArray()
            .Select(item => LowerHex(item, 32, "authority replica id")).ToArray();
        var keys = value.GetProperty("replicaSigningPublicKeys").EnumerateArray()
            .Select(item => LowerHex(item, 32, "authority replica key")).ToArray();
        Require(ids.Length == 2 && keys.Length == 2, "Public authority must pin two client replicas.");
        var epochValues = value.GetProperty("epochs");
        Require(epochValues.ValueKind == JsonValueKind.Array && epochValues.GetArrayLength() == 2,
            "Public authority must contain exact E/E+1.");
        var epochs = epochValues.EnumerateArray()
            .Select(item => ParseEpoch(item, "authority epoch", includesReplicas: true)).ToArray();
        var selections = value.GetProperty("selections");
        Require(selections.ValueKind == JsonValueKind.Array &&
                selections.GetArrayLength() == 0,
            "Schema-v2 DEV authority does not accept unverified route selections.");
        var coordinatorText = value.GetProperty("coordinatorUrl").GetString();
        Require(Uri.TryCreate(coordinatorText, UriKind.Absolute, out var coordinator) && coordinator is not null &&
                string.IsNullOrEmpty(coordinator.UserInfo) && string.IsNullOrEmpty(coordinator.Query) &&
                string.IsNullOrEmpty(coordinator.Fragment),
            "Public authority coordinator is invalid.");
        var parsed = new ParsedPublicAuthority(
            LowerHex(value.GetProperty("networkId"), 16, "authority network"),
            value.GetProperty("minimumGeneration").GetUInt64(),
            value.GetProperty("maximumGeneration").GetUInt64(),
            value.GetProperty("issuerValidFromUnixSeconds").GetUInt64(),
            value.GetProperty("issuerValidUntilUnixSeconds").GetUInt64(),
            coordinator!, epochs[0], epochs[1],
            [new ParsedReplica(ids[0], keys[0]), new ParsedReplica(ids[1], keys[1])]);
        Require(parsed.MinimumGeneration > 0 &&
                parsed.MaximumGeneration == parsed.MinimumGeneration + 1 &&
                parsed.IssuerValidFrom <= parsed.Current.NotBefore &&
                parsed.IssuerValidUntil >= parsed.Next.ExpiresAt,
            "Public authority generation or issuer window is invalid.");
        return parsed;
    }

    private static void ValidatePublicAuthority(ParsedPublicAuthority authority, ParsedBundle bundle)
    {
        Require(Fixed(authority.NetworkId, bundle.NetworkId) &&
                authority.MinimumGeneration == bundle.Current.Epoch &&
                authority.MaximumGeneration == bundle.Next.Epoch &&
                SameEpoch(authority.Current, bundle.Current) &&
                SameEpoch(authority.Next, bundle.Next) &&
                authority.Coordinator == bundle.Coordinator &&
                authority.Replicas.Zip(bundle.Replicas).All(pair =>
                    Fixed(pair.First.Id, pair.Second.Id) &&
                    Fixed(pair.First.SigningKey, pair.Second.SigningKey)),
            "Credential bundle differs from the independently hashed public authority.");
    }

    private static void ValidatePair(JsonElement manifest, ParsedBundle android, ParsedBundle windows)
    {
        var androidHolder = LowerHex(manifest.GetProperty("androidHolderPublicKey"), 32, "android holder");
        var windowsHolder = LowerHex(manifest.GetProperty("windowsHolderPublicKey"), 32, "windows holder");
        Require(Fixed(android.Holder, androidHolder) && Fixed(windows.Holder, windowsHolder) &&
                Fixed(android.PeerHolder, windows.Holder) && Fixed(windows.PeerHolder, android.Holder) &&
                Fixed(android.PeerMailbox, windows.OwnMailbox) &&
                Fixed(windows.PeerMailbox, android.OwnMailbox) &&
                !Fixed(android.OwnMailbox, windows.OwnMailbox) &&
                Fixed(android.NetworkId, windows.NetworkId) &&
                SameEpoch(android.Current, windows.Current) && SameEpoch(android.Next, windows.Next) &&
                android.Replicas.Zip(windows.Replicas).All(pair =>
                    Fixed(pair.First.Id, pair.Second.Id) &&
                    Fixed(pair.First.SigningKey, pair.Second.SigningKey)),
            "Android/Windows bundles are not one exact atomic counterpart pair.");
        var serials = android.AllGrants.Concat(windows.AllGrants)
            .Select(grant => Convert.ToHexString(grant.Serial.Span))
            .ToHashSet(StringComparer.Ordinal);
        Require(serials.Count == 12,
            "Mailbox grant serials must be unique across the atomic pair.");
    }

    private static bool SameEpoch(ParsedEpoch left, ParsedEpoch right) =>
        left.Epoch == right.Epoch && left.NotBefore == right.NotBefore &&
        left.ExpiresAt == right.ExpiresAt &&
        Fixed(left.MembershipCommitment, right.MembershipCommitment) &&
        Fixed(left.PlacementId, right.PlacementId) &&
        Fixed(left.PlacementCommitment, right.PlacementCommitment);

    private static void ValidateGrantSet(
        ParsedBundle bundle,
        ParsedGrantSet set,
        MailboxCapabilityDomain domain,
        byte[] mailbox)
    {
        ValidateGrant(bundle, set.Current, bundle.Current, domain, mailbox);
        ValidateGrant(bundle, set.Next, bundle.Next, domain, mailbox);
    }

    private static void ValidateGrant(
        ParsedBundle bundle,
        MailboxAuthenticatedGrant grant,
        ParsedEpoch epoch,
        MailboxCapabilityDomain domain,
        byte[] mailbox)
    {
        Require(grant.Epoch == epoch.Epoch && grant.Generation == epoch.Epoch &&
                grant.Domain == domain && grant.Lifecycle == MailboxCapabilityLifecycle.Active &&
                grant.OverlapUntilUnixSeconds == 0 &&
                grant.NotBeforeUnixSeconds == epoch.NotBefore &&
                grant.ExpiresAtUnixSeconds == epoch.ExpiresAt &&
                Fixed(grant.NetworkId.Span, bundle.NetworkId) &&
                Fixed(grant.HolderPublicKey.Span, bundle.Holder) &&
                Fixed(grant.PlacementCommitment.Span, epoch.PlacementCommitment) &&
                Fixed(grant.MembershipCommitment.Span, epoch.MembershipCommitment),
            "Mailbox grant is not bound to its exact scope, holder and epoch.");
        _ = mailbox; // Mailbox ID is deliberately blinded outside the signed grant.
    }

    private static ParsedGrantSet ParseGrantSet(JsonElement value, string label)
    {
        Require(value.ValueKind == JsonValueKind.Array && value.GetArrayLength() == 2,
            $"{label} must contain exact E/E+1 grants.");
        var grants = value.EnumerateArray().Select(item =>
        {
            RequireExactProperties(item, ["epoch", "canonicalGrant", "sha256"], label);
            var encoded = Convert.FromBase64String(item.GetProperty("canonicalGrant").GetString() ?? "");
            Require(Fixed(SHA256.HashData(encoded), LowerHex(item.GetProperty("sha256"), 32, label + " hash")),
                $"{label} hash is invalid.");
            var decoded = MailboxAuthenticatedCapabilityCodec.DecodeGrant(encoded);
            Require(Fixed(encoded, MailboxAuthenticatedCapabilityCodec.EncodeGrant(decoded)) &&
                    decoded.Epoch == item.GetProperty("epoch").GetUInt64(),
                $"{label} is not canonical.");
            return decoded;
        }).ToArray();
        return new ParsedGrantSet(grants[0], grants[1]);
    }

    private static ParsedEpoch ParseEpoch(
        JsonElement value,
        string label,
        bool includesReplicas = false)
    {
        RequireExactProperties(value, includesReplicas
            ? ["epoch", "notBeforeUnixSeconds", "expiresAtUnixSeconds", "membershipCommitment",
               "placementId", "placementCommitment", "replicas"]
            : ["epoch", "notBeforeUnixSeconds", "expiresAtUnixSeconds", "membershipCommitment",
               "placementId", "placementCommitment"], label);
        var placement = LowerHex(value.GetProperty("placementId"), 32, label + " placement");
        var commitment = LowerHex(value.GetProperty("placementCommitment"), 32, label + " commitment");
        Require(Fixed(commitment, MailboxPlacementCommitment.Compute(new BlindedPlacementId(placement))),
            $"{label} placement commitment is invalid.");
        if (includesReplicas)
        {
            var replicas = value.GetProperty("replicas");
            Require(replicas.ValueKind == JsonValueKind.Array &&
                    replicas.GetArrayLength() == 0,
                $"{label} does not accept unverified nested replica proofs.");
        }
        return new ParsedEpoch(
            value.GetProperty("epoch").GetUInt64(),
            value.GetProperty("notBeforeUnixSeconds").GetUInt64(),
            value.GetProperty("expiresAtUnixSeconds").GetUInt64(),
            LowerHex(value.GetProperty("membershipCommitment"), 32, label + " membership"),
            placement,
            commitment);
    }

    private static MailboxCredentialEpoch ToEpoch(ParsedEpoch value) => new(
        value.Epoch, value.NotBefore, value.ExpiresAt,
        value.MembershipCommitment, value.PlacementId, value.PlacementCommitment);

    private static MailboxCapabilityIssuerAuthority Issuer(
        byte[] issuer,
        MailboxCapabilityDomain domain,
        ParsedPublicAuthority authority) => new()
        {
            PublicKey = issuer.ToArray(),
            Domain = domain,
            AllowedLifecycle = MailboxCapabilityLifecycle.Active,
            MinimumGeneration = authority.MinimumGeneration,
            MaximumGeneration = authority.MaximumGeneration,
            ValidFromUnixSeconds = authority.IssuerValidFrom,
            ValidUntilUnixSeconds = authority.IssuerValidUntil
        };

    private static ParsedMailboxRevocationSnapshot LoadRevocations(
        string protectedRoot,
        string path,
        byte[] expectedHash,
        byte[] authority,
        byte[] issuer,
        ulong minimumGeneration,
        ulong maximumGeneration,
        TimeProvider timeProvider)
    {
        var bytes = ReadStableBounded(
            protectedRoot, RequireSafeFile(protectedRoot, path));
        Require(Fixed(SHA256.HashData(bytes), expectedHash), "Revocation snapshot hash is not pinned.");
        using var document = Parse(bytes, "revocation snapshot");
        var root = document.RootElement;
        RequireExactProperties(root,
            ["schemaVersion", "authoritySha256", "issuerPublicKey", "generatedAtUnixSeconds",
             "expiresAtUnixSeconds", "revoked"], "revocation snapshot");
        var generated = root.GetProperty("generatedAtUnixSeconds").GetUInt64();
        var expires = root.GetProperty("expiresAtUnixSeconds").GetUInt64();
        Require(root.GetProperty("schemaVersion").GetInt32() == 1 &&
                Fixed(LowerHex(root.GetProperty("authoritySha256"), 32, "revocation authority"), authority) &&
                Fixed(LowerHex(root.GetProperty("issuerPublicKey"), 32, "revocation issuer"), issuer) &&
                generated < expires &&
                generated <= checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds()) &&
                checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds()) <= expires,
            "Revocation snapshot is invalid or expired.");
        var revoked = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in root.GetProperty("revoked").EnumerateArray())
        {
            RequireExactProperties(item,
                ["serial", "domain", "generation", "epoch", "membershipCommitment"], "revocation");
            var domainValue = item.GetProperty("domain").GetInt32();
            Require(Enum.IsDefined((MailboxCapabilityDomain)domainValue),
                "Revocation capability domain is undefined.");
            var generation = item.GetProperty("generation").GetUInt64();
            var epoch = item.GetProperty("epoch").GetUInt64();
            Require(generation == epoch && generation >= minimumGeneration &&
                    generation <= maximumGeneration,
                "Revocation is outside the authoritative E/E+1 window.");
            var key = DurableMailboxRevocationSnapshot.Key(
                issuer,
                LowerHex(item.GetProperty("serial"), 16, "revocation serial"),
                (MailboxCapabilityDomain)domainValue,
                generation,
                epoch,
                LowerHex(item.GetProperty("membershipCommitment"), 32, "revocation membership"));
            Require(revoked.Add(key), "Revocation snapshot contains a duplicate entry.");
        }
        return new ParsedMailboxRevocationSnapshot(generated, expires, revoked);
    }

    private static string RequireSafeRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Pair root is required.", nameof(path));
        var full = CanonicalDirectory(path);
        var comparison = Comparison();
        var fileSystemRoot = Path.GetPathRoot(full);
        Require(!string.IsNullOrEmpty(fileSystemRoot) &&
                !full.Equals(CanonicalDirectory(fileSystemRoot), comparison),
            "Mailbox protected root cannot be a filesystem root.");
        Require(Directory.Exists(full), "Mailbox bundle directory is missing.");
        RequireNoReparsePath(full, full);
        return full;
    }

    private static string RequireSafeRoot(string protectedRoot, string path)
    {
        var root = CanonicalDirectory(protectedRoot);
        var full = CanonicalDirectory(path);
        RequireContained(root, full, allowSame: true);
        Require(Directory.Exists(full), "Mailbox bundle directory is missing.");
        RequireNoReparsePath(full, root);
        return full;
    }

    private static string RequireSafeFile(string protectedRoot, string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("A pinned file path is required.", nameof(path));
        var full = Path.GetFullPath(path);
        RequireContained(protectedRoot, full, allowSame: false);
        RequireNoReparsePath(full, protectedRoot);
        Require(File.Exists(full), "Pinned file is missing.");
        return full;
    }

    private static string SafeChild(string root, params string[] parts)
    {
        var candidate = Path.GetFullPath(Path.Combine([root, .. parts]));
        RequireContained(root, candidate, allowSame: false);
        RequireNoReparsePath(candidate, root);
        return candidate;
    }

    private static void RequireSafeDirectory(string protectedRoot, string path)
    {
        RequireContained(protectedRoot, path, allowSame: true);
        Require(Directory.Exists(path), "Mailbox bundle directory is missing.");
        RequireNoReparsePath(path, protectedRoot);
    }

    private static void RequireNoReparsePath(string path, string protectedRoot)
    {
        var current = Path.GetFullPath(path);
        var root = CanonicalDirectory(protectedRoot);
        var comparison = Comparison();
        RequireContained(root, current, allowSame: true);
        while (true)
        {
            if (File.Exists(current) || Directory.Exists(current))
                Require((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0,
                    "Mailbox bundle path contains a reparse point.");
            if (current.Equals(root, comparison)) return;
            var parent = Path.GetDirectoryName(current);
            Require(!string.IsNullOrEmpty(parent) &&
                    !string.Equals(parent, current, comparison),
                "Mailbox bundle path did not reach its protected root.");
            current = parent!;
        }
    }

    private static void RequireContained(
        string protectedRoot,
        string candidate,
        bool allowSame)
    {
        var root = CanonicalDirectory(protectedRoot);
        var full = Path.GetFullPath(candidate);
        var comparison = Comparison();
        Require((allowSame && full.Equals(root, comparison)) ||
                full.StartsWith(root + Path.DirectorySeparatorChar, comparison),
            "Mailbox bundle path escaped its protected root.");
    }

    private static StringComparison Comparison() => OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;

    private static string CanonicalDirectory(string path) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private static byte[] ReadStableBounded(string protectedRoot, string path) =>
        ProtectedMailboxFileReader.ReadBounded(
            protectedRoot, path, MaximumJsonBytes);

    private static JsonDocument Parse(byte[] bytes, string label)
    {
        try
        {
            return JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16
            });
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"{label} is not strict JSON.", exception);
        }
    }

    private static void RequireExactProperties(JsonElement value, string[] expected, string label)
    {
        Require(value.ValueKind == JsonValueKind.Object, $"{label} must be an object.");
        var actual = value.EnumerateObject().Select(property => property.Name).ToArray();
        Require(actual.Length == expected.Length &&
                actual.ToHashSet(StringComparer.Ordinal).SetEquals(expected),
            $"{label} has missing, duplicate or unknown properties.");
    }

    private static byte[] LowerHex(JsonElement value, int bytes, string label)
    {
        var text = value.GetString();
        if (text is null || text.Length != bytes * 2 ||
            text.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new InvalidDataException($"{label} is not canonical lowercase hexadecimal.");
        var decoded = Convert.FromHexString(text);
        Require(decoded.AsSpan().IndexOfAnyExcept((byte)0) >= 0, $"{label} is all zero.");
        return decoded;
    }

    private static byte[] ExactBytes(ReadOnlySpan<byte> value, int length, string label)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{label} is invalid.");
        return value.ToArray();
    }

    private static byte[] DomainHash(string domain, params byte[][] values)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(domain));
        foreach (var value in values) hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    private static byte[] ScopedGeneration(
        MailboxCredentialSelector selector,
        ReadOnlySpan<byte> holder,
        ReadOnlySpan<byte> mailbox,
        MailboxCredentialEpoch current,
        MailboxCredentialEpoch next,
        MailboxCredentialGrantSet? retrieve,
        MailboxCredentialGrantSet deposit,
        MailboxCredentialReplicaPair replicas)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("deep.mailbox.scoped-import-generation.v2"u8);
        hash.AppendData([(byte)selector.Kind]);
        hash.AppendData(selector.ScopeId.Span);
        hash.AppendData(holder);
        hash.AppendData(mailbox);
        AppendEpoch(hash, current);
        AppendEpoch(hash, next);
        AppendGrantSet(hash, retrieve);
        AppendGrantSet(hash, deposit);
        hash.AppendData(replicas.FirstId.Span);
        hash.AppendData(replicas.FirstSigningKey.Span);
        hash.AppendData(replicas.SecondId.Span);
        hash.AppendData(replicas.SecondSigningKey.Span);
        return hash.GetHashAndReset();
    }

    private static void AppendEpoch(IncrementalHash hash, MailboxCredentialEpoch epoch)
    {
        Span<byte> scalar = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(scalar, epoch.Epoch);
        hash.AppendData(scalar);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, epoch.NotBeforeUnixSeconds);
        hash.AppendData(scalar);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, epoch.ExpiresAtUnixSeconds);
        hash.AppendData(scalar);
        hash.AppendData(epoch.MembershipCommitment.Span);
        hash.AppendData(epoch.PlacementId.Span);
        hash.AppendData(epoch.PlacementCommitment.Span);
    }

    private static void AppendGrantSet(
        IncrementalHash hash,
        MailboxCredentialGrantSet? grants)
    {
        hash.AppendData([grants is null ? (byte)0 : (byte)1]);
        if (grants is null) return;
        hash.AppendData(grants.CurrentGrant.Span);
        hash.AppendData(grants.NextGrant.Span);
    }

    private static byte[] PairGeneration(
        ReadOnlySpan<byte> authority,
        ReadOnlySpan<byte> androidHash,
        ReadOnlySpan<byte> windowsHash) => SHA256.HashData(Encoding.UTF8.GetBytes(
        "deep.mailbox-pair-generation.v1\n" +
        Convert.ToHexStringLower(authority) + "\n" +
        Convert.ToHexStringLower(androidHash) + "\n" +
        Convert.ToHexStringLower(windowsHash) + "\n"));

    private static SessionId SessionIdFromEd25519(ReadOnlySpan<byte> ed25519)
    {
        var curve = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519.ToArray());
        try
        {
            return SessionId.Parse("05" + Convert.ToHexStringLower(curve));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(curve);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }

    private sealed record ParsedReplica(byte[] Id, byte[] SigningKey);
    private sealed record ParsedMrXApproval(byte[] PayloadSha256);
    private sealed record ParsedPublicAuthority(
        byte[] NetworkId,
        ulong MinimumGeneration,
        ulong MaximumGeneration,
        ulong IssuerValidFrom,
        ulong IssuerValidUntil,
        Uri Coordinator,
        ParsedEpoch Current,
        ParsedEpoch Next,
        ParsedReplica[] Replicas);
    private sealed record ParsedEpoch(
        ulong Epoch, ulong NotBefore, ulong ExpiresAt,
        byte[] MembershipCommitment, byte[] PlacementId, byte[] PlacementCommitment);
    private sealed record ParsedGrantSet(
        MailboxAuthenticatedGrant Current,
        MailboxAuthenticatedGrant Next);
    private sealed record ParsedBundle(
        string Identity,
        byte[] NetworkId,
        byte[] Holder,
        byte[] PeerHolder,
        byte[] OwnMailbox,
        byte[] PeerMailbox,
        Uri Coordinator,
        ParsedEpoch Current,
        ParsedEpoch Next,
        ParsedReplica[] Replicas,
        ParsedGrantSet OwnRetrieve,
        ParsedGrantSet OwnDeposit,
        ParsedGrantSet PeerDeposit)
    {
        public IEnumerable<MailboxAuthenticatedGrant> AllGrants =>
            [OwnRetrieve.Current, OwnRetrieve.Next, OwnDeposit.Current, OwnDeposit.Next,
             PeerDeposit.Current, PeerDeposit.Next];
    }
}

public interface IFreshMailboxCapabilityRevocationSource :
    IMailboxCapabilityRevocationSource
{
    void ValidateFreshness();
}

internal sealed record ParsedMailboxRevocationSnapshot(
    ulong GeneratedAtUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    IReadOnlySet<string> Revoked);

public sealed class DurableMailboxRevocationSnapshot :
    IFreshMailboxCapabilityRevocationSource
{
    private readonly object gate = new();
    private readonly TimeProvider timeProvider;
    private Snapshot current;

    internal DurableMailboxRevocationSnapshot(
        ParsedMailboxRevocationSnapshot snapshot,
        TimeProvider timeProvider)
    {
        this.timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        current = Snapshot.From(snapshot);
        ValidateFreshness();
    }

    internal void ReplaceMonotonic(ParsedMailboxRevocationSnapshot replacement)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        var candidate = Snapshot.From(replacement);
        ValidateFreshness(candidate);
        lock (gate)
        {
            var active = current;
            if (candidate.GeneratedAtUnixSeconds < active.GeneratedAtUnixSeconds ||
                candidate.GeneratedAtUnixSeconds == active.GeneratedAtUnixSeconds &&
                !candidate.ExactlyEquals(active))
            {
                throw new InvalidDataException(
                    "Revocation snapshot is not an exact replay or a monotonic replacement.");
            }
            if (candidate.GeneratedAtUnixSeconds > active.GeneratedAtUnixSeconds)
                Volatile.Write(ref current, candidate);
        }
    }

    public void ValidateFreshness() => ValidateFreshness(Volatile.Read(ref current));

    private void ValidateFreshness(Snapshot snapshot)
    {
        var now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (now <= 0 || checked((ulong)now) < snapshot.GeneratedAtUnixSeconds ||
            checked((ulong)now) > snapshot.ExpiresAtUnixSeconds)
        {
            throw new InvalidOperationException(
                "Authenticated mailbox revocation snapshot is unavailable or expired.");
        }
    }

    public bool IsRevoked(MailboxCapabilityRevocationQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        var snapshot = Volatile.Read(ref current);
        ValidateFreshness(snapshot);
        return snapshot.Revoked.Contains(Key(
            query.IssuerPublicKey.Span,
            query.Serial.Span,
            query.Domain,
            query.Generation,
            query.Epoch,
            query.MembershipCommitment.Span));
    }

    internal static string Key(
        ReadOnlySpan<byte> issuer,
        ReadOnlySpan<byte> serial,
        MailboxCapabilityDomain domain,
        ulong generation,
        ulong epoch,
        ReadOnlySpan<byte> membership) =>
        $"{Convert.ToHexString(issuer)}:{Convert.ToHexString(serial)}:{(byte)domain}:{generation}:{epoch}:" +
        Convert.ToHexString(membership);

    private sealed record Snapshot(
        ulong GeneratedAtUnixSeconds,
        ulong ExpiresAtUnixSeconds,
        IReadOnlySet<string> Revoked)
    {
        public static Snapshot From(ParsedMailboxRevocationSnapshot source) => new(
            source.GeneratedAtUnixSeconds,
            source.ExpiresAtUnixSeconds,
            new HashSet<string>(source.Revoked, StringComparer.Ordinal));

        public bool ExactlyEquals(Snapshot other) =>
            GeneratedAtUnixSeconds == other.GeneratedAtUnixSeconds &&
            ExpiresAtUnixSeconds == other.ExpiresAtUnixSeconds &&
            Revoked.SetEquals(other.Revoked);
    }
}

/// <summary>
/// Fail-closed revocation source. Before publication it validates the already prepared
/// immutable candidate; after the credential transaction commits every validation reads
/// the authoritative SQLite checkpoint, which also fences independent processes.
/// </summary>
internal sealed class SqliteMailboxRevocationSource :
    IFreshMailboxCapabilityRevocationSource
{
    private readonly SqliteSessionStore store;
    private readonly string checkpointKey;
    private readonly MailboxRevocationRuntimeCheckpoint prepared;
    private readonly TimeProvider timeProvider;
    private int activated;

    internal SqliteMailboxRevocationSource(
        SqliteSessionStore store,
        string checkpointKey,
        MailboxRevocationRuntimeCheckpoint prepared,
        TimeProvider timeProvider)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.checkpointKey = string.IsNullOrWhiteSpace(checkpointKey)
            ? throw new ArgumentException("Checkpoint key is required.", nameof(checkpointKey))
            : checkpointKey;
        this.prepared = prepared ?? throw new ArgumentNullException(nameof(prepared));
        this.timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        ValidateFreshness(prepared);
    }

    internal void ActivateCommittedNoThrow() => Volatile.Write(ref activated, 1);

    public void ValidateFreshness() => ValidateFreshness(Load());

    public bool IsRevoked(MailboxCapabilityRevocationQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        var checkpoint = Load();
        ValidateFreshness(checkpoint);
        return Array.BinarySearch(
            checkpoint.RevokedKeys,
            DurableMailboxRevocationSnapshot.Key(
                query.IssuerPublicKey.Span,
                query.Serial.Span,
                query.Domain,
                query.Generation,
                query.Epoch,
                query.MembershipCommitment.Span),
            StringComparer.Ordinal) >= 0;
    }

    private MailboxRevocationRuntimeCheckpoint Load() =>
        Volatile.Read(ref activated) == 0
            ? prepared
            : store.ReadMailboxRevocationCheckpoint(checkpointKey);

    private void ValidateFreshness(MailboxRevocationRuntimeCheckpoint checkpoint)
    {
        var now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (now <= 0 || checked((ulong)now) < checkpoint.GeneratedAtUnixSeconds ||
            checked((ulong)now) > checkpoint.ExpiresAtUnixSeconds)
        {
            throw new InvalidOperationException(
                "Authenticated mailbox revocation snapshot is unavailable or expired.");
        }
    }
}

public sealed class SodiumClientMailboxReceiptCrypto : IMailboxPeerReplicationCrypto
{
    public byte[] Digest(ReadOnlySpan<byte> payload) => SHA256.HashData(payload);

    public bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        try
        {
            return publicKey.Length == 32 && signature.Length == 64 &&
                PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), publicKey.ToArray());
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
