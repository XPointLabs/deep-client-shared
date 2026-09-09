using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence.PreKeyV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services.ContactV1;

internal sealed class PreKeyV1InventoryAuthoringContext
{
    private readonly byte[] serviceCapability;
    private readonly byte[] xps1Reference;
    private readonly byte[] currentDrs1Reference;
    private readonly byte[] predecessorXpi1Hash;
    private readonly byte[] publicationOperationId;
    private readonly byte[] placementHash;

    internal PreKeyV1InventoryAuthoringContext(
        Dpk2AuthoringContext dpk2,
        ReadOnlySpan<byte> serviceCapability,
        ReadOnlySpan<byte> xps1Reference,
        ReadOnlySpan<byte> currentDrs1Reference,
        ReadOnlySpan<byte> predecessorXpi1Hash,
        ReadOnlySpan<byte> publicationOperationId,
        ReadOnlySpan<byte> placementHash,
        ushort oneTimePreKeyCount,
        ushort lastResortReuseLimit)
    {
        Dpk2 = dpk2 ?? throw new ArgumentNullException(nameof(dpk2));
        Nonzero(serviceCapability, 32, nameof(serviceCapability));
        Nonzero(xps1Reference, 38, nameof(xps1Reference));
        Nonzero(currentDrs1Reference, 38, nameof(currentDrs1Reference));
        if (predecessorXpi1Hash.Length != 32)
            throw new ArgumentException("The predecessor XPI1 hash must be exactly 32 bytes.", nameof(predecessorXpi1Hash));
        Nonzero(publicationOperationId, 32, nameof(publicationOperationId));
        Nonzero(placementHash, 32, nameof(placementHash));
        if (oneTimePreKeyCount is < 32 or > 4096)
            throw new ArgumentOutOfRangeException(nameof(oneTimePreKeyCount));
        if (lastResortReuseLimit is < 1 or > 64)
            throw new ArgumentOutOfRangeException(nameof(lastResortReuseLimit));
        this.serviceCapability = serviceCapability.ToArray();
        this.xps1Reference = xps1Reference.ToArray();
        this.currentDrs1Reference = currentDrs1Reference.ToArray();
        this.predecessorXpi1Hash = predecessorXpi1Hash.ToArray();
        this.publicationOperationId = publicationOperationId.ToArray();
        this.placementHash = placementHash.ToArray();
        OneTimePreKeyCount = oneTimePreKeyCount;
        LastResortReuseLimit = lastResortReuseLimit;
    }

    internal Dpk2AuthoringContext Dpk2 { get; }
    internal ushort OneTimePreKeyCount { get; }
    internal ushort LastResortReuseLimit { get; }
    internal ReadOnlySpan<byte> ServiceCapability => serviceCapability;
    internal ReadOnlySpan<byte> Xps1Reference => xps1Reference;
    internal ReadOnlySpan<byte> CurrentDrs1Reference => currentDrs1Reference;
    internal ReadOnlySpan<byte> PredecessorXpi1Hash => predecessorXpi1Hash;
    internal ReadOnlySpan<byte> PublicationOperationId => publicationOperationId;
    internal ReadOnlySpan<byte> PlacementHash => placementHash;

    private static void Nonzero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be nonzero and exactly {length} bytes.", name);
    }
}

internal interface IPreKeyV1InventoryOwner
{
    ValueTask<PreKeyV1InventoryStageResult> EnsureInventoryAsync(
        PreKeyV1InventoryAuthoringContext context,
        CancellationToken cancellationToken = default);
}

internal sealed class DormantPreKeyV1InventoryOwner : IPreKeyV1InventoryOwner
{
    internal static DormantPreKeyV1InventoryOwner Instance { get; } = new();
    private DormantPreKeyV1InventoryOwner() { }

    public ValueTask<PreKeyV1InventoryStageResult> EnsureInventoryAsync(
        PreKeyV1InventoryAuthoringContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        throw new NotSupportedException(
            "Production DPK2 inventory is dormant until an approved ML-KEM asset and a device-owned authoring authority are configured.");
    }
}

/// <summary>
/// Account/device-wide production author.  It creates one bounded DPK2 epoch,
/// signs XPI1 with the current device, builds exact XPP1 through Protocol, and
/// atomically transfers every private capability to SQLCipher before returning
/// publication bytes.
/// </summary>
internal sealed class ProductionPreKeyV1InventoryOwner : IPreKeyV1InventoryOwner, IDisposable
{
    private readonly SqlitePreKeyV1SecretOwner store;
    private readonly DeepAccountService accountService;
    private readonly DeepLocalIdentitySnapshot localIdentity;
    private Dpk2AuthoringAuthority? authoringAuthority;
    private int active;

    internal ProductionPreKeyV1InventoryOwner(
        SqlitePreKeyV1SecretOwner store,
        DeepAccountService accountService,
        DeepLocalIdentitySnapshot localIdentity,
        Dpk2AuthoringAuthority authoringAuthority)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.accountService = accountService ?? throw new ArgumentNullException(nameof(accountService));
        this.localIdentity = localIdentity ?? throw new ArgumentNullException(nameof(localIdentity));
        this.authoringAuthority = authoringAuthority ?? throw new ArgumentNullException(nameof(authoringAuthority));
        if (!store.OwnsResponder(
                localIdentity.NetworkId.Span,
                localIdentity.Account.AccountIdentity.AccountId.Bytes.Span,
                localIdentity.Device.DeviceId.Bytes.Span,
                localIdentity.Device.DeviceGeneration) ||
            !Fixed(authoringAuthority.DeviceId.Span, localIdentity.Device.DeviceId.Bytes.Span) ||
            authoringAuthority.DeviceGeneration != localIdentity.Device.DeviceGeneration)
            throw new CryptographicException("The DPK2 authoring authority is outside the exact local account/device store scope.");
    }

    internal static async ValueTask<ProductionPreKeyV1InventoryOwner> CreateAsync(
        SqlitePreKeyV1SecretOwner store,
        DeepAccountService accountService,
        DeepLocalIdentitySnapshot localIdentity,
        VerifiedDeviceRelative verifiedDevice,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(accountService);
        ArgumentNullException.ThrowIfNull(localIdentity);
        ArgumentNullException.ThrowIfNull(verifiedDevice);
        Dpk2AuthoringAuthority? authority = await accountService.OpenCurrentDpk2AuthoringAuthorityAsync(
                localIdentity,
                verifiedDevice,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var result = new ProductionPreKeyV1InventoryOwner(
                store,
                accountService,
                localIdentity,
                authority);
            authority = null;
            return result;
        }
        finally
        {
            authority?.Dispose();
        }
    }

    public async ValueTask<PreKeyV1InventoryStageResult> EnsureInventoryAsync(
        PreKeyV1InventoryAuthoringContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.CompareExchange(ref active, 1, 0) != 0)
            throw new InvalidOperationException("A DPK2 inventory operation is already active.");
        var offerings = new List<AuthoredDpk2Offering>(context.OneTimePreKeyCount);
        AuthoredDpk2Offering? lastResort = null;
        var capabilities = new List<PreKeyV1ProvisioningCapability>(context.OneTimePreKeyCount + 1);
        byte[][]? exactOneTime = null;
        byte[][]? exactHashes = null;
        byte[]? merkleRoot = null;
        byte[]? lastHash = null;
        byte[]? signatureInput = null;
        byte[]? signature = null;
        byte[]? exactXpi1 = null;
        byte[]? exactXpp1 = null;
        byte[]? xpi1Hash = null;
        try
        {
            var existing = await store.ReadLatestPublicationAsync(cancellationToken)
                .ConfigureAwait(false);
            if (existing is not null)
            {
                if (existing.InventoryEpoch > context.Dpk2.InventoryEpoch)
                    throw new CryptographicException(
                        "The requested inventory epoch rolls back the durable current publication.");
                if (existing.InventoryEpoch < context.Dpk2.InventoryEpoch)
                {
                    if (!Fixed(context.PredecessorXpi1Hash, existing.Xpi1HashSpan))
                        throw new CryptographicException(
                            "The requested inventory does not name the durable current XPI1 predecessor.");
                }
                else
                {
                    RequireExistingMatches(context, existing);
                    return new(PreKeyV1InventoryStageDisposition.ExactReplay, existing, false);
                }
            }

            var authority = Volatile.Read(ref authoringAuthority) ??
                throw new ObjectDisposedException(nameof(ProductionPreKeyV1InventoryOwner));
            for (var index = 0; index < context.OneTimePreKeyCount; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                offerings.Add(authority.AuthorOneTime(context.Dpk2));
            }
            offerings.Sort(static (left, right) =>
                left.Record.OneTimeX25519PrekeyId.Span.SequenceCompareTo(
                    right.Record.OneTimeX25519PrekeyId.Span));
            lastResort = authority.AuthorLastResort(context.Dpk2, context.LastResortReuseLimit);

            exactOneTime = offerings.Select(static value => value.ExactDpk2.ToArray()).ToArray();
            exactHashes = offerings.Select(static value => value.ExactDpk2Hash.ToArray()).ToArray();
            merkleRoot = PreKeyInventoryPublicationVerifier.ComputeMerkleRoot(exactHashes);
            lastHash = lastResort.ExactDpk2Hash.ToArray();
            var directory = context.Dpk2.CurrentDirectory;
            var first = offerings[0].Record;
            var fields = new Xpi1UnsignedFields(
                first.NetworkId.Span,
                context.ServiceCapability,
                first.ResponderDeviceId.Span,
                first.ResponderDpd1Ref.Span,
                context.Dpk2.PrekeyServiceGeneration,
                context.Xps1Reference,
                context.Dpk2.InventoryEpoch,
                context.PredecessorXpi1Hash,
                context.OneTimePreKeyCount,
                merkleRoot,
                lastHash,
                directory.Head.Record.RecordHash.Span,
                context.CurrentDrs1Reference,
                context.Dpk2.NotBeforeUnixSeconds,
                context.Dpk2.ExpiresAtUnixSeconds);
            signatureInput = Xpi1Codec.CreateSignatureInput(fields);
            signature = await accountService.SignWithCurrentDeviceAsync(
                    localIdentity,
                    signatureInput,
                    cancellationToken)
                .ConfigureAwait(false);
            exactXpi1 = Xpi1Codec.Encode(fields, signature);
            var manifest = Xpi1Codec.Decode(exactXpi1);
            exactXpp1 = Xpp1Codec.Encode(
                first.NetworkId.Span,
                context.PublicationOperationId,
                context.PlacementHash,
                manifest,
                exactOneTime.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(),
                lastResort.ExactDpk2.Span);
            xpi1Hash = Xpi1Codec.ComputeHash(exactXpi1);
            var request = new PreKeyV1PublicationRequest(
                context.Dpk2.InventoryEpoch,
                context.Dpk2.PrekeyServiceGeneration,
                context.PublicationOperationId,
                context.PredecessorXpi1Hash,
                directory.Head.Record.DirectoryGeneration,
                directory.Head.Record.RecordHash.Span,
                xpi1Hash,
                exactXpi1,
                exactXpp1);

            foreach (var offering in offerings)
                capabilities.Add(store.SealAuthored(offering));
            capabilities.Add(store.SealAuthored(lastResort));
            return await store.StageInventoryAsync(request, capabilities, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            foreach (var capability in capabilities) capability.Dispose();
            foreach (var offering in offerings) offering.Dispose();
            lastResort?.Dispose();
            Zero(exactOneTime);
            Zero(exactHashes);
            Zero(merkleRoot); Zero(lastHash); Zero(signatureInput); Zero(signature);
            Zero(exactXpi1); Zero(exactXpp1); Zero(xpi1Hash);
            Volatile.Write(ref active, 0);
        }
    }

    public void Dispose() => Interlocked.Exchange(ref authoringAuthority, null)?.Dispose();

    internal static byte[] ComputeInventoryMerkleRoot(IReadOnlyList<byte[]> exactDpk2Hashes) =>
        PreKeyInventoryPublicationVerifier.ComputeMerkleRoot(exactDpk2Hashes);

    private static void RequireExistingMatches(
        PreKeyV1InventoryAuthoringContext context,
        PreKeyV1PublicationRequest existing)
    {
        var directory = context.Dpk2.CurrentDirectory;
        if (existing.ServiceGeneration != context.Dpk2.PrekeyServiceGeneration ||
            existing.CurrentDmd1Generation != directory.Head.Record.DirectoryGeneration ||
            !Fixed(existing.CurrentDmd1HashSpan, directory.Head.Record.RecordHash.Span) ||
            !Fixed(existing.PredecessorXpi1HashSpan, context.PredecessorXpi1Hash))
            throw new CryptographicException(
                "The requested inventory epoch conflicts with its durable service/DMD1 lineage.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static void Zero(byte[]? value) { if (value is not null) CryptographicOperations.ZeroMemory(value); }
    private static void Zero(byte[][]? values)
    {
        if (values is null) return;
        foreach (var value in values) CryptographicOperations.ZeroMemory(value);
    }
}
