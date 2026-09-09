using Deep.Protocol.AccountDirectoryV1;
using Deep.Client.Shared.Domain.AccountDirectoryV1;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.XPointNetworkV1;

/// <summary>
/// Fetches an untrusted, byte-exact directory package.  Implementations are
/// transport adapters only: none of the returned values are authority until
/// the protocol verifiers accept the complete package.
/// </summary>
public interface IContactResolveDirectoryArtifactSource
{
    ValueTask<ContactResolveDirectoryArtifacts> FetchCurrentAsync(
        ContactResolveDirectoryFetchContext context,
        CancellationToken cancellationToken);
}

/// <summary>
/// Read-only projection of the source-owned rollback floors needed by a
/// directory adapter to request an exact ADP1 continuation or XNF1/NFP1
/// recovery package.  Callers cannot construct this context.
/// </summary>
public sealed class ContactResolveDirectoryFetchContext
{
    private readonly byte[] expectedNetworkId;
    private readonly byte[] directoryLkgCoreHash;
    private readonly byte[] requiredDirectoryLookupKey;

    internal ContactResolveDirectoryFetchContext(
        ReadOnlySpan<byte> expectedNetworkId,
        AccountDirectoryStateSnapshot? directoryState,
        XPointNetworkStateSnapshot? networkState,
        ReadOnlySpan<byte> requiredDirectoryLookupKey = default)
    {
        if (expectedNetworkId.Length != 16 || expectedNetworkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Expected network ID must be exactly 16 non-zero bytes.", nameof(expectedNetworkId));
        this.expectedNetworkId = expectedNetworkId.ToArray();
        if (directoryState?.ProtectedLkg is { } directoryLkg)
        {
            DirectoryLkgLogGeneration = directoryLkg.LogGeneration;
            DirectoryLkgTreeSize = directoryLkg.TreeSize;
            directoryLkgCoreHash = directoryLkg.CoreHash.ToArray();
        }
        else
        {
            directoryLkgCoreHash = [];
        }

        if (!requiredDirectoryLookupKey.IsEmpty &&
            (requiredDirectoryLookupKey.Length != 32 ||
             requiredDirectoryLookupKey.IndexOfAnyExcept((byte)0) < 0))
            throw new ArgumentException(
                "Required directory lookup key must be empty or exactly 32 non-zero bytes.",
                nameof(requiredDirectoryLookupKey));
        this.requiredDirectoryLookupKey = requiredDirectoryLookupKey.ToArray();

        ProtectedNetworkLkg = networkState is null
            ? null
            : XPointNetworkStateSnapshot.Clone(networkState.ProtectedLkg);
    }

    public ReadOnlyMemory<byte> ExpectedNetworkId => expectedNetworkId.ToArray();
    public ulong? DirectoryLkgLogGeneration { get; }
    public ulong? DirectoryLkgTreeSize { get; }
    public ReadOnlyMemory<byte> DirectoryLkgCoreHash => directoryLkgCoreHash.ToArray();
    public ReadOnlyMemory<byte> RequiredDirectoryLookupKey => requiredDirectoryLookupKey.ToArray();
    public XPointNetworkProtectedLkg? ProtectedNetworkLkg { get; }
}

/// <summary>
/// Optional bounded XNF1/NFP1 recovery package used when a process no longer
/// holds the non-serializable predecessor network capability.
/// </summary>
public sealed class ContactResolveForwardCheckpointArtifacts
{
    public const long MaximumForwardPackageBytes = 560L * 1024;
    private readonly ReadOnlyMemory<byte>[] exactOrderedXnf1Chain;
    private readonly byte[] exactNfp1;
    private readonly byte[] exactTargetXnv1;
    private readonly byte[] exactTargetXnh1;

    public ContactResolveForwardCheckpointArtifacts(
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnf1Chain,
        ReadOnlyMemory<byte> exactNfp1,
        ReadOnlyMemory<byte> exactTargetXnv1,
        ReadOnlyMemory<byte> exactTargetXnh1)
    {
        var total = ContactResolveDirectoryArtifacts.ValidateChain(
            exactOrderedXnf1Chain, nameof(exactOrderedXnf1Chain), 64)
            + ContactResolveDirectoryArtifacts.ValidateArtifact(exactNfp1, nameof(exactNfp1))
            + ContactResolveDirectoryArtifacts.ValidateArtifact(exactTargetXnv1, nameof(exactTargetXnv1))
            + ContactResolveDirectoryArtifacts.ValidateArtifact(exactTargetXnh1, nameof(exactTargetXnh1));
        if (total > MaximumForwardPackageBytes)
            throw new ArgumentException(
                $"The forward-checkpoint package exceeds {MaximumForwardPackageBytes} bytes.");
        this.exactOrderedXnf1Chain = ContactResolveDirectoryArtifacts.CopyChain(
            exactOrderedXnf1Chain, nameof(exactOrderedXnf1Chain), 64);
        this.exactNfp1 = ContactResolveDirectoryArtifacts.CopyArtifact(exactNfp1, nameof(exactNfp1));
        this.exactTargetXnv1 = ContactResolveDirectoryArtifacts.CopyArtifact(exactTargetXnv1, nameof(exactTargetXnv1));
        this.exactTargetXnh1 = ContactResolveDirectoryArtifacts.CopyArtifact(exactTargetXnh1, nameof(exactTargetXnh1));
    }

    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnf1Chain => Copy(exactOrderedXnf1Chain);
    public ReadOnlyMemory<byte> ExactNfp1 => exactNfp1.ToArray();
    public ReadOnlyMemory<byte> ExactTargetXnv1 => exactTargetXnv1.ToArray();
    public ReadOnlyMemory<byte> ExactTargetXnh1 => exactTargetXnh1.ToArray();

    internal long TotalBytes => exactOrderedXnf1Chain.Sum(static value => (long)value.Length)
        + exactNfp1.Length + exactTargetXnv1.Length + exactTargetXnh1.Length;

    private static IReadOnlyList<ReadOnlyMemory<byte>> Copy(IEnumerable<ReadOnlyMemory<byte>> values) =>
        Array.AsReadOnly(values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
}

/// <summary>
/// Bounded raw input for the production ContactResolve authority verifier.
/// The package deliberately contains no caller-constructible verified DTO.
/// </summary>
public sealed class ContactResolveDirectoryArtifacts
{
    public const int MaximumChainArtifacts = 4_096;
    public const int MaximumSingleArtifactBytes = 16 * 1024 * 1024;
    public const long MaximumPackageBytes = 68L * 1024 * 1024;

    private readonly ReadOnlyMemory<byte>[] exactXna1AuthorityChain;
    private readonly ReadOnlyMemory<byte>[] exactDts1PolicyChain;
    private readonly byte[] exactAdh1;
    private readonly byte[] exactDtt1;
    private readonly byte[] exactAdp1;
    private readonly byte[] callerNonce;
    private readonly byte[] queriedDirectoryLeafKey;
    private readonly ReadOnlyMemory<byte>[] exactOrderedXvp1Chain;
    private readonly ReadOnlyMemory<byte>[] exactOrderedXnv1Chain;
    private readonly ReadOnlyMemory<byte>[] exactOrderedXnh1Chain;
    private readonly ReadOnlyMemory<byte>[] exactActiveXnd1;
    private readonly ReadOnlyMemory<byte>[] exactOrderedPmt2Chain;

    public ContactResolveDirectoryArtifacts(
        IReadOnlyList<ReadOnlyMemory<byte>> exactXna1AuthorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactDts1PolicyChain,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactDtt1,
        ReadOnlyMemory<byte> exactAdp1,
        ReadOnlyMemory<byte> callerNonce32,
        ReadOnlyMemory<byte> queriedDirectoryLeafKey32,
        AccountDirectoryMonotonicRequestWindow monotonicRequestWindow,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXvp1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnv1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnh1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactActiveXnd1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedPmt2Chain,
        ContactResolveForwardCheckpointArtifacts? forwardCheckpoint = null)
    {
        ArgumentNullException.ThrowIfNull(exactXna1AuthorityChain);
        ArgumentNullException.ThrowIfNull(exactDts1PolicyChain);
        ArgumentNullException.ThrowIfNull(exactOrderedXvp1Chain);
        ArgumentNullException.ThrowIfNull(exactOrderedXnv1Chain);
        ArgumentNullException.ThrowIfNull(exactOrderedXnh1Chain);
        ArgumentNullException.ThrowIfNull(exactActiveXnd1);
        ArgumentNullException.ThrowIfNull(exactOrderedPmt2Chain);
        var targetedCurrentValueShape =
            exactOrderedXvp1Chain.Count == 0 &&
            exactActiveXnd1.Count == 0 &&
            exactXna1AuthorityChain.Count == 1 &&
            exactDts1PolicyChain.Count == 1 &&
            exactOrderedXnv1Chain.Count == 1 &&
            exactOrderedXnh1Chain.Count == 1 &&
            exactOrderedPmt2Chain.Count == 1 &&
            forwardCheckpoint is null;
        if (!targetedCurrentValueShape &&
            (exactOrderedXvp1Chain.Count == 0 || exactActiveXnd1.Count == 0))
            throw new ArgumentException(
                "Only the exact targeted current-value transport shape may omit XVP1 and XND1.");

        var total = ValidateChain(exactXna1AuthorityChain, nameof(exactXna1AuthorityChain), MaximumChainArtifacts)
            + ValidateChain(exactDts1PolicyChain, nameof(exactDts1PolicyChain), MaximumChainArtifacts)
            + ValidateArtifact(exactAdh1, nameof(exactAdh1))
            + ValidateArtifact(exactDtt1, nameof(exactDtt1))
            + ValidateArtifact(exactAdp1, nameof(exactAdp1))
            + ValidateFixed(callerNonce32, 32, nameof(callerNonce32))
            + ValidateFixed(queriedDirectoryLeafKey32, 32, nameof(queriedDirectoryLeafKey32))
            + ValidateOptionalChain(exactOrderedXvp1Chain, nameof(exactOrderedXvp1Chain), MaximumChainArtifacts)
            + ValidateChain(exactOrderedXnv1Chain, nameof(exactOrderedXnv1Chain), MaximumChainArtifacts)
            + ValidateChain(exactOrderedXnh1Chain, nameof(exactOrderedXnh1Chain), MaximumChainArtifacts)
            + ValidateOptionalChain(exactActiveXnd1, nameof(exactActiveXnd1), MaximumChainArtifacts)
            + ValidateChain(exactOrderedPmt2Chain, nameof(exactOrderedPmt2Chain), MaximumChainArtifacts)
            + (forwardCheckpoint?.TotalBytes ?? 0);
        if (total > MaximumPackageBytes)
            throw new ArgumentException($"The ContactResolve directory package exceeds {MaximumPackageBytes} bytes.");

        this.exactXna1AuthorityChain = CopyChain(exactXna1AuthorityChain, nameof(exactXna1AuthorityChain), MaximumChainArtifacts);
        this.exactDts1PolicyChain = CopyChain(exactDts1PolicyChain, nameof(exactDts1PolicyChain), MaximumChainArtifacts);
        if (this.exactXna1AuthorityChain.Length != this.exactDts1PolicyChain.Length)
            throw new ArgumentException("XNA1 and DTS1 authority chains must be positionally complete.");

        this.exactAdh1 = CopyArtifact(exactAdh1, nameof(exactAdh1));
        this.exactDtt1 = CopyArtifact(exactDtt1, nameof(exactDtt1));
        this.exactAdp1 = CopyArtifact(exactAdp1, nameof(exactAdp1));
        callerNonce = CopyFixed(callerNonce32, 32, nameof(callerNonce32));
        queriedDirectoryLeafKey = CopyFixed(queriedDirectoryLeafKey32, 32, nameof(queriedDirectoryLeafKey32));
        ArgumentNullException.ThrowIfNull(monotonicRequestWindow);
        MonotonicRequestWindow = new AccountDirectoryMonotonicRequestWindow(
            monotonicRequestWindow.BootId.Span,
            monotonicRequestWindow.NonceCreatedAt,
            monotonicRequestWindow.ResponseReceivedAt,
            monotonicRequestWindow.CurrentSample);

        this.exactOrderedXvp1Chain = CopyOptionalChain(
            exactOrderedXvp1Chain, nameof(exactOrderedXvp1Chain), MaximumChainArtifacts);
        this.exactOrderedXnv1Chain = CopyChain(exactOrderedXnv1Chain, nameof(exactOrderedXnv1Chain), MaximumChainArtifacts);
        this.exactOrderedXnh1Chain = CopyChain(exactOrderedXnh1Chain, nameof(exactOrderedXnh1Chain), MaximumChainArtifacts);
        this.exactActiveXnd1 = CopyOptionalChain(
            exactActiveXnd1, nameof(exactActiveXnd1), MaximumChainArtifacts);
        this.exactOrderedPmt2Chain = CopyChain(exactOrderedPmt2Chain, nameof(exactOrderedPmt2Chain), MaximumChainArtifacts);
        if (this.exactOrderedXnv1Chain.Length != this.exactOrderedXnh1Chain.Length)
            throw new ArgumentException("XNV1 and XNH1 chains must contain exact corresponding pairs.");
        ForwardCheckpoint = forwardCheckpoint;

    }

    public IReadOnlyList<ReadOnlyMemory<byte>> ExactXna1AuthorityChain => Copy(exactXna1AuthorityChain);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactDts1PolicyChain => Copy(exactDts1PolicyChain);
    public ReadOnlyMemory<byte> ExactAdh1 => exactAdh1.ToArray();
    public ReadOnlyMemory<byte> ExactDtt1 => exactDtt1.ToArray();
    public ReadOnlyMemory<byte> ExactAdp1 => exactAdp1.ToArray();
    public ReadOnlyMemory<byte> CallerNonce => callerNonce.ToArray();
    public ReadOnlyMemory<byte> QueriedDirectoryLeafKey => queriedDirectoryLeafKey.ToArray();
    public AccountDirectoryMonotonicRequestWindow MonotonicRequestWindow { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXvp1Chain => Copy(exactOrderedXvp1Chain);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnv1Chain => Copy(exactOrderedXnv1Chain);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnh1Chain => Copy(exactOrderedXnh1Chain);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactActiveXnd1 => Copy(exactActiveXnd1);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedPmt2Chain => Copy(exactOrderedPmt2Chain);
    public ContactResolveForwardCheckpointArtifacts? ForwardCheckpoint { get; }

    internal static ReadOnlyMemory<byte>[] CopyChain(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        string name,
        int maximumCount)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count is 0 || values.Count > maximumCount)
            throw new ArgumentException($"{name} must contain 1..{maximumCount} artifacts.", name);
        return values.Select(value => (ReadOnlyMemory<byte>)CopyArtifact(value, name)).ToArray();
    }

    internal static long ValidateChain(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        string name,
        int maximumCount)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count is 0 || values.Count > maximumCount)
            throw new ArgumentException($"{name} must contain 1..{maximumCount} artifacts.", name);
        var total = 0L;
        foreach (var value in values)
            total = checked(total + ValidateArtifact(value, name));
        return total;
    }

    private static ReadOnlyMemory<byte>[] CopyOptionalChain(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        string name,
        int maximumCount)
    {
        ValidateOptionalChain(values, name, maximumCount);
        return values.Select(value => (ReadOnlyMemory<byte>)CopyArtifact(value, name)).ToArray();
    }

    private static long ValidateOptionalChain(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        string name,
        int maximumCount)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count > maximumCount)
            throw new ArgumentException($"{name} must contain 0..{maximumCount} artifacts.", name);
        var total = 0L;
        foreach (var value in values)
            total = checked(total + ValidateArtifact(value, name));
        return total;
    }

    internal static int ValidateArtifact(ReadOnlyMemory<byte> value, string name)
    {
        if (value.IsEmpty || value.Length > MaximumSingleArtifactBytes)
            throw new ArgumentException(
                $"{name} entries must contain 1..{MaximumSingleArtifactBytes} bytes.", name);
        return value.Length;
    }

    internal static byte[] CopyArtifact(ReadOnlyMemory<byte> value, string name)
    {
        ValidateArtifact(value, name);
        return value.ToArray();
    }

    private static byte[] CopyFixed(ReadOnlyMemory<byte> value, int length, string name)
    {
        ValidateFixed(value, length, name);
        return value.ToArray();
    }

    private static int ValidateFixed(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.Length;
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> Copy(IEnumerable<ReadOnlyMemory<byte>> values) =>
        Array.AsReadOnly(values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
}
