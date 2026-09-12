using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.XPointNetworkV1;

internal sealed class HttpContactResolveDirectoryRequest
{
    internal required byte[] NetworkId { get; init; }
    internal required byte[] Nonce { get; init; }
    internal required byte[] BootId { get; init; }
    internal required ulong NonceCreatedAt { get; init; }
    internal ulong? DirectoryTreeSize { get; init; }
    internal byte[]? DirectoryCoreHash { get; init; }
    internal byte[]? RequiredDirectoryLookupKey { get; init; }
    internal XPointNetworkProtectedLkg? NetworkLkg { get; init; }
}

/// <summary>
/// Transport-only framing. It deliberately validates shape and request echoes,
/// but never authenticates directory or XPoint authority artifacts.
/// </summary>
internal static class HttpContactResolveDirectoryCodec
{
    internal const string ResponseMediaType = "application/vnd.deep.contact-resolve-directory.v1";
    internal const string RequestMediaType = "application/vnd.deep.contact-resolve-directory-request.v1";
    internal const int AbsoluteMaximumEnvelopeBytes =
        (int)ContactResolveDirectoryArtifacts.MaximumPackageBytes + (256 * 1024);

    private const ushort Version = 1;
    private const ushort ResponseForwardFlag = 0x0001;
    private const ushort RequestDirectoryFloorFlag = 0x0001;
    private const ushort RequestNetworkFloorFlag = 0x0002;
    private const ushort RequestDirectoryLookupFlag = 0x0004;
    private const int ResponseFixedBytes = 4 + 2 + 2 + 4 + 16 + 32 + 16 + 8 + 32;
    private static readonly byte[] RequestMagic = "CDQ1"u8.ToArray();
    private static readonly byte[] ResponseMagic = "CDR1"u8.ToArray();

    internal static byte[] EncodeRequest(
        ContactResolveDirectoryFetchContext context,
        ReadOnlySpan<byte> nonce,
        OnionMonotonicReading created)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(created);
        RequireNonZero(context.ExpectedNetworkId.Span, 16, "expected network ID");
        RequireNonZero(nonce, 32, "request nonce");
        RequireNonZero(created.BootId.Span, 16, "monotonic boot ID");

        var flags = (ushort)0;
        if (context.DirectoryLkgTreeSize.HasValue)
        {
            RequireNonZero(context.DirectoryLkgCoreHash.Span, 32, "directory LKG core hash");
            flags |= RequestDirectoryFloorFlag;
        }
        else if (!context.DirectoryLkgCoreHash.IsEmpty)
        {
            throw new InvalidOperationException("The directory LKG floor is incomplete.");
        }

        var network = context.ProtectedNetworkLkg;
        if (network is not null)
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    context.ExpectedNetworkId.Span, network.NetworkId.Span))
                throw new InvalidOperationException("The protected network LKG belongs to another network.");
            flags |= RequestNetworkFloorFlag;
        }
        if (!context.RequiredDirectoryLookupKey.IsEmpty)
        {
            RequireNonZero(context.RequiredDirectoryLookupKey.Span, 32,
                "required directory lookup key");
            flags |= RequestDirectoryLookupFlag;
        }

        using var stream = new MemoryStream(512);
        WriteHeader(stream, RequestMagic, flags, 0);
        Write(stream, context.ExpectedNetworkId.Span);
        Write(stream, nonce);
        Write(stream, created.BootId.Span);
        WriteU64(stream, created.SampleSeconds);

        if ((flags & RequestDirectoryFloorFlag) != 0)
        {
            WriteU64(stream, context.DirectoryLkgTreeSize!.Value);
            Write(stream, context.DirectoryLkgCoreHash.Span);
        }

        if (network is not null)
            WriteNetworkFloor(stream, network);
        if ((flags & RequestDirectoryLookupFlag) != 0)
            Write(stream, context.RequiredDirectoryLookupKey.Span);

        var encoded = stream.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(8, 4), checked((uint)encoded.Length));
        return encoded;
    }

    internal static HttpContactResolveDirectoryRequest DecodeRequest(ReadOnlySpan<byte> encoded)
    {
        var reader = new Reader(encoded);
        var flags = reader.ReadHeader(RequestMagic,
            RequestDirectoryFloorFlag | RequestNetworkFloorFlag | RequestDirectoryLookupFlag);
        var networkId = reader.ReadFixed(16, nonZero: true, "network ID");
        var nonce = reader.ReadFixed(32, nonZero: true, "nonce");
        var bootId = reader.ReadFixed(16, nonZero: true, "boot ID");
        var createdAt = reader.ReadU64();

        ulong? directoryTreeSize = null;
        byte[]? directoryCoreHash = null;
        if ((flags & RequestDirectoryFloorFlag) != 0)
        {
            directoryTreeSize = reader.ReadU64();
            directoryCoreHash = reader.ReadFixed(32, nonZero: true, "directory LKG core hash");
        }

        XPointNetworkProtectedLkg? networkLkg = null;
        if ((flags & RequestNetworkFloorFlag) != 0)
            networkLkg = ReadNetworkFloor(ref reader, networkId);
        byte[]? requiredDirectoryLookupKey = null;
        if ((flags & RequestDirectoryLookupFlag) != 0)
            requiredDirectoryLookupKey = reader.ReadFixed(
                32, nonZero: true, "required directory lookup key");
        reader.EnsureComplete();

        return new HttpContactResolveDirectoryRequest
        {
            NetworkId = networkId,
            Nonce = nonce,
            BootId = bootId,
            NonceCreatedAt = createdAt,
            DirectoryTreeSize = directoryTreeSize,
            DirectoryCoreHash = directoryCoreHash,
            RequiredDirectoryLookupKey = requiredDirectoryLookupKey,
            NetworkLkg = networkLkg,
        };
    }

    internal static ContactResolveDirectoryArtifacts DecodeResponse(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedNetworkId,
        ReadOnlySpan<byte> expectedNonce,
        OnionMonotonicReading requestCreated,
        OnionMonotonicReading responseReceived,
        OnionMonotonicReading current)
    {
        ArgumentNullException.ThrowIfNull(requestCreated);
        ArgumentNullException.ThrowIfNull(responseReceived);
        ArgumentNullException.ThrowIfNull(current);
        var reader = new Reader(encoded);
        var flags = reader.ReadHeader(ResponseMagic, ResponseForwardFlag);
        var networkId = reader.ReadFixed(16, nonZero: true, "network ID");
        var nonce = reader.ReadFixed(32, nonZero: true, "nonce");
        var bootId = reader.ReadFixed(16, nonZero: true, "boot ID");
        var nonceCreatedAt = reader.ReadU64();
        var leafKey = reader.ReadFixed(32, nonZero: true, "directory leaf key");

        RequireExact(networkId, expectedNetworkId, "response network ID");
        RequireExact(nonce, expectedNonce, "response nonce");
        RequireExact(bootId, requestCreated.BootId.Span, "response monotonic boot ID");
        if (nonceCreatedAt != requestCreated.SampleSeconds)
            throw new FormatException("The response does not echo the local nonce creation sample.");
        RequireExact(responseReceived.BootId.Span, requestCreated.BootId.Span,
            "response-received monotonic boot ID");
        RequireExact(current.BootId.Span, requestCreated.BootId.Span,
            "current monotonic boot ID");
        if (responseReceived.SampleSeconds < requestCreated.SampleSeconds
            || current.SampleSeconds < responseReceived.SampleSeconds)
            throw new FormatException("The local monotonic request window is not ordered.");

        var xna = reader.ReadChain(ContactResolveDirectoryArtifacts.MaximumChainArtifacts, "XNA1");
        var dts = reader.ReadChain(ContactResolveDirectoryArtifacts.MaximumChainArtifacts, "DTS1");
        var adh = reader.ReadArtifact("ADH1");
        var dtt = reader.ReadArtifact("DTT1");
        var adp = reader.ReadArtifact("ADP1");
        var xvp = reader.ReadChain(ContactResolveDirectoryArtifacts.MaximumChainArtifacts, "XVP1");
        var xnv = reader.ReadChain(ContactResolveDirectoryArtifacts.MaximumChainArtifacts, "XNV1");
        var xnh = reader.ReadChain(ContactResolveDirectoryArtifacts.MaximumChainArtifacts, "XNH1");
        var xnd = reader.ReadChain(ContactResolveDirectoryArtifacts.MaximumChainArtifacts, "XND1");
        var pmt = reader.ReadChain(ContactResolveDirectoryArtifacts.MaximumChainArtifacts, "PMT2");

        ContactResolveForwardCheckpointArtifacts? forward = null;
        if ((flags & ResponseForwardFlag) != 0)
        {
            forward = new ContactResolveForwardCheckpointArtifacts(
                reader.ReadChain(64, "XNF1"),
                reader.ReadArtifact("NFP1"),
                reader.ReadArtifact("target XNV1"),
                reader.ReadArtifact("target XNH1"));
        }
        reader.EnsureComplete();

        try
        {
            return new ContactResolveDirectoryArtifacts(
                xna, dts, adh, dtt, adp, nonce, leafKey,
                new AccountDirectoryMonotonicRequestWindow(
                    requestCreated.BootId.Span,
                    requestCreated.SampleSeconds,
                    responseReceived.SampleSeconds,
                    current.SampleSeconds),
                xvp, xnv, xnh, xnd, pmt, forward);
        }
        catch (ArgumentException exception)
        {
            throw new FormatException("The ContactResolve directory envelope has an invalid package shape.", exception);
        }
    }

    internal static byte[] EncodeResponseForTest(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> echoedNonce,
        ReadOnlySpan<byte> echoedBootId,
        ulong echoedNonceCreatedAt,
        ContactResolveDirectoryArtifacts artifacts)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        var flags = artifacts.ForwardCheckpoint is null ? (ushort)0 : ResponseForwardFlag;
        using var stream = new MemoryStream();
        WriteHeader(stream, ResponseMagic, flags, 0);
        Write(stream, networkId);
        Write(stream, echoedNonce);
        Write(stream, echoedBootId);
        WriteU64(stream, echoedNonceCreatedAt);
        Write(stream, artifacts.QueriedDirectoryLeafKey.Span);
        WriteChain(stream, artifacts.ExactXna1AuthorityChain);
        WriteChain(stream, artifacts.ExactDts1PolicyChain);
        WriteArtifact(stream, artifacts.ExactAdh1.Span);
        WriteArtifact(stream, artifacts.ExactDtt1.Span);
        WriteArtifact(stream, artifacts.ExactAdp1.Span);
        WriteChain(stream, artifacts.ExactOrderedXvp1Chain);
        WriteChain(stream, artifacts.ExactOrderedXnv1Chain);
        WriteChain(stream, artifacts.ExactOrderedXnh1Chain);
        WriteChain(stream, artifacts.ExactActiveXnd1);
        WriteChain(stream, artifacts.ExactOrderedPmt2Chain);
        if (artifacts.ForwardCheckpoint is { } forward)
        {
            WriteChain(stream, forward.ExactOrderedXnf1Chain);
            WriteArtifact(stream, forward.ExactNfp1.Span);
            WriteArtifact(stream, forward.ExactTargetXnv1.Span);
            WriteArtifact(stream, forward.ExactTargetXnh1.Span);
        }

        var encoded = stream.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(8, 4), checked((uint)encoded.Length));
        return encoded;
    }

    private static void WriteNetworkFloor(Stream stream, XPointNetworkProtectedLkg value)
    {
        Write(stream, value.HeadCoreReference.Span);
        WriteU64(stream, value.HeadTreeSize);
        Write(stream, value.HeadRoot.Span);
        Write(stream, value.ViewCoreReference.Span);
        WriteU64(stream, value.ViewGeneration);
        Write(stream, value.AuthorityCoreReference.Span);
        stream.WriteByte(value.LastForwardCheckpointGeneration.HasValue ? (byte)1 : (byte)0);
        if (value.LastForwardCheckpointGeneration.HasValue)
        {
            Write(stream, value.LastForwardCheckpointCoreReference.Span);
            WriteU64(stream, value.LastForwardCheckpointGeneration.Value);
        }
    }

    private static XPointNetworkProtectedLkg ReadNetworkFloor(ref Reader reader, ReadOnlySpan<byte> networkId)
    {
        var head = reader.ReadFixed(38, nonZero: true, "XNH1 floor reference");
        var treeSize = reader.ReadU64();
        var root = reader.ReadFixed(32, nonZero: true, "XNH1 floor root");
        var view = reader.ReadFixed(38, nonZero: true, "XNV1 floor reference");
        var generation = reader.ReadU64();
        var authority = reader.ReadFixed(38, nonZero: true, "XNA1 floor reference");
        var checkpointPresence = reader.ReadByte();
        if (checkpointPresence > 1)
            throw new FormatException("The network checkpoint floor presence flag is invalid.");
        var checkpoint = checkpointPresence == 1
            ? reader.ReadFixed(38, nonZero: true, "XNF1 floor reference")
            : [];
        ulong? checkpointGeneration = checkpointPresence == 1 ? reader.ReadU64() : null;
        try
        {
            return new XPointNetworkProtectedLkg(
                networkId.ToArray(), head, treeSize, root, view, generation, authority,
                checkpoint, checkpointGeneration);
        }
        catch (ArgumentException exception)
        {
            throw new FormatException("The protected network LKG floor is malformed.", exception);
        }
    }

    private static void WriteHeader(Stream stream, byte[] magic, ushort flags, uint length)
    {
        Write(stream, magic);
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(header, Version);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], flags);
        BinaryPrimitives.WriteUInt32BigEndian(header[4..], length);
        Write(stream, header);
    }

    private static void WriteChain(Stream stream, IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        WriteU32(stream, checked((uint)values.Count));
        foreach (var value in values)
            WriteArtifact(stream, value.Span);
    }

    private static void WriteArtifact(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteU32(stream, checked((uint)value.Length));
        Write(stream, value);
    }

    private static void WriteU32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        Write(stream, bytes);
    }

    private static void WriteU64(Stream stream, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        Write(stream, bytes);
    }

    private static void Write(Stream stream, ReadOnlySpan<byte> value) => stream.Write(value);

    private static void RequireNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"The {name} must be exactly {length} non-zero bytes.", name);
    }

    private static void RequireExact(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (actual.Length != expected.Length
            || !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw new FormatException($"The {name} does not match the local request.");
    }

    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> value;
        private int offset;

        internal Reader(ReadOnlySpan<byte> value)
        {
            if (value.Length > AbsoluteMaximumEnvelopeBytes)
                throw new FormatException("The ContactResolve directory envelope exceeds its absolute limit.");
            this.value = value;
            offset = 0;
        }

        internal ushort ReadHeader(ReadOnlySpan<byte> expectedMagic, ushort allowedFlags)
        {
            if (value.Length < 12)
                throw new FormatException("The ContactResolve directory envelope is truncated.");
            if (!ReadSpan(4).SequenceEqual(expectedMagic)
                || BinaryPrimitives.ReadUInt16BigEndian(ReadSpan(2)) != Version)
                throw new FormatException("The ContactResolve directory envelope header is invalid.");
            var flags = BinaryPrimitives.ReadUInt16BigEndian(ReadSpan(2));
            if ((flags & ~allowedFlags) != 0)
                throw new FormatException("The ContactResolve directory envelope has unknown flags.");
            var declared = BinaryPrimitives.ReadUInt32BigEndian(ReadSpan(4));
            if (declared != value.Length)
                throw new FormatException("The ContactResolve directory envelope length is not canonical.");
            return flags;
        }

        internal byte ReadByte() => ReadSpan(1)[0];
        internal ulong ReadU64() => BinaryPrimitives.ReadUInt64BigEndian(ReadSpan(8));

        internal byte[] ReadFixed(int length, bool nonZero, string name)
        {
            var result = ReadSpan(length);
            if (nonZero && result.IndexOfAnyExcept((byte)0) < 0)
                throw new FormatException($"The {name} must be non-zero.");
            return result.ToArray();
        }

        internal byte[] ReadArtifact(string name)
        {
            var length = ReadLength(name);
            if (length is 0 or > ContactResolveDirectoryArtifacts.MaximumSingleArtifactBytes)
                throw new FormatException($"The {name} length is outside the allowed artifact bound.");
            return ReadSpan(length).ToArray();
        }

        internal IReadOnlyList<ReadOnlyMemory<byte>> ReadChain(int maximumCount, string name)
        {
            var countValue = BinaryPrimitives.ReadUInt32BigEndian(ReadSpan(4));
            if (countValue is 0 || countValue > maximumCount)
                throw new FormatException($"The {name} chain count is outside its bound.");
            var count = checked((int)countValue);
            var result = new ReadOnlyMemory<byte>[count];
            for (var index = 0; index < count; index++)
                result[index] = ReadArtifact(name);
            return Array.AsReadOnly(result);
        }

        internal void EnsureComplete()
        {
            if (offset != value.Length)
                throw new FormatException("The ContactResolve directory envelope has trailing bytes.");
        }

        private int ReadLength(string name)
        {
            var value = BinaryPrimitives.ReadUInt32BigEndian(ReadSpan(4));
            if (value > int.MaxValue)
                throw new FormatException($"The {name} length cannot be represented locally.");
            return (int)value;
        }

        private ReadOnlySpan<byte> ReadSpan(int length)
        {
            if (length < 0 || offset > value.Length - length)
                throw new FormatException("The ContactResolve directory envelope is truncated.");
            var result = value.Slice(offset, length);
            offset += length;
            return result;
        }
    }
}
