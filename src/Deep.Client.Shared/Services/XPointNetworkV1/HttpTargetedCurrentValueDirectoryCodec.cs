using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.XPointNetworkV1;

internal sealed class HttpTargetedCurrentValueDirectoryRequest
{
    internal required byte[] ExactAdl1 { get; init; }
    internal required byte[] NetworkId { get; init; }
    internal required byte[] DirectoryLookupKey { get; init; }
    internal required byte[] Nonce { get; init; }
    internal required byte[] BootId { get; init; }
    internal required ulong NonceCreatedAt { get; init; }
}

/// <summary>
/// Transport-only framing for Registry's targeted current-value endpoint.
/// Decoding validates request echoes and bounds but does not project authority.
/// </summary>
internal static class HttpTargetedCurrentValueDirectoryCodec
{
    internal const ushort Version = 1;
    internal const int ExactAdl1Bytes = 228;
    internal const int RequestBytes = 2 + ExactAdl1Bytes + 32 + 16 + 8;
    internal const int AbsoluteMaximumEnvelopeBytes =
        (int)ContactResolveDirectoryArtifacts.MaximumPackageBytes + 256;
    internal const string RequestMediaType =
        "application/vnd.deep.directory-current-value-request.v1+octet-stream";
    internal const string ResponseMediaType =
        "application/vnd.deep.directory-current-value.v1+octet-stream";

    private const int ResponseFixedBytes = 2 + 2 + 4 + 16 + 32 + 32 + 16 + 8;
    private const int ArtifactCount = 8;

    internal static byte[] EncodeRequest(
        ContactResolveDirectoryFetchContext context,
        ReadOnlySpan<byte> nonce,
        OnionMonotonicReading created)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(created);
        RequireNonZero(context.ExpectedNetworkId.Span, 16, "expected network ID");
        RequireNonZero(context.RequiredDirectoryLookupKey.Span, 32, "required directory lookup key");
        RequireNonZero(nonce, 32, "request nonce");
        RequireNonZero(created.BootId.Span, 16, "monotonic boot ID");
        if (context.DirectoryLkgLogGeneration is not { } generation ||
            context.DirectoryLkgCoreHash.Length != 32)
            throw new InvalidOperationException(
                "A targeted current-value request requires a protected account-directory LKG floor.");
        RequireNonZero(context.DirectoryLkgCoreHash.Span, 32, "directory LKG core hash");

        var exactAdl1 = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
            context.ExpectedNetworkId.Span,
            context.RequiredDirectoryLookupKey.Span,
            generation,
            context.DirectoryLkgCoreHash.Span,
            serviceProfile: 1,
            new byte[38],
            new byte[32]));
        try
        {
            if (exactAdl1.Length != ExactAdl1Bytes)
                throw new InvalidOperationException("The generated ADL1 request is not exact-length canonical.");
            var result = GC.AllocateUninitializedArray<byte>(RequestBytes);
            BinaryPrimitives.WriteUInt16BigEndian(result, Version);
            exactAdl1.CopyTo(result, 2);
            nonce.CopyTo(result.AsSpan(2 + ExactAdl1Bytes, 32));
            created.BootId.Span.CopyTo(result.AsSpan(2 + ExactAdl1Bytes + 32, 16));
            BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(RequestBytes - 8), created.SampleSeconds);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactAdl1);
        }
    }

    internal static HttpTargetedCurrentValueDirectoryRequest DecodeRequest(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != RequestBytes ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded) != Version)
            throw new FormatException("The targeted current-value request is not canonical.");
        var exactAdl1 = encoded.Slice(2, ExactAdl1Bytes).ToArray();
        var adl1 = AccountDirectoryAdl1Codec.Decode(exactAdl1);
        if (!encoded.Slice(2, ExactAdl1Bytes).SequenceEqual(AccountDirectoryAdl1Codec.Encode(adl1)))
            throw new FormatException("The targeted current-value ADL1 is not byte-canonical.");
        var nonce = encoded.Slice(2 + ExactAdl1Bytes, 32).ToArray();
        var bootId = encoded.Slice(2 + ExactAdl1Bytes + 32, 16).ToArray();
        RequireNonZero(nonce, 32, "request nonce");
        RequireNonZero(bootId, 16, "monotonic boot ID");
        return new HttpTargetedCurrentValueDirectoryRequest
        {
            ExactAdl1 = exactAdl1,
            NetworkId = adl1.NetworkId.ToArray(),
            DirectoryLookupKey = adl1.DirectoryLookupKey.ToArray(),
            Nonce = nonce,
            BootId = bootId,
            NonceCreatedAt = BinaryPrimitives.ReadUInt64BigEndian(encoded[^8..]),
        };
    }

    internal static ContactResolveDirectoryArtifacts DecodeResponse(
        ReadOnlySpan<byte> encoded,
        ContactResolveDirectoryFetchContext context,
        ReadOnlySpan<byte> expectedNonce,
        OnionMonotonicReading requestCreated,
        OnionMonotonicReading responseReceived,
        OnionMonotonicReading current)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestCreated);
        ArgumentNullException.ThrowIfNull(responseReceived);
        ArgumentNullException.ThrowIfNull(current);
        if (encoded.Length < ResponseFixedBytes + (ArtifactCount * 4) ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded) != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded[2..]) != 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(encoded[4..]) != (uint)encoded.Length)
            throw new FormatException("The targeted current-value response header is invalid.");

        var offset = 8;
        var networkId = ReadFixed(encoded, ref offset, 16, "network ID");
        var lookupKey = ReadFixed(encoded, ref offset, 32, "directory lookup key");
        var nonce = ReadFixed(encoded, ref offset, 32, "nonce");
        var bootId = ReadFixed(encoded, ref offset, 16, "boot ID");
        var nonceCreatedAt = ReadU64(encoded, ref offset);
        RequireExact(networkId, context.ExpectedNetworkId.Span, "response network ID");
        RequireExact(lookupKey, context.RequiredDirectoryLookupKey.Span, "response directory lookup key");
        RequireExact(nonce, expectedNonce, "response nonce");
        RequireExact(bootId, requestCreated.BootId.Span, "response monotonic boot ID");
        if (nonceCreatedAt != requestCreated.SampleSeconds)
            throw new FormatException("The targeted response does not echo the request sample.");
        ValidateMonotonicWindow(requestCreated, responseReceived, current);

        var artifacts = new byte[ArtifactCount][];
        for (var index = 0; index < artifacts.Length; index++)
            artifacts[index] = ReadArtifact(encoded, ref offset);
        if (offset != encoded.Length)
            throw new FormatException("The targeted current-value response has trailing bytes.");

        try
        {
            return new ContactResolveDirectoryArtifacts(
                [artifacts[0]], [artifacts[1]], artifacts[2], artifacts[3], artifacts[4],
                nonce, lookupKey,
                new AccountDirectoryMonotonicRequestWindow(
                    requestCreated.BootId.Span,
                    requestCreated.SampleSeconds,
                    responseReceived.SampleSeconds,
                    current.SampleSeconds),
                [], [artifacts[5]], [artifacts[6]], [], [artifacts[7]], null);
        }
        catch (ArgumentException exception)
        {
            throw new FormatException("The targeted current-value response has an invalid package shape.", exception);
        }
    }

    internal static byte[] EncodeResponseForTest(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> lookupKey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> bootId,
        ulong nonceCreatedAt,
        ContactResolveDirectoryArtifacts artifacts)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        using var stream = new MemoryStream();
        WriteU16(stream, Version);
        WriteU16(stream, 0);
        WriteU32(stream, 0);
        stream.Write(networkId);
        stream.Write(lookupKey);
        stream.Write(nonce);
        stream.Write(bootId);
        WriteU64(stream, nonceCreatedAt);
        WriteArtifact(stream, artifacts.ExactXna1AuthorityChain[^1].Span);
        WriteArtifact(stream, artifacts.ExactDts1PolicyChain[^1].Span);
        WriteArtifact(stream, artifacts.ExactAdh1.Span);
        WriteArtifact(stream, artifacts.ExactDtt1.Span);
        WriteArtifact(stream, artifacts.ExactAdp1.Span);
        WriteArtifact(stream, artifacts.ExactOrderedXnv1Chain[^1].Span);
        WriteArtifact(stream, artifacts.ExactOrderedXnh1Chain[^1].Span);
        WriteArtifact(stream, artifacts.ExactOrderedPmt2Chain[^1].Span);
        var result = stream.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4), checked((uint)result.Length));
        return result;
    }

    private static byte[] ReadFixed(ReadOnlySpan<byte> encoded, ref int offset, int length, string name)
    {
        if (encoded.Length - offset < length)
            throw new FormatException($"The targeted response {name} is truncated.");
        var result = encoded.Slice(offset, length).ToArray();
        offset += length;
        RequireNonZero(result, length, name);
        return result;
    }

    private static ulong ReadU64(ReadOnlySpan<byte> encoded, ref int offset)
    {
        if (encoded.Length - offset < 8)
            throw new FormatException("The targeted response sample is truncated.");
        var result = BinaryPrimitives.ReadUInt64BigEndian(encoded[offset..]);
        offset += 8;
        return result;
    }

    private static byte[] ReadArtifact(ReadOnlySpan<byte> encoded, ref int offset)
    {
        if (encoded.Length - offset < 4)
            throw new FormatException("A targeted response artifact length is truncated.");
        var length = BinaryPrimitives.ReadUInt32BigEndian(encoded[offset..]);
        offset += 4;
        if (length == 0 || length > ContactResolveDirectoryArtifacts.MaximumSingleArtifactBytes ||
            length > (uint)(encoded.Length - offset))
            throw new FormatException("A targeted response artifact is outside its bound.");
        var result = encoded.Slice(offset, checked((int)length)).ToArray();
        offset += checked((int)length);
        return result;
    }

    private static void ValidateMonotonicWindow(
        OnionMonotonicReading created,
        OnionMonotonicReading received,
        OnionMonotonicReading current)
    {
        RequireExact(received.BootId.Span, created.BootId.Span, "response-received monotonic boot ID");
        RequireExact(current.BootId.Span, created.BootId.Span, "current monotonic boot ID");
        if (received.SampleSeconds < created.SampleSeconds || current.SampleSeconds < received.SampleSeconds)
            throw new FormatException("The local monotonic request window is not ordered.");
    }

    private static void WriteArtifact(Stream stream, ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty || value.Length > ContactResolveDirectoryArtifacts.MaximumSingleArtifactBytes)
            throw new ArgumentException("A targeted response artifact is outside its bound.", nameof(value));
        WriteU32(stream, checked((uint)value.Length));
        stream.Write(value);
    }

    private static void WriteU16(Stream stream, ushort value)
    {
        Span<byte> encoded = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static void WriteU32(Stream stream, uint value)
    {
        Span<byte> encoded = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static void WriteU64(Stream stream, ulong value)
    {
        Span<byte> encoded = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static void RequireNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException($"The targeted current-value {name} is invalid.");
    }

    private static void RequireExact(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw new FormatException($"The targeted current-value {name} does not match the request.");
    }
}
