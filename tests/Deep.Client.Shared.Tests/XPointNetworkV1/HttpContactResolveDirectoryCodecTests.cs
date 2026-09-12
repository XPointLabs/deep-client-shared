using System.Reflection;
using System.Runtime.CompilerServices;
using Deep.Client.Shared.Domain.AccountDirectoryV1;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Tests.XPointNetworkV1;

public sealed class HttpContactResolveDirectoryCodecTests
{
    [Fact]
    public void Request_RoundTripsExactPublicRollbackFloorsWithoutArtifactBytes()
    {
        var directoryState = DirectoryState(treeSize: 17, hashMarker: 0x31);
        var networkLkg = NetworkLkg(withCheckpoint: true);
        var context = new ContactResolveDirectoryFetchContext(
            B(16, 0x11), directoryState, new XPointNetworkStateSnapshot(3, networkLkg, false));
        var nonce = B(32, 0x41);
        var reading = new OnionMonotonicReading(B(16, 0x51), 99);

        var encoded = HttpContactResolveDirectoryCodec.EncodeRequest(context, nonce, reading);
        var decoded = HttpContactResolveDirectoryCodec.DecodeRequest(encoded);

        Assert.Equal(B(16, 0x11), decoded.NetworkId);
        Assert.Equal(nonce, decoded.Nonce);
        Assert.Equal(B(16, 0x51), decoded.BootId);
        Assert.Equal(99UL, decoded.NonceCreatedAt);
        Assert.Equal(17UL, decoded.DirectoryTreeSize);
        Assert.Equal(B(32, 0x31), decoded.DirectoryCoreHash);
        AssertNetworkLkg(networkLkg, Assert.IsType<XPointNetworkProtectedLkg>(decoded.NetworkLkg));
        Assert.DoesNotContain(directoryState.ProtectedLkg!.ExactAdh1.Span.ToArray(), encoded);
    }

    [Fact]
    public void Request_RoundTripsValidEmptyDirectoryGenesisFloor()
    {
        var directoryState = DirectoryState(treeSize: 0, hashMarker: 0x31);
        var context = new ContactResolveDirectoryFetchContext(
            B(16, 0x11), directoryState, null);
        var nonce = B(32, 0x41);
        var reading = new OnionMonotonicReading(B(16, 0x51), 99);

        var encoded = HttpContactResolveDirectoryCodec.EncodeRequest(context, nonce, reading);
        var decoded = HttpContactResolveDirectoryCodec.DecodeRequest(encoded);

        Assert.Equal(0UL, decoded.DirectoryTreeSize);
        Assert.Equal(B(32, 0x31), decoded.DirectoryCoreHash);
    }

    [Fact]
    public void TargetedCurrentValueRequest_RoundTripsExactAdl1LookupKey()
    {
        var lookupKey = B(32, 0x67);
        var context = new ContactResolveDirectoryFetchContext(
            B(16, 0x11), null, null, lookupKey);

        var encoded = HttpContactResolveDirectoryCodec.EncodeRequest(
            context, B(32, 0x41), new OnionMonotonicReading(B(16, 0x51), 99));
        var decoded = HttpContactResolveDirectoryCodec.DecodeRequest(encoded);

        Assert.Equal(lookupKey, decoded.RequiredDirectoryLookupKey);
        Assert.Equal(lookupKey, context.RequiredDirectoryLookupKey.ToArray());
        var escaped = context.RequiredDirectoryLookupKey.ToArray();
        escaped[0] ^= 0xff;
        Assert.Equal(lookupKey, context.RequiredDirectoryLookupKey.ToArray());
    }

    [Fact]
    public void TargetedRegistryRequest_UsesExact286ByteCanonicalAdl1Framing()
    {
        var context = new ContactResolveDirectoryFetchContext(
            B(16, 0x11), DirectoryState(treeSize: 17, hashMarker: 0x31), null, B(32, 0x67));
        var nonce = B(32, 0x41);
        var reading = new OnionMonotonicReading(B(16, 0x51), 99);

        var encoded = HttpTargetedCurrentValueDirectoryCodec.EncodeRequest(context, nonce, reading);
        var decoded = HttpTargetedCurrentValueDirectoryCodec.DecodeRequest(encoded);
        var adl1 = AccountDirectoryAdl1Codec.Decode(decoded.ExactAdl1);

        Assert.Equal(HttpTargetedCurrentValueDirectoryCodec.RequestBytes, encoded.Length);
        Assert.Equal(286, encoded.Length);
        Assert.Equal(B(16, 0x11), decoded.NetworkId);
        Assert.Equal(B(32, 0x67), decoded.DirectoryLookupKey);
        Assert.Equal(nonce, decoded.Nonce);
        Assert.Equal(B(16, 0x51), decoded.BootId);
        Assert.Equal(99UL, decoded.NonceCreatedAt);
        Assert.Equal(2UL, adl1.MinimumAdhGeneration);
        Assert.Equal(B(32, 0x31), adl1.MinimumAdhHash.ToArray());
        Assert.Equal((ushort)1, adl1.ServiceProfile);
        Assert.All(adl1.ExactOhttpXod1CoreReference.ToArray(), value => Assert.Equal(0, value));
        Assert.All(adl1.ExactOhttpXod1CoreHash.ToArray(), value => Assert.Equal(0, value));
    }

    [Fact]
    public void TargetedRegistryRequest_RequiresProtectedDirectoryFloor()
    {
        var context = new ContactResolveDirectoryFetchContext(
            B(16, 0x11), null, null, B(32, 0x67));

        Assert.Throws<InvalidOperationException>(() =>
            HttpTargetedCurrentValueDirectoryCodec.EncodeRequest(
                context, B(32, 0x41), new OnionMonotonicReading(B(16, 0x51), 99)));
    }

    [Fact]
    public void TargetedRegistryResponse_RoundTripsOnlyTheExactCompactArtifactSet()
    {
        var package = Artifacts();
        var context = new ContactResolveDirectoryFetchContext(
            B(16, 0x11), DirectoryState(treeSize: 17, hashMarker: 0x31), null, B(32, 0x67));
        var nonce = B(32, 0x41);
        var boot = B(16, 0x51);
        var encoded = HttpTargetedCurrentValueDirectoryCodec.EncodeResponseForTest(
            context.ExpectedNetworkId.Span,
            context.RequiredDirectoryLookupKey.Span,
            nonce,
            boot,
            10,
            package);

        var decoded = HttpTargetedCurrentValueDirectoryCodec.DecodeResponse(
            encoded,
            context,
            nonce,
            new OnionMonotonicReading(boot, 10),
            new OnionMonotonicReading(boot, 11),
            new OnionMonotonicReading(boot, 12));

        Assert.Equal(package.ExactXna1AuthorityChain[^1].ToArray(), decoded.ExactXna1AuthorityChain.Single().ToArray());
        Assert.Equal(package.ExactDts1PolicyChain[^1].ToArray(), decoded.ExactDts1PolicyChain.Single().ToArray());
        Assert.Equal(package.ExactAdh1.ToArray(), decoded.ExactAdh1.ToArray());
        Assert.Equal(package.ExactDtt1.ToArray(), decoded.ExactDtt1.ToArray());
        Assert.Equal(package.ExactAdp1.ToArray(), decoded.ExactAdp1.ToArray());
        Assert.Empty(decoded.ExactOrderedXvp1Chain);
        Assert.Equal(package.ExactOrderedXnv1Chain[^1].ToArray(), decoded.ExactOrderedXnv1Chain.Single().ToArray());
        Assert.Equal(package.ExactOrderedXnh1Chain[^1].ToArray(), decoded.ExactOrderedXnh1Chain.Single().ToArray());
        Assert.Empty(decoded.ExactActiveXnd1);
        Assert.Equal(package.ExactOrderedPmt2Chain[^1].ToArray(), decoded.ExactOrderedPmt2Chain.Single().ToArray());
        Assert.Null(decoded.ForwardCheckpoint);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(4)]
    public void TargetedRegistryResponse_RejectsHostileHeaderFraming(int offset)
    {
        var context = new ContactResolveDirectoryFetchContext(
            B(16, 0x11), DirectoryState(treeSize: 17, hashMarker: 0x31), null, B(32, 0x67));
        var nonce = B(32, 0x41);
        var boot = B(16, 0x51);
        var encoded = HttpTargetedCurrentValueDirectoryCodec.EncodeResponseForTest(
            context.ExpectedNetworkId.Span, context.RequiredDirectoryLookupKey.Span,
            nonce, boot, 10, Artifacts());
        encoded[offset] ^= 0x7f;

        Assert.Throws<FormatException>(() => HttpTargetedCurrentValueDirectoryCodec.DecodeResponse(
            encoded, context, nonce,
            new OnionMonotonicReading(boot, 10),
            new OnionMonotonicReading(boot, 11),
            new OnionMonotonicReading(boot, 12)));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public void TargetedCurrentValueRequest_RejectsMissingMalformedOrZeroLookupKey(int length)
    {
        var malformed = new byte[length];
        if (length > 0) malformed.AsSpan().Fill(0x61);
        Assert.Throws<ArgumentException>(() => new ContactResolveDirectoryFetchContext(
            B(16, 0x11), null, null, malformed));
    }

    [Fact]
    public void TargetedCurrentValueRequest_RejectsAllZeroLookupKey() =>
        Assert.Throws<ArgumentException>(() => new ContactResolveDirectoryFetchContext(
            B(16, 0x11), null, null, new byte[32]));

    [Fact]
    public void Response_RoundTripsEveryArtifactIncludingForwardRecoveryTarget()
    {
        var package = Artifacts(withForward: true);
        var network = B(16, 0x11);
        var nonce = B(32, 0x41);
        var boot = B(16, 0x51);
        var encoded = HttpContactResolveDirectoryCodec.EncodeResponseForTest(
            network, nonce, boot, 10, package);

        var decoded = HttpContactResolveDirectoryCodec.DecodeResponse(
            encoded, network, nonce,
            new OnionMonotonicReading(boot, 10),
            new OnionMonotonicReading(boot, 12),
            new OnionMonotonicReading(boot, 13));

        Assert.Equal(package.ExactXna1AuthorityChain[0].ToArray(), decoded.ExactXna1AuthorityChain[0].ToArray());
        Assert.Equal(package.ExactDts1PolicyChain[0].ToArray(), decoded.ExactDts1PolicyChain[0].ToArray());
        Assert.Equal(package.ExactAdh1.ToArray(), decoded.ExactAdh1.ToArray());
        Assert.Equal(package.ExactDtt1.ToArray(), decoded.ExactDtt1.ToArray());
        Assert.Equal(package.ExactAdp1.ToArray(), decoded.ExactAdp1.ToArray());
        Assert.Equal(package.ExactOrderedXvp1Chain[0].ToArray(), decoded.ExactOrderedXvp1Chain[0].ToArray());
        Assert.Equal(package.ExactOrderedXnv1Chain[0].ToArray(), decoded.ExactOrderedXnv1Chain[0].ToArray());
        Assert.Equal(package.ExactOrderedXnh1Chain[0].ToArray(), decoded.ExactOrderedXnh1Chain[0].ToArray());
        Assert.Equal(package.ExactActiveXnd1[0].ToArray(), decoded.ExactActiveXnd1[0].ToArray());
        Assert.Equal(package.ExactOrderedPmt2Chain[0].ToArray(), decoded.ExactOrderedPmt2Chain[0].ToArray());
        Assert.Equal(package.ForwardCheckpoint!.ExactOrderedXnf1Chain[0].ToArray(),
            decoded.ForwardCheckpoint!.ExactOrderedXnf1Chain[0].ToArray());
        Assert.Equal(package.ForwardCheckpoint.ExactNfp1.ToArray(), decoded.ForwardCheckpoint.ExactNfp1.ToArray());
        Assert.Equal(package.ForwardCheckpoint.ExactTargetXnv1.ToArray(), decoded.ForwardCheckpoint.ExactTargetXnv1.ToArray());
        Assert.Equal(package.ForwardCheckpoint.ExactTargetXnh1.ToArray(), decoded.ForwardCheckpoint.ExactTargetXnh1.ToArray());
        Assert.Equal(10UL, decoded.MonotonicRequestWindow.NonceCreatedAt);
        Assert.Equal(12UL, decoded.MonotonicRequestWindow.ResponseReceivedAt);
        Assert.Equal(13UL, decoded.MonotonicRequestWindow.CurrentSample);
    }

    [Fact]
    public void Response_RejectsTruncatedAndTrailingFrames()
    {
        var package = Artifacts();
        var network = B(16, 0x11);
        var nonce = B(32, 0x41);
        var boot = B(16, 0x51);
        var encoded = HttpContactResolveDirectoryCodec.EncodeResponseForTest(
            network, nonce, boot, 10, package);
        var readings = new[]
        {
            new OnionMonotonicReading(boot, 10),
            new OnionMonotonicReading(boot, 11),
            new OnionMonotonicReading(boot, 12),
        };

        Assert.Throws<FormatException>(() => HttpContactResolveDirectoryCodec.DecodeResponse(
            encoded.AsSpan(0, encoded.Length - 1), network, nonce, readings[0], readings[1], readings[2]));

        var trailing = encoded.Concat(new byte[] { 0x7f }).ToArray();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
            trailing.AsSpan(8, 4), checked((uint)trailing.Length));
        Assert.Throws<FormatException>(() => HttpContactResolveDirectoryCodec.DecodeResponse(
            trailing, network, nonce, readings[0], readings[1], readings[2]));
    }

    [Theory]
    [InlineData(0, 0x00)]
    [InlineData(5, 0x00)]
    [InlineData(6, 0x80)]
    public void Response_RejectsMalformedHeader(int offset, byte replacement)
    {
        var package = Artifacts();
        var network = B(16, 0x11);
        var nonce = B(32, 0x41);
        var boot = B(16, 0x51);
        var encoded = HttpContactResolveDirectoryCodec.EncodeResponseForTest(
            network, nonce, boot, 10, package);
        encoded[offset] = replacement;

        Assert.Throws<FormatException>(() => HttpContactResolveDirectoryCodec.DecodeResponse(
            encoded, network, nonce,
            new OnionMonotonicReading(boot, 10),
            new OnionMonotonicReading(boot, 11),
            new OnionMonotonicReading(boot, 12)));
    }

    internal static ContactResolveDirectoryArtifacts Artifacts(bool withForward = false) => new(
        [B(3, 0x01)],
        [B(4, 0x02)],
        B(5, 0x03),
        B(6, 0x04),
        B(7, 0x05),
        B(32, 0x41),
        B(32, 0x61),
        new AccountDirectoryMonotonicRequestWindow(B(16, 0x51), 10, 11, 12),
        [B(8, 0x06)],
        [B(9, 0x07)],
        [B(10, 0x08)],
        [B(11, 0x09)],
        [B(12, 0x0a)],
        withForward
            ? new ContactResolveForwardCheckpointArtifacts(
                [B(13, 0x0b)], B(14, 0x0c), B(15, 0x0d), B(16, 0x0e))
            : null);

    internal static byte[] B(int length, byte marker) => Enumerable.Repeat(marker, length).ToArray();

    internal static XPointNetworkProtectedLkg NetworkLkg(bool withCheckpoint = false) => new(
        B(16, 0x11),
        Reference("XNH1", 0x21),
        5,
        B(32, 0x22),
        Reference("XNV1", 0x23),
        4,
        Reference("XNA1", 0x24),
        withCheckpoint ? Reference("XNF1", 0x25) : default,
        withCheckpoint ? 3UL : null);

    internal static AccountDirectoryStateSnapshot DirectoryState(ulong treeSize, byte hashMarker)
    {
        var lkg = (AccountDirectoryProtectedLkgState)RuntimeHelpers.GetUninitializedObject(
            typeof(AccountDirectoryProtectedLkgState));
        Set(lkg, "exactAdh1", B(23, 0x71));
        Set(lkg, "coreHash", B(32, hashMarker));
        Set(lkg, "<LogGeneration>k__BackingField", 2UL);
        Set(lkg, "<TreeSize>k__BackingField", treeSize);
        return new AccountDirectoryStateSnapshot(1, lkg, false, []);
    }

    private static void AssertNetworkLkg(XPointNetworkProtectedLkg expected, XPointNetworkProtectedLkg actual)
    {
        Assert.Equal(expected.NetworkId.ToArray(), actual.NetworkId.ToArray());
        Assert.Equal(expected.HeadCoreReference.ToArray(), actual.HeadCoreReference.ToArray());
        Assert.Equal(expected.HeadTreeSize, actual.HeadTreeSize);
        Assert.Equal(expected.HeadRoot.ToArray(), actual.HeadRoot.ToArray());
        Assert.Equal(expected.ViewCoreReference.ToArray(), actual.ViewCoreReference.ToArray());
        Assert.Equal(expected.ViewGeneration, actual.ViewGeneration);
        Assert.Equal(expected.AuthorityCoreReference.ToArray(), actual.AuthorityCoreReference.ToArray());
        Assert.Equal(expected.LastForwardCheckpointCoreReference.ToArray(), actual.LastForwardCheckpointCoreReference.ToArray());
        Assert.Equal(expected.LastForwardCheckpointGeneration, actual.LastForwardCheckpointGeneration);
    }

    private static byte[] Reference(string magic, byte marker)
    {
        var value = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        value[5] = 1;
        value.AsSpan(6).Fill(marker);
        return value;
    }

    private static void Set(object target, string fieldName, object value) =>
        target.GetType().GetField(fieldName, BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(target, value);
}
