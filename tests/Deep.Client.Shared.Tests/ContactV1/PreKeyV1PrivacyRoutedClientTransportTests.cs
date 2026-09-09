using System.Net.Http;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Tests.ContactV1;

public sealed class PreKeyV1PrivacyRoutedClientTransportTests
{
    [Fact]
    public void DurableClaimRequiresExactCanonicalJournaledOperation()
    {
        var operationId = Bytes(32, 0x11);
        var exactXpk1 = Xpk1Codec.Encode(
            Bytes(16, 0x21),
            operationId,
            Bytes(32, 0x31),
            Bytes(32, 0x41),
            1_000,
            1_100,
            Bytes(32, 0x51),
            Bytes(32, 0x61),
            Bytes(32, 0x71),
            Bytes(32, 0x81),
            Bytes(32, 0x91));

        var durable = new PreKeyV1DurableClaimOperation(exactXpk1, operationId, 7);

        Assert.Equal(7UL, durable.JournalRevision);
        Assert.True(durable.OperationIdSpan.SequenceEqual(operationId));
        Assert.True(durable.ExactXpk1Span.SequenceEqual(exactXpk1));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new PreKeyV1DurableClaimOperation(exactXpk1, operationId, 0));
        Assert.Throws<CryptographicException>(() =>
            new PreKeyV1DurableClaimOperation(exactXpk1, Bytes(32, 0xa1), 7));

        exactXpk1[0] ^= 0xff;
        operationId[0] ^= 0xff;
        Assert.NotEqual(exactXpk1[0], durable.ExactXpk1Span[0]);
        Assert.NotEqual(operationId[0], durable.OperationIdSpan[0]);
    }

    [Fact]
    public async Task UncomposedClaimAdapterReportsNoProtocolCapabilityBlocker()
    {
        var operationId = Bytes(32, 0x12);
        var exactXpk1 = Xpk1Codec.Encode(
            Bytes(16, 0x22),
            operationId,
            Bytes(32, 0x32),
            Bytes(32, 0x42),
            2_000,
            2_100,
            Bytes(32, 0x52),
            Bytes(32, 0x62),
            Bytes(32, 0x72),
            Bytes(32, 0x82),
            Bytes(32, 0x92));
        var durable = new PreKeyV1DurableClaimOperation(exactXpk1, operationId, 1);

        var error = await Assert.ThrowsAsync<PreKeyV1PrivacyRouteCapabilityUnavailableException>(
            async () => await UnavailablePreKeyV1PrivacyRoutedClientTransport.Instance
                .ClaimPreKeyAsync(durable));

        Assert.Equal(PreKeyV1PrivacyRouteOperation.ClaimPreKey, error.Operation);
        Assert.Empty(error.Blockers);
    }

    [Fact]
    public void BoundedPublicationHasNoRemainingProtocolCapabilityBlocker()
    {
        var error = new PreKeyV1PrivacyRouteCapabilityUnavailableException(
            PreKeyV1PrivacyRouteOperation.PublishInventory);

        Assert.Equal(PreKeyV1PrivacyRouteOperation.PublishInventory, error.Operation);
        Assert.Empty(error.Blockers);
        Assert.True(Xpp1BoundedCodec.MaximumCanonicalRequestBytes <
            OnionLimits.MaximumCanonicalRequestBytes);
        Assert.Equal(65_945, Xpp1BoundedCodec.MaximumCanonicalRequestBytes);
        Assert.Contains(nameof(OnionOperation.ContactResolve), Enum.GetNames<OnionOperation>());
    }

    [Fact]
    public void ProtocolAlreadyPromotesExactXpk1ToTypedContactResolveRequest()
    {
        var networkId = Bytes(16, 0x24);
        var operationId = Bytes(32, 0x34);
        var exactXpk1 = Xpk1Codec.Encode(
            networkId,
            operationId,
            Bytes(32, 0x44),
            Bytes(32, 0x54),
            4_000,
            4_100,
            Bytes(32, 0x64),
            Bytes(32, 0x74),
            Bytes(32, 0x84),
            Bytes(32, 0x94),
            Bytes(32, 0xa4));
        var network = CreateNetwork(networkId);

        var verified = OnionTerminalPayloadVerifierV1.VerifyRequest(
            network,
            OnionOperation.ContactResolve,
            exactXpk1);

        Assert.Equal(OnionOperation.ContactResolve, verified.Operation);
        Assert.True(verified.CanonicalBytes.Span.SequenceEqual(exactXpk1));
    }

    [Fact]
    public void BoundaryCannotReturnRawXic1Xpc1OrDcb1Bytes()
    {
        var methods = typeof(IPreKeyV1PrivacyRoutedClientTransport).GetMethods();

        Assert.Collection(
            methods.OrderBy(static method => method.Name),
            method => Assert.Equal(
                typeof(ValueTask<VerifiedXpc1PreKeyClaimReceipt>),
                method.ReturnType),
            method => Assert.Equal(
                typeof(ValueTask<VerifiedPreKeyInventoryPublication>),
                method.ReturnType));

        Assert.DoesNotContain(
            methods.SelectMany(static method => method.GetParameters()),
            static parameter => parameter.ParameterType == typeof(byte[]) ||
                parameter.ParameterType == typeof(ReadOnlyMemory<byte>));
    }

    [Fact]
    public void FailClosedAdapterOwnsNoHttpOrAddressFallbackSurface()
    {
        var fields = typeof(UnavailablePreKeyV1PrivacyRoutedClientTransport)
            .GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        Assert.DoesNotContain(fields, static field =>
            typeof(HttpClient).IsAssignableFrom(field.FieldType) ||
            typeof(HttpMessageHandler).IsAssignableFrom(field.FieldType) ||
            field.FieldType == typeof(Uri) ||
            typeof(Delegate).IsAssignableFrom(field.FieldType));
    }

    [Fact]
    public async Task CancellationWinsBeforeCapabilityError()
    {
        var operationId = Bytes(32, 0x13);
        var exactXpk1 = Xpk1Codec.Encode(
            Bytes(16, 0x23), operationId, Bytes(32, 0x33), Bytes(32, 0x43),
            3_000, 3_100, Bytes(32, 0x53), Bytes(32, 0x63), Bytes(32, 0x73),
            Bytes(32, 0x83), Bytes(32, 0x93));
        var durable = new PreKeyV1DurableClaimOperation(exactXpk1, operationId, 1);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            async () => await UnavailablePreKeyV1PrivacyRoutedClientTransport.Instance
                .ClaimPreKeyAsync(durable, cancellation.Token));
    }

    private static byte[] Bytes(int length, byte seed) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index))).ToArray();

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedOnionNetworkContext CreateNetwork(ReadOnlySpan<byte> networkId);
}
