using Deep.Client.Shared.Services.AccountDirectoryV1;

namespace Deep.Client.Shared.Tests.Services.AccountDirectoryV1;

public sealed class AccountDirectoryBoundaryTests
{
    [Fact]
    public void TransportBoundary_ExposesOnlyExactOpaqueBytesAndCancellation()
    {
        var method = Assert.Single(typeof(IAccountDirectoryOpaqueTransport).GetMethods());
        Assert.Equal("ExchangeExactXoq1ForExactXor1Async", method.Name);
        Assert.Equal(typeof(ReadOnlyMemory<byte>), method.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(CancellationToken), method.GetParameters()[1].ParameterType);
        Assert.Equal(typeof(ValueTask<ReadOnlyMemory<byte>>), method.ReturnType);
        Assert.DoesNotContain(typeof(IAccountDirectoryOpaqueTransport).Assembly.GetTypes(), type =>
            typeof(IAccountDirectoryOpaqueTransport).IsAssignableFrom(type) && !type.IsInterface);
    }
}
