using System.Reflection;
using System.Runtime.CompilerServices;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.MessagingV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Tests.MessagingV1;

public sealed class DeepDirectMessagingPreKeyClaimCoordinatorSurfaceTests
{
    [Fact]
    public void PublicSurfaceAcceptsOnlyProtectedAuthoritiesAndOpaqueClaimStart()
    {
        var constructor = Assert.Single(
            typeof(DeepDirectMessagingPreKeyClaimCoordinator).GetConstructors());
        Assert.Equal(
            [
                typeof(SqliteXpk1ClaimJournal),
                typeof(PrivacyRoutedContactResolverTransport),
                typeof(IContactResolvePathAuthoritySource),
                typeof(OnionTrustedTimeAuthority),
                typeof(ContactResolverReverifiedPeerAuthority),
            ],
            constructor.GetParameters()
                .Select(static parameter => parameter.ParameterType)
                .ToArray());

        var method = typeof(DeepDirectMessagingPreKeyClaimCoordinator).GetMethod(
            nameof(DeepDirectMessagingPreKeyClaimCoordinator.ClaimAsync));
        Assert.NotNull(method);
        Assert.Equal(
            [typeof(DeepDirectMessagingInitiatorClaimStart), typeof(CancellationToken)],
            method.GetParameters()
                .Select(static parameter => parameter.ParameterType)
                .ToArray());
        Assert.DoesNotContain(method.GetParameters(), static parameter =>
            parameter.ParameterType == typeof(byte[]) ||
            parameter.ParameterType == typeof(ReadOnlyMemory<byte>) ||
            parameter.ParameterType == typeof(bool));
    }

    [Fact]
    public async Task CancellationFailsBeforeAnyProtectedAuthorityIsTouched()
    {
        var coordinator = new DeepDirectMessagingPreKeyClaimCoordinator(
            Uninitialized<SqliteXpk1ClaimJournal>(),
            Uninitialized<PrivacyRoutedContactResolverTransport>(),
            new ThrowingPathAuthority(),
            Uninitialized<OnionTrustedTimeAuthority>(),
            Uninitialized<ContactResolverReverifiedPeerAuthority>());
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await coordinator.ClaimAsync(
                Uninitialized<DeepDirectMessagingInitiatorClaimStart>(),
                cancellation.Token));
    }

    private static T Uninitialized<T>() where T : class =>
        (T)RuntimeHelpers.GetUninitializedObject(typeof(T));

    private sealed class ThrowingPathAuthority : IContactResolvePathAuthoritySource
    {
        public ValueTask<ContactResolvePathAuthority> GetCurrentAsync(
            Deep.Protocol.ContactV1.Xiq1Request request,
            CancellationToken cancellationToken) =>
            throw new Xunit.Sdk.XunitException("Path authority must not run after cancellation.");
    }
}
