using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2KnownContactAddresses_ActualProtectedOwnerKeepsExactDescriptorsAfterEncryptedColdReopen()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckKnownContactAddressesAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckKnownContactAddressesAsync()
        {
            var address = (await peerAccounts!.GetCurrentAsync())!.PermanentId;
            var selector = new string('a', 64);
            Assert.Empty(await SenderCompactionOwner().KnownContactAddressesAsync(1_000, pq, null, default));
            var input = new Dictionary<string, DeepPermanentIdV2> { [selector] = address };
            Assert.Equal(address.CanonicalText, Assert.Single(await SenderCompactionOwner()
                .KnownContactAddressesAsync(1_000, pq, input, default)).Value.CanonicalText);
            input.Clear();
            ColdReopenCompactionStorage();
            var restored = await SenderCompactionOwner().KnownContactAddressesAsync(1_000, pq, null, default);
            Assert.Equal(selector.ToUpperInvariant(), Assert.Single(restored).Key);
            Assert.Equal(address.CanonicalText, restored.Values.Single().CanonicalText);
            using var before = await storage.ReadOwnedAsync(ProtectedKnownContactAddresses.Slot);
            var exact = before!.Use(bytes => bytes.ToArray());
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => SenderCompactionOwner()
                .KnownContactAddressesAsync(1_000, pq, new Dictionary<string, DeepPermanentIdV2>
                    { [new string('b', 64)] = address }, cancelled.Token));
            using var after = await storage.ReadOwnedAsync(ProtectedKnownContactAddresses.Slot);
            var previous = after!.Use(bytes => bytes.ToArray());
            Assert.Equal(exact, previous);
            // Data cannot be silently consumed under a different account instance.
            exact[52] ^= 1;
            Assert.True(await storage.CompareExchangeAsync(ProtectedKnownContactAddresses.Slot, previous, exact));
            ColdReopenCompactionStorage();
            await Assert.ThrowsAsync<InvalidDataException>(() => SenderCompactionOwner()
                .KnownContactAddressesAsync(1_000, pq, null, default));
        }
    }
}
