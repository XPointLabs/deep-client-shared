using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    private sealed partial class Fixture
    {
        private async Task CheckInitialDraftRootAsync(byte[] intent, ParsedDmc2 init, ParsedDmc2 hello,
            VerifiedDeepIdV2PermanentContactResolveClosure contact, DeepIdV2ContactPathAuthoritySource source)
        {
            using var key = await storage.ReadOwnedAsync("deep.store.v2.sql-generation");
            var instance = key!.Use(bytes => bytes.Slice(56, 32).ToArray());
            using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot);
            var exact = root!.Use(bytes => bytes.ToArray());
            var account = init.SenderAccountId.ToArray();
            try
            {
                using var state = ProtectedDid2ContactStartJournal.Decode(exact, Network, account, instance);
                var entry = Assert.Single(state.Entries).Value;
                Assert.Equal(intent, entry.Intent.ToArray());
                Assert.Equal(init.CanonicalBytes.ToArray(), entry.Init.ToArray());
                Assert.Equal(hello.CanonicalBytes.ToArray(), entry.Hello.ToArray());
                Assert.Equal(entry.Exact.Length, (int)BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(92)));
                foreach (var offset in new[] { 96 + 64, 96 + 224, 96 + 256 })
                {
                    var changed = exact.ToArray(); changed[offset] ^= 1;
                    Assert.Throws<CryptographicException>(() => ProtectedDid2ContactStartJournal.Decode(changed, Network, account, instance));
                }
                for (var offset = 0; offset < 288; offset += 32)
                {
                    var zero = exact.ToArray(); zero.AsSpan(96 + offset, 32).Clear();
                    Assert.ThrowsAny<Exception>(() => ProtectedDid2ContactStartJournal.Decode(zero, Network, account, instance));
                }
                var hostile = exact.ToArray(); BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(92), uint.MaxValue);
                Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactStartJournal.Decode(hostile, Network, account, instance));
                foreach (var lengthOffset in new[] { 96 + 288, 96 + 292 })
                {
                    var changed = exact.ToArray(); BinaryPrimitives.WriteUInt32BigEndian(changed.AsSpan(lengthOffset), uint.MaxValue);
                    Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactStartJournal.Decode(changed, Network, account, instance));
                }
                // A structurally valid substituted peer hash is not authority.
                // The owned command must compare it with the verified peer.
                var foreignPeer = exact.ToArray(); foreignPeer[96 + 32] ^= 1;
                using (var untrusted = ProtectedDid2ContactStartJournal.Decode(foreignPeer, Network, account, instance)) { }
                Assert.True(await storage.CompareExchangeAsync(ProtectedDid2ContactStartJournal.Slot, exact, foreignPeer));
                await Assert.ThrowsAsync<CryptographicException>(() => accounts.PrepareOwnInitialContactDraftAsync(intent, contact, source));
                Assert.True(await storage.CompareExchangeAsync(ProtectedDid2ContactStartJournal.Slot, foreignPeer, exact));
                await storage.DeleteBatchAsync([ProtectedDid2ContactStartJournal.Slot]);
                await Assert.ThrowsAsync<InvalidDataException>(() => ReopenAccount().GetCurrentAsync());
                await storage.WriteBatchAsync([new DeepSecureStorageWrite(ProtectedDid2ContactStartJournal.Slot, exact)]);
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => accounts.PrepareOwnInitialContactDraftAsync(intent, contact, source, cancelled.Token));
                using var readback = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot);
                Assert.Equal(exact, readback!.Use(bytes => bytes.ToArray()));
                state.Dispose(); Assert.Throws<ObjectDisposedException>(() => entry.Exact.ToArray());
            }
            finally { foreach (var bytes in new[] { instance, exact, account }) CryptographicOperations.ZeroMemory(bytes); }
        }
    }
}
