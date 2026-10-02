using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    private sealed partial class Fixture
    {
        private async Task CheckOwnedContactObjectAsync(byte[] intent, Did2ContactRouteConfiguration config, OwnedRouteThreshold threshold)
        {
            const string profile = "DID2 contact QA";
            var hit = false;
            using (Did2ContactRouteTestHooks.Push(point =>
            { if (point == Did2ContactRouteFailpoint.AfterContactObject) { hit = true; throw new IOException("Injected committed contact-object response loss."); } }))
                await Assert.ThrowsAsync<IOException>(() => EnsureObject(profile));
            Assert.True(hit); Assert.Equal(1, threshold.Calls);
            using (var state = await RouteState())
                Assert.Equal((byte)4, state.Entries[Convert.ToHexString(intent)].Phase);
            var snapshot = await RouteSnapshot();
            // Concurrent independent reopen callers must release one exact winner.
            var concurrent = await Task.WhenAll(EnsureObject(profile), EnsureObject(profile));
            var restored = concurrent[0]; var repeated = concurrent[1];
            Assert.Empty(typeof(AuthoredDeepIdV2ContactObject).GetConstructors());
            Assert.True(restored.ProtectedDcr1.Span.SequenceEqual(repeated.ProtectedDcr1.Span));
            Assert.True(restored.Closure.CanonicalBytes.Span.SequenceEqual(repeated.Closure.CanonicalBytes.Span));
            Assert.Equal(restored.Closure.CanonicalBytes.Length + 40, restored.ProtectedDcr1.Length);
            Assert.Equal(profile, System.Text.Encoding.UTF8.GetString(restored.Closure.Bundle.Field(15).Span));
            Assert.Equal(9u, BinaryPrimitives.ReadUInt32BigEndian(restored.Closure.Bundle.Field(16).Span));
            Assert.Equal(1, threshold.Calls);
            var after = await RouteSnapshot();
            try { Assert.True(snapshot.AsSpan().SequenceEqual(after)); }
            finally { CryptographicOperations.ZeroMemory(after); }
            await Assert.ThrowsAsync<CryptographicException>(() => EnsureObject("Changed profile"));

            var route = await EnsureRoute(intent, config, threshold, reopen: true);
            var capability = (await accounts.GetCurrentAsync())!.PermanentId.ResolverReadCapability.ToArray();
            try
            {
                var ciphertext = restored.ProtectedDcr1.ToArray(); ciphertext[^1] ^= 1;
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreAsync(
                    route, restored.Closure.CanonicalBytes, ciphertext, capability));
                var wrongCapability = capability.ToArray(); wrongCapability[0] ^= 1;
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreAsync(
                    route, restored.Closure.CanonicalBytes, restored.ProtectedDcr1, wrongCapability));
                CryptographicOperations.ZeroMemory(wrongCapability);
                var changed = restored.Closure.CanonicalBytes.ToArray(); changed[^1] ^= 1;
                await RequireRouteRejectionAsync(async () => await DeepIdV2ContactObjectAuthor.RestoreAsync(
                    route, changed, restored.ProtectedDcr1, capability));
                using var otherDevice = new OwnedGenesisDeviceSecrets();
                var staged = (await accounts.ReadOwnStagedPreKeyPublicationAsync())!;
                var services = new[] { DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span) };
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(
                    route, otherDevice, [services[0], services[0]], profile, capability));
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(
                    route, otherDevice, services, profile, capability));
                await Assert.ThrowsAsync<ArgumentException>(async () => await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(
                    route, otherDevice, services, new string('Ж', 65), capability));
                var badService = staged.ExactXps1.ToArray(); badService[^1] ^= 1;
                await RequireRouteRejectionAsync(async () => await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(
                    route, otherDevice, [DeepIdV2PreKeyServiceCodec.Decode(badService)], profile, capability));
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await DeepIdV2ContactObjectAuthor.RestoreAsync(
                    route, restored.Closure.CanonicalBytes, restored.ProtectedDcr1, capability, cancelled.Token));
                var mutablePlaintext = restored.Closure.CanonicalBytes.ToArray();
                var mutableCiphertext = restored.ProtectedDcr1.ToArray(); var mutableCapability = capability.ToArray();
                var mutate = false;
                var copyingClock = new CallbackRendezvousClock(() =>
                {
                    if (mutate) { Array.Clear(mutablePlaintext); Array.Clear(mutableCiphertext); Array.Clear(mutableCapability); }
                    return new(Boot, Sample);
                });
                var copyingRoute = await DeepIdV2ContactRouteVerifier.VerifyAsync(route.Recipient, route.Network, route.NetworkAuthority,
                    route.ExactXir1V2, route.ExactRouteClosure, new(copyingClock));
                mutate = true;
                var copied = await DeepIdV2ContactObjectAuthor.RestoreAsync(copyingRoute, mutablePlaintext, mutableCiphertext, mutableCapability);
                Assert.True(restored.ProtectedDcr1.Span.SequenceEqual(copied.ProtectedDcr1.Span));
                Assert.True(restored.Closure.CanonicalBytes.Span.SequenceEqual(copied.Closure.CanonicalBytes.Span));
                var reverseTime = false; var reads = 0;
                var reverseClock = new CallbackRendezvousClock(() => new(Boot,
                    reverseTime && ++reads == 1 ? Sample + 1 : Sample));
                var reverseRoute = await DeepIdV2ContactRouteVerifier.VerifyAsync(route.Recipient, route.Network, route.NetworkAuthority,
                    route.ExactXir1V2, route.ExactRouteClosure, new(reverseClock));
                reverseTime = true;
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactObjectAuthor.RestoreAsync(
                    reverseRoute, restored.Closure.CanonicalBytes, restored.ProtectedDcr1, capability));
                var oldSample = Sample;
                try
                {
                    Sample = route.Recipient.Freshness.FreshnessDeadlineMonotonicSeconds;
                    await RequireRouteRejectionAsync(async () => await DeepIdV2ContactObjectAuthor.RestoreAsync(
                        route, restored.Closure.CanonicalBytes, restored.ProtectedDcr1, capability));
                }
                finally { Sample = oldSample; }
            }
            finally { CryptographicOperations.ZeroMemory(capability); }

            // Authenticated corruption is rejected on reopen, not re-created.
            var damaged = snapshot.ToArray();
            // Later phases add empty LP32 records after ciphertext. Corrupt
            // the actual ciphertext, not the new journal framing trailer.
            var recordOffset = ProtectedDid2ContactRouteJournal.HeaderBytes + 4 + ProtectedDid2ContactRouteJournal.PrefixBytes;
            for (var index = 0; index <= 8; index++)
            {
                var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(damaged.AsSpan(recordOffset)));
                recordOffset += 4;
                if (index == 8) { Assert.True(length > 40); damaged[recordOffset + length - 1] ^= 1; break; }
                recordOffset += length;
            }
            try
            {
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, snapshot, damaged));
                await Assert.ThrowsAsync<CryptographicException>(() => EnsureObject(profile));
                Assert.Equal(1, threshold.Calls);
            }
            finally
            {
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, damaged, snapshot));
                CryptographicOperations.ZeroMemory(snapshot); CryptographicOperations.ZeroMemory(damaged);
            }
            Task<AuthoredDeepIdV2ContactObject> EnsureObject(string name)
            {
                var account = ReopenAccount();
                return account.EnsureOwnContactObjectAsync(intent, Source(account), config, threshold, name);
            }
        }
    }
}
