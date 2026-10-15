using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2PublicationLease_ReauthorizesExactExpiredIntentWithCurrentOwnerAndWitnesses()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckRetainedPublicationIntentAsync(5);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    public async Task Did2PublicationLease_HostileBytesCurrentScopeAndCallbacksFailClosed(int mode)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckRetainedPublicationIntentAsync(mode);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckPublicationLeaseAsync(int mode, VerifiedDeepIdV2OwnedPublicationIntent owned,
            VerifiedDeepIdV2IssuerPublicationIntent issuer, VerifiedDeepIdV2ContactRouteClosure route,
            OwnedGenesisDeviceSecrets device, Action<Action?> setCallback)
        {
            var request = await DeepIdV2PublicationLeaseAuthor.AuthorRequestAsync(owned, device);
            var lease = await DeepIdV2PublicationLeaseAuthor.AuthorThresholdAsync(issuer, request, PublicationLeaseWitnesses());
            var exact = lease.CanonicalBytes.ToArray();
            var original = lease.OriginalRequest;
            Assert.True(request.IssuedAtUnixSeconds > original.ExpiresAtUnixSeconds);
            Assert.Equal(original.RequestHash.ToArray(), owned.RequestHash.ToArray());
            var response = DeepIdV2PublicationLeaseWireCodec.EncodeResponse(request, exact);
            Assert.Equal(exact, DeepIdV2PublicationLeaseWireCodec.DecodeResponse(request, response).CanonicalBytes.ToArray());
            var capability = await DeepIdV2PublicationLeaseAuthor.VerifyOwnedResponseAsync(owned, request, exact);
            await capability.EnsureCurrentAsync();
            Assert.Equal(original.CanonicalBytes.ToArray(), Xpu1Codec.Decode(
                DeepIdV2PublicationLeaseCodec.Decode(capability.ExactDispatchRequest.Span).OriginalRequest.CanonicalBytes.Span).CanonicalBytes.ToArray());
            Assert.Equal(original.RequestHash.ToArray(), capability.RequestHash.ToArray());
            Assert.Equal(original.OperationId.ToArray(), capability.OperationId.ToArray());
            Assert.Equal(original.Generation, capability.Generation);
            Assert.Equal(original.ExactXpa1.ToArray(), capability.ExactXpa1.ToArray());

            if (mode == 6)
            {
                var hostile = new List<byte[]> { Array.Empty<byte>(), exact[..^1], exact.Append((byte)1).ToArray(), new byte[DeepIdV2PublicationLeaseCodec.MaximumBytes + 1] };
                foreach (var offset in new[] { 4, 6, 8, 10, 12, FieldOffset(exact, 2), FieldOffset(exact, 9) + 20 })
                { var changed = exact.ToArray(); changed[offset] ^= 1; hostile.Add(changed); }
                var rows = FieldOffset(exact, 11);
                var duplicate = exact.ToArray(); exact.AsSpan(rows, 96).CopyTo(duplicate.AsSpan(rows + 96)); hostile.Add(duplicate);
                var unsorted = exact.ToArray(); exact.AsSpan(rows, 96).CopyTo(unsorted.AsSpan(rows + 96));
                exact.AsSpan(rows + 96, 96).CopyTo(unsorted.AsSpan(rows)); hostile.Add(unsorted);
                foreach (var changed in hostile)
                {
                    var error = Record.Exception(() => DeepIdV2PublicationLeaseCodec.Decode(changed));
                    Assert.True(error is FormatException or CryptographicException or ArgumentException,
                        "Noncanonical lease must reject during structural parsing.");
                }
                foreach (var offset in new[] { 0, 2, 4, 160, 192, 240 })
                {
                    var changed = request.CanonicalBytes.ToArray(); changed[offset] ^= 1;
                    var error = await Record.ExceptionAsync(async () => await DeepIdV2PublicationLeaseAuthor.VerifyIssuerRequestAsync(
                        issuer, DeepIdV2PublicationLeaseWireCodec.DecodeRequest(changed)));
                    Assert.True(error is FormatException or CryptographicException);
                }
                var mismatched = response.ToArray(); mismatched[24] ^= 1;
                Assert.Throws<FormatException>(() => DeepIdV2PublicationLeaseWireCodec.DecodeResponse(request, mismatched));
            }
            if (mode == 7)
            {
                foreach (var tag in new ushort[] { 3, 4, 7, 11 })
                {
                    var changed = exact.ToArray(); changed[FieldOffset(changed, tag) + (tag == 11 ? 32 : 0)] ^= 1;
                    await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                        await DeepIdV2PublicationLeaseAuthor.VerifyOwnedResponseAsync(owned, request, changed));
                }
                var future = exact.ToArray();
                BinaryPrimitives.WriteUInt64BigEndian(future.AsSpan(FieldOffset(future, 5)), request.IssuedAtUnixSeconds + 1);
                await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationLeaseAuthor.VerifyOwnedResponseAsync(owned, request, future));
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                    await DeepIdV2PublicationLeaseAuthor.AuthorRequestAsync(owned, device, cancelled.Token));
                Sample += request.ExpiresAtUnixSeconds - ProofTime + 1;
                await Assert.ThrowsAnyAsync<CryptographicException>(async () => await capability.EnsureCurrentAsync());
            }
            if (mode == 8)
            {
                var mutable = exact.ToArray(); setCallback(() => Array.Clear(mutable));
                var captured = await DeepIdV2PublicationLeaseAuthor.VerifyOwnedResponseAsync(owned, request, mutable);
                setCallback(null); Assert.All(mutable, value => Assert.Equal(0, value));
                Assert.Equal(exact, captured.ExactDispatchRequest.ToArray());
                using var during = new CancellationTokenSource(); setCallback(during.Cancel);
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                    await DeepIdV2PublicationLeaseAuthor.AuthorRequestAsync(owned, device, during.Token));
                setCallback(null);
                var saved = Sample; var reads = 0; setCallback(() => Sample = ++reads == 1 ? saved + 1 : saved);
                await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationLeaseAuthor.AuthorRequestAsync(owned, device));
                setCallback(null); Sample = saved;
                Sample += 201;
                await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationLeaseAuthor.AuthorRequestAsync(owned, device));
            }
        }

        private static int FieldOffset(byte[] exact, ushort tag)
        {
            var offset = 12;
            while (offset < exact.Length)
            {
                var current = BinaryPrimitives.ReadUInt16BigEndian(exact.AsSpan(offset));
                var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(offset + 4)));
                if (current == tag) return offset + 8;
                offset = checked(offset + 8 + length);
            }
            throw new InvalidDataException("Missing canonical fixture field.");
        }
    }
}
