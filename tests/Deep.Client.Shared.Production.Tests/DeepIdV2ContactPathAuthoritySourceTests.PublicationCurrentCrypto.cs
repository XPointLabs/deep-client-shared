using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2PublicationCurrent_UsesCurrentApprovalAndImmutableBody()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckRetainedPublicationIntentAsync(5);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    public async Task Did2PublicationCurrent_HostileBytesCurrentScopeAndCallbacksFailClosed(int mode)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckRetainedPublicationIntentAsync(mode);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckCurrentPublicationCryptoAsync(int mode, VerifiedDeepIdV2ContactRouteClosure route,
            AuthoredDeepIdV2ContactObject contact, ContactPublicationAuthorityWireRequest originalIntent,
            OwnedGenesisDeviceSecrets device, Action<Action?> setCallback)
        {
            // Actual signatures, not a permanent-journal or live-device claim.
            // No prior result was persisted; the old body is approved NOW.
            var originalBytes = ContactPublicationAuthorityWireCodec.EncodeRequest(originalIntent);
            var request = await DeepIdV2PublicationCurrentAuthor.AuthorOwnedRequestAsync(route, contact, originalIntent, device);
            var submission = await DeepIdV2PublicationCurrentAuthor.VerifyIssuerRequestAsync(route, request);
            var original = await DeepIdV2PublicationCurrentAuthor.AuthorApprovalAsync(submission, PublicationWitnesses());
            var issuer = await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route, originalIntent, original.CanonicalBytes);
            var lease = await DeepIdV2PublicationCurrentAuthor.AuthorLeaseAsync(submission, issuer, PublicationLeaseWitnesses());
            var exact = lease.CanonicalBytes.ToArray();
            Assert.True(request.IssuedAtUnixSeconds > original.ExpiresAtUnixSeconds);
            Assert.Equal(originalIntent.IssuedAtUnixSeconds, original.IssuedAtUnixSeconds);
            Assert.Equal(originalIntent.ExpiresAtUnixSeconds, original.ExpiresAtUnixSeconds);
            var approval = original.ExactXpa1.ToArray();
            Assert.True(BinaryPrimitives.ReadUInt64BigEndian(approval.AsSpan(FieldOffset(approval, 15))) > original.ExpiresAtUnixSeconds);
            Assert.Equal(originalBytes, ContactPublicationAuthorityWireCodec.EncodeRequest(request.OriginalRequest));
            var response = DeepIdV2PublicationCurrentWireCodec.EncodeResponse(request, exact);
            Assert.Equal(exact, DeepIdV2PublicationCurrentWireCodec.DecodeResponse(request, response).CanonicalBytes.ToArray());
            var capability = await DeepIdV2PublicationCurrentAuthor.VerifyOwnedResponseAsync(route, contact, originalIntent, request, response);
            await capability.EnsureCurrentAsync();
            Assert.Equal(exact, capability.ExactDispatchRequest.ToArray());
            Assert.Equal(original.CanonicalBytes.ToArray(), capability.ExactOriginalXpu1.ToArray());
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
                    Assert.True(error is FormatException or CryptographicException or ArgumentException);
                }
                var mismatched = response.ToArray(); mismatched[24] ^= 1;
                Assert.Throws<FormatException>(() => DeepIdV2PublicationCurrentWireCodec.DecodeResponse(request, mismatched));
            }
            if (mode == 7)
            {
                foreach (var tag in new ushort[] { 3, 4, 7, 11 })
                {
                    var changed = response.ToArray(); changed[60 + FieldOffset(exact, tag) + (tag == 11 ? 32 : 0)] ^= 1;
                    var error = await Record.ExceptionAsync(async () => await DeepIdV2PublicationCurrentAuthor.VerifyOwnedResponseAsync(
                        route, contact, originalIntent, request, changed));
                    if (tag == 3) Assert.IsType<FormatException>(error);
                    else Assert.IsAssignableFrom<CryptographicException>(error);
                }
                var future = response.ToArray();
                BinaryPrimitives.WriteUInt64BigEndian(future.AsSpan(60 + FieldOffset(exact, 5)), request.IssuedAtUnixSeconds + 1);
                await Assert.ThrowsAsync<FormatException>(async () => await DeepIdV2PublicationCurrentAuthor.VerifyOwnedResponseAsync(
                    route, contact, originalIntent, request, future));
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                    await DeepIdV2PublicationCurrentAuthor.AuthorOwnedRequestAsync(route, contact, originalIntent, device, cancelled.Token));
                Sample += request.ExpiresAtUnixSeconds - ProofTime + 1;
                await Assert.ThrowsAnyAsync<CryptographicException>(async () => await capability.EnsureCurrentAsync());
            }
            if (mode == 8)
            {
                var mutable = response.ToArray(); setCallback(() => Array.Clear(mutable));
                var captured = await DeepIdV2PublicationCurrentAuthor.VerifyOwnedResponseAsync(route, contact, originalIntent, request, mutable);
                setCallback(null); Assert.All(mutable, value => Assert.Equal(0, value));
                Assert.Equal(exact, captured.ExactDispatchRequest.ToArray());
                using var during = new CancellationTokenSource(); setCallback(during.Cancel);
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                    await DeepIdV2PublicationCurrentAuthor.AuthorOwnedRequestAsync(route, contact, originalIntent, device, during.Token));
                setCallback(null);
                var saved = Sample; var reads = 0; setCallback(() => Sample = ++reads == 1 ? saved + 1 : saved);
                await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationCurrentAuthor.AuthorOwnedRequestAsync(route, contact, originalIntent, device));
                setCallback(null); Sample = saved;
                Sample += 201;
                await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationCurrentAuthor.AuthorOwnedRequestAsync(route, contact, originalIntent, device));
            }
            if (mode == 9)
            {
                var wrapper = ContactCoordinationOnionCodec.EncodeRequest(ContactCoordinationTarget.PublicationCurrent, request.CanonicalBytes.Span);
                var parsed = ContactCoordinationOnionCodec.DecodeRequest(wrapper);
                var path = Deep.Client.Shared.Services.XPointNetworkV1.ContactResolveCanonicalPathRequest.Decode(wrapper);
                Assert.Equal(request.ViewHash.ToArray(), path.ViewHash.ToArray());
                Assert.Equal(request.GatewayShard.ToArray(), path.ShardKey.ToArray());
                Assert.Equal(request.GatewayShard.ToArray(), parsed.GatewayShard.ToArray());
                Assert.Equal(response, ContactCoordinationOnionCodec.DecodeResponse(parsed, ContactCoordinationOnionCodec.EncodeResponse(parsed, response)));
                foreach (var offset in new[] { 0, 2, 4, 8, 24, 56, 88, 96, 128, 160, 168, 176, 180, request.CanonicalBytes.Length - 1 })
                {
                    var changed = request.CanonicalBytes.ToArray(); changed[offset] ^= 1;
                    var error = await Record.ExceptionAsync(async () => await DeepIdV2PublicationCurrentAuthor.VerifyIssuerRequestAsync(
                        route, DeepIdV2PublicationCurrentWireCodec.DecodeRequest(changed)));
                    Assert.True(error is FormatException or CryptographicException or ArgumentException, $"Current field offset {offset} was not rejected.");
                }
                foreach (var damaged in new[] { request.CanonicalBytes[..^1].ToArray(), request.CanonicalBytes.ToArray().Append((byte)0).ToArray(),
                    new byte[DeepIdV2PublicationCurrentWireCodec.MaximumRequestBytes + 1], Array.Empty<byte>() })
                    Assert.Throws<FormatException>(() => DeepIdV2PublicationCurrentWireCodec.DecodeRequest(damaged));
                foreach (var retired in new byte[] { 3, 4 })
                {
                    var changed = wrapper.ToArray(); changed[6] = retired;
                    Assert.Throws<FormatException>(() => ContactCoordinationOnionCodec.DecodeRequest(changed));
                }
                foreach (var offset in new[] { 0, 2, 4, 8, 24, 56, response.Length - 1 })
                {
                    var changed = response.ToArray(); changed[offset] ^= 1;
                    var error = await Record.ExceptionAsync(async () => await DeepIdV2PublicationCurrentAuthor.VerifyOwnedResponseAsync(
                        route, contact, originalIntent, request, changed));
                    Assert.True(error is FormatException or CryptographicException or ArgumentException);
                }
                using var cancel = new CancellationTokenSource(); cancel.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                    await DeepIdV2PublicationCurrentAuthor.VerifyIssuerRequestAsync(route, request, ct: cancel.Token));
                var oldSample = Sample; setCallback(() => Sample--);
                var clockFailure = await Assert.ThrowsAsync<Deep.Protocol.AccountDirectoryV1.AccountDirectoryFreshnessVerificationException>(
                    async () => await DeepIdV2PublicationCurrentAuthor.VerifyIssuerRequestAsync(route, request));
                Assert.Equal("DirectoryFreshnessExpired", clockFailure.Code);
                setCallback(null); Sample = oldSample;
                Xpu1Request futureApproval;
                try
                {
                    Sample++;
                    var later = await DeepIdV2PublicationCurrentAuthor.AuthorOwnedRequestAsync(route, contact, originalIntent, device);
                    var laterSubmission = await DeepIdV2PublicationCurrentAuthor.VerifyIssuerRequestAsync(route, later);
                    futureApproval = await DeepIdV2PublicationCurrentAuthor.AuthorApprovalAsync(laterSubmission, PublicationWitnesses());
                }
                finally { Sample = oldSample; }
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route, originalIntent, futureApproval.CanonicalBytes));
            }
            CryptographicOperations.ZeroMemory(originalBytes);
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
