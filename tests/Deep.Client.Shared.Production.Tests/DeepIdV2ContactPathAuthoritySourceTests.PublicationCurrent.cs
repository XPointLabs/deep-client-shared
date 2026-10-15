using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0, 0, false)]
    [InlineData(1, 0, false)]
    [InlineData(2, 0, false)]
    [InlineData(2, 1, false)]
    [InlineData(2, 2, false)]
    [InlineData(2, 3, false)]
    [InlineData(0, 0, true)]
    [InlineData(1, 0, true)]
    [InlineData(2, 0, true)]
    public async Task Did2PublicationCurrent_RecoversAllUnfinishedOriginalOutcomes(int outcome, int fault, bool lostStore)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckCurrentPublicationRecoveryAsync(outcome, fault, lostStore);
    }

    private sealed partial class Fixture
    {
        internal async Task<VerifiedDeepIdV2ContactRouteClosure> CurrentPublicationIssuerRouteAsync(
            ContactPublicationAuthorityWireRequest original, CancellationToken ct)
        {
            var source = Source(); var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, ct);
            var checkpoint = fresh.Proof.CurrentCheckpoint!;
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(original.ExactDca1.Span),
                checkpoint.Binding, checkpoint.Directory);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, Boot, Sample);
            var contact = DeepIdV2ResolverClosureCodec.Decode(original.ExactDcr1.Span);
            return await DeepIdV2ContactRouteVerifier.VerifyAsync(authorization, fresh.Network, fresh.Authority,
                contact.Bundle.Field(14)[40..], original.ExactRouteClosure, source.RendezvousTrustedTime, ct);
        }

        internal async Task CheckCurrentPublicationRecoveryAsync(int outcome, int fault, bool lostStore)
        {
            // Real PQ/device/witness/node signatures, protected SQL and encrypted
            // cold reopen; in-process journal and synthetic replica receipts are
            // NOT real Registry/node transport or physical-device evidence.
            var backend = new RenewalBackend(this)
            {
                LoseBeforeReservation = outcome == 0,
                LoseAfterReservation = outcome == 1,
                LosePublicationResponse = outcome == 2
            };
            await Assert.ThrowsAsync<IOException>(() => accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend));
            Assert.Equal(outcome == 0 ? 0 : 1, backend.ReservationCount);
            Assert.Equal(outcome == 2 ? 1 : 0, backend.CompletedCount);
            Assert.Equal(outcome == 2 ? 1 : 0, backend.PublicationSignings);
            byte[][] original;
            ContactPublicationAuthorityWireRequest request;
            using (var state = await RouteState())
            {
                var entry = Assert.Single(state.Entries.Values); Assert.Equal((byte)5, entry.Phase);
                original = Enumerable.Range(0, 14).Select(index => entry.Record(index).ToArray()).ToArray();
                request = ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span);
            }
            // Move the COMPLETE conservative interval past expiry, not just
            // its centre (the genuine DTT1 fixture uncertainty is five seconds).
            var advance = checked(request.ExpiresAtUnixSeconds + 11 - CurrentProofTime);
            ProofTime += advance; Sample += advance;
            ColdReopenCompactionStorage(); var reopened = ReopenAccount();
            await backend.PrepareCurrentAsync(request); // outside the held client account lease
            backend.CurrentResponseFault = fault;
            if (fault != 0)
            {
                var error = await Record.ExceptionAsync(() => reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend));
                Assert.NotNull(error);
                if (fault == 1) Assert.IsType<FormatException>(error);
                else if (fault == 2) Assert.IsAssignableFrom<CryptographicException>(error);
                else Assert.IsType<IOException>(error);
                using var rejected = await RouteState(); var entry = Assert.Single(rejected.Entries.Values);
                Assert.Equal((byte)5, entry.Phase);
                for (var index = 0; index < 14; index++) Assert.Equal(original[index], entry.Record(index).ToArray());
                Assert.Equal(0, backend.ReplicaCalls); Assert.Equal(1, backend.PublicationSignings);
                backend.CurrentResponseFault = 0;
            }
            backend.LoseReplicaResponse = lostStore;
            byte[]? phase6Winner = null;
            if (lostStore)
            {
                await Assert.ThrowsAsync<IOException>(() => reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend));
                using (var pending = await RouteState())
                {
                    var entry = Assert.Single(pending.Entries.Values); Assert.Equal((byte)6, entry.Phase);
                    phase6Winner = entry.Record(10).ToArray(); Assert.NotEmpty(phase6Winner);
                    foreach (var index in Enumerable.Range(0, 10).Concat([12, 13])) Assert.Equal(original[index], entry.Record(index).ToArray());
                }
                var elapsed = checked(backend.LastCurrentRequest!.ExpiresAtUnixSeconds + 11 - CurrentProofTime);
                ProofTime += elapsed; Sample += elapsed;
                ColdReopenCompactionStorage(); reopened = ReopenAccount();
                await backend.PrepareCurrentAsync(request);
            }
            var result = await reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend);
            Assert.Equal(0UL, result.Generation);
            Assert.Equal(2 + (fault == 0 ? 0 : 1) + (lostStore ? 1 : 0), backend.PublicationCalls);
            Assert.Equal(1, backend.PublicationSignings); Assert.Equal(1, backend.RouteSignings);
            Assert.Equal(1, backend.ReservationCount); Assert.Equal(1, backend.CompletedCount);
            Assert.Equal(lostStore ? 2 : 1, backend.ReplicaCalls);
            using (var adopted = await RouteState())
            {
                var entry = Assert.Single(adopted.Entries.Values); Assert.Equal((byte)7, entry.Phase);
                foreach (var index in Enumerable.Range(0, 10).Concat([12, 13])) Assert.Equal(original[index], entry.Record(index).ToArray());
                var winner = ContactPublicationAuthorityWireCodec.DecodeResponse(request, entry.Record(10).Span);
                var xpu = Xpu1Codec.Decode(winner.ExactXpu1.Span);
                Assert.Equal(request.IssuedAtUnixSeconds, xpu.IssuedAtUnixSeconds);
                Assert.Equal(request.ExpiresAtUnixSeconds, xpu.ExpiresAtUnixSeconds);
                var approvalIssued = BinaryPrimitives.ReadUInt64BigEndian(xpu.ExactXpa1.Span.Slice(FieldOffset(xpu.ExactXpa1.ToArray(), 15), 8));
                if (outcome != 2) Assert.True(approvalIssued > request.ExpiresAtUnixSeconds);
                if (phase6Winner is not null) Assert.Equal(phase6Winner, entry.Record(10).ToArray());
                Assert.Equal(result.ExactXpo1.ToArray(), entry.Record(11).ToArray());
            }
            var submissions = backend.PublicationCalls; var replicas = backend.ReplicaCalls;
            var again = await reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend);
            Assert.Equal(result.ExactXpo1.ToArray(), again.ExactXpo1.ToArray());
            Assert.Equal(submissions, backend.PublicationCalls); Assert.Equal(replicas, backend.ReplicaCalls);
            foreach (var bytes in original) CryptographicOperations.ZeroMemory(bytes);
            if (phase6Winner is not null) CryptographicOperations.ZeroMemory(phase6Winner);
        }
    }
}
