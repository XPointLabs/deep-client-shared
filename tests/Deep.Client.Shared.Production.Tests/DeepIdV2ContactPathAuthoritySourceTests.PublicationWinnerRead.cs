using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Did2PublicationWinnerRead_ExpiredLostReplyColdReopenKeepsOriginalIntent(int fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckPublicationWinnerReadAsync(fault);
    }

    private sealed partial class Fixture
    {
        internal async Task<VerifiedDeepIdV2ContactRouteClosure> CurrentWinnerReadRouteAsync(
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

        internal async Task CheckPublicationWinnerReadAsync(int fault)
        {
            // Real protected SQL/owner/device/witness crypto; in-process backend
            // and synthetic replica receipts are not Registry/device E2E.
            var backend = new RenewalBackend(this) { LosePublicationResponse = true };
            await Assert.ThrowsAsync<IOException>(() => accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend));
            byte[][] original;
            ContactPublicationAuthorityWireRequest request;
            using (var state = await RouteState())
            {
                var entry = Assert.Single(state.Entries.Values); Assert.Equal((byte)5, entry.Phase);
                original = Enumerable.Range(0, 14).Select(index => entry.Record(index).ToArray()).ToArray();
                request = ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span);
            }
            var advance = checked(request.ExpiresAtUnixSeconds + 2 - ProofTime);
            ProofTime += advance; Sample += advance;
            ColdReopenCompactionStorage(); var reopened = ReopenAccount();
            // Prepare the independent in-process issuer outside the client's
            // held account lease. A real Registry reader never calls this owner.
            await backend.PrepareWinnerReadAsync(request);
            backend.WinnerReadFault = fault;
            if (fault != 0)
            {
                var error = await Record.ExceptionAsync(() => reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend));
                Assert.NotNull(error);
                if (fault == 1) Assert.IsType<FormatException>(error);
                else if (fault == 2) Assert.IsType<ApplicationCoreFormatException>(error);
                else Assert.IsType<IOException>(error);
                using var rejected = await RouteState(); var entry = Assert.Single(rejected.Entries.Values);
                Assert.Equal((byte)5, entry.Phase);
                for (var i = 0; i < 14; i++) Assert.Equal(original[i], entry.Record(i).ToArray());
                Assert.Equal(0, backend.ReplicaCalls); Assert.Equal(1, backend.PublicationSignings);
                backend.WinnerReadFault = 0;
            }
            var result = await reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend);
            Assert.Equal(0UL, result.Generation);
            Assert.Equal(fault == 0 ? 1 : 2, backend.WinnerReadCalls);
            Assert.Equal(1, backend.PublicationCalls); Assert.Equal(1, backend.PublicationSignings); Assert.Equal(1, backend.RouteSignings);
            using (var adopted = await RouteState())
            {
                var entry = Assert.Single(adopted.Entries.Values); Assert.Equal((byte)7, entry.Phase);
                foreach (var i in Enumerable.Range(0, 10).Concat([12, 13])) Assert.Equal(original[i], entry.Record(i).ToArray());
                Assert.NotEmpty(entry.Record(10).ToArray()); Assert.Equal(result.ExactXpo1.ToArray(), entry.Record(11).ToArray());
            }
            var reads = backend.WinnerReadCalls; var replicas = backend.ReplicaCalls;
            var again = await reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend);
            Assert.Equal(result.ExactXpo1.ToArray(), again.ExactXpo1.ToArray());
            Assert.Equal(reads, backend.WinnerReadCalls); Assert.Equal(replicas, backend.ReplicaCalls);
            foreach (var bytes in original) CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
